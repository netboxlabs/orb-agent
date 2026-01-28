#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""Device Discovery Policy Runner."""

import logging
import time
import uuid
from datetime import datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.base import BaseTrigger
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from napalm import get_network_driver

from device_discovery.client import Client
from device_discovery.discovery import discover_device_driver, supported_drivers
from device_discovery.metrics import get_metric
from device_discovery.policy.models import Config, Defaults, Napalm, Options, Status
from device_discovery.policy.portscan import (
    expand_hostnames,
    find_reachable_hosts,
)
from device_discovery.policy.run import RunStatus, RunStore

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PolicyRunner:
    """Policy Runner class."""

    def __init__(self):
        """Initialize the PolicyRunner."""
        self.name = ""
        self.scopes = dict[str, Napalm]()
        self.config = None
        self.status = Status.NEW
        self.scheduler = BackgroundScheduler()
        self.run_store = None

    def setup(
        self, name: str, config: Config, scopes: list[Napalm], run_store: RunStore
    ):
        """
        Set up the policy runner.

        Args:
        ----
            name: Policy name.
            config: Configuration data containing site information.
            scopes: scope data for the devices.
            run_store: RunStore instance for tracking runs.

        """
        self.name = name.replace("\r\n", "").replace("\n", "")
        self.config = config
        self.run_store = run_store

        self.config = self.config or Config(defaults=Defaults(), options=Options())
        self.config.defaults = self.config.defaults or Defaults()
        self.config.options = self.config.options or Options()

        self.scheduler.start()
        set_telemetry = True
        for scope in scopes:
            sanitized_hostname = scope.hostname.replace("\r\n", "").replace("\n", "")
            if scope.driver and scope.driver not in supported_drivers:
                self.scheduler.shutdown()
                raise Exception(
                    f"Policy {self.name}, Hostname {sanitized_hostname}: specified driver '{scope.driver}' "
                    f"was not found in the current installed drivers list: {supported_drivers}."
                )

            if self.config.schedule is not None:
                logger.info(
                    f"Policy {self.name}, Hostname {sanitized_hostname}: Scheduled to run with '{self.config.schedule}'"
                )
                trigger = CronTrigger.from_crontab(self.config.schedule)
            else:
                logger.info(
                    f"Policy {self.name}, Hostname {sanitized_hostname}: One-time run"
                )
                trigger = DateTrigger(run_date=datetime.now() + timedelta(seconds=1))

            id = str(uuid.uuid4())
            self.scopes[id] = scope

            config = self.config.model_copy(deep=True)
            if scope.override_defaults is not None:
                config.defaults = config.defaults.model_copy(
                    update=scope.override_defaults.model_dump(exclude_none=True)
                )
            hostnames, parsed_as_range = expand_hostnames(sanitized_hostname)

            if parsed_as_range:
                logger.info(
                    f"Policy {self.name}, Hostname {sanitized_hostname}: Expanded to {len(hostnames)} addresses"
                )
                self.scheduler.add_job(
                    self.run_scan,
                    id=id,
                    trigger=DateTrigger(run_date=datetime.now() + timedelta(seconds=1)),
                    args=[hostnames, trigger, scope, config],
                    misfire_grace_time=None,
                )
            else:
                self.scheduler.add_job(
                    self.run,
                    id=id,
                    trigger=trigger,
                    args=[id, scope, config],
                    misfire_grace_time=None,
                )
            if set_telemetry:
                set_telemetry = False
                self.scheduler.add_job(
                    self.telemetry,
                    id=str(uuid.uuid4()),
                    trigger=trigger,
                )
            self.status = Status.RUNNING

        active_policies = get_metric("active_policies")
        if active_policies:
            active_policies.add(1, {"policy": self.name})

    def telemetry(self):
        """Telemetry job."""
        policy_executions = get_metric("policy_executions")
        if policy_executions:
            policy_executions.add(1, {"policy": self.name})

    def _discover_driver(self, scope: Napalm, sanitized_hostname: str) -> bool:
        """
        Discover the device driver if not provided.

        Args:
        ----
            scope: Scope data for the device.
            sanitized_hostname: Sanitized hostname for logging.

        Returns:
        -------
            bool: True if driver discovery succeeded or wasn't needed, False otherwise.

        """
        if scope.driver is None:
            logger.info(
                f"Policy {self.name}, Hostname {sanitized_hostname}: Driver not informed, discovering it"
            )
            scope.driver = discover_device_driver(scope)
            if scope.driver is None:
                self.status = Status.FAILED
                logger.error(
                    f"Policy {self.name}, Hostname {sanitized_hostname}: Not able to discover device driver"
                )
                return False
        return True

    def _collect_device_data(
        self, scope: Napalm, sanitized_hostname: str, config: Config
    ):
        """
        Connect to device and collect data.

        Args:
        ----
            scope: Scope data for the device.
            sanitized_hostname: Sanitized hostname for logging.
            config: Configuration data containing site information.

        """
        np_driver = get_network_driver(scope.driver)
        logger.info(
            f"Policy {self.name}, Hostname {sanitized_hostname}: Getting information"
        )

        # Measure device connection time
        connection_start_time = time.perf_counter()
        with np_driver(
            scope.hostname,
            scope.username,
            scope.password,
            scope.timeout,
            scope.optional_args,
        ) as device:
            connection_duration = (time.perf_counter() - connection_start_time) * 1000
            device_connection_latency = get_metric("device_connection_latency")
            if device_connection_latency:
                device_connection_latency.record(
                    connection_duration,
                    {
                        "policy": self.name,
                        "hostname": sanitized_hostname,
                        "driver": scope.driver,
                    },
                )

            data = {
                "driver": scope.driver,
                "device": device.get_facts(),
                "interface": device.get_interfaces(),
                "interface_ip": device.get_interfaces_ip(),
                "defaults": config.defaults,
                "options": config.options,
            }
            try:
                data["vlan"] = device.get_vlans()
            except Exception as e:
                logger.warning(
                    f"Policy {self.name}, Hostname {sanitized_hostname}: Error getting VLANs: {e}. Continuing without VLAN data."
                )
            metadata = {"policy_name": self.name, "hostname": sanitized_hostname}
            Client().ingest(metadata, data)
            discovery_success = get_metric("discovery_success")
            if discovery_success:
                discovery_success.add(1, {"policy": self.name})

    def run_scan(
        self, hostnames: list[str], trigger: BaseTrigger, scope: Napalm, config: Config
    ):
        """
        Scan hostnames for reachable ports and schedule discovery jobs.

        Args:
        ----
            hostnames: Hostnames or addresses expanded from the policy scope.
            trigger: Trigger used when scheduling discovery jobs for reachable hosts.
            scope: Base scope data for the devices.
            config: Configuration data containing defaults and options.

        """
        options = config.options or Options()
        ports = options.port_scan_ports
        timeout = options.port_scan_timeout
        if not hostnames:
            return

        # Get original hostname from scope for parent tracking
        original_hostname = scope.hostname

        # CREATE RUN FOR SCAN OPERATION
        scan_run = self.run_store.create_run(
            policy_name=self.name,
            target=original_hostname,
            parent_target="",
        )

        try:
            results = find_reachable_hosts(hostnames, ports, timeout)
            reachable_count = sum(1 for v in results.values() if v)

            # UPDATE SCAN RUN
            self.run_store.update_run(
                policy_name=self.name,
                target=original_hostname,
                run_id=scan_run.id,
                status=RunStatus.COMPLETED,
                error=None,
                entity_count=reachable_count,
            )

            for hostname in hostnames:
                if results.get(hostname):
                    logger.info(
                        f"Policy {self.name}, Hostname {hostname}: Reachable port found, scheduling discovery job"
                    )
                    id = str(uuid.uuid4())
                    self.scopes[id] = scope.model_copy(update={"hostname": hostname})
                    self.scheduler.add_job(
                        self.run_with_parent,
                        id=id,
                        trigger=trigger,
                        args=[id, self.scopes[id], config, original_hostname],
                        misfire_grace_time=None,
                    )
                else:
                    logger.info(
                        f"Policy {self.name}, Hostname {hostname}: No reachable port found, skipping discovery job"
                    )
        except Exception as e:
            logger.error(
                f"Policy {self.name}, Error during port scan for {original_hostname}: {e}"
            )
            # UPDATE SCAN RUN AS FAILED
            self.run_store.update_run(
                policy_name=self.name,
                target=original_hostname,
                run_id=scan_run.id,
                status=RunStatus.FAILED,
                error=e,
                entity_count=0,
            )

    def run(self, id: str, scope: Napalm, config: Config):
        """
        Run the device driver code for a single scope item.

        Args:
        ----
            id: Job ID.
            scope: scope data for the device.
            config: Configuration data containing site information.

        """
        discovery_start_time = time.perf_counter()
        sanitized_hostname = scope.hostname.replace("\r\n", "").replace("\n", "")

        # CREATE RUN AT START
        run = self.run_store.create_run(
            policy_name=self.name,
            target=sanitized_hostname,
            parent_target="",
        )

        # Try to discover driver if needed
        if not self._discover_driver(scope, sanitized_hostname):
            # UPDATE RUN ON DRIVER DISCOVERY FAILURE
            self.run_store.update_run(
                policy_name=self.name,
                target=sanitized_hostname,
                run_id=run.id,
                status=RunStatus.FAILED,
                error=Exception("Not able to discover device driver"),
                entity_count=0,
            )
            try:
                self.scheduler.remove_job(id)
            except Exception as e:
                logger.error(
                    f"Policy {self.name}, Hostname {sanitized_hostname}: Error removing job: {e}"
                )
            return

        logger.info(
            f"Policy {self.name}, Hostname {sanitized_hostname}: Get driver '{scope.driver}'"
        )

        try:
            discovery_attempts = get_metric("discovery_attempts")
            if discovery_attempts:
                discovery_attempts.add(1, {"policy": self.name})

            # Collect data from device
            self._collect_device_data(scope, sanitized_hostname, config)

            # UPDATE RUN ON SUCCESS
            self.run_store.update_run(
                policy_name=self.name,
                target=sanitized_hostname,
                run_id=run.id,
                status=RunStatus.COMPLETED,
                error=None,
                entity_count=1,
            )

            # Record total discovery duration
            discovery_latency = get_metric("discovery_latency")
            if discovery_latency:
                discovery_duration = (time.perf_counter() - discovery_start_time) * 1000
                discovery_latency.record(
                    discovery_duration,
                    {
                        "policy": self.name,
                        "hostname": sanitized_hostname,
                        "driver": scope.driver,
                    },
                )

        except Exception as e:
            # UPDATE RUN ON FAILURE
            self.run_store.update_run(
                policy_name=self.name,
                target=sanitized_hostname,
                run_id=run.id,
                status=RunStatus.FAILED,
                error=e,
                entity_count=0,
            )

            discovery_failure = get_metric("discovery_failure")
            if discovery_failure:
                discovery_failure.add(1, {"policy": self.name})
            logger.error(
                f"Policy {self.name}, Hostname {sanitized_hostname}: {e}", exc_info=True
            )
            # Still record discovery duration on failure
            discovery_latency = get_metric("discovery_latency")
            if discovery_latency:
                discovery_duration = (time.perf_counter() - discovery_start_time) * 1000
                discovery_latency.record(
                    discovery_duration,
                    {
                        "policy": self.name,
                        "hostname": sanitized_hostname,
                        "driver": str(scope.driver),
                        "status": "failed",
                    },
                )

    def run_with_parent(
        self, id: str, scope: Napalm, config: Config, parent_target: str
    ):
        """
        Run the device driver code for a single scope item with parent tracking.

        This is used for targets discovered from range scans to maintain the
        parent-child relationship.

        Args:
        ----
            id: Job ID.
            scope: scope data for the device.
            config: Configuration data containing site information.
            parent_target: Parent target that this target was discovered from.

        """
        discovery_start_time = time.perf_counter()
        sanitized_hostname = scope.hostname.replace("\r\n", "").replace("\n", "")

        # CREATE RUN WITH PARENT
        run = self.run_store.create_run(
            policy_name=self.name,
            target=sanitized_hostname,
            parent_target=parent_target,
        )

        # Try to discover driver if needed
        if not self._discover_driver(scope, sanitized_hostname):
            # UPDATE RUN ON DRIVER DISCOVERY FAILURE
            self.run_store.update_run(
                policy_name=self.name,
                target=sanitized_hostname,
                run_id=run.id,
                status=RunStatus.FAILED,
                error=Exception("Not able to discover device driver"),
                entity_count=0,
            )
            try:
                self.scheduler.remove_job(id)
            except Exception as e:
                logger.error(
                    f"Policy {self.name}, Hostname {sanitized_hostname}: Error removing job: {e}"
                )
            return

        logger.info(
            f"Policy {self.name}, Hostname {sanitized_hostname}: Get driver '{scope.driver}'"
        )

        try:
            discovery_attempts = get_metric("discovery_attempts")
            if discovery_attempts:
                discovery_attempts.add(1, {"policy": self.name})

            # Collect data from device
            self._collect_device_data(scope, sanitized_hostname, config)

            # UPDATE RUN ON SUCCESS
            self.run_store.update_run(
                policy_name=self.name,
                target=sanitized_hostname,
                run_id=run.id,
                status=RunStatus.COMPLETED,
                error=None,
                entity_count=1,
            )

            # Record total discovery duration
            discovery_latency = get_metric("discovery_latency")
            if discovery_latency:
                discovery_duration = (time.perf_counter() - discovery_start_time) * 1000
                discovery_latency.record(
                    discovery_duration,
                    {
                        "policy": self.name,
                        "hostname": sanitized_hostname,
                        "driver": scope.driver,
                    },
                )

        except Exception as e:
            # UPDATE RUN ON FAILURE
            self.run_store.update_run(
                policy_name=self.name,
                target=sanitized_hostname,
                run_id=run.id,
                status=RunStatus.FAILED,
                error=e,
                entity_count=0,
            )

            discovery_failure = get_metric("discovery_failure")
            if discovery_failure:
                discovery_failure.add(1, {"policy": self.name})
            logger.error(
                f"Policy {self.name}, Hostname {sanitized_hostname}: {e}", exc_info=True
            )
            # Still record discovery duration on failure
            discovery_latency = get_metric("discovery_latency")
            if discovery_latency:
                discovery_duration = (time.perf_counter() - discovery_start_time) * 1000
                discovery_latency.record(
                    discovery_duration,
                    {
                        "policy": self.name,
                        "hostname": sanitized_hostname,
                        "driver": str(scope.driver),
                        "status": "failed",
                    },
                )

    def stop(self):
        """Stop the policy runner."""
        self.scheduler.shutdown()
        active_policies = get_metric("active_policies")
        if active_policies:
            active_policies.add(-1, {"policy": self.name})
        self.status = Status.FINISHED
