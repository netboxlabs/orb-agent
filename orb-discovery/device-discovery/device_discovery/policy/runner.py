#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""Orb Discovery Policy Runner."""

import logging
import uuid
from datetime import datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from napalm import get_network_driver

from device_discovery.client import Client
from device_discovery.discovery import discover_device_driver, supported_drivers
from device_discovery.policy.models import Config, Defaults, Napalm, Status

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

    def setup(self, name: str, config: Config, scopes: list[Napalm]):
        """
        Set up the policy runner.

        Args:
        ----
            name: Policy name.
            config: Configuration data containing site information.
            scopes: scope data for the devices.

        """
        self.name = name.replace('\r\n', '').replace('\n', '')
        self.config = config

        if self.config is None:
            self.config = Config(defaults={})
        elif self.config.defaults is None:
            self.config.defaults = {}

        self.scheduler.start()
        for scope in scopes:
            sanitized_hostname = scope.hostname.replace('\r\n', '').replace('\n', '')
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
            self.scheduler.add_job(
                self.run, id=id, trigger=trigger, args=[id, scope, self.config]
            )

            self.status = Status.RUNNING

    def run(self, id: str, scope: Napalm, config: Config):
        """
        Run the device driver code for a single scope item.

        Args:
        ----
            id: Job ID.
            scope: scope data for the device.
            config: Configuration data containing site information.

        """
        sanitized_hostname = scope.hostname.replace('\r\n', '').replace('\n', '')
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
            np_driver = get_network_driver(scope.driver)
            logger.info(
                f"Policy {self.name}, Hostname {sanitized_hostname}: Getting information"
            )
            with np_driver(
                scope.hostname,
                scope.username,
                scope.password,
                scope.timeout,
                scope.optional_args,
            ) as device:
                data = {
                    "driver": scope.driver,
                    "device": device.get_facts(),
                    "interface": device.get_interfaces(),
                    "interface_ip": device.get_interfaces_ip(),
                    "defaults": config.defaults,
                }
                Client().ingest(scope.hostname, data)
        except Exception as e:
            logger.error(f"Policy {self.name}, Hostname {sanitized_hostname}: {e}")

    def stop(self):
        """Stop the policy runner."""
        self.scheduler.shutdown()
        self.status = Status.FINISHED
