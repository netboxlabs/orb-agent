#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""Orb Worker Policy Runner."""

import logging
import time
from datetime import datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from netboxlabs.diode.sdk import (
    DiodeClient,
    DiodeDryRunClient,
    DiodeOTLPClient,
    create_message_chunks,
    estimate_message_size,
)

from worker.backend import Backend, load_class
from worker.metrics import get_metric
from worker.models import DiodeConfig, Policy, Status

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PolicyRunner:
    """Policy Runner class."""

    def __init__(self):
        """Initialize the PolicyRunner."""
        self.name = ""
        self.metadata = None
        self.policy = None
        self.status = Status.NEW
        self.scheduler = BackgroundScheduler()

    def setup(self, name: str, diode_config: DiodeConfig, policy: Policy):
        """
        Set up the policy runner.

        Args:
        ----
            name: Policy name.
            diode_config: Diode configuration data.
            policy: Policy configuration data.

        """
        self.name = name.replace("\r\n", "").replace("\n", "")
        policy.config.package = policy.config.package.replace("\r\n", "").replace(
            "\n", ""
        )
        backend_class = load_class(policy.config.package)
        backend = backend_class()

        metadata = backend.setup()
        app_name = (
            f"{diode_config.prefix}/{metadata.app_name}"
            if diode_config.prefix
            else metadata.app_name
        )
        if diode_config.dry_run:
            client = DiodeDryRunClient(
                app_name=app_name,
                output_dir=diode_config.dry_run_output_dir,
            )
        elif (
            diode_config.client_id is not None
            and diode_config.client_secret is not None
        ):
            client = DiodeClient(
                target=diode_config.target,
                app_name=app_name,
                app_version=metadata.app_version,
                client_id=diode_config.client_id,
                client_secret=diode_config.client_secret,
            )
        else:
            logger.debug("Initializing Diode OTLP client")
            client = DiodeOTLPClient(
                target=diode_config.target,
                app_name=app_name,
                app_version=metadata.app_version,
            )

        self.metadata = metadata
        self.policy = policy

        self.scheduler.start()

        if self.policy.config.schedule is not None:
            logger.info(
                f"Policy {self.name}, Package {self.policy.config.package}: Scheduled to run with '{self.policy.config.schedule}'"
            )
            trigger = CronTrigger.from_crontab(self.policy.config.schedule)
        else:
            logger.info(
                f"Policy {self.name}, Package {self.policy.config.package}: One-time run"
            )
            trigger = DateTrigger(run_date=datetime.now() + timedelta(seconds=1))

        self.scheduler.add_job(
            self.run,
            trigger=trigger,
            args=[client, backend, self.policy],
        )

        self.status = Status.RUNNING

        active_policies = get_metric("active_policies")
        if active_policies:
            active_policies.add(1, {"policy": self.name})

    def run(
        self,
        client: DiodeClient | DiodeDryRunClient | DiodeOTLPClient,
        backend: Backend,
        policy: Policy,
    ):
        """
        Run the custom backend code for the specified scope.

        Args:
        ----
            client: Diode client.
            backend: Backend class.
            policy: Policy configuration.

        """
        policy_executions = get_metric("policy_executions")
        if policy_executions:
            policy_executions.add(1, {"policy": self.name})

        exec_start_time = time.perf_counter()
        try:
            entities = backend.run(self.name, policy)
            metadata = {
                "policy_name": self.name,
                "worker_backend": self.metadata.name,
            }
            chunk_num = 1
            size_bytes = estimate_message_size(entities)

            if size_bytes > (3.0 * 1024 * 1024):
                chunks = create_message_chunks(entities)
                chunk_num = len(chunks)
                for chunk in chunks:
                    response = client.ingest(entities=chunk, metadata=metadata)
                    if response.errors:
                        raise RuntimeError(
                            f"Chunk ingestion failed: {response.errors}"
                        )
            else:
                response = client.ingest(entities=entities, metadata=metadata)
                if response.errors:
                    raise RuntimeError(f"Entities ingestion failed: {response.errors}")
            logger.info(
                f"Policy {self.name}: Successfully ingested {len(entities)} entities in {chunk_num} chunks"
            )
            run_success = get_metric("backend_execution_success")
            if run_success:
                run_success.add(
                    1,
                    {
                        "policy": self.name,
                        "backend": self.metadata.name,
                        "app_name": self.metadata.app_name,
                        "app_version": self.metadata.app_version,
                    },
                )
        except Exception as e:
            logger.error(f"Policy {self.name}: {e}")
            run_failure = get_metric("backend_execution_failure")
            if run_failure:
                run_failure.add(
                    1,
                    {
                        "policy": self.name,
                        "backend": self.metadata.name,
                        "app_name": self.metadata.app_name,
                        "app_version": self.metadata.app_version,
                    },
                )

        backend_execution_latency = get_metric("backend_execution_latency")
        if backend_execution_latency:
            exec_duration = (time.perf_counter() - exec_start_time) * 1000
            backend_execution_latency.record(
                exec_duration,
                {
                    "policy": self.name,
                    "backend": self.metadata.name,
                    "app_name": self.metadata.app_name,
                    "app_version": self.metadata.app_version,
                },
            )

    def stop(self):
        """Stop the policy runner."""
        self.scheduler.shutdown()
        self.status = Status.FINISHED
        active_policies = get_metric("active_policies")
        if active_policies:
            active_policies.add(-1, {"policy": self.name})
