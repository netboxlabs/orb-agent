#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""Orb Worker Policy Runner."""

import logging
from datetime import datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from netboxlabs.diode.sdk import DiodeClient

from worker.backend import Backend, load_class
from worker.models import DiodeConfig, Policy, Status

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PolicyRunner:
    """Policy Runner class."""

    def __init__(self):
        """Initialize the PolicyRunner."""
        self.name = ""
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
        client = DiodeClient(
            target=diode_config.target,
            app_name=(
                f"{diode_config.prefix}/{metadata.app_name}"
                if diode_config.prefix
                else metadata.app_name
            ),
            app_version=metadata.app_version,
            api_key=diode_config.api_key,
        )

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

    def run(self, client: DiodeClient, backend: Backend, policy: Policy):
        """
        Run the custom backend code for the specified scope.

        Args:
        ----
            client: Diode client.
            backend: Backend class.
            policy: Policy configuration.

        """
        try:
            entities = backend.run(self.name, policy)
            response = client.ingest(entities)
            if response.errors:
                logger.error(
                    f"ERROR ingestion failed for {self.name} : {response.errors}"
                )
            else:
                logger.info(f"Policy {self.name}: Successful ingestion")
        except Exception as e:
            logger.error(f"Policy {self.name}: {e}")

    def stop(self):
        """Stop the policy runner."""
        self.scheduler.shutdown()
        self.status = Status.FINISHED
