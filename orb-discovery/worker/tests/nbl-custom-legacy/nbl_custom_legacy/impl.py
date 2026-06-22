#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
NetBox Labs - Legacy Mock Impl.

A deliberately legacy backend: it implements only the deprecated instance
``setup()`` and does NOT implement the ``describe()`` classmethod. It exists to
prove the worker's legacy fallback path still works end to end — the worker must
construct it bare, read its metadata via ``setup()`` on the instance it then
schedules, and attach the ingest sink afterwards.
"""

import logging
from collections.abc import Iterable

from netboxlabs.diode.sdk.ingester import Device, Entity
from worker.backend import Backend
from worker.models import Metadata, Policy

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LegacyMockBackend(Backend):
    """Legacy (setup()-only) mock backend for testing the deprecated path."""

    def __init__(self) -> None:
        """Construct with a custom zero-arg signature (no ingest_sink kwarg)."""
        self.app_started = False

    def setup(self) -> Metadata:
        """Initialise instance state and return metadata (legacy contract)."""
        # State set here must be live when run() executes — i.e. the instance
        # set up here is the instance the worker schedules.
        self.app_started = True
        return Metadata(
            name="legacy_mock",
            app_name="legacy_mock_app",
            app_version="0.1.0",
        )

    def run(self, policy_name: str, policy: Policy) -> Iterable[Entity]:
        """Return a single Device entity; assert setup() ran first."""
        if not self.app_started:
            raise RuntimeError("run() reached before setup() initialised the instance")
        device = Device(
            name=f"legacy-device-{policy_name}",
            device_type="Legacy Device Type",
            platform="Legacy Platform",
            manufacturer="Legacy Manufacturer",
            site="Site Legacy",
            role="Role Legacy",
            status="active",
        )
        return [Entity(device=device)]
