#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""NetBox Labs - Mock Impl."""

from collections.abc import Iterable
from typing import Any

from netboxlabs.diode.sdk.ingester import Device, Entity
from worker.backend import Backend
from worker.models import Metadata, Policy


class MockBackend(Backend):
    """Mock backend class."""

    def setup(self) -> Metadata:
        """Mock setup method."""
        return Metadata(name="mock_custom", app_name="mock_app", app_version="1.0.0")

    def run(self, policy_name: str, policy: Policy) -> Iterable[Entity]:
        """Mock run method."""
        entities = []

        device = Device(
            name="Device A",
            device_type="Device Type A",
            platform="Platform A",
            manufacturer="Manufacturer A",
            description=policy_name,
            comments=policy.model_dump_json(),
            site="Site ABC",
            role="Role ABC",
            serial="123456",
            asset_tag="123456",
            status="active",
            tags=["tag 1", "tag 2"],
        )

        entities.append(Entity(device=device))
        return entities
