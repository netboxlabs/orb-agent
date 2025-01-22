#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""NetBox Labs - Mock Impl."""

import logging
from collections.abc import Iterable

from netboxlabs.diode.sdk.ingester import Device, Entity
from pydantic import BaseModel, Field, ValidationError
from worker.backend import Backend
from worker.models import Metadata, Policy

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CustomConfig(BaseModel):
    """Validation model for config field."""

    package: str = Field(..., description="Package name")
    custom: str = Field(..., description="Custom field, can be of any type")


class ScopeItem(BaseModel):
    """Validation model for individual scope entries."""

    hostname: str = Field(..., description="Target hostname or IP")
    username: str = Field(..., description="Login username")
    password: str = Field(..., description="Login password")


class ScopeMap(BaseModel):
    """Validation model for individual scope entries."""

    target: str = Field(..., description="Target hostname or IP")
    port: int = Field(..., description="Target port number")


class MockBackend(Backend):
    """Mock backend class."""

    def setup(self) -> Metadata:
        """Mock setup method."""
        return Metadata(name="mock_custom", app_name="mock_app", app_version="1.0.0")

    def run(self, policy_name: str, policy: Policy) -> Iterable[Entity]:
        """Mock run method."""
        entities = []

        config = CustomConfig(**policy.config.model_dump())
        # Sample of how to handle a scope list
        if isinstance(policy.scope, list):
            scope = [ScopeItem(**item) for item in policy.scope]
        # Sample of how to handle a scope dictionary
        elif isinstance(policy.scope, dict):
            scope = ScopeMap(**policy.scope)
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
        logger.info(f"Policy '{policy_name}' config: {config}")
        logger.info(f"Policy '{policy_name}' scope: {scope}")

        entities.append(Entity(device=device))
        return entities
