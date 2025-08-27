#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""Device Discovery Policy Models."""

from enum import Enum
from typing import Any

from croniter import CroniterBadCronError, croniter
from pydantic import BaseModel, Field, field_validator


class Status(Enum):
    """Enumeration for status."""

    NEW = "new"
    RUNNING = "running"
    FINISHED = "finished"
    FAILED = "failed"


class ObjectParameters(BaseModel):
    """Model for object parameters."""

    comments: str | None = Field(default=None, description="Comments, optional")
    description: str | None = Field(default=None, description="Description, optional")
    tags: list[str] | None = Field(default=None, description="Tags, optional")


class DeviceParameters(ObjectParameters):
    """Model for device specific parameters."""

    model: str | None = Field(
        default=None, description="Device model override, optional"
    )
    manufacturer: str | None = Field(
        default=None, description="Device manufacturer override, optional"
    )
    platform: str | None = Field(
        default=None, description="Device platform override, optional"
    )


class VlanParameters(ObjectParameters):
    """Model for VLAN parameters."""

    group: str | None = Field(default=None, description="VLAN group, optional")
    tenant: str | None = Field(default=None, description="VLAN tenant, optional")
    role: str | None = Field(default=None, description="VLAN role, optional")


class IpamParameters(ObjectParameters):
    """Model for IPAM parameters."""

    role: str | None = Field(default=None, description="IPAM role, optional")
    tenant: str | None = Field(default=None, description="IPAM tenant, optional")
    vrf: str | None = Field(default=None, description="IPAM VRF, optional")


class Defaults(BaseModel):
    """Model for default configuration."""

    site: str | None = Field(default="undefined", description="Site name, optional")
    role: str | None = Field(
        default="undefined", description="Device Role name, optional"
    )
    if_type: str | None = Field(default="other", description="Interface type, optional")
    location: str | None = Field(default=None, description="Location name, optional")
    tenant: str | None = Field(default=None, description="Tenant name, optional")
    tags: list[str] | None = Field(default=None, description="Tags, optional")
    device: DeviceParameters | None = Field(
        default=None, description="Device parameters, optional"
    )
    interface: ObjectParameters | None = Field(
        default=None, description="Interface parameters, optional"
    )
    ipaddress: IpamParameters | None = Field(
        default=None, description="IP Address parameters, optional"
    )
    prefix: IpamParameters | None = Field(
        default=None, description="Prefix parameters, optional"
    )
    vlan: VlanParameters | None = Field(
        default=None, description="VLAN parameters, optional"
    )


class Options(BaseModel):
    """Model for discovery options."""

    platform_omit_version: bool | None = Field(
        default=False, description="Omit platform version, optional"
    )


class Config(BaseModel):
    """Model for discovery configuration."""

    schedule: str | None = Field(default=None, description="cron interval, optional")
    defaults: Defaults | None = Field(
        default=None, description="Default configuration, optional"
    )
    options: Options | None = Field(
        default=None, description="Discovery options, optional"
    )

    @field_validator("schedule")
    @classmethod
    def validate_cron(cls, value):
        """
        Validate the cron schedule format.

        Args:
        ----
            value: The cron schedule value.

        Raises:
        ------
            ValueError: If the cron schedule format is invalid.

        """
        try:
            croniter(value)
        except CroniterBadCronError:
            raise ValueError("Invalid cron schedule format.")
        return value


class Napalm(BaseModel):
    """Model for NAPALM configuration."""

    driver: str | None = Field(default=None, description="Driver name, optional")
    hostname: str
    username: str
    password: str
    timeout: int = 60
    optional_args: dict[str, Any] | None = Field(
        default=None, description="Optional arguments"
    )
    override_defaults: Defaults | None = Field(
        default=None,
        description="Override default configuration for this host, optional",
    )


class Policy(BaseModel):
    """Model for a policy configuration."""

    config: Config | None = Field(default=None, description="Configuration data")
    scope: list[Napalm]


class PolicyRequest(BaseModel):
    """Model for a policy request."""

    policies: dict[str, Policy]
