#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""Device Discovery Policy Models."""

import re
import time
import uuid
from enum import Enum
from typing import Any, Literal

from croniter import CroniterBadCronError, croniter
from pydantic import BaseModel, Field, field_validator


class Status(Enum):
    """Enumeration for status."""

    NEW = "new"
    RUNNING = "running"
    FINISHED = "finished"
    FAILED = "failed"


class InterfacePattern(BaseModel):
    """Model for interface type pattern matching."""

    match: str = Field(
        description="Regular expression pattern to match interface names"
    )
    type: str = Field(description="Interface type to assign when pattern matches")

    @field_validator("match")
    @classmethod
    def validate_regex(cls, value: str) -> str:
        """
        Validate the regex pattern at configuration load time.

        Args:
        ----
            value: The regex pattern string.

        Raises:
        ------
            ValueError: If the regex pattern is invalid.

        Returns:
        -------
            str: The validated regex pattern.

        """
        try:
            re.compile(value)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")
        return value


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
    asset_tag: str | None = Field(default=None, description="Asset tag, optional")


class TenantParameters(ObjectParameters):
    """Model for Tenant parameters."""

    name: str
    group: str | None = Field(default=None, description="Tenant group, optional")


class VrfParameters(ObjectParameters):
    """Model for VRF parameters."""

    name: str
    rd: str | None = Field(default=None, description="Route distinguisher, optional")


class VlanParameters(ObjectParameters):
    """Model for VLAN parameters."""

    group: str | None = Field(default=None, description="VLAN group, optional")
    tenant: str | TenantParameters | None = Field(
        default=None, description="VLAN tenant, optional"
    )
    role: str | None = Field(default=None, description="VLAN role, optional")


class IpamParameters(ObjectParameters):
    """Model for IPAM parameters."""

    role: str | None = Field(default=None, description="IPAM role, optional")
    tenant: str | TenantParameters | None = Field(
        default=None, description="IPAM tenant, optional"
    )
    vrf: str | VrfParameters | None = Field(default=None, description="IPAM VRF, optional")


class PrefixParameters(IpamParameters):
    """Model for prefix-specific parameters."""

    scope_site: str | None = Field(default=None, description="Prefix scope site, optional")
    scope_location: str | None = Field(default=None, description="Prefix scope location, optional")


class Defaults(BaseModel):
    """Model for default configuration."""

    site: str | None = Field(default="undefined", description="Site name, optional")
    role: str | None = Field(
        default="undefined", description="Device Role name, optional"
    )
    if_type: str | None = Field(default="other", description="Interface type, optional")
    interface_patterns: list[InterfacePattern] | None = Field(
        default=None,
        description="Interface type patterns for name-based matching, optional",
    )
    interface_exclude_patterns: list[str] | None = Field(
        default=None,
        description="Interface name patterns (regex) to exclude from ingestion, optional",
    )
    location: str | None = Field(default=None, description="Location name, optional")
    rack: str | None = Field(default=None, description="Rack name, optional")

    @field_validator("interface_patterns", "interface_exclude_patterns", mode="before")
    @classmethod
    def coerce_empty_list_to_none(cls, v: object) -> object:
        """Treat an empty list as None so override_defaults does not clear the global list."""
        if isinstance(v, list) and len(v) == 0:
            return None
        return v
    tenant: str | TenantParameters | None = Field(
        default=None, description="Tenant, optional"
    )
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
    prefix: PrefixParameters | None = Field(
        default=None, description="Prefix parameters, optional"
    )
    vlan: VlanParameters | None = Field(
        default=None, description="VLAN parameters, optional"
    )

    @field_validator("prefix", mode="before")
    @classmethod
    def coerce_ipam_to_prefix_parameters(cls, v: object) -> object:
        """
        Coerce a bare IpamParameters to PrefixParameters for back-compat.

        Legacy in-process callers used to build ``Defaults(prefix=
        IpamParameters(role="x"))`` before PrefixParameters existed.
        Without this coercion Pydantic raises ValidationError because
        IpamParameters isn't a PrefixParameters subclass. Round-trip
        through model_dump → dict so the matching fields land on the
        new model.
        """
        if isinstance(v, IpamParameters) and not isinstance(v, PrefixParameters):
            return v.model_dump()
        return v


class Options(BaseModel):
    """Model for discovery options."""

    platform_omit_version: bool | None = Field(
        default=False, description="Omit platform version, optional"
    )
    port_scan_ports: list[int] | None = Field(
        default=[22, 23, 80, 443, 830, 57400],
        description="TCP ports to probe before discovery (e.g. [22,23,80,443])",
    )
    port_scan_timeout: float | None = Field(
        default=0.5,
        description="TCP port probe timeout in seconds",
    )
    capture_running_config: bool | None = Field(
        default=False, description="Capture running configuration, optional"
    )
    capture_startup_config: bool | None = Field(
        default=False, description="Capture startup/saved configuration, optional"
    )
    sanitize_config: bool | None = Field(
        default=True, description="Redact sensitive values from captured configuration, optional"
    )
    discovery_drivers: list[str] | None = Field(
        default=None,
        description="Restrict auto-discovery to this driver list. If not set, all supported drivers are tried.",
    )
    create_unknown_vlans: bool = Field(
        default=True,
        description=(
            "Auto-emit VLAN entities for VIDs referenced on interfaces "
            "but absent from the device's VLAN database. Stubs inherit "
            "attributes from defaults.vlan for stable matching. Set "
            "False to drop unknown VIDs from associations."
        ),
    )
    discover_modules: Literal["off", "linecards", "full"] = Field(
        default="off",
        description=(
            "Enable module / module-bay emission for modular chassis. "
            "'off' (default) skips module discovery entirely — drivers "
            "are not asked for module data. 'linecards' emits chassis-level "
            "bays and their non-transceiver modules (linecards, supervisors, "
            "and any psu/fan a driver classifies explicitly); transceiver "
            "sub-bays are dropped. 'full' adds the per-port transceiver "
            "sub-bays."
        ),
    )
    propagate_defaults_to_prefix_scope: bool = Field(
        default=False,
        description=(
            "When True AND no explicit defaults.prefix.scope_* is set, "
            "defaults.site cascades to Prefix.scope_site (unless it's "
            "the literal placeholder 'undefined') and defaults.location "
            "cascades to Prefix.scope_location. Any explicit "
            "defaults.prefix.scope_* skips the cascade wholesale. "
            "Default False preserves the no-cascade behavior."
        ),
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
    netbox_id: int | None = Field(
        default=None,
        description="NetBox device primary key for PK-based matching. Ignored when hostname is a range or subnet.",
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


class RunStatus(str, Enum):
    """Run status enumeration."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Run(BaseModel):
    """Model for a single run execution."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    policy_id: str
    status: RunStatus
    reason: str = ""
    entity_count: int = 0
    driver: str | None = Field(
        default=None,
        description="Resolved NAPALM driver after a successful device session",
    )
    metadata: dict[str, str] = Field(default_factory=dict)
    created_at: int = Field(default_factory=time.time_ns)
    updated_at: int = Field(default_factory=time.time_ns)


class PolicyStatus(BaseModel):
    """Status response for a policy with run history."""

    name: str
    status: str  # Derived from latest run
    runs: list[Run]
