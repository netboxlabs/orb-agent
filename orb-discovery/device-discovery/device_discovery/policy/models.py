#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""Orb Discovery Policy Models."""

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

class ObjectParameters(BaseModel):
    """Model for object parameters."""

    comments: str | None = Field(default=None, description="Comments, optional")
    description: str | None = Field(default=None, description="Description, optional")
    tags: list[str] | None = Field(default=None, description="Tags, optional")

class Defaults(BaseModel):
    """Model for default configuration."""

    site: str | None = Field(default=None, description="Site name, optional")
    role: str | None = Field(default=None, description="Device Role name, optional")
    tags: list[str] | None = Field(default=None, description="Tags, optional")
    device: ObjectParameters | None = Field(default=None, description="Device parameters, optional")
    interface: ObjectParameters | None = Field(default=None, description="Interface parameters, optional")
    ipaddress: ObjectParameters | None = Field(default=None, description="IP Address parameters, optional")
    prefix: ObjectParameters | None = Field(default=None, description="Prefix parameters, optional")

class Config(BaseModel):
    """Model for discovery configuration."""

    schedule: str | None = Field(default=None, description="cron interval, optional")
    defaults: Defaults | None = Field(default=None, description="Default configuration, optional")

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


class Policy(BaseModel):
    """Model for a policy configuration."""

    config: Config | None = Field(default=None, description="Configuration data")
    scope: list[Napalm]


class PolicyRequest(BaseModel):
    """Model for a policy request."""

    policies: dict[str, Policy]
