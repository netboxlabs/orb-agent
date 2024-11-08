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


class Config(BaseModel):
    """Model for discovery configuration."""

    schedule: str | None = Field(default=None, description="cron interval, optional")
    defaults: dict[str, str] | None = Field(
        default=None, description="NetBox configuration"
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


class Policy(BaseModel):
    """Model for a policy configuration."""

    config: Config | None = Field(default=None, description="Configuration data")
    scope: list[Napalm]


class Discovery(BaseModel):
    """Model for Discovery containing configuration and policies."""

    policies: dict[str, Policy]


class PolicyRequest(BaseModel):
    """Model for a policy request."""

    discovery: Discovery
