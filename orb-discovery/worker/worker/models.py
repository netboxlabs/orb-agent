#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""Orb Worker Models."""

from enum import Enum
from typing import Any

from croniter import CroniterBadCronError, croniter
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Status(Enum):
    """Enumeration for status."""

    NEW = "new"
    RUNNING = "running"
    FINISHED = "finished"
    FAILED = "failed"


class DiodeConfig(BaseModel):
    """Model for a diode configuration."""

    target: str
    prefix: str | None = None
    api_key: str | None = None


class Metadata(BaseModel):
    """Model for a policy request."""

    name: str
    app_name: str
    app_version: str
    description: str | None = None


class Config(BaseModel):
    """Model for discovery configuration."""

    model_config = ConfigDict(extra="allow")
    package: str
    schedule: str | None = Field(default=None, description="cron interval, optional")

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

    config: Config
    scope: Any = Field(..., description="Scope data; must not be None")


class PolicyRequest(BaseModel):
    """Model for a policy request."""

    policies: dict[str, Policy]
