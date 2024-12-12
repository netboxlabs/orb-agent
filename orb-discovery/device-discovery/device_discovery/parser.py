#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""Parse Orb Discovery Config file."""

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError


class ParseException(Exception):
    """Custom exception for parsing errors."""

    pass


class DiscoveryConfig(BaseModel):
    """Model for Diode configuration."""

    host: str = "0.0.0.0"
    port: int = 8072


class Discovery(BaseModel):
    """Model for Discovery containing configuration and policies."""

    config: DiscoveryConfig


class DiscoveryBase(BaseModel):
    """Top-level model for the entire configuration."""

    device_discovery: Discovery | None = Field(
        default=Discovery(config=DiscoveryConfig()),
        description="Device discovery config, optional",
    )


class DiodeConfig(BaseModel):
    """Model for Diode configuration."""

    target: str
    api_key: str


class Diode(BaseModel):
    """Model for Diode containing configuration."""

    config: DiodeConfig


class DiodeBase(BaseModel):
    """Top-level model for the entire configuration."""

    diode: Diode


def resolve_env_vars(config):
    """
    Recursively resolve environment variables in the configuration.

    Args:
    ----
        config (dict): The configuration dictionary.

    Returns:
    -------
        dict: The configuration dictionary with environment variables resolved.

    """
    if isinstance(config, dict):
        return {k: resolve_env_vars(v) for k, v in config.items()}
    if isinstance(config, list):
        return [resolve_env_vars(i) for i in config]
    if isinstance(config, str) and config.startswith("${") and config.endswith("}"):
        env_var = config[2:-1]
        return os.getenv(env_var, config)
    return config


def parse_config(config_data: str) -> tuple[DiscoveryBase, DiodeBase]:
    """
    Parse the YAML configuration data into a Config object.

    Args:
    ----
        config_data (str): The YAML configuration data as a string.

    Returns:
    -------
        Tuple[DiscoveryBase, DiodeBase]: The parsed configuration

    Raises:
    ------
        ParseException: If there is an error in parsing the YAML or validating the data.

    """
    try:
        # Parse the YAML configuration data
        config_dict = yaml.safe_load(config_data)
        # Resolve environment variables
        resolved_config = resolve_env_vars(config_dict)
        # Parse the data into the Config model
        discovery_config = DiscoveryBase(**resolved_config)
        diode_config = DiodeBase(**resolved_config)
        return discovery_config, diode_config
    except yaml.YAMLError as e:
        raise ParseException(f"YAML ERROR: {e}")
    except ValidationError as e:
        raise ParseException("Validation ERROR:", e)


def parse_config_file(file_path: Path) -> tuple[DiscoveryConfig, DiodeConfig]:
    """
    Parse the Device Discovery configuration file and return the `Discovery` and `Diode` configuration.

    This function reads the content of the specified YAML configuration file,
    parses it into a `Config` object, and returns the `Discovery` part of the configuration.

    Args:
    ----
        file_path (Path): The path to the YAML configuration file.

    Returns:
    -------
        DiscoveryConfig: The `Discovery` configuration object.
        DiodeConfig: The `Diode` configuration object.

    Raises:
    ------
        ParseException: If there is an error parsing the YAML content or validating the data.
        Exception: If there is an error opening the file or any other unexpected error.

    """
    try:
        with open(file_path) as f:
            discovery, diode = parse_config(f.read())
    except ParseException:
        raise
    except Exception as e:
        raise Exception(f"Unable to open config file {file_path}: {e.args[1]}")
    return discovery.device_discovery.config, diode.diode.config
