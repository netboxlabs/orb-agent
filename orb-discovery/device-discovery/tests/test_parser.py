#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""NetBox Labs - Parser Unit Tests."""

import os
from pathlib import Path
from unittest.mock import mock_open, patch

import pytest

from device_discovery.parser import (
    Base,
    ParseException,
    parse_config,
    parse_config_file,
    resolve_env_vars,
)


@pytest.fixture
def valid_yaml():
    """Valid Yaml Generator."""
    return """
    discovery:
      config:
        target: "target_value"
        api_key: "api_key_value"
    """


@pytest.fixture
def invalid_yaml():
    """Invalid Yaml Generator."""
    return """
    discovery:
      config:
        api_key: "api_key_value"
        host: "host_value"
    """


def test_parse_valid_config(valid_yaml):
    """Ensure we can parse a valid configuration."""
    config = parse_config(valid_yaml)
    assert isinstance(config, Base)
    assert config.discovery.config.target == "target_value"
    assert config.discovery.config.host == "0.0.0.0"


def test_parse_invalid_config(invalid_yaml):
    """Ensure an invalid configuration raises a ParseException."""
    with pytest.raises(ParseException):
        parse_config(invalid_yaml)


@patch("builtins.open", new_callable=mock_open, read_data="valid_yaml")
def test_parse_config_file(mock_file, valid_yaml):
    """Ensure we can parse a configuration file."""
    with patch(
        "device_discovery.parser.parse_config", return_value=parse_config(valid_yaml)
    ):
        config = parse_config_file(Path("fake_path.yaml"))
        assert config.config.target == "target_value"
        mock_file.assert_called_once_with(Path("fake_path.yaml"))


@patch("builtins.open", new_callable=mock_open, read_data="invalid_yaml")
def test_parse_config_file_parse_exception(mock_file):
    """Ensure a ParseException in parse_config is propagated."""
    with patch(
        "device_discovery.parser.parse_config",
        side_effect=ParseException("Test Parse Exception"),
    ):
        with pytest.raises(ParseException):
            parse_config_file(Path("fake_path.yaml"))
        mock_file.assert_called_once_with(Path("fake_path.yaml"))


@patch.dict(os.environ, {"API_KEY": "env_api_key"})
def test_resolve_env_vars():
    """Ensure environment variables are resolved correctly."""
    config_with_env_var = {"api_key": "${API_KEY}"}
    resolved_config = resolve_env_vars(config_with_env_var)
    assert resolved_config["api_key"] == "env_api_key"


def test_resolve_env_vars_no_env():
    """Ensure missing environment variables are handled correctly."""
    config_with_no_env_var = {"api_key": "${MISSING_KEY}"}
    resolved_config = resolve_env_vars(config_with_no_env_var)
    assert resolved_config["api_key"] == "${MISSING_KEY}"


def test_parse_config_file_exception():
    """Ensure file parsing errors are handled correctly."""
    with pytest.raises(Exception):
        parse_config_file(Path("non_existent_file.yaml"))
