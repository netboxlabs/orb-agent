#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""NetBox Labs - Main Unit Tests."""

import sys
from unittest.mock import MagicMock, patch

import pytest

from device_discovery.main import main


@pytest.fixture
def mock_parse_args():
    """
    Fixture to mock argparse.ArgumentParser.parse_args.

    Mocks the parse_args method to control CLI arguments.
    """
    with patch("device_discovery.main.argparse.ArgumentParser.parse_args") as mock:
        yield mock


@pytest.fixture
def mock_client():
    """
    Fixture to mock the Client class.

    Mocks the Client class to control its behavior during tests.
    """
    with patch("device_discovery.main.Client") as mock:
        yield mock


@pytest.fixture
def mock_uvicorn_run():
    """
    Fixture to mock the uvicorn.run function.

    Mocks the uvicorn.run function to prevent it from actually starting a server.
    """
    with patch("device_discovery.main.uvicorn.run") as mock:
        yield mock


def test_main_keyboard_interrupt(mock_parse_args):
    """Test handling of KeyboardInterrupt in main."""
    mock_parse_args.return_value = MagicMock(
        diode_target="grpc", diode_api_key="abc", host="0.0.0.0", port=1234
    )

    with patch.object(sys, "exit", side_effect=Exception("Test Exit")):
        try:
            main()
        except Exception as e:
            assert str(e) == "Test Exit"


def test_main_with_config(mock_parse_args, mock_client, mock_uvicorn_run):
    """Test running the CLI with a configuration file and no environment file."""
    mock_parse_args.return_value = MagicMock(
        diode_target="grpc", diode_api_key="abc", host="0.0.0.0", port=1234
    )

    with patch.object(sys, "exit", side_effect=Exception("Test Exit")):
        try:
            main()
        except Exception as e:
            assert str(e) == "Test Exit"

    mock_parse_args.assert_called_once()
    mock_client.assert_called_once()
    mock_uvicorn_run.assert_called_once()


def test_main_start_server_failure(mock_parse_args, mock_client, mock_uvicorn_run):
    """Test CLI failure when starting the agent."""
    mock_parse_args.return_value = MagicMock(
        diode_target="grpc", diode_api_key="abc", host="0.0.0.0", port=1234
    )
    mock_uvicorn_run.side_effect = Exception("Test Start Server Failure")

    with patch.object(sys, "exit", side_effect=Exception("Test Exit")) as mock_exit:
        try:
            main()
        except Exception as e:
            assert str(e) == "Test Exit"

    mock_parse_args.assert_called_once()
    mock_client.assert_called_once()
    mock_uvicorn_run.assert_called_once()
    mock_exit.assert_called_once_with(
        "ERROR: Unable to start discovery backend: Test Start Server Failure"
    )


def test_main_no_config_file(mock_parse_args):
    """
    Test running the CLI without a configuration file.

    Args:
    ----
        mock_parse_args: Mocked parse_args function.

    """
    mock_parse_args.return_value = MagicMock(config=None)

    with patch.object(sys, "exit", side_effect=Exception("Test Exit")) as mock_exit:
        try:
            main()
        except Exception as e:
            print(f"Caught exception: {str(e)}")  # Debug statement
            assert str(e) == "Test Exit"

    mock_exit.assert_called_once()


def test_main_missing_policy(mock_parse_args):
    """Test handling of missing policy in start_agent."""
    mock_parse_args.return_value = MagicMock(
        diode_target="grpc", diode_api_key="abc", host="0.0.0.0", port=1234
    )
    mock_cfg = MagicMock()
    mock_cfg.policies = {"policy1": None}  # Simulating a missing policy

    with patch.object(sys, "exit", side_effect=Exception("Test Exit")):
        try:
            main()
        except Exception as e:
            assert str(e) == "Test Exit"
