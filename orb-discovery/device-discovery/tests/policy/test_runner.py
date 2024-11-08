#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""NetBox Labs - Policy Manager Unit Tests."""

from unittest.mock import MagicMock, patch

import pytest
from apscheduler.triggers.date import DateTrigger

from device_discovery.policy.models import Config, Napalm, Status
from device_discovery.policy.runner import PolicyRunner


@pytest.fixture
def policy_runner():
    """Fixture to create a PolicyRunner instance."""
    return PolicyRunner()


@pytest.fixture
def sample_config():
    """Fixture for a sample Config object."""
    return Config(schedule="0 * * * *", defaults={"site": "New York"})


@pytest.fixture
def sample_scopes():
    """Fixture for a sample list of Napalm objects."""
    return [
        Napalm(driver="ios", hostname="router1", username="admin", password="password")
    ]


def test_initial_status(policy_runner):
    """Test initial status of PolicyRunner."""
    assert policy_runner.status == Status.NEW


def test_setup_policy_runner_with_cron(policy_runner, sample_config, sample_scopes):
    """Test setting up the PolicyRunner with a cron schedule."""
    with patch.object(policy_runner.scheduler, "start") as mock_start, patch.object(
        policy_runner.scheduler, "add_job"
    ) as mock_add_job:

        policy_runner.setup("policy1", sample_config, sample_scopes)

        # Ensure scheduler starts and job is added
        mock_start.assert_called_once()
        mock_add_job.assert_called_once()
        assert policy_runner.status == Status.RUNNING


def test_setup_policy_runner_with_one_time_run(policy_runner, sample_scopes):
    """Test setting up the PolicyRunner with a one-time schedule."""
    one_time_config = Config()
    with patch.object(policy_runner.scheduler, "start") as mock_start, patch.object(
        policy_runner.scheduler, "add_job"
    ) as mock_add_job:

        policy_runner.setup("policy1", one_time_config, sample_scopes)

        # Verify that DateTrigger is used for one-time scheduling
        trigger = mock_add_job.call_args[1]["trigger"]
        assert isinstance(trigger, DateTrigger)
        assert mock_start.called
        assert policy_runner.status == Status.RUNNING


def test_setup_with_unsupported_driver_raises_error(policy_runner, sample_scopes):
    """Test setup raises error if driver is unsupported."""
    sample_scopes[0].driver = "unsupported_driver"
    with patch("device_discovery.policy.runner.supported_drivers", ["ios"]), pytest.raises(
        Exception, match="specified driver 'unsupported_driver' was not found"
    ):
        policy_runner.setup("policy1", Config(), sample_scopes)
    assert policy_runner.status == Status.NEW


def test_run_device_with_discovered_driver(policy_runner, sample_scopes, sample_config):
    """Test running a device where the driver needs discovery."""
    sample_scopes[0].driver = None  # Force driver discovery
    with patch(
        "device_discovery.policy.runner.discover_device_driver", return_value="ios"
    ) as mock_discover, patch(
        "device_discovery.policy.runner.get_network_driver"
    ) as mock_get_driver, patch(
        "device_discovery.client.Client.ingest"
    ) as mock_ingest:

        # Mock the network driver instance
        mock_driver_instance = MagicMock()
        mock_get_driver.return_value.return_value.__enter__.return_value = (
            mock_driver_instance
        )
        mock_driver_instance.get_facts.return_value = {"model": "SampleModel"}
        mock_driver_instance.get_interfaces.return_value = {"eth0": "up"}
        mock_driver_instance.get_interfaces_ip.return_value = {"eth0": "192.168.1.1"}

        # Run the device with the setup runner
        policy_runner.run("test_id", sample_scopes[0], sample_config)

        # Verify driver discovery and ingestion
        mock_discover.assert_called_once_with(sample_scopes[0])
        mock_ingest.assert_called_once()
        data = mock_ingest.call_args[0][1]
        assert data["driver"] == "ios"
        assert data["device"] == {"model": "SampleModel"}
        assert data["interface"] == {"eth0": "up"}
        assert data["interface_ip"] == {"eth0": "192.168.1.1"}


def test_run_discovered_driver_error(policy_runner, sample_scopes, sample_config):
    """Test running a device where the driver discovery fails."""
    sample_scopes[0].driver = None  # Force driver discovery
    with patch(
        "device_discovery.policy.runner.discover_device_driver", return_value=None
    ) as mock_discover, patch(
        "device_discovery.policy.runner.logger.error"
    ) as mock_logger_error:

        # Run the device with an error to check error handling
        policy_runner.run("test_id", sample_scopes[0], sample_config)

        mock_discover.assert_called_once()
        assert mock_logger_error.call_count == 2
        assert policy_runner.status == Status.FAILED


def test_run_device_with_error_in_job(policy_runner, sample_scopes, sample_config):
    """Test run handles an error during device interaction gracefully."""
    with patch(
        "device_discovery.policy.runner.get_network_driver",
        side_effect=Exception("Connection error"),
    ), patch("device_discovery.policy.runner.logger.error") as mock_logger_error:

        # Run the device with an error to check error handling
        policy_runner.run("test_id", sample_scopes[0], sample_config)
        mock_logger_error.assert_called_once()


def test_stop_policy_runner(policy_runner):
    """Test stopping the PolicyRunner."""
    with patch.object(policy_runner.scheduler, "shutdown") as mock_shutdown:
        policy_runner.stop()

        # Ensure scheduler shutdown is called and status is updated
        mock_shutdown.assert_called_once()
        assert policy_runner.status == Status.FINISHED
