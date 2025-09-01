#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""NetBox Labs - Policy Manager Unit Tests."""

from unittest.mock import MagicMock, patch

import pytest
from apscheduler.triggers.date import DateTrigger

from device_discovery.policy.models import Config, Defaults, Napalm, Options, Status
from device_discovery.policy.runner import PolicyRunner


@pytest.fixture
def policy_runner():
    """Fixture to create a PolicyRunner instance."""
    return PolicyRunner()


@pytest.fixture
def sample_config():
    """Fixture for a sample Config object."""
    return Config(schedule="0 * * * *", defaults=Defaults(site="New York"))


@pytest.fixture
def sample_scopes():
    """Fixture for a sample list of Napalm objects."""
    return [
        Napalm(
            driver="ios",
            hostname="router1",
            username="admin",
            password="password",
            override_defaults=Defaults(role="Router", site="New York/NY"),
        ),
    ]


def test_initial_status(policy_runner):
    """Test initial status of PolicyRunner."""
    assert policy_runner.status == Status.NEW


def test_setup_policy_runner_with_cron(policy_runner, sample_config, sample_scopes):
    """Test setting up the PolicyRunner with a cron schedule."""
    with (
        patch.object(policy_runner.scheduler, "start") as mock_start,
        patch.object(policy_runner.scheduler, "add_job") as mock_add_job,
    ):

        policy_runner.setup("policy1", sample_config, sample_scopes)

        # Ensure scheduler starts and job is added
        mock_start.assert_called_once()

        assert mock_add_job.call_count == 2
        call_args = mock_add_job.call_args_list[0]  # First call
        passed_config = call_args[1]["args"][2]

        assert passed_config.defaults.site == "New York/NY"
        assert passed_config.defaults.role == "Router"

        # default was not modified, only inside the scope
        assert policy_runner.status == Status.RUNNING
        assert policy_runner.config.defaults.role == "undefined"
        assert policy_runner.config.defaults.site == "New York"


def test_setup_policy_runner_with_one_time_run(policy_runner, sample_scopes):
    """Test setting up the PolicyRunner with a one-time schedule."""
    one_time_config = Config()
    with (
        patch.object(policy_runner.scheduler, "start") as mock_start,
        patch.object(policy_runner.scheduler, "add_job") as mock_add_job,
    ):

        policy_runner.setup("policy1", one_time_config, sample_scopes)

        # Verify that DateTrigger is used for one-time scheduling
        trigger = mock_add_job.call_args[1]["trigger"]
        assert isinstance(trigger, DateTrigger)
        assert mock_start.called
        assert policy_runner.status == Status.RUNNING


def test_setup_policy_runner_with_none_config(policy_runner, sample_scopes):
    """Ensure PolicyRunner uses default config when none is provided."""
    with (
        patch.object(policy_runner.scheduler, "start") as mock_start,
        patch.object(policy_runner.scheduler, "add_job") as mock_add_job,
    ):

        policy_runner.setup("policy1", None, sample_scopes)

        mock_start.assert_called_once()
        assert mock_add_job.call_count == 2
        assert isinstance(policy_runner.config.defaults, Defaults)
        assert isinstance(policy_runner.config.options, Options)
        assert policy_runner.status == Status.RUNNING


def test_setup_with_unsupported_driver_raises_error(policy_runner, sample_scopes):
    """Test setup raises error if driver is unsupported."""
    sample_scopes[0].driver = "unsupported_driver"
    with (
        patch("device_discovery.policy.runner.supported_drivers", ["ios"]),
        pytest.raises(
            Exception, match="specified driver 'unsupported_driver' was not found"
        ),
    ):
        policy_runner.setup("policy1", Config(), sample_scopes)
    assert policy_runner.status == Status.NEW


def test_run_device_with_discovered_driver(policy_runner, sample_scopes, sample_config):
    """Test running a device where the driver needs discovery."""
    sample_scopes[0].driver = None  # Force driver discovery
    with (
        patch(
            "device_discovery.policy.runner.discover_device_driver", return_value="ios"
        ) as mock_discover,
        patch("device_discovery.policy.runner.get_network_driver") as mock_get_driver,
        patch("device_discovery.client.Client.ingest") as mock_ingest,
    ):

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
    with (
        patch(
            "device_discovery.policy.runner.discover_device_driver", return_value=None
        ) as mock_discover,
        patch("device_discovery.policy.runner.logger.error") as mock_logger_error,
    ):

        # Run the device with an error to check error handling
        policy_runner.run("test_id", sample_scopes[0], sample_config)

        mock_discover.assert_called_once()
        assert mock_logger_error.call_count == 2
        assert policy_runner.status == Status.FAILED


def test_run_device_with_error_in_job(policy_runner, sample_scopes, sample_config):
    """Test run handles an error during device interaction gracefully."""
    with (
        patch(
            "device_discovery.policy.runner.get_network_driver",
            side_effect=Exception("Connection error"),
        ),
        patch("device_discovery.policy.runner.logger.error") as mock_logger_error,
    ):

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


def test_metrics_during_policy_lifecycle(policy_runner, sample_config, sample_scopes):
    """Test that metrics are properly updated during the policy lifecycle."""
    # Create mock metrics
    mock_active_policies = MagicMock()
    mock_policy_executions = MagicMock()
    mock_discovery_attempts = MagicMock()
    mock_discovery_success = MagicMock()
    mock_discovery_failure = MagicMock()
    mock_device_connection_latency = MagicMock()
    mock_discovery_latency = MagicMock()

    # Map of metric names to mock objects
    mock_metrics = {
        "active_policies": mock_active_policies,
        "policy_executions": mock_policy_executions,
        "discovery_attempts": mock_discovery_attempts,
        "discovery_success": mock_discovery_success,
        "discovery_failure": mock_discovery_failure,
        "device_connection_latency": mock_device_connection_latency,
        "discovery_latency": mock_discovery_latency,
    }

    # Setup mock for get_metric function
    def mock_get_metric(name):
        return mock_metrics.get(name)

    with (
        patch("device_discovery.policy.runner.get_metric", side_effect=mock_get_metric),
        patch.object(policy_runner.scheduler, "start"),
        patch.object(policy_runner.scheduler, "add_job"),
        patch("device_discovery.policy.runner.get_network_driver"),
        patch("device_discovery.client.Client.ingest"),
    ):

        # Test setup - should increment active_policies
        policy_runner.setup("test_policy", sample_config, sample_scopes)
        mock_active_policies.add.assert_called_once_with(1, {"policy": "test_policy"})

        # Test telemetry job - should increment policy_executions
        policy_runner.telemetry()
        mock_policy_executions.add.assert_called_once_with(1, {"policy": "test_policy"})

        # Test run - should record attempts, success, and latency
        policy_runner.run("test_id", sample_scopes[0], sample_config)

        mock_discovery_attempts.add.assert_called_once_with(
            1, {"policy": "test_policy"}
        )
        mock_discovery_success.add.assert_called_once_with(1, {"policy": "test_policy"})
        mock_device_connection_latency.record.assert_called_once()
        mock_discovery_latency.record.assert_called_once()

        # Verify connection latency recorded with correct values
        latency_args = mock_device_connection_latency.record.call_args[0][0]
        latency_kwargs = mock_device_connection_latency.record.call_args[0][1]
        assert latency_args > 0.01  # 0.1 seconds in milliseconds
        assert latency_kwargs["policy"] == "test_policy"
        assert latency_kwargs["driver"] == "ios"

        # Test stop - should decrement active_policies
        with patch.object(policy_runner.scheduler, "shutdown") as mock_shutdown:
            policy_runner.stop()
            mock_shutdown.assert_called_once()
            mock_active_policies.add.assert_called_with(-1, {"policy": "test_policy"})


def test_metrics_during_failed_discovery(policy_runner, sample_config):
    """Test that metrics are properly updated when discovery fails."""
    # Create a scope with no driver to force discovery
    scope = Napalm(
        driver=None, hostname="router1", username="admin", password="password"
    )

    mock_discovery_attempts = MagicMock()
    mock_discovery_failure = MagicMock()
    mock_discovery_latency = MagicMock()

    mock_metrics = {
        "discovery_attempts": mock_discovery_attempts,
        "discovery_failure": mock_discovery_failure,
        "discovery_latency": mock_discovery_latency,
    }

    def mock_get_metric(name):
        return mock_metrics.get(name)

    with (
        patch("device_discovery.policy.runner.get_metric", side_effect=mock_get_metric),
        patch(
            "device_discovery.policy.runner.discover_device_driver", return_value="ios"
        ),
        patch(
            "device_discovery.policy.runner.get_network_driver",
            side_effect=Exception("Connection error"),
        ),
        patch.object(policy_runner.scheduler, "remove_job"),
    ):

        # Run the device with discovery that will fail
        policy_runner.run("test_id", scope, sample_config)

        # Verify failure metric was called
        mock_discovery_failure.add.assert_called_once_with(1, {"policy": ""})

        # Verify discovery latency recorded with failure status
        mock_discovery_latency.record.assert_called_once()
        latency_args = mock_discovery_latency.record.call_args[0][0]
        latency_kwargs = mock_discovery_latency.record.call_args[0][1]
        assert latency_args > 0.01
        assert latency_kwargs["status"] == "failed"
