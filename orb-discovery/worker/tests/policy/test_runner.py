#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""NetBox Labs - Policy Manager Unit Tests."""

from unittest.mock import MagicMock, patch

import pytest
from apscheduler.triggers.date import DateTrigger

from worker.backend import Backend
from worker.models import Config, DiodeConfig, Policy, Status
from worker.policy.runner import PolicyRunner


@pytest.fixture
def policy_runner():
    """Fixture to create a PolicyRunner instance."""
    return PolicyRunner()


@pytest.fixture
def sample_policy():
    """Fixture for a sample policy object."""
    return Policy(
        config=Config(schedule="0 * * * *", package="custom"), scope={"custom": "value"}
    )


@pytest.fixture
def sample_diode_config():
    """Fixture for a sample DiodeConfig object."""
    return DiodeConfig(target="http://localhost:8080", prefix="test")


@pytest.fixture
def mock_load_class():
    """
    Fixture to mock the load_class function.

    Returns
    -------
        MagicMock: A mock object for the load_class function.

    """
    with patch("worker.policy.runner.load_class") as mock_load:
        mock_backend_class = MagicMock(spec=Backend)
        mock_load.return_value = mock_backend_class
        yield mock_load


@pytest.fixture
def mock_diode_client():
    """Fixture to mock the DiodeClient constructor."""
    with patch("worker.policy.runner.DiodeClient") as mock_diode_client:
        mock_instance = MagicMock()
        mock_diode_client.return_value = mock_instance
        yield mock_diode_client


@pytest.fixture
def mock_backend():
    """Fixture to mock a backend."""
    backend = MagicMock()
    backend.run.return_value = ["entity1", "entity2"]  # Mock returned entities
    return backend


def test_initial_status(policy_runner):
    """Test initial status of PolicyRunner."""
    assert policy_runner.status == Status.NEW


def test_setup_policy_runner_with_cron(
    policy_runner,
    sample_policy,
    sample_diode_config,
    mock_load_class,
    mock_diode_client,
):
    """Test setting up the PolicyRunner with a cron schedule."""
    with patch.object(policy_runner.scheduler, "start") as mock_start, patch.object(
        policy_runner.scheduler, "add_job"
    ) as mock_add_job:

        policy_runner.setup("policy1", sample_diode_config, sample_policy)

        # Ensure scheduler starts and job is added
        mock_start.assert_called_once()
        mock_add_job.assert_called_once()
        mock_load_class.assert_called_once()
        mock_diode_client.assert_called_once()
        assert policy_runner.status == Status.RUNNING


def test_setup_policy_runner_with_one_time_run(
    policy_runner,
    sample_diode_config,
    sample_policy,
    mock_load_class,
    mock_diode_client,
):
    """Test setting up the PolicyRunner with a one-time schedule."""
    one_time_config = Config(package="custom")
    with patch.object(policy_runner.scheduler, "start") as mock_start, patch.object(
        policy_runner.scheduler, "add_job"
    ) as mock_add_job:
        sample_policy.config = one_time_config
        policy_runner.setup("policy1", sample_diode_config, sample_policy)

        # Verify that DateTrigger is used for one-time scheduling
        trigger = mock_add_job.call_args[1]["trigger"]
        mock_load_class.assert_called_once()
        mock_diode_client.assert_called_once()
        assert isinstance(trigger, DateTrigger)
        assert mock_start.called
        assert policy_runner.status == Status.RUNNING


def test_run_success(policy_runner, sample_policy, mock_diode_client, mock_backend):
    """Test the run function for a successful execution."""
    policy_runner.name = "test_policy"

    # Call the run method
    policy_runner.run(mock_diode_client, mock_backend, sample_policy)

    # Assertions
    mock_backend.run.assert_called_once_with(policy_runner.name, sample_policy)
    mock_diode_client.ingest.assert_called_once_with(mock_backend.run.return_value)
    mock_diode_client.ingest.return_value.errors = []
    assert mock_diode_client.ingest.return_value.errors == []


def test_run_ingestion_errors(
    policy_runner,
    sample_policy,
    mock_diode_client,
    mock_backend,
    caplog,
):
    """Test the run function when ingestion has errors."""
    policy_runner.name = "test_policy"

    # Simulate ingestion errors
    mock_diode_client.ingest.return_value.errors = ["error1", "error2"]

    # Call the run method
    with caplog.at_level("ERROR"):
        policy_runner.run(mock_diode_client, mock_backend, sample_policy)

    # Assertions
    mock_backend.run.assert_called_once_with(policy_runner.name, sample_policy)
    mock_diode_client.ingest.assert_called_once_with(mock_backend.run.return_value)
    assert (
        "ERROR ingestion failed for test_policy : ['error1', 'error2']" in caplog.text
    )


def test_run_backend_exception(
    policy_runner,
    sample_policy,
    mock_diode_client,
    mock_backend,
    caplog,
):
    """Test the run function when an exception is raised by the backend."""
    policy_runner.name = "test_policy"

    # Simulate backend throwing an exception
    mock_backend.run.side_effect = Exception("Backend error")

    # Call the run method
    with caplog.at_level("ERROR"):
        policy_runner.run(mock_diode_client, mock_backend, sample_policy)

    # Assertions
    mock_backend.run.assert_called_once_with(policy_runner.name, sample_policy)
    mock_diode_client.ingest.assert_not_called()  # Client ingestion should not be called
    assert "Policy test_policy: Backend error" in caplog.text


def test_stop_policy_runner(policy_runner):
    """Test stopping the PolicyRunner."""
    with patch.object(policy_runner.scheduler, "shutdown") as mock_shutdown:
        policy_runner.stop()

        # Ensure scheduler shutdown is called and status is updated
        mock_shutdown.assert_called_once()
        assert policy_runner.status == Status.FINISHED
