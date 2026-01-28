#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""NetBox Labs - Policy Manager Unit Tests."""

from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from device_discovery.policy.manager import PolicyManager
from device_discovery.policy.models import Policy, PolicyRequest


@pytest.fixture
def policy_manager():
    """Fixture to create a PolicyManager instance."""
    return PolicyManager()


@pytest.fixture
def sample_policy():
    """Fixture for a sample Policy object."""
    return Policy(
        config={"schedule": "0 * * * *", "defaults": {"site": "New York"}},
        scope=[
            {
                "driver": "ios",
                "hostname": "router1",
                "username": "admin",
                "password": "password",
            }
        ],
    )


def test_start_policy(policy_manager, sample_policy):
    """Test starting a policy."""
    with patch("device_discovery.policy.manager.PolicyRunner") as MockPolicyRunner:
        mock_runner = MockPolicyRunner.return_value
        policy_manager.start_policy("policy1", sample_policy)

        # Check that PolicyRunner.setup was called with correct arguments (including run_store)
        mock_runner.setup.assert_called_once_with(
            "policy1",
            sample_policy.config,
            sample_policy.scope,
            policy_manager.run_store,
        )

        # Ensure the policy runner was added to the manager's runners
        assert "policy1" in policy_manager.runners


def test_start_existing_policy_raises_error(policy_manager, sample_policy):
    """Test that starting an already existing policy raises an error."""
    policy_manager.runners["policy1"] = MagicMock()
    with pytest.raises(ValueError, match="policy 'policy1' already exists"):
        policy_manager.start_policy("policy1", sample_policy)


def test_parse_policy(policy_manager):
    """Test parsing YAML configuration into a PolicyRequest object."""
    config_data = b"""
    policies:
      policy1:
        config:
          schedule: "0 * * * *"
          defaults:
            site: "New York"
        scope:
          - driver: "ios"
            hostname: "router1"
            username: "admin"
            password: "password"
    """
    policy_request = policy_manager.parse_policy(config_data)

    # Verify structure of the parsed PolicyRequest
    assert isinstance(policy_request, PolicyRequest)
    assert "policy1" in policy_request.policies


def test_parse_policy_invalid_cron(policy_manager):
    """Test parsing YAML configuration with an invalid cron string."""
    # Invalid cron string in schedule
    config_data = b"""
    policies:
      policy1:
        config:
          schedule: "invalid cron string"
          defaults:
            site: "New York"
        scope:
          - driver: "ios"
            hostname: "router1"
            username: "admin"
            password: "password"
    """

    with pytest.raises(ValidationError) as exc_info:
        policy_manager.parse_policy(config_data)

    # Validate that the error is related to the invalid cron string
    assert exc_info.match("Invalid cron schedule format.")


def test_policy_exists(policy_manager):
    """Test checking if a policy exists."""
    policy_manager.runners["policy1"] = MagicMock()
    assert policy_manager.policy_exists("policy1") is True
    assert policy_manager.policy_exists("nonexistent_policy") is False


def test_delete_policy(policy_manager):
    """Test deleting a policy."""
    mock_runner = MagicMock()
    policy_manager.runners["policy1"] = mock_runner
    policy_manager.delete_policy("policy1")

    # Verify stop was called on the runner
    mock_runner.stop.assert_called_once()
    assert "policy1" not in policy_manager.runners


def test_delete_nonexistent_policy_raises_error(policy_manager):
    """Test deleting a nonexistent policy raises an error."""
    with pytest.raises(ValueError, match="policy 'nonexistent_policy' not found"):
        policy_manager.delete_policy("nonexistent_policy")


def test_stop_all_policies(policy_manager):
    """Test stopping all policies."""
    mock_runner1 = MagicMock()
    mock_runner2 = MagicMock()
    policy_manager.runners = {"policy1": mock_runner1, "policy2": mock_runner2}

    policy_manager.stop()

    # Verify stop was called on each runner
    mock_runner1.stop.assert_called_once()
    mock_runner2.stop.assert_called_once()

    # Ensure runners dictionary is emptied
    assert policy_manager.runners == {}


def test_get_policy_statuses_empty(policy_manager):
    """Test getting policy statuses when no policies exist."""
    statuses = policy_manager.get_policy_statuses()
    assert statuses == []


def test_get_policy_statuses_active_policy_with_runs(policy_manager):
    """Test getting status for an active policy with run history."""
    from datetime import datetime

    from device_discovery.policy.models import Status
    from device_discovery.policy.run import Run, RunStatus

    # Create mock runner
    mock_runner = MagicMock()
    mock_runner.status = Status.RUNNING
    policy_manager.runners["policy1"] = mock_runner

    # Add runs to the run store
    run1 = Run(
        policy_id="policy1",
        status=RunStatus.COMPLETED,
        entity_count=10,
        created_at=datetime(2026, 1, 27, 10, 0, 0),
    )
    run2 = Run(
        policy_id="policy1",
        status=RunStatus.RUNNING,
        entity_count=0,
        created_at=datetime(2026, 1, 27, 11, 0, 0),
    )

    # Mock the run store to return runs (sorted newest first)
    policy_manager.run_store.get_all_policies_with_runs = MagicMock(
        return_value={"policy1": [run2, run1]}
    )

    statuses = policy_manager.get_policy_statuses()

    assert len(statuses) == 1
    assert statuses[0].name == "policy1"
    assert statuses[0].status == "running"  # From latest run (run2)
    assert len(statuses[0].runs) == 2
    assert statuses[0].runs[0].id == run2.id
    assert statuses[0].runs[1].id == run1.id


def test_get_policy_statuses_active_policy_without_runs(policy_manager):
    """Test getting status for an active policy with no run history."""
    from device_discovery.policy.models import Status

    # Create mock runner
    mock_runner = MagicMock()
    mock_runner.status = Status.NEW
    policy_manager.runners["policy1"] = mock_runner

    # Mock the run store to return no runs
    policy_manager.run_store.get_all_policies_with_runs = MagicMock(return_value={})

    statuses = policy_manager.get_policy_statuses()

    assert len(statuses) == 1
    assert statuses[0].name == "policy1"
    assert statuses[0].status == "new"  # From runner.status since no runs
    assert statuses[0].runs == []


def test_get_policy_statuses_historical_policy_no_active_runner(policy_manager):
    """Test getting status for a policy with historical runs but no active runner."""
    from datetime import datetime

    from device_discovery.policy.run import Run, RunStatus

    # No active runners
    assert len(policy_manager.runners) == 0

    # Add runs to the run store for a policy that's not running
    run1 = Run(
        policy_id="old_policy",
        status=RunStatus.COMPLETED,
        entity_count=5,
        created_at=datetime(2026, 1, 26, 10, 0, 0),
    )
    run2 = Run(
        policy_id="old_policy",
        status=RunStatus.FAILED,
        reason="Connection timeout",
        created_at=datetime(2026, 1, 27, 10, 0, 0),
    )

    # Mock the run store to return runs (sorted newest first)
    policy_manager.run_store.get_all_policies_with_runs = MagicMock(
        return_value={"old_policy": [run2, run1]}
    )

    statuses = policy_manager.get_policy_statuses()

    assert len(statuses) == 1
    assert statuses[0].name == "old_policy"
    assert statuses[0].status == "failed"  # From latest run (run2)
    assert len(statuses[0].runs) == 2
    assert statuses[0].runs[0].id == run2.id
    assert statuses[0].runs[1].id == run1.id


def test_get_policy_statuses_mixed_active_and_historical(policy_manager):
    """Test getting statuses with both active policies and historical runs."""
    from datetime import datetime

    from device_discovery.policy.models import Status
    from device_discovery.policy.run import Run, RunStatus

    # Create active runner
    mock_runner = MagicMock()
    mock_runner.status = Status.RUNNING
    policy_manager.runners["active_policy"] = mock_runner

    # Create runs for both active and historical policies
    active_run = Run(
        policy_id="active_policy",
        status=RunStatus.COMPLETED,
        entity_count=15,
        created_at=datetime(2026, 1, 27, 12, 0, 0),
    )
    historical_run1 = Run(
        policy_id="historical_policy",
        status=RunStatus.COMPLETED,
        entity_count=8,
        created_at=datetime(2026, 1, 26, 10, 0, 0),
    )
    historical_run2 = Run(
        policy_id="historical_policy",
        status=RunStatus.COMPLETED,
        entity_count=12,
        created_at=datetime(2026, 1, 27, 9, 0, 0),
    )

    # Mock the run store
    policy_manager.run_store.get_all_policies_with_runs = MagicMock(
        return_value={
            "active_policy": [active_run],
            "historical_policy": [historical_run2, historical_run1],
        }
    )

    statuses = policy_manager.get_policy_statuses()

    assert len(statuses) == 2

    # Find statuses by name (order not guaranteed)
    active_status = next(s for s in statuses if s.name == "active_policy")
    historical_status = next(s for s in statuses if s.name == "historical_policy")

    # Verify active policy status
    assert active_status.status == "completed"
    assert len(active_status.runs) == 1
    assert active_status.runs[0].id == active_run.id

    # Verify historical policy status
    assert historical_status.status == "completed"
    assert len(historical_status.runs) == 2
    assert historical_status.runs[0].id == historical_run2.id


def test_get_policy_statuses_multiple_active_policies(policy_manager):
    """Test getting statuses for multiple active policies with different states."""
    from datetime import datetime

    from device_discovery.policy.models import Status
    from device_discovery.policy.run import Run, RunStatus

    # Create multiple active runners
    mock_runner1 = MagicMock()
    mock_runner1.status = Status.RUNNING
    policy_manager.runners["policy1"] = mock_runner1

    mock_runner2 = MagicMock()
    mock_runner2.status = Status.NEW
    policy_manager.runners["policy2"] = mock_runner2

    # Create runs only for policy1
    run1 = Run(
        policy_id="policy1",
        status=RunStatus.FAILED,
        reason="Network error",
        created_at=datetime(2026, 1, 27, 10, 0, 0),
    )

    # Mock the run store
    policy_manager.run_store.get_all_policies_with_runs = MagicMock(
        return_value={"policy1": [run1]}
    )

    statuses = policy_manager.get_policy_statuses()

    assert len(statuses) == 2

    # Find statuses by name
    status1 = next(s for s in statuses if s.name == "policy1")
    status2 = next(s for s in statuses if s.name == "policy2")

    # policy1 has runs, status from latest run
    assert status1.status == "failed"
    assert len(status1.runs) == 1

    # policy2 has no runs, status from runner
    assert status2.status == "new"
    assert status2.runs == []


def test_get_policy_statuses_prefer_running_status(policy_manager):
    """Test that RUNNING status is preferred when any run is still running."""
    from datetime import datetime

    from device_discovery.policy.models import Status
    from device_discovery.policy.run import Run, RunStatus

    # Create mock runner
    mock_runner = MagicMock()
    mock_runner.status = Status.RUNNING
    policy_manager.runners["policy1"] = mock_runner

    # Create runs: latest is completed, but one is still running
    run1 = Run(
        policy_id="policy1",
        status=RunStatus.RUNNING,
        entity_count=0,
        created_at=datetime(2026, 1, 27, 10, 0, 0),
    )
    run2 = Run(
        policy_id="policy1",
        status=RunStatus.COMPLETED,
        entity_count=15,
        created_at=datetime(2026, 1, 27, 11, 0, 0),  # Latest run
    )

    # Mock the run store to return runs (sorted newest first)
    policy_manager.run_store.get_all_policies_with_runs = MagicMock(
        return_value={"policy1": [run2, run1]}
    )

    statuses = policy_manager.get_policy_statuses()

    assert len(statuses) == 1
    assert statuses[0].name == "policy1"
    # Should be RUNNING even though latest run is COMPLETED
    assert statuses[0].status == "running"
    assert len(statuses[0].runs) == 2
