#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""NetBox Labs - Policy Manager Unit Tests."""

from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from orb_discovery.policy.manager import PolicyManager
from orb_discovery.policy.models import Policy, PolicyRequest


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
    with patch("orb_discovery.policy.manager.PolicyRunner") as MockPolicyRunner:
        mock_runner = MockPolicyRunner.return_value
        policy_manager.start_policy("policy1", sample_policy)

        # Check that PolicyRunner.setup was called with correct arguments
        mock_runner.setup.assert_called_once_with(
            "policy1", sample_policy.config, sample_policy.scope
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
    discovery:
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
    with patch("orb_discovery.parser.resolve_env_vars", side_effect=lambda x: x):
        policy_request = policy_manager.parse_policy(config_data)

        # Verify structure of the parsed PolicyRequest
        assert isinstance(policy_request, PolicyRequest)
        assert "policy1" in policy_request.discovery.policies


def test_parse_policy_invalid_cron(policy_manager):
    """Test parsing YAML configuration with an invalid cron string."""
    # Invalid cron string in schedule
    config_data = b"""
    discovery:
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
    with patch("orb_discovery.parser.resolve_env_vars", side_effect=lambda x: x):
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
    assert policy_manager.runners == []
