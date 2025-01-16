#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""NetBox Labs - Server Unit Tests."""

from unittest.mock import patch

import pytest
import yaml
from fastapi.testclient import TestClient

from worker.models import PolicyRequest
from worker.server import app, manager

client = TestClient(app)


@pytest.fixture
def valid_policy_yaml():
    """
    Valid PolicyRequest YAML string.

    Returns a YAML string that represents a valid PolicyRequest object.
    """
    return """
    policies:
      policy1:
        config:
          package: "custom-package"
          schedule: "0 * * * *"
          extra: extra_value
        scope:
          - custom: any
    """


@pytest.fixture
def multiple_policies_yaml():
    """
    Multiple PolicyRequest YAML string.

    Returns a YAML string that represents a valid PolicyRequest object.
    """
    return """
    policies:
      policy1:
        config:
          package: "custom-package-1"
          schedule: "0 * * * *"
          extra: extra_config
        scope:
          custom: any
      policy2:
        config:
          package: "custom-package-2"
          schedule: "0 * * * *"
        scope:
          - array:
                - item1
                - item2
    """


@pytest.fixture
def invalid_policy_yaml():
    """
    Invalid PolicyRequest YAML string.

    Returns a YAML string that represents a valid PolicyRequest object.
    """
    return """
    policies:
      policy1:
        config:
          schedule: "0 * * * *"
          extra: any_extra
        scope:
            custom: "value"
            username: "admin"
            password: "password"
    """


@pytest.fixture
def mock_valid_policy_request(valid_policy_yaml):
    """
    Fixture to mock a PolicyRequest object from YAML.

    Parses the valid YAML content and converts it to a PolicyRequest.
    """
    yaml_dict = yaml.safe_load(valid_policy_yaml)
    policy_request = PolicyRequest.model_validate(yaml_dict)
    with patch("worker.server.manager.start_policy") as mock_start_policy:
        print(f"Created PolicyRequest: {policy_request}")
        yield policy_request, mock_start_policy


@pytest.fixture
def mock_multiple_policies_request(multiple_policies_yaml):
    """
    Fixture to mock a PolicyRequest object from YAML.

    Parses the valid YAML content and converts it to a PolicyRequest.
    """
    yaml_dict = yaml.safe_load(multiple_policies_yaml)
    with patch("worker.server.manager.start_policy") as mock_start_policy:
        yield PolicyRequest.model_validate(yaml_dict), mock_start_policy


@pytest.fixture
def mock_version_semver():
    """
    Fixture to mock version_semver.

    Mocks the version_semver function to control version response in status endpoint.
    """
    with patch("worker.server.version_semver", return_value="1.0.0") as mock:
        yield mock


@pytest.fixture
def mock_manager():
    """
    Fixture to mock the PolicyManager.

    Mocks the PolicyManager to control policy behavior in tests.
    """
    with patch("worker.server.manager") as mock:
        yield mock


def test_read_status(mock_version_semver):
    """
    Test the /api/v1/status endpoint.

    Ensures that the version and uptime are correctly returned.

    Args:
    ----
        mock_version_semver: Mocked version_semver function.

    """
    response = client.get("/api/v1/status")
    mock_version_semver.assert_called_once()
    assert response.status_code == 200
    assert response.json()["version"] == "1.0.0"
    assert "up_time_seconds" in response.json()


def test_read_capabilities():
    """
    Test the /api/v1/capabilities endpoint.

    Verifies it returns the mocked loaded packages.
    """
    mock_loaded_modules = ["module1", "module2", "module3"]
    with patch(
        "worker.server.manager.get_loaded_modules", return_value=mock_loaded_modules
    ) as mock_get_modules:
        response = client.get("/api/v1/capabilities")

        assert response.status_code == 200
        assert response.json() == {"loaded_modules": mock_loaded_modules}

        mock_get_modules.assert_called_once()


def test_write_policy_valid_yaml(mock_valid_policy_request, valid_policy_yaml):
    """
    Test posting a valid YAML policy.

    Ensures it is accepted and returns the correct response.

    Args:
    ----
        mock_valid_policy_request: Mocked PolicyRequest object.
        valid_policy_yaml: Valid PolicyRequest YAML string.

    """
    manager.runners = {}
    mock_request, mock_start_policy = mock_valid_policy_request

    with patch(
        "worker.server.manager.parse_policy",
        return_value=mock_request,
    ):
        response = client.post(
            "/api/v1/policies",
            headers={"Content-Type": "application/x-yaml"},
            data=valid_policy_yaml,
        )
        assert response.status_code == 201
        assert response.json() == {"detail": "policy 'policy1' was started"}

        mock_start_policy.assert_any_call("policy1", mock_request.policies["policy1"])
        assert mock_start_policy.call_count == 1


def test_write_policy_invalid_yaml():
    """Test posting a invalid YAML policy."""
    with patch(
        "worker.server.manager.parse_policy",
        side_effect=yaml.YAMLError("invalid"),
    ):
        response = client.post(
            "/api/v1/policies",
            headers={"Content-Type": "application/x-yaml"},
            json={"policies": {"policy1": {}}},
        )
        assert response.status_code == 400
        assert response.json() == {"detail": "Invalid YAML format"}


def test_write_policy_validation_error(invalid_policy_yaml):
    """Test posting a valid YAML policy but with invalid field."""
    response = client.post(
        "/api/v1/policies",
        headers={"Content-Type": "application/x-yaml"},
        data=invalid_policy_yaml,
    )
    assert response.status_code == 403
    assert response.json() == {
        "detail": [
            {
                "field": "policies.policy1.config.package",
                "type": "missing",
                "error": "Field required",
            }
        ]
    }


def test_write_policy_unexpected_parser_error():
    """Test posting a invalid YAML policy."""
    with patch(
        "worker.server.manager.parse_policy",
        side_effect=Exception("unexpected error"),
    ):
        response = client.post(
            "/api/v1/policies",
            headers={"Content-Type": "application/x-yaml"},
            json={"policies": {"policy1": {}}},
        )
        assert response.status_code == 400
        assert response.json() == {"detail": "unexpected error"}


def test_write_policy_invalid_content_type():
    """
    Test the /api/v1/policies endpoint with invalid content type.

    Ensures a 400 error is returned.

    """
    response = client.post(
        "/api/v1/policies",
        headers={"content-type": "application/json"},
        json={"policies": {"policy1": {}}},
    )
    assert response.status_code == 400
    assert (
        response.json()["detail"]
        == "invalid Content-Type. Only 'application/x-yaml' is supported"
    )


def test_write_policy_multiple_policies(
    mock_multiple_policies_request, multiple_policies_yaml
):
    """
    Test posting multiple policies in a single request.

    Args:
    ----
        mock_multiple_policies_request: Mocked PolicyRequest object.
        multiple_policies_yaml: Multiple policies YAML string.

    """
    manager.runners = {}

    mock_request, mock_start_policy = mock_multiple_policies_request
    with patch(
        "worker.server.manager.parse_policy",
        return_value=mock_request,
    ):
        response = client.post(
            "/api/v1/policies",
            headers={"Content-Type": "application/x-yaml"},
            data=multiple_policies_yaml,
        )
        assert (
            response.json()["detail"] == "policies ['policy1', 'policy2'] were started"
        )
        assert response.status_code == 201

        mock_start_policy.assert_any_call("policy1", mock_request.policies["policy1"])
        mock_start_policy.assert_any_call("policy2", mock_request.policies["policy2"])
        assert mock_start_policy.call_count == 2


def test_write_policy_no_policy_error():
    """
    Test posting a request with no policies.

    Ensures a 400 error is returned, indicating no policy was found.

    """
    with patch(
        "worker.server.parse_yaml_body",
        return_value=PolicyRequest(policies={}),
    ):
        response = client.post(
            "/api/v1/policies",
            headers={"Content-Type": "application/x-yaml"},
            json={"policies": {}},
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "no policies found in request"


def test_policy_start_error(mock_valid_policy_request, valid_policy_yaml):
    """
    Test starting a policy that already exists.

    Args:
    ----
        mock_valid_policy_request: Mocked PolicyRequest object.
        valid_policy_yaml: Valid PolicyRequest YAML string.

    """
    mock_request, mock_start_policy = mock_valid_policy_request
    with patch(
        "worker.server.manager.parse_policy",
        return_value=mock_request,
    ), patch(
        "worker.server.manager.start_policy",
        side_effect=Exception("Policy exists"),
    ):
        response = client.post(
            "/api/v1/policies",
            headers={"Content-Type": "application/x-yaml"},
            data=valid_policy_yaml,
        )
        assert response.status_code == 400
        assert response.json() == {"detail": "Policy exists"}
        assert mock_start_policy.call_count == 0


def test_delete_policy(mock_manager):
    """
    Test deleting a valid policy.

    Ensures the policy is successfully deleted and correct response is returned.

    Args:
    ----
        mock_manager: Mocked PolicyManager instance.

    """
    mock_manager.policy_exists.return_value = True
    response = client.delete("/api/v1/policies/policy1")
    assert response.status_code == 200
    assert response.json() == {"detail": "policy 'policy1' was deleted"}


def test_delete_policy_not_found(mock_manager):
    """
    Test deleting a non-existent policy.

    Ensures a 404 error is returned if the policy does not exist.

    Args:
    ----
        mock_manager: Mocked PolicyManager instance.

    """
    mock_manager.delete_policy.side_effect = ValueError("policy 'policy1' not found")
    response = client.delete("/api/v1/policies/policy1")
    assert response.status_code == 404
    assert response.json()["detail"] == "policy 'policy1' not found"


def test_delete_policy_error(mock_manager):
    """
    Test deleting a policy that raises an exception.

    Ensures a 400 error is returned if an exception is raised.

    Args:
    ----
        mock_manager: Mocked PolicyManager instance.

    """
    mock_manager.delete_policy.side_effect = Exception("unexpected error")
    response = client.delete("/api/v1/policies/policy1")
    assert response.status_code == 400
    assert response.json()["detail"] == "unexpected error"
