#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""NetBox Labs - Discovery Unit Tests."""

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from napalm.base.base import NetworkDriver

from device_discovery.discovery import (
    discover_device_driver,
    napalm_driver_list,
    set_napalm_logs_level,
    supported_drivers,
    walk_napalm_packages,
)


@pytest.fixture
def mock_get_network_driver():
    """Mock the get_network_driver function from napalm."""
    with patch("device_discovery.discovery.get_network_driver") as mock:
        yield mock


@pytest.fixture
def mock_packages_distributions():
    """Mock the importlib.metadata.packages_distributions function."""
    with patch("device_discovery.discovery.packages_distributions") as mock:
        yield mock


@pytest.fixture
def mock_loggers():
    """Mock the logging.getLogger function for various loggers."""
    with patch("device_discovery.discovery.logging.getLogger") as mock:
        yield mock


@pytest.fixture
def mock_import_module():
    """Fixture to mock import_module."""
    with patch("device_discovery.discovery.import_module") as mock_import:
        yield mock_import


@pytest.fixture
def mock_walk_packages():
    """Fixture to mock walk_packages."""
    with patch("device_discovery.discovery.walk_packages") as mock_import:
        yield mock_import


def test_discover_device_driver_success(mock_get_network_driver):
    """
    Test successful discovery of a NAPALM driver.

    Args:
    ----
        mock_get_network_driver: Mocked get_network_driver function.

    """
    mock_driver_instance = MagicMock()
    mock_driver_instance.get_facts.return_value = {"serial_number": "ABC123"}

    mock_get_network_driver.side_effect = [
        MagicMock(return_value=mock_driver_instance)
    ] * len(supported_drivers)

    info = SimpleNamespace(
        hostname="testhost",
        username="testuser",
        password="testpass",
        timeout=10,
        optional_args={},
    )

    driver = discover_device_driver(info)
    assert driver in supported_drivers, "Expected one of the supported drivers"


def test_discover_device_driver_no_serial_number(mock_get_network_driver):
    """
    Test discovery when no serial number is found.

    Args:
    ----
        mock_get_network_driver: Mocked get_network_driver function.

    """

    def side_effect():
        mock_driver_instance = MagicMock()
        mock_driver_instance.get_facts.return_value = {"serial_number": "Unknown"}
        return mock_driver_instance

    mock_get_network_driver.side_effect = side_effect

    info = SimpleNamespace(
        hostname="testhost",
        username="testuser",
        password="testpass",
        timeout=10,
        optional_args={},
    )

    driver = discover_device_driver(info)
    assert driver is None, "Expected no driver to be found"


def test_discover_device_driver_exception(mock_get_network_driver):
    """
    Test discovery when exceptions are raised.

    Args:
    ----
        mock_get_network_driver: Mocked get_network_driver function.

    """
    mock_get_network_driver.side_effect = Exception("Connection failed")

    info = SimpleNamespace(
        hostname="testhost",
        username="testuser",
        password="testpass",
        timeout=10,
        optional_args={},
    )

    driver = discover_device_driver(info)
    assert driver is None, "Expected no driver to be found due to exception"


def test_discover_device_driver_mixed_results(mock_get_network_driver):
    """
    Test discovery with mixed results from drivers.

    Args:
    ----
        mock_get_network_driver: Mocked get_network_driver function.

    """

    def side_effect(driver_name):
        if driver_name == "nxos":
            mock_driver_instance = MagicMock()
            mock_driver_instance.get_facts.return_value = {"serial_number": "ABC123"}
            return mock_driver_instance
        raise Exception("Connection failed")

    mock_get_network_driver.side_effect = side_effect

    info = SimpleNamespace(
        hostname="testhost",
        username="testuser",
        password="testpass",
        timeout=10,
        optional_args={},
    )

    driver = discover_device_driver(info)
    assert driver == "nxos", "Expected the 'ios' driver to be found"


def test_napalm_driver_list(mock_packages_distributions, mock_import_module):
    """
    Test the napalm_driver_list function to ensure it correctly lists available NAPALM drivers.

    Args:
    ----
        mock_packages_distributions: Mocked importlib.metadata.packages_distributions function.
        mock_import_module: Mocked import_module function.

    """
    mock_distributions = [
        "napalm_srl",
        "napalm_fake_driver",
    ]

    class MockDriver(NetworkDriver):
        pass

    mock_module = MagicMock()
    setattr(mock_module, "MockDriver", MockDriver)
    mock_import_module.return_value = mock_module

    mock_packages_distributions.return_value = mock_distributions

    expected_drivers = [
        "eos",
        "ios",
        "iosxr_netconf",
        "junos",
        "nxos",
        "nxos_ssh",
        "srl",
        "fake_driver",
    ]
    drivers = napalm_driver_list()
    assert drivers == expected_drivers, f"Expected {expected_drivers}, got {drivers}"


def test_napalm_driver_list_error(mock_packages_distributions, mock_import_module):
    """
    Test the napalm_driver_list function when an error occurs during driver import.

    Args:
    ----
        mock_packages_distributions: Mocked importlib.metadata.packages_distributions function.
        mock_import_module: Mocked import_module function.

    """
    mock_distributions = [
        "napalm_srl",
    ]

    mock_import_module.side_effect = Exception("Import failed")
    mock_packages_distributions.return_value = mock_distributions
    expected_drivers = ["eos", "ios", "iosxr_netconf", "junos", "nxos", "nxos_ssh"]

    with patch("device_discovery.discovery.logger") as mock_logger:
        drivers = napalm_driver_list()
        mock_logger.error.assert_called_once_with(
            f"Error importing module {mock_distributions[0]}: Import failed"
        )
        assert (
            drivers == expected_drivers
        ), f"Expected {expected_drivers}, got {drivers}"


def test_napalm_driver_list_nested(mock_packages_distributions, mock_import_module):
    """
    Test the napalm_driver_list function when a driver is found in a nested module.

    Args:
    ----
        mock_packages_distributions: Mocked importlib.metadata.packages_distributions function.
        mock_import_module: Mocked import_module function.

    """
    mock_distributions = [
        "napalm_srl",
    ]

    mock_module = MagicMock()
    mock_import_module.return_value = mock_module

    mock_packages_distributions.return_value = mock_distributions

    expected_drivers = ["ios", "eos", "junos", "nxos", "srl.nested"]

    with patch(
        "device_discovery.discovery.walk_napalm_packages", return_value=expected_drivers
    ):
        drivers = napalm_driver_list()
        assert (
            drivers == expected_drivers
        ), f"Expected {expected_drivers}, got {drivers}"


def test_walk_napalm_packages_success(mock_import_module, mock_walk_packages):
    """
    Test walk_napalm_packages function with valid modules.

    Args:
    ----
        mock_import_module: Mocked import_module function.
        mock_walk_packages: Mocked walk_packages function.

    """

    class MockDriver(NetworkDriver):
        pass

    mock_module = MagicMock()
    setattr(mock_module, "MockDriver", MockDriver)
    mock_module.__path__ = ["mock/path"]
    mock_module.__name__ = "napalm_test"
    mock_package = MagicMock()
    mock_package.name = "napalm_test.test_driver"

    mock_import_module.return_value = mock_module
    mock_walk_packages.return_value = [mock_package]

    result = walk_napalm_packages(mock_module, "napalm_", ["ios"])
    assert result == ["ios", "test.test_driver"]


def test_walk_napalm_packages_no_drivers(mock_import_module, mock_walk_packages):
    """
    Test walk_napalm_packages function when no valid drivers are found.

    Args:
    ----
        mock_import_module: Mocked import_module function.
        mock_walk_packages: Mocked walk_packages function.

    """
    mock_module = MagicMock()
    mock_module.__path__ = ["mock/path"]
    mock_module.__name__ = "napalm"
    mock_package = MagicMock()
    mock_package.name = "napalm.invalid_driver"

    mock_import_module.return_value = MagicMock()
    mock_walk_packages.return_value = [mock_package]

    with patch("device_discovery.discovery.inspect.getmembers", return_value=[]):
        result = walk_napalm_packages(mock_module, "napalm.", [])
        assert result == [], f"Expected an empty list, got {result}"


def test_walk_napalm_packages_exception_handling(
    mock_import_module, mock_walk_packages
):
    """
    Test walk_napalm_packages function with exceptions during module import.

    Args:
    ----
        mock_import_module: Mocked import_module function.
        mock_walk_packages: Mocked walk_packages function.

    """
    mock_module = MagicMock()
    mock_module.__path__ = ["mock/path"]
    mock_module.__name__ = "napalm"
    mock_package = MagicMock()
    mock_package.name = "napalm.error_driver"

    mock_import_module.side_effect = Exception("Import failed")
    mock_walk_packages.return_value = [mock_package]

    with patch("device_discovery.discovery.logger") as mock_logger:
        result = walk_napalm_packages(mock_module, "napalm.", [])
        mock_logger.error.assert_called_once_with(
            f"Error importing module {mock_package.name}: Import failed"
        )
        assert result == [], f"Expected an empty list, got {result}"


def test_set_napalm_logs_level(mock_loggers):
    """
    Test setting the logging level for NAPALM and related libraries.

    Args:
    ----
        mock_loggers: Mocked loggers for various libraries.

    """
    set_napalm_logs_level(logging.DEBUG)

    for logger in mock_loggers.values():
        logger.setLevel.assert_called_once_with(logging.DEBUG)
