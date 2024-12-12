#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""NetBox Labs - Discovery Unit Tests."""

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from device_discovery.discovery import (
    discover_device_driver,
    napalm_driver_list,
    set_napalm_logs_level,
    supported_drivers,
)


@pytest.fixture
def mock_get_network_driver():
    """Mock the get_network_driver function from napalm."""
    with patch("device_discovery.discovery.get_network_driver") as mock:
        yield mock

@pytest.fixture
def mock_importlib_metadata_packages_distributions():
    """Mock the importlib_metadata.packages_distributions function."""
    with patch(
        "device_discovery.discovery.importlib_metadata.packages_distributions"
    ) as mock:
        yield mock


@pytest.fixture
def mock_loggers():
    """Mock the logging.getLogger function for various loggers."""
    with patch("device_discovery.discovery.logging.getLogger") as mock:
        yield mock


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


def test_napalm_driver_list(mock_importlib_metadata_packages_distributions):
    """
    Test the napalm_driver_list function to ensure it correctly lists available NAPALM drivers.

    Args:
    ----
        mock_importlib_metadata_packages_distributions: Mocked
        importlib_metadata.packages_distributions function.

    """
    mock_distributions = [
        "napalm_srl",
        "napalm_fake_driver",
    ]
    mock_importlib_metadata_packages_distributions.return_value = mock_distributions
    expected_drivers = ["ios", "eos", "junos", "nxos", "srl", "fake_driver"]
    drivers = napalm_driver_list()
    assert drivers == expected_drivers, f"Expected {expected_drivers}, got {drivers}"


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
