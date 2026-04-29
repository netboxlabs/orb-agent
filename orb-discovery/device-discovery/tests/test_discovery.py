#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""NetBox Labs - Discovery Unit Tests."""

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from napalm.base.base import NetworkDriver

from device_discovery.discovery import (
    _DRIVER_MISMATCH_MARKERS,
    _default_discovery_drivers,
    custom_napalm_driver_list,
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


def _make_driver_mock(mock_get_network_driver, facts: dict):
    """
    Configure mock_get_network_driver so device.get_facts() returns facts.

    The call chain in discover_device_driver is:
      np_driver = get_network_driver(name)   → class mock
      with np_driver(host, ...) as device:   → instance mock used as context manager
          device_info = device.get_facts()   → device is __enter__'s return value
    """
    mock_class = MagicMock()
    mock_class.return_value.__enter__.return_value.get_facts.return_value = facts
    mock_get_network_driver.return_value = mock_class


@pytest.mark.parametrize(
    "hostname,fqdn,marker",
    [
        ("% Invalid", "", "%"),
        ("", "^ bad fqdn", "^"),
        ("Invalid input detected", "", "Invalid input"),
        ("", "prefix-Invalid input-suffix", "Invalid input"),
    ],
)
def test_discover_device_driver_mismatch_marker_in_facts(
    mock_get_network_driver, hostname, fqdn, marker
):
    """Test that a driver is skipped when device facts contain a mismatch marker."""
    _make_driver_mock(mock_get_network_driver, {
        "serial_number": "ABC123",
        "hostname": hostname,
        "fqdn": fqdn,
    })

    info = SimpleNamespace(
        hostname="testhost",
        username="testuser",
        password="testpass",
        timeout=10,
        optional_args={},
    )

    driver = discover_device_driver(info)
    assert driver is None, f"Expected no driver when '{marker}' marker is in facts"


def test_discover_device_driver_mismatch_marker_falls_through_to_valid_driver(
    mock_get_network_driver,
):
    """Test that discovery succeeds on a later driver when an earlier one returns mismatch markers."""

    def side_effect(driver_name):
        mock_class = MagicMock()
        if driver_name == "eos":
            facts = {"serial_number": "ABC123", "hostname": "% invalid", "fqdn": ""}
        else:
            facts = {"serial_number": "ABC123", "hostname": "real-device", "fqdn": "real-device.example.com"}
        mock_class.return_value.__enter__.return_value.get_facts.return_value = facts
        return mock_class

    mock_get_network_driver.side_effect = side_effect

    info = SimpleNamespace(
        hostname="testhost",
        username="testuser",
        password="testpass",
        timeout=10,
        optional_args={},
    )

    driver = discover_device_driver(info)
    assert driver is not None
    assert driver != "eos"


def test_driver_mismatch_markers_constant():
    """Test that _DRIVER_MISMATCH_MARKERS contains the expected markers."""
    assert "%" in _DRIVER_MISMATCH_MARKERS
    assert "^" in _DRIVER_MISMATCH_MARKERS
    assert "Invalid input" in _DRIVER_MISMATCH_MARKERS


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


def test_custom_napalm_driver_list(mock_import_module, mock_walk_packages):
    """Test that custom_napalm_driver_list discovers drivers from the custom_napalm package."""
    class MockVRPDriver(NetworkDriver):
        pass

    mock_module = MagicMock()
    mock_module.__path__ = ["custom_napalm"]
    mock_module.__name__ = "custom_napalm"
    setattr(mock_module, "MockVRPDriver", MockVRPDriver)

    mock_package = MagicMock()
    mock_package.name = "custom_napalm.vrp"

    mock_import_module.return_value = mock_module
    mock_walk_packages.return_value = [mock_package]

    result = custom_napalm_driver_list()

    mock_import_module.assert_any_call("custom_napalm")
    assert "vrp" in result


def test_supported_drivers_includes_custom_napalm():
    """Test that supported_drivers contains drivers from custom_napalm."""
    pytest.importorskip("custom_napalm")
    for driver in ("paloalto_panos", "paloalto_panos_ssh", "huawei_vrp"):
        assert driver in supported_drivers, f"Expected '{driver}' in supported_drivers"


def test_default_discovery_drivers_excludes_custom_napalm():
    """Test that _default_discovery_drivers does not include custom_napalm drivers."""
    pytest.importorskip("custom_napalm")
    for driver in ("paloalto_panos", "paloalto_panos_ssh", "huawei_vrp"):
        assert driver not in _default_discovery_drivers, (
            f"Custom driver '{driver}' must not appear in default auto-discovery pool"
        )


def test_discover_device_driver_uses_provided_drivers(mock_get_network_driver):
    """discover_device_driver only tries drivers from the provided list."""
    _make_driver_mock(mock_get_network_driver, {
        "serial_number": "XYZ999",
        "hostname": "mydevice",
        "fqdn": "mydevice.local",
    })

    info = SimpleNamespace(
        hostname="testhost",
        username="testuser",
        password="testpass",
        timeout=10,
        optional_args={},
    )

    driver = discover_device_driver(info, drivers=["panos"])
    assert driver == "panos"
    mock_get_network_driver.assert_called_once_with("panos")


def test_discover_device_driver_defaults_to_standard_napalm_only(mock_get_network_driver):
    """discover_device_driver defaults to standard NAPALM drivers only (no custom_napalm) when drivers=None."""
    _make_driver_mock(mock_get_network_driver, {
        "serial_number": "ABC123",
        "hostname": "host",
        "fqdn": "host.local",
    })

    info = SimpleNamespace(
        hostname="testhost",
        username="testuser",
        password="testpass",
        timeout=10,
        optional_args={},
    )

    driver = discover_device_driver(info)  # no drivers= arg
    assert driver in _default_discovery_drivers
    # custom_napalm-ONLY drivers (not also in the standard NAPALM list) must not
    # be tried by default.  Drivers like 'eos' and 'ios' appear in both lists
    # because custom_napalm ships subclasses that override the upstream driver;
    # those are intentionally included in _default_discovery_drivers.
    custom_drivers = set(custom_napalm_driver_list())
    custom_only_drivers = custom_drivers - set(_default_discovery_drivers)
    for call in mock_get_network_driver.call_args_list:
        assert call.args[0] not in custom_only_drivers, (
            f"Custom driver '{call.args[0]}' was tried during default auto-discovery"
        )
