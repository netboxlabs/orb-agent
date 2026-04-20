"""Unit tests for custom_napalm.ciena_saos.SAOSDriver."""

from pathlib import Path

import pytest

from custom_napalm.ciena_saos import SAOSDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestSAOSDriver(BaseDriverTest):
    """Unit tests for SAOSDriver using file-based CLI mocks."""

    driver_cls = SAOSDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"


class TestSAOSDriverInit:
    """Tests for SAOSDriver __init__ and optional_args handling."""

    def test_default_device_type(self):
        """Default driver uses ciena_saos Netmiko device type."""
        driver = SAOSDriver("host", "user", "pass")
        assert driver._device_type == "ciena_saos"

    def test_saos10_device_type_string(self):
        """saos_version='10' selects ciena_saos10 device type."""
        driver = SAOSDriver("host", "user", "pass", optional_args={"saos_version": "10"})
        assert driver._device_type == "ciena_saos10"

    def test_saos10_device_type_integer(self):
        """saos_version=10 (integer from YAML) is coerced correctly."""
        driver = SAOSDriver("host", "user", "pass", optional_args={"saos_version": 10})
        assert driver._device_type == "ciena_saos10"

    @pytest.mark.parametrize("version", ["6", "8", "other", None])
    def test_non_10_version_falls_back_to_saos(self, version):
        """Any saos_version other than '10' uses ciena_saos."""
        args = {} if version is None else {"saos_version": version}
        driver = SAOSDriver("host", "user", "pass", optional_args=args)
        assert driver._device_type == "ciena_saos"

    def test_custom_port_in_optional_args(self):
        """Port from optional_args is forwarded to netmiko_optional_args."""
        driver = SAOSDriver("host", "user", "pass", optional_args={"port": 2222})
        assert driver.netmiko_optional_args["port"] == 2222

    def test_default_port(self):
        """Default port is 22 when not provided."""
        driver = SAOSDriver("host", "user", "pass")
        assert driver.netmiko_optional_args["port"] == 22
