"""Tests for the JunOSDriver subclass — VLAN-association coverage only."""

from pathlib import Path

import pytest

from custom_napalm.junos import JunOSDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakePyEZDevice


class TestJunOSDriver(BaseDriverTest):
    """Tests for the Juniper Junos custom NAPALM driver."""

    driver_cls = JunOSDriver
    fake_device_cls = FakePyEZDevice
    mock_data_root = Path(__file__).parent / "mock_data"

    def test_get_facts(self, scenario):
        """Skip: inherited from napalm.junos.junos.JunOSDriver."""
        pytest.skip("inherited from napalm.junos.junos.JunOSDriver")

    def test_get_interfaces(self, scenario):
        """Skip: inherited from napalm.junos.junos.JunOSDriver."""
        pytest.skip("inherited from napalm.junos.junos.JunOSDriver")

    def test_get_interfaces_ip(self, scenario):
        """Skip: inherited from napalm.junos.junos.JunOSDriver."""
        pytest.skip("inherited from napalm.junos.junos.JunOSDriver")

    def test_get_config(self, scenario):
        """Skip: inherited from napalm.junos.junos.JunOSDriver."""
        pytest.skip("inherited from napalm.junos.junos.JunOSDriver")

    def test_get_config_sanitized(self, scenario):
        """Skip: inherited from napalm.junos.junos.JunOSDriver."""
        pytest.skip("inherited from napalm.junos.junos.JunOSDriver")

    def test_get_vlans(self, scenario):
        """Skip: inherited from napalm.junos.junos.JunOSDriver."""
        pytest.skip("inherited from napalm.junos.junos.JunOSDriver")
