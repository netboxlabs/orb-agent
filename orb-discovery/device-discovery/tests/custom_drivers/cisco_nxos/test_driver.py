"""Tests for the NXOSDriver subclass — VLAN-association coverage only."""

from pathlib import Path

import pytest

from custom_napalm.nxos import NXOSDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeJsonRpcDevice


class TestNXOSDriver(BaseDriverTest):
    """Tests for the Cisco NX-OS custom driver."""

    driver_cls = NXOSDriver
    fake_device_cls = FakeJsonRpcDevice
    mock_data_root = Path(__file__).parent / "mock_data"

    def test_get_facts(self, scenario):
        """Skip: inherited from napalm.nxos.nxos.NXOSDriver."""
        pytest.skip("inherited from napalm.nxos.nxos.NXOSDriver")

    def test_get_interfaces(self, scenario):
        """Skip: inherited from napalm.nxos.nxos.NXOSDriver."""
        pytest.skip("inherited from napalm.nxos.nxos.NXOSDriver")

    def test_get_interfaces_ip(self, scenario):
        """Skip: inherited from napalm.nxos.nxos.NXOSDriver."""
        pytest.skip("inherited from napalm.nxos.nxos.NXOSDriver")

    def test_get_config(self, scenario):
        """Skip: inherited from napalm.nxos.nxos.NXOSDriver."""
        pytest.skip("inherited from napalm.nxos.nxos.NXOSDriver")

    def test_get_config_sanitized(self, scenario):
        """Skip: inherited from napalm.nxos.nxos.NXOSDriver."""
        pytest.skip("inherited from napalm.nxos.nxos.NXOSDriver")

    def test_get_vlans(self, scenario):
        """Skip: inherited from napalm.nxos.nxos.NXOSDriver."""
        pytest.skip("inherited from napalm.nxos.nxos.NXOSDriver")
