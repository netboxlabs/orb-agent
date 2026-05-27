"""Tests for the NXOSDriver subclass — VLAN-association coverage only."""

from pathlib import Path

import pytest

from custom_napalm.nxos import NXOSDriver, classify_module_type_nexus
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeJsonRpcDevice


@pytest.mark.parametrize("pid,name,expected", [
    ("N9K-SUP-A", "Slot 1", "supervisor"),
    ("N7K-SUP2E", "Slot 5", "supervisor"),
    ("N77-SUP2E", "Slot 1", "supervisor"),  # Nexus 7700 sup — form N77-, no K
    ("N77-SUP3E", "Slot 2", "supervisor"),
    ("N9K-X9736C-FX", "Slot 3", "linecard"),
    ("N9K-C9508-FM-E", "Slot 21", "linecard"),  # fabric → linecard
    ("QDD-400G-DR4-S", "Ethernet1/1", "transceiver"),  # optic (Bug 1 fix)
])
def test_classify_module_type_nexus(pid, name, expected):
    """Nexus PID classification incl. 7700 supervisors (N77-SUPxE)."""
    assert classify_module_type_nexus(pid, name) == expected


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

    def test_nxos_driver_exposes_get_modules(self) -> None:
        """get_modules() must exist on NXOSDriver after this batch lands."""
        assert hasattr(NXOSDriver, "get_modules")
        assert callable(getattr(NXOSDriver, "get_modules"))
