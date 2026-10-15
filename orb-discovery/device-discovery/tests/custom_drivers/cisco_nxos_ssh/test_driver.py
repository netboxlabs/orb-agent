"""Tests for the NXOSSSHDriver subclass — VLAN-association coverage only."""

from pathlib import Path

import pytest

from custom_napalm.nxos_ssh import NXOSSSHDriver, classify_module_type_nexus_ssh
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


@pytest.mark.parametrize("pid,name,expected", [
    ("N9K-SUP-A", "Slot 1", "supervisor"),
    ("N7K-SUP2E", "Slot 5", "supervisor"),
    ("N77-SUP2E", "Slot 1", "supervisor"),  # Nexus 7700 sup — form N77-, no K
    ("N77-SUP3E", "Slot 2", "supervisor"),
    ("N9K-X9736C-FX", "Slot 3", "linecard"),
    ("N9K-C9508-FM-E", "Slot 21", "linecard"),  # fabric → linecard
    ("QDD-400G-DR4-S", "Ethernet1/1", "transceiver"),  # optic (Bug 1 fix)
])
def test_classify_module_type_nexus_ssh(pid, name, expected):
    """SSH-path classifier must stay in sync with the NX-API duplicate."""
    assert classify_module_type_nexus_ssh(pid, name) == expected


class TestNXOSSSHDriver(BaseDriverTest):
    """Tests for the Cisco NX-OS-SSH custom driver."""

    driver_cls = NXOSSSHDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"

    def test_get_facts(self, scenario):
        """Skip: inherited from napalm.nxos_ssh.nxos_ssh.NXOSSSHDriver."""
        pytest.skip("inherited from napalm.nxos_ssh.nxos_ssh.NXOSSSHDriver")

    def test_get_interfaces(self, scenario):
        """Skip: inherited from napalm.nxos_ssh.nxos_ssh.NXOSSSHDriver."""
        pytest.skip("inherited from napalm.nxos_ssh.nxos_ssh.NXOSSSHDriver")

    def test_get_config(self, scenario):
        """Skip: inherited from napalm.nxos_ssh.nxos_ssh.NXOSSSHDriver."""
        pytest.skip("inherited from napalm.nxos_ssh.nxos_ssh.NXOSSSHDriver")

    def test_get_config_sanitized(self, scenario):
        """Skip: inherited from napalm.nxos_ssh.nxos_ssh.NXOSSSHDriver."""
        pytest.skip("inherited from napalm.nxos_ssh.nxos_ssh.NXOSSSHDriver")

    def test_get_vlans(self, scenario):
        """Skip: inherited from napalm.nxos_ssh.nxos_ssh.NXOSSSHDriver."""
        pytest.skip("inherited from napalm.nxos_ssh.nxos_ssh.NXOSSSHDriver")

    def test_get_interfaces_vlans_names_match_get_interfaces(self) -> None:
        """
        Keys use the names napalm's get_interfaces() reports.

        NX-OS prints ``port-channel10`` in ``show interface switchport`` while
        napalm canonicalizes it to ``Port-channel10``; the interface VLAN
        mapping matches on exact names, so a raw key leaves the port-channel
        without its VLANs.
        """
        driver = self._build_driver(self.mock_data_root / "test_get_interfaces_vlans" / "port_channel")
        vlans = driver.get_interfaces_vlans()
        assert "Port-channel10" in vlans
        assert set(vlans) <= set(driver.get_interfaces())

    def test_get_interfaces_ip_names_match_get_interfaces(self) -> None:
        """
        Addresses are keyed by the names napalm's get_interfaces() reports.

        ``show ip interface vrf all`` prints ``loopback0``, ``mgmt0`` and
        ``port-channel20``; get_interfaces() reports ``Loopback0``,
        ``Management0`` and ``Port-channel20``. A raw key put the address on a
        second, lowercase interface instead of the real one.
        """
        driver = self._build_driver(self.mock_data_root / "test_get_interfaces_ip" / "routed")
        addresses = driver.get_interfaces_ip()
        assert set(addresses) <= set(driver.get_interfaces())
        assert addresses["Loopback0"] == {
            "ipv4": {"192.0.2.1": {"prefix_length": 32}},
            "ipv6": {"2001:db8::1": {"prefix_length": 128}},
        }
        assert addresses["Management0"]["ipv4"] == {"203.0.113.10": {"prefix_length": 24}}
        assert addresses["Port-channel20"]["ipv4"] == {"198.51.100.5": {"prefix_length": 30}}

    def test_get_network_instances_names_match_get_interfaces(self) -> None:
        """VRF members are keyed by the names napalm's get_interfaces() reports."""
        driver = self._build_driver(self.mock_data_root / "test_get_network_instances" / "routed")
        members = {
            name
            for instance in driver.get_network_instances().values()
            for name in instance["interfaces"]["interface"]
        }
        assert members == {"Loopback0", "Management0", "Ethernet1/1", "Port-channel20"}
        assert members <= set(driver.get_interfaces())

    def test_nxos_ssh_driver_exposes_get_modules(self) -> None:
        """get_modules() must exist on NXOSSSHDriver after this batch lands."""
        assert hasattr(NXOSSSHDriver, "get_modules")
        assert callable(getattr(NXOSSSHDriver, "get_modules"))
