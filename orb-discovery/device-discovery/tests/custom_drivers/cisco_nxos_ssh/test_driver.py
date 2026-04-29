"""Tests for the NXOSSSHDriver subclass — VLAN-association coverage only."""

from pathlib import Path

import pytest

from custom_napalm.nxos_ssh import NXOSSSHDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


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

    def test_get_interfaces_ip(self, scenario):
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
