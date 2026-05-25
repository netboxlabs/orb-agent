"""Unit tests for custom_napalm.fortinet_fortios_ssh.FortiOSSSHDriver."""

from pathlib import Path

from custom_napalm.fortinet_fortios_ssh import (
    FortiOSSSHDriver,
    _parse_fnsysctl_mac_addresses,
)
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestFortiOSSSHDriver(BaseDriverTest):
    """Unit tests for FortiOSSSHDriver using file-based CLI mocks."""

    driver_cls = FortiOSSSHDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"


# ---------------------------------------------------------------------------
# _parse_fnsysctl_mac_addresses — parser unit tests
# ---------------------------------------------------------------------------


def test_parse_fnsysctl_mac_addresses_typical_two_ports():
    """Two-NIC ``fnsysctl ifconfig`` output → {port: normalised MAC}."""
    text = """\
port1   Link encap:Ethernet  HWaddr 00:09:0F:09:00:01
        inet addr:192.168.1.1  Mask:255.255.255.0
        UP BROADCAST RUNNING

port2   Link encap:Ethernet  HWaddr 00:09:0F:09:00:02
        BROADCAST MULTICAST
"""
    assert _parse_fnsysctl_mac_addresses(text) == {
        "port1": "00:09:0F:09:00:01",
        "port2": "00:09:0F:09:00:02",
    }


def test_parse_fnsysctl_mac_addresses_skips_loopback():
    """``Link encap:Local Loopback`` doesn't match the Ethernet-only header."""
    text = """\
port1   Link encap:Ethernet  HWaddr 00:09:0F:09:00:01

lo      Link encap:Local Loopback
        inet addr:127.0.0.1  Mask:255.0.0.0
"""
    assert _parse_fnsysctl_mac_addresses(text) == {"port1": "00:09:0F:09:00:01"}


def test_parse_fnsysctl_mac_addresses_empty_and_none():
    """Empty / None input → empty dict, never raises (admin without shell access)."""
    assert _parse_fnsysctl_mac_addresses("") == {}
    assert _parse_fnsysctl_mac_addresses(None) == {}  # type: ignore[arg-type]
