"""Unit tests for custom_napalm.fortinet_fortios_ssh.FortiOSSSHDriver."""

from pathlib import Path

import pytest

from custom_napalm.fortinet_fortios_ssh import (
    FortiOSSSHDriver,
    _parse_fnsysctl_mac_addresses,
    _scan_fields,
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


# ---------------------------------------------------------------------------
# _scan_fields — anchored key/value scanner
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        # A colon inside a value must not read as a key. This is the shape on
        # every up interface: 27 of 73 real physical blocks.
        ("speed: 1000Mbps (Duplex: full)", {"speed": "1000Mbps (Duplex: full)"}),
        # Right anchor: a colon with no following space is not a marker.
        ("description: site-a:core", {"description": "site-a:core"}),
        # Two whitespace-separated tokens stay one value here; _parse_flat splits them.
        ("ip: 10.0.0.1 255.255.255.0", {"ip": "10.0.0.1 255.255.255.0"}),
        # Real keys are mixed case, underscored and hyphenated.
        ("FEC_cap: none", {"fec_cap": "none"}),
        ("netbios-forward: disable", {"netbios-forward": "disable"}),
        (
            "name: port1 mode: static status: up trunk: disable",
            {"name": "port1", "mode": "static", "status": "up", "trunk": "disable"},
        ),
        # Fields the reporter's 7.4.12 device emits.
        ("medium: n/a", {"medium": "n/a"}),
        ("switch: sw0", {"switch": "sw0"}),
        ("aggregate: some long value", {"aggregate": "some long value"}),
        # No space after the colon: deliberately not a field.
        ("status:up", {}),
        ("", {}),
    ],
)
def test_scan_fields(line, expected):
    """Markers are recognised only when anchored on both sides."""
    fields, anomalies = _scan_fields(line)
    assert fields == expected
    assert anomalies == 0


def test_scan_fields_duplicate_key_keeps_the_first_and_counts_it():
    """Two markers for one key is ambiguous, so it surfaces rather than resolving."""
    fields, anomalies = _scan_fields("name: port1 ip: 10.0.0.1 255.255.255.0 name: port2")
    assert fields["name"] == "port1"
    assert anomalies == 1
