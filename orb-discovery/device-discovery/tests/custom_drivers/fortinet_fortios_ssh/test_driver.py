"""Unit tests for custom_napalm.fortinet_fortios_ssh.FortiOSSSHDriver."""

from pathlib import Path

import pytest

from custom_napalm.fortinet_fortios_ssh import (
    FortiOSSSHDriver,
    _normalise_speed,
    _parse_flat,
    _parse_fnsysctl_mac_addresses,
    _parse_physical,
    _scan_fields,
    _valid_quad,
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


# ---------------------------------------------------------------------------
# _normalise_speed / _parse_physical
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("1000Mbps (Duplex: full)", "1000"),
        ("10000Mbps (Duplex: full)", "10000"),  # five digits occur in the corpus
        ("n/a", "n/a"),                          # the sentinel get_interfaces tests for
        ("n/a (Duplex: n/a)", "n/a"),
        ("10Gbps (Duplex: full)", ""),           # never a unit-less number
        ("auto", ""),
        ("", ""),
    ],
)
def test_normalise_speed(value, expected):
    """Digits only for Mbps; the n/a sentinel preserved; anything else empty."""
    assert _normalise_speed(value) == expected


PHYSICAL_TWO_PORTS = """\
== [onboard]
    ==[port1]
        mode: static
        status: up
        speed: 1000Mbps (Duplex: full)
    ==[port2]
        mode: static
        status: down
        speed: n/a
"""


def test_parse_physical_typical_two_blocks():
    """Group header ignored, one row per interface, speed normalised."""
    rows, anomalies = _parse_physical(PHYSICAL_TWO_PORTS)
    assert [(r["name"], r["status"], r["speed"]) for r in rows] == [
        ("port1", "up", "1000"),
        ("port2", "down", "n/a"),
    ]
    assert anomalies == 0


def test_parse_physical_emits_the_block_left_open_at_end_of_input():
    """Every real capture ends on a field line, so EOF must close the block."""
    rows, anomalies = _parse_physical(PHYSICAL_TWO_PORTS.rstrip("\n"))
    assert [r["name"] for r in rows] == ["port1", "port2"]
    assert anomalies == 0


def test_parse_physical_unreadable_header_does_not_move_fields_to_the_previous_block():
    """An unrecognised header must not let its fields land on the interface above."""
    raw = """\
== [onboard]
    ==[port1]
        status: up
        speed: 1000Mbps (Duplex: full)
    ==[port2] (SFP+)
        status: down
        speed: n/a
"""
    rows, anomalies = _parse_physical(raw)
    assert [(r["name"], r["status"], r["speed"]) for r in rows] == [("port1", "up", "1000")]
    assert anomalies == 3, "the unreadable header plus its two orphaned field lines"


def test_parse_physical_discards_a_block_with_an_unreadable_field_line():
    """An unreadable field line closes the block, so the block is absent."""
    raw = """\
== [onboard]
    ==[port1]
        status:up
        speed: 1000Mbps (Duplex: full)
    ==[port2]
        status: up
        speed: 1000Mbps (Duplex: full)
"""
    rows, anomalies = _parse_physical(raw)
    assert [r["name"] for r in rows] == ["port2"], "port1 lacked a readable status"
    assert anomalies == 3


def test_parse_physical_discards_a_block_that_scanned_only_status():
    """The status AND speed rule: one field is not enough."""
    raw = (
        "== [onboard]\n    ==[port1]\n        status: up\n"
        "    ==[port2]\n        status: up\n        speed: 1000Mbps (Duplex: full)\n"
    )
    rows, anomalies = _parse_physical(raw)
    assert [r["name"] for r in rows] == ["port2"], "port1 never scanned a speed"
    assert anomalies == 1


def test_parse_physical_discards_a_block_that_scanned_only_speed():
    """Mirror of the status-only case, so `and` cannot be relaxed to `or`."""
    raw = (
        "== [onboard]\n    ==[port1]\n        speed: n/a\n"
        "    ==[port2]\n        status: up\n        speed: 1000Mbps (Duplex: full)\n"
    )
    rows, anomalies = _parse_physical(raw)
    assert [r["name"] for r in rows] == ["port2"]
    assert anomalies == 1


def test_parse_physical_tolerates_crlf_line_endings():
    """One vendored capture is CRLF; splitlines handles it, so pin that."""
    raw = "== [onboard]\r\n    ==[port1]\r\n        status: up\r\n        speed: n/a\r\n"
    rows, anomalies = _parse_physical(raw)
    assert [(r["name"], r["status"], r["speed"]) for r in rows] == [("port1", "up", "n/a")]
    assert anomalies == 0


def test_parse_physical_tolerates_tabs_and_blank_lines():
    """Indentation may be tabs; blank lines neither close a block nor count."""
    raw = "== [onboard]\n\t==[port1]\n\n\t\tstatus: up\n\t\tspeed: 1000Mbps (Duplex: full)\n"
    rows, anomalies = _parse_physical(raw)
    assert [(r["name"], r["status"]) for r in rows] == [("port1", "up")]
    assert anomalies == 0


def test_parse_physical_ignores_unknown_fields():
    """The point of the change: a new FortiOS field changes nothing."""
    raw = PHYSICAL_TWO_PORTS.replace(
        "        status: up\n", "        medium: n/a\n        status: up\n"
    )
    rows, anomalies = _parse_physical(raw)
    assert [(r["name"], r["status"], r["speed"]) for r in rows] == [
        ("port1", "up", "1000"),
        ("port2", "down", "n/a"),
    ]
    assert anomalies == 0
    assert rows[0]["medium"] == "n/a"


@pytest.mark.parametrize("raw", [None, "", "   \n\n"])
def test_parse_physical_empty_input(raw):
    """Empty or missing output is zero rows, never an exception."""
    assert _parse_physical(raw) == ([], 0)


# ---------------------------------------------------------------------------
# _valid_quad / _parse_flat
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("255.255.255.0", True),
        ("0.0.0.0", True),
        ("255.2", False),
        ("255.255.255.255.255", False),
        ("255.255.255.256", False),
        ("", False),
    ],
)
def test_valid_quad(value, expected):
    """Four dotted decimal octets in 0-255, restoring what the template enforced."""
    assert _valid_quad(value) is expected


FLAT_TWO_ROWS = """\
== [ port1 ]
name: port1 mode: static ip: 10.0.0.1 255.255.255.0 status: up type: physical
== [ mgmt ]
name: mgmt management-ip: 10.99.99.1 255.255.255.0 ip: 0.0.0.0 0.0.0.0 status: up
"""


def test_parse_flat_splits_ip_and_keeps_management_ip_distinct():
    """The two-token ip becomes ip_address + netmask, under the names the getter reads."""
    rows, anomalies = _parse_flat(FLAT_TWO_ROWS)
    assert anomalies == 0
    assert [(r["name"], r["ip_address"], r["netmask"]) for r in rows] == [
        ("port1", "10.0.0.1", "255.255.255.0"),
        ("mgmt", "0.0.0.0", "0.0.0.0"),
    ]
    assert rows[1]["management_ip"] == "10.99.99.1"
    assert rows[1]["management_netmask"] == "255.255.255.0"
    assert "ip" not in rows[0] and "management-ip" not in rows[1]


def test_parse_flat_ignores_headers_without_counting_them():
    """Headers are 1:1 with rows, so counting them would warn on every device."""
    rows, anomalies = _parse_flat(FLAT_TWO_ROWS)
    assert len(rows) == 2
    assert anomalies == 0


def test_parse_flat_derives_nothing_from_the_header():
    """One real capture has `== [ VPN-TUN ]` above `name: VPN-LAB`."""
    raw = "== [ VPN-TUN ]\nname: VPN-LAB ip: 10.1.1.1 255.255.255.0 status: up\n"
    rows, _ = _parse_flat(raw)
    assert [r["name"] for r in rows] == ["VPN-LAB"]


@pytest.mark.parametrize(
    "value",
    [
        "10.20.30.40",                      # truncated: one token
        "10.20.30.40 255.2",                # malformed mask
        "10.20.30.40 255.255.255.256",      # octet out of range
        "10.20.30.40 255.255.255.0 extra",  # three tokens: pins `== 2`, not `>= 2`
    ],
)
def test_parse_flat_drops_an_unusable_address_pair(value):
    """Anything but two valid dotted quads yields no address, and is counted."""
    rows, anomalies = _parse_flat(f"name: port1 ip: {value} status: up\n")
    assert rows[0]["name"] == "port1"
    assert "ip_address" not in rows[0] and "netmask" not in rows[0]
    assert anomalies == 1


def test_parse_flat_empty_name_is_not_a_row():
    """A nameless row would make len(rows) non-zero and silence signal 1."""
    rows, anomalies = _parse_flat("name:  status: up\n")
    assert rows == []
    assert anomalies == 1


def test_parse_flat_ignores_unknown_fields():
    """trunk:/switch:/aggregate: from 7.4.12 change nothing."""
    raw = (
        "name: port1 ip: 10.0.0.1 255.255.255.0 status: up "
        "trunk: disable switch: sw0 aggregate: agg1\n"
    )
    rows, anomalies = _parse_flat(raw)
    assert (rows[0]["name"], rows[0]["ip_address"]) == ("port1", "10.0.0.1")
    assert rows[0]["trunk"] == "disable"
    assert anomalies == 0


@pytest.mark.parametrize("raw", [None, "", "   \n\n"])
def test_parse_flat_empty_input(raw):
    """Empty or missing output is zero rows, never an exception."""
    assert _parse_flat(raw) == ([], 0)
