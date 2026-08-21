"""Unit tests for custom_napalm.fortinet_fortios_ssh.FortiOSSSHDriver."""

import logging
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


# ---------------------------------------------------------------------------
# Parse signals
# ---------------------------------------------------------------------------

_LOGGER_NAME = "custom_napalm.fortinet_fortios_ssh"


def _driver_with(responses: dict[str, str | None]) -> FortiOSSSHDriver:
    """Build a driver whose device returns canned text per command."""

    class _Device:
        def send_command(self, command, **_kwargs):
            return responses.get(command, "")

    driver = object.__new__(FortiOSSSHDriver)
    driver.hostname, driver.username, driver.password = "h", "u", "p"
    driver.timeout = 60
    driver.device = _Device()
    return driver


def test_signal_one_warns_when_output_parsed_to_nothing(caplog):
    """Non-empty output and zero rows is the state the reporter hit."""
    driver = _driver_with({"get system interface physical": "Command fail. Return code -61\n"})
    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        assert driver.get_interfaces() == {}
    assert any("no interfaces could be parsed" in r.getMessage() for r in caplog.records)


def test_signal_one_is_silent_on_empty_output(caplog):
    """An empty answer is not evidence of a parsing defect."""
    driver = _driver_with({"get system interface physical": ""})
    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        assert driver.get_interfaces() == {}
    assert [r for r in caplog.records if r.levelno == logging.WARNING] == []


def test_signal_two_warns_on_unreadable_lines(caplog):
    """Rows parsed, but something in the output could not be read."""
    raw = (
        "== [onboard]\n    ==[port1]\n        status: up\n"
        "        speed: 1000Mbps (Duplex: full)\n    ==[port2] (SFP+)\n        status: up\n"
    )
    driver = _driver_with({"get system interface physical": raw})
    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        interfaces = driver.get_interfaces()
    assert "port1" in interfaces and "port2" not in interfaces
    assert any("problem(s) reading" in r.getMessage() for r in caplog.records)


def test_flat_signal_one_warns_when_output_parsed_to_nothing(caplog):
    """The flat command's counterpart of signal 1."""
    driver = _driver_with({"get system interface": "Command fail. Return code -61\n"})
    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        assert driver.get_interfaces_ip() == {}
    assert any("no interfaces could be parsed" in r.getMessage() for r in caplog.records)


def test_flat_signal_two_warns_on_unreadable_lines(caplog):
    """One row parsed, its address dropped: the anomaly must surface."""
    driver = _driver_with(
        {"get system interface": "name: port1 ip: 10.20.30.40 255.2 status: up\n"}
    )
    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        assert driver.get_interfaces_ip() == {}
    assert any("problem(s) reading" in r.getMessage() for r in caplog.records)


def test_signal_three_warns_when_addresses_were_present_but_none_emitted(caplog):
    """Catches a future rename of ip: silently emptying every address."""
    raw = "name: port1 ipaddr: 10.0.0.1 255.255.255.0 status: up\n"
    driver = _driver_with({"get system interface": raw})
    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        assert driver.get_interfaces_ip() == {}
    assert any("were emitted" in r.getMessage() for r in caplog.records)


def test_signal_three_silent_when_every_address_is_unnumbered(caplog):
    """45 of 102 real rows are 0.0.0.0; an all-DHCP box must not warn forever."""
    raw = "name: port1 ip: 0.0.0.0 0.0.0.0 status: up\n"
    driver = _driver_with({"get system interface": raw})
    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        assert driver.get_interfaces_ip() == {}
    assert [r for r in caplog.records if r.levelno == logging.WARNING] == []


def test_signal_three_silent_when_only_a_management_address_is_present(caplog):
    """A management address on an unnumbered box must not warn on every poll."""
    raw = (
        "name: port1 management-ip: 10.99.99.1 255.255.255.0 "
        "ip: 0.0.0.0 0.0.0.0 status: up\n"
    )
    driver = _driver_with({"get system interface": raw})
    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        assert driver.get_interfaces_ip() == {}
    assert [r for r in caplog.records if r.levelno == logging.WARNING] == []


@pytest.mark.parametrize("getter", ["get_interfaces", "get_interfaces_ip"])
def test_getters_tolerate_a_none_command_result(getter, caplog):
    """policy/runner.py has no handler of its own, so nothing may escape these."""
    command = (
        "get system interface physical" if getter == "get_interfaces" else "get system interface"
    )
    driver = _driver_with({command: None})
    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        assert getattr(driver, getter)() == {}
    assert [r for r in caplog.records if r.levelno == logging.WARNING] == []


# ---------------------------------------------------------------------------
# Unknown-field drift logging
# ---------------------------------------------------------------------------


def test_unknown_field_is_logged_once_at_debug(caplog):
    """The drift sensor that replaces the template's `^. -> Error`."""
    raw = (
        "== [onboard]\n    ==[port1]\n        medium: n/a\n        status: up\n"
        "        speed: 1000Mbps (Duplex: full)\n    ==[port2]\n        medium: n/a\n"
        "        status: up\n        speed: 1000Mbps (Duplex: full)\n"
    )
    with caplog.at_level(logging.DEBUG, logger=_LOGGER_NAME):
        rows, anomalies = _parse_physical(raw)
    assert len(rows) == 2 and anomalies == 0
    medium_logs = [r for r in caplog.records if "medium" in r.getMessage()]
    assert len(medium_logs) == 1, "log once per distinct unknown key per parse"


def test_known_fields_are_not_logged(caplog):
    """Real captures must log nothing, or the one line that matters is buried."""
    raw = (
        "== [onboard]\n    ==[port1]\n        mode: static\n        ip: 0.0.0.0 0.0.0.0\n"
        "        ipv6: ::/0\n        status: up\n        speed: n/a\n        FEC: none\n"
    )
    with caplog.at_level(logging.DEBUG, logger=_LOGGER_NAME):
        _parse_physical(raw)
    assert [r for r in caplog.records if "unknown field" in r.getMessage()] == []


def test_parse_flat_logs_an_unknown_field_once_per_parse(caplog):
    """The flat path carries the reporter's trunk:/switch:/aggregate:."""
    raw = (
        "name: port1 ip: 10.0.0.1 255.255.255.0 status: up trunk: disable\n"
        "name: port2 ip: 10.0.0.2 255.255.255.0 status: up trunk: disable\n"
    )
    with caplog.at_level(logging.DEBUG, logger=_LOGGER_NAME):
        rows, anomalies = _parse_flat(raw)
    assert len(rows) == 2 and anomalies == 0
    assert len([r for r in caplog.records if "trunk" in r.getMessage()]) == 1


def test_parse_flat_does_not_log_known_fields(caplog):
    """A real flat line must produce no drift noise."""
    raw = (
        "name: port1 mode: static ip: 10.0.0.1 255.255.255.0 status: up "
        "netbios-forward: disable type: physical ring-rx: 0 ring-tx: 0\n"
    )
    with caplog.at_level(logging.DEBUG, logger=_LOGGER_NAME):
        _parse_flat(raw)
    assert [r for r in caplog.records if "unknown field" in r.getMessage()] == []


def test_7412_flat_scenario_does_not_warn_about_addresses(caplog):
    """port1 is unnumbered, so signal 3 must stay silent on this scenario."""
    mock_dir = Path(__file__).parent / "mock_data" / "test_get_interfaces_ip" / "7412"
    driver = object.__new__(FortiOSSSHDriver)
    driver.hostname = driver.username = driver.password = "x"
    driver.timeout = 60
    driver.device = FakeCLIDevice(mock_dir)
    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        assert driver.get_interfaces_ip() == {
            "port2": {"ipv4": {"10.10.10.1": {"prefix_length": 24}}}
        }
    assert [r for r in caplog.records if r.levelno == logging.WARNING] == []


@pytest.mark.parametrize("name", ["1-P20/1", "amc-sw1/1", "port1", "npu0_vlink0", "l2t.root"])
def test_parse_physical_accepts_any_non_bracket_interface_name(name):
    """
    The replaced template matched any non-whitespace name, so slashes must keep working.

    FortiGate AMC and 7000-series split ports are named amc-sw1/1 and 1-P20/1. A
    hand-listed alphabet omitted the slash, and the whole interface was dropped from
    get_facts and get_interfaces while the template it replaced parsed it fine.
    """
    raw = (
        f"== [onboard]\n    ==[{name}]\n        mode: static\n"
        "        status: up\n        speed: 25000Mbps (Duplex: full)\n"
    )
    rows, anomalies = _parse_physical(raw)
    assert rows == [
        {"name": name, "mode": "static", "status": "up", "speed": "25000"}
    ]
    assert anomalies == 0


def test_parse_physical_counts_a_speed_it_cannot_read():
    """An unreadable rate is reported, not passed off as a missing one."""
    raw = (
        "== [onboard]\n    ==[port1]\n        status: up\n        speed: 10Gbps (Duplex: full)\n"
    )
    rows, anomalies = _parse_physical(raw)
    assert [(r["name"], r["status"], r["speed"]) for r in rows] == [("port1", "up", "")]
    assert anomalies == 1, "a present but unreadable speed must surface"


def test_parse_physical_discards_a_block_whose_status_is_empty():
    """An empty status would reach NetBox as is_up=False, which is a wrong value."""
    raw = (
        "== [onboard]\n    ==[port1]\n        status: \n        speed: n/a\n"
        "    ==[port2]\n        status: up\n        speed: n/a\n"
    )
    rows, anomalies = _parse_physical(raw)
    assert [r["name"] for r in rows] == ["port2"]
    assert anomalies == 1
