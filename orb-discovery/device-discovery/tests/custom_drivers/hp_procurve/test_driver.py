"""Unit tests for custom_napalm.hp_procurve.ProcurveDriver."""

from pathlib import Path

from custom_napalm.hp_procurve import (
    _EMPTY_FIELD_RE,
    HEAVY_COMMAND_READ_TIMEOUT,
    ProcurveDriver,
    _parse_procurve_intf_mac_addresses,
    _parse_show_system,
)
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestProcurveDriver(BaseDriverTest):
    """Unit tests for ProcurveDriver using file-based CLI mocks."""

    driver_cls = ProcurveDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"


# ---------------------------------------------------------------------------
# _parse_procurve_intf_mac_addresses — parser unit tests
# ---------------------------------------------------------------------------


def test_parse_procurve_intf_mac_addresses_typical_multi_block():
    """Two-port ``show interfaces <port-list>`` output → {port: normalised mac}."""
    text = """\
 Status and Counters - Port Counters for port 1

  Name (intended)                  : Uplink
  MAC Address                      : 001234-567801
  Link Status                      : Up

 Status and Counters - Port Counters for port 2

  Name (intended)                  :
  MAC Address                      : 001234-567802
  Link Status                      : Down
"""
    # napalm.mac() converts ProCurve dashed-pair form to canonical colon form.
    assert _parse_procurve_intf_mac_addresses(text) == {
        "1": "00:12:34:56:78:01",
        "2": "00:12:34:56:78:02",
    }


def test_parse_procurve_intf_mac_addresses_module_port_id():
    """Module-style port IDs like ``A1`` parse the same as plain numeric ports."""
    text = """\
 Status and Counters - Port Counters for port A1

  MAC Address                      : 001234-5678A1
  Link Status                      : Up
"""
    assert _parse_procurve_intf_mac_addresses(text) == {"A1": "00:12:34:56:78:A1"}


def test_parse_procurve_intf_mac_addresses_skips_block_without_mac():
    """A port block missing the MAC Address row is silently skipped (e.g. logical ports)."""
    text = """\
 Status and Counters - Port Counters for port 99

  Name (intended)                  :
  Link Status                      : Up

 Status and Counters - Port Counters for port 100

  MAC Address                      : 001234-567064
"""
    assert _parse_procurve_intf_mac_addresses(text) == {"100": "00:12:34:56:70:64"}


def test_parse_procurve_intf_mac_addresses_empty_and_none():
    """Empty / None input → empty dict, never raises."""
    assert _parse_procurve_intf_mac_addresses("") == {}
    assert _parse_procurve_intf_mac_addresses(None) == {}  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Heavy-command read timeouts (issue #484)
# ---------------------------------------------------------------------------


class _RecordingDevice:
    """CLI fake that records the read_timeout each command was sent with."""

    def __init__(self, responses: dict[str, str]):
        self._responses = responses
        self.calls: list[tuple[str, float | None]] = []

    def send_command(self, command: str, **kwargs) -> str:
        self.calls.append((command, kwargs.get("read_timeout")))
        return self._responses.get(command, "")

    def timeout_for(self, command: str) -> float | None:
        return next(t for c, t in self.calls if c == command)


def _driver_with(device) -> ProcurveDriver:
    drv = ProcurveDriver("host", "user", "pw")
    drv.device = device
    return drv


def test_show_tech_fallback_gets_an_explicit_read_timeout():
    """
    ``show tech`` must not run on Netmiko's 10s default read timeout.

    Devices that omit the model banner (e.g. ProCurve 2510G) fall back to
    ``show tech``, which emits thousands of lines on real hardware and blows
    past the default, aborting get_facts() and taking the whole driver down.
    """
    # show system without a model banner -> forces the show tech fallback.
    system = " Status and Counters - General System Information\n\n  System Name        : sw1\n"
    dev = _RecordingDevice({"show system": system, "show tech": "Name:      HP ProCurve Switch 2510G-48\n"})
    facts = _driver_with(dev).get_facts()

    assert dev.timeout_for("show tech") == HEAVY_COMMAND_READ_TIMEOUT
    assert HEAVY_COMMAND_READ_TIMEOUT >= 60
    # The model still comes from show tech, not a placeholder.
    assert facts["model"] == "HP ProCurve Switch 2510G-48"


def test_banner_model_skips_show_tech_entirely():
    """When the banner carries the model, the heavy command is never sent."""
    system = "HP ProCurve Switch 2650\n\n Status and Counters - General System Information\n\n  System Name : sw1\n"
    dev = _RecordingDevice({"show system": system})
    facts = _driver_with(dev).get_facts()

    assert "show tech" not in [c for c, _ in dev.calls]
    assert facts["model"] == "HP ProCurve Switch 2650"


def test_config_commands_get_an_explicit_read_timeout():
    """Full-config retrieval is also far too large for the 10s default."""
    dev = _RecordingDevice({"show running-config": "cfg\n", "show config": "cfg\n"})
    _driver_with(dev).get_config(retrieve="all")

    assert dev.timeout_for("show running-config") == HEAVY_COMMAND_READ_TIMEOUT
    assert dev.timeout_for("show config") == HEAVY_COMMAND_READ_TIMEOUT


# ---------------------------------------------------------------------------
# `show system` robustness: unset fields must not abort the parse (issue #484)
# ---------------------------------------------------------------------------


# Real 2510G-48 body (issue #484) with System Location left unset. The
# ntc-templates >= 9.2 template requires a non-empty value there and ends its
# Start state in `^. -> Error`, so this exact shape used to raise TextFSMError
# straight out of get_facts().
_SHOW_SYSTEM_EMPTY_LOCATION = """ Status and Counters - General System Information

  System Name        : 2510G-48-1
  System Contact     : netops@example.com
  System Location    :

  MAC Age Time (sec) : 300

  Time Zone          : -300
  Daylight Time Rule : Continental-US-and-Canada


  Software revision  : Y.11.52          Base MAC Addr      : 001122-334455
  ROM Version        : N.10.02          Serial Number      : SG00XX0000

  Up Time            : 6 hours          Memory   - Total   : 23,546,528
  CPU Util (%)       : 11                          Free    : 15,295,568

  IP Mgmt  - Pkts Rx : 28,953           Packet   - Total   : 3022
             Pkts Tx : 12,243           Buffers    Free    : 2787
                                                   Lowest  : 2660
                                                   Missed  : 0
"""


def test_empty_field_re_matches_only_valueless_lines():
    """The filter targets `key :` with nothing after it, and nothing else."""
    assert _EMPTY_FIELD_RE.match("  System Location    : ")
    assert _EMPTY_FIELD_RE.match("  System Location    :")
    # A populated field, a header and a blank line must all survive.
    assert not _EMPTY_FIELD_RE.match("  System Name        : 2510G-48-1")
    assert not _EMPTY_FIELD_RE.match(" Status and Counters - General System Information")
    assert not _EMPTY_FIELD_RE.match("")


def test_parse_show_system_survives_unset_location():
    """An unset System Location still yields hostname, version and serial."""
    lines = [
        ln
        for ln in _SHOW_SYSTEM_EMPTY_LOCATION.splitlines()
        if not _EMPTY_FIELD_RE.match(ln)
    ]
    rows = _parse_show_system(lines)
    assert rows, "expected a parsed row, got nothing"
    row = rows[0]
    assert row.get("name") == "2510G-48-1"
    assert row.get("software_version") == "Y.11.52"
    assert row.get("serial") == "SG00XX0000"


def test_parse_show_system_falls_back_when_template_rejects_output():
    """
    A body the template cannot parse degrades instead of raising.

    Passing the unfiltered text (System Location still unset) drives the
    template into its Error state. The driver must recover the three fields it
    needs rather than let the exception escape and cost us the whole device.
    """
    rows = _parse_show_system(_SHOW_SYSTEM_EMPTY_LOCATION.splitlines())
    assert rows, "fallback should still produce a row"
    row = rows[0]
    assert row.get("name") == "2510G-48-1"
    assert row.get("software_version") == "Y.11.52"
    assert row.get("serial") == "SG00XX0000"


def test_parse_show_system_returns_empty_for_unusable_output():
    """Nothing recognizable at all → empty list, never an exception."""
    assert _parse_show_system(["total garbage", "no fields here"]) == []


def test_parse_show_system_leaves_valueless_fields_unset():
    r"""
    A configured-but-empty field must not absorb the next field's label.

    Post-colon whitespace has to stay horizontal: with ``\s*`` the match runs
    past the newline and captures the following line's label as the value, so a
    blank ``System Name :`` yields the hostname ``System`` from the
    ``System Contact`` line under it, and a blank serial yields ``Up`` from
    ``Up Time``. Both would reach NetBox as real values.
    """
    body = """ Status and Counters - General System Information

  System Name        :
  System Contact     :
  Software revision  : Y.11.16
  ROM Version        : Y.11.03   Serial Number :
  Up Time            : 64 days
"""
    rows = _parse_show_system(body.splitlines())
    row = rows[0] if rows else {}

    assert row.get("name") is None, f"blank System Name leaked {row.get('name')!r}"
    assert row.get("serial") is None, f"blank Serial Number leaked {row.get('serial')!r}"
    # The field that does have a value is still recovered.
    assert row.get("software_version") == "Y.11.16"
