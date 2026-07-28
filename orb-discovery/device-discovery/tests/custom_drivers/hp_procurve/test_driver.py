"""Unit tests for custom_napalm.hp_procurve.ProcurveDriver."""

from pathlib import Path

from custom_napalm.hp_procurve import (
    HEAVY_COMMAND_READ_TIMEOUT,
    ProcurveDriver,
    _parse_procurve_intf_mac_addresses,
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
