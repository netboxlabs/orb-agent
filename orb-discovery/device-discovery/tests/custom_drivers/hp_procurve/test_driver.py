"""Unit tests for custom_napalm.hp_procurve.ProcurveDriver."""

from pathlib import Path

from custom_napalm.hp_procurve import (
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
