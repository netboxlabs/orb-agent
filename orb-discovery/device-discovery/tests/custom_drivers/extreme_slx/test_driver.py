"""Unit tests for custom_napalm.extreme_slx.SLXOSDriver."""

from pathlib import Path

from custom_napalm.extreme_slx import SLXOSDriver, _parse_intf_hw_addresses
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestSLXOSDriver(BaseDriverTest):
    """Unit tests for SLXOSDriver using file-based CLI mocks."""

    driver_cls = SLXOSDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"


# ---------------------------------------------------------------------------
# _parse_intf_hw_addresses — parser unit tests
# ---------------------------------------------------------------------------


def test_parse_intf_hw_addresses_typical_multi_block():
    """Multi-port `show interface` output → {name: normalised_mac}."""
    text = """\
Ethernet 0/1 is up, line protocol is up (connected)
Hardware is Ethernet, address is 6cb1.580f.b901 (bia 6cb1.580f.b901)
Description: uplink
MTU 9216 bytes

Ethernet 0/2 is down, line protocol is down (link down)
Hardware is Ethernet, address is 6cb1.580f.b902 (bia 6cb1.580f.b902)
"""
    # napalm.mac() converts SLX-OS dotted form to canonical colon form, uppercase.
    assert _parse_intf_hw_addresses(text) == {
        "Ethernet 0/1": "6C:B1:58:0F:B9:01",
        "Ethernet 0/2": "6C:B1:58:0F:B9:02",
    }


def test_parse_intf_hw_addresses_skips_block_without_hw_address():
    """Loopback / VE / port-channel blocks lacking ``Hardware ... address`` are skipped."""
    text = """\
Ethernet 0/1 is up, line protocol is up
Hardware is Ethernet, address is 6cb1.580f.b901 (bia 6cb1.580f.b901)

Loopback 1 is up, line protocol is up
Internet address is 10.0.0.1/32

Port-channel 1 is up, line protocol is up
Description: aggregate
"""
    assert _parse_intf_hw_addresses(text) == {"Ethernet 0/1": "6C:B1:58:0F:B9:01"}


def test_parse_intf_hw_addresses_empty_and_none():
    """Empty / None input → empty dict, never raises."""
    assert _parse_intf_hw_addresses("") == {}
    assert _parse_intf_hw_addresses(None) == {}  # type: ignore[arg-type]


def test_parse_intf_hw_addresses_management_interface_included():
    """Management 1 interface block is captured the same as Ethernet ports."""
    text = """\
Management 1 is up, line protocol is up
Hardware is Ethernet, address is 6cb1.580f.b900 (bia 6cb1.580f.b900)
"""
    assert _parse_intf_hw_addresses(text) == {"Management 1": "6C:B1:58:0F:B9:00"}
