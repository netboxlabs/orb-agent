"""Unit tests for custom_napalm.nokia_srl.SRLDriver."""

from pathlib import Path

from custom_napalm.nokia_srl import SRLDriver, _parse_hw_mac_addresses
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestSRLDriver(BaseDriverTest):
    """Unit tests for SRLDriver using file-based CLI mocks."""

    driver_cls = SRLDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"


# ---------------------------------------------------------------------------
# _parse_hw_mac_addresses — parser unit tests
# ---------------------------------------------------------------------------


def test_parse_hw_mac_addresses_typical_output():
    """Three-interface YANG block → name→MAC dict, normalised to colon form."""
    text = """\
    interface ethernet-1/1 {
        ethernet {
            hw-mac-address 1A:CD:EE:FF:00:01
        }
    }
    interface ethernet-1/2 {
        ethernet {
            hw-mac-address 1A:CD:EE:FF:00:02
        }
    }
    interface mgmt0 {
        ethernet {
            hw-mac-address 02:42:AC:12:00:06
        }
    }
"""
    result = _parse_hw_mac_addresses(text)
    assert result == {
        "ethernet-1/1": "1A:CD:EE:FF:00:01",
        "ethernet-1/2": "1A:CD:EE:FF:00:02",
        "mgmt0": "02:42:AC:12:00:06",
    }


def test_parse_hw_mac_addresses_lowercase_normalised_to_canonical():
    """Lowercase hex digits in source still resolve via napalm normalize_mac."""
    text = """\
    interface ethernet-1/3 {
        ethernet {
            hw-mac-address aa:bb:cc:dd:ee:ff
        }
    }
"""
    result = _parse_hw_mac_addresses(text)
    # napalm.base.helpers.mac() upper-cases the canonical form.
    assert result == {"ethernet-1/3": "AA:BB:CC:DD:EE:FF"}


def test_parse_hw_mac_addresses_empty_and_none_inputs():
    """Empty string and None inputs return empty dict — never raise."""
    assert _parse_hw_mac_addresses("") == {}
    assert _parse_hw_mac_addresses(None) == {}  # type: ignore[arg-type]


def test_parse_hw_mac_addresses_skips_interfaces_without_ethernet_block():
    """Loopback / system interfaces have no ethernet/hw-mac-address — silently skipped."""
    text = """\
    interface system0 {
        admin-state enable
    }
    interface lo0 {
        subinterface 0 {
            admin-state enable
        }
    }
    interface ethernet-1/1 {
        ethernet {
            hw-mac-address 1A:CD:EE:FF:00:01
        }
    }
"""
    # Only the ethernet-1/1 block matches.
    assert _parse_hw_mac_addresses(text) == {"ethernet-1/1": "1A:CD:EE:FF:00:01"}


def test_parse_hw_mac_addresses_no_matches_returns_empty():
    """A blob with zero MAC blocks (e.g. error banner) returns an empty dict."""
    assert _parse_hw_mac_addresses("Error: invalid path\n") == {}


def test_parse_hw_mac_addresses_accepts_non_padded_mac():
    """napalm.mac() accepts ``aa:bb:cc:dd:ee:1`` and pads to ``AA:BB:CC:DD:EE:01`` — regex must allow shorter form too."""
    text = """\
    interface ethernet-1/1 {
        ethernet {
            hw-mac-address aa:bb:cc:dd:ee:1
        }
    }
"""
    assert _parse_hw_mac_addresses(text) == {"ethernet-1/1": "AA:BB:CC:DD:EE:01"}
