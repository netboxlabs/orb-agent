"""Unit tests for custom_napalm.cisco_s300.S300Driver."""

from pathlib import Path

from custom_napalm.cisco_s300 import S300Driver, _expand_interface_range, _maybe_int, _parse_vlan_ports_raw
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


def test_s300_maybe_int_rejects_bool_true():
    """Reject ``bool`` (int subclass) so it does not coerce to VID 1."""
    assert _maybe_int(True) is None


def test_s300_maybe_int_rejects_bool_false():
    """Mirrors True case: False must not coerce to VID 0."""
    assert _maybe_int(False) is None


def test_s300_maybe_int_passes_through_string_int():
    """Plain string-int still coerces normally."""
    assert _maybe_int("42") == 42


def test_s300_expand_interface_range_skips_oversized_ranges():
    """Oversized device-provided ranges must not be materialized."""
    assert _expand_interface_range("fa1-129,gi1") == ["gi1"]


def test_s300_parse_vlan_ports_raw_skips_oversized_ranges():
    """Malicious show vlan ranges must not exhaust memory during parsing."""
    raw = """
Vlan       Name               Ports              Created by
---- ----------------- --------------------------- ----------------
1    default           fa1-100000000,gi1           Static
"""
    assert _parse_vlan_ports_raw(raw) == {"1": ["gi1"]}


class TestS300Driver(BaseDriverTest):
    """Unit tests for S300Driver using file-based CLI mocks."""

    driver_cls = S300Driver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"

    def test_get_interfaces_vlans_malformed_trunk_does_not_promote(self, caplog) -> None:
        """Junk Trunking VLANs Enabled value must NOT silently widen the trunk."""
        import logging

        from custom_napalm._vlan import classify_switchport
        from custom_napalm.cisco_s300 import _s300_block_to_switchport_info
        block = {
            "Switchport": "enable",
            "Administrative Mode": "trunk",
            "Access Mode VLAN": "1",
            "Trunking Native Mode VLAN": "99",
            "Trunking VLANs Enabled": "not-a-vlan",
        }
        with caplog.at_level(logging.WARNING, logger="custom_napalm.cisco_s300"):
            result = classify_switchport(_s300_block_to_switchport_info(block))
        # NOT trunk-all — fall back to plain trunk with empty tagged list.
        assert result == {"mode": "trunk", "tagged": [], "untagged": 99}
        assert any("could not be parsed" in r.message for r in caplog.records)

    def test_get_interfaces_vlans_explicit_all_still_trunk_all(self) -> None:
        """Sanity: literal "all" still maps to trunk-all after the typed-signal refactor."""
        from custom_napalm._vlan import classify_switchport
        from custom_napalm.cisco_s300 import _s300_block_to_switchport_info
        block = {
            "Switchport": "enable",
            "Administrative Mode": "trunk",
            "Access Mode VLAN": "1",
            "Trunking Native Mode VLAN": "99",
            "Trunking VLANs Enabled": "all",
        }
        result = classify_switchport(_s300_block_to_switchport_info(block))
        assert result == {"mode": "trunk-all", "tagged": [], "untagged": 99}
