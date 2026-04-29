"""Unit tests for custom_napalm.cisco_s300.S300Driver."""

from pathlib import Path

from custom_napalm.cisco_s300 import S300Driver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestS300Driver(BaseDriverTest):
    """Unit tests for S300Driver using file-based CLI mocks."""

    driver_cls = S300Driver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"

    def test_get_interfaces_vlans_malformed_trunk_does_not_promote(self, caplog) -> None:
        """Junk Trunking VLANs Enabled value must NOT silently widen the trunk."""
        import logging

        from custom_napalm.cisco_s300 import _s300_switchport_block_to_entry
        block = {
            "Switchport": "enable",
            "Administrative Mode": "trunk",
            "Access Mode VLAN": "1",
            "Trunking Native Mode VLAN": "99",
            "Trunking VLANs Enabled": "not-a-vlan",
        }
        with caplog.at_level(logging.WARNING, logger="custom_napalm.cisco_s300"):
            result = _s300_switchport_block_to_entry(block)
        # NOT trunk-all — fall back to plain trunk with empty tagged list.
        assert result == {"mode": "trunk", "tagged": [], "untagged": 99}
        assert any("could not be parsed" in r.message for r in caplog.records)

    def test_get_interfaces_vlans_explicit_all_still_trunk_all(self) -> None:
        """Sanity: literal "all" still maps to trunk-all after the typed-signal refactor."""
        from custom_napalm.cisco_s300 import _s300_switchport_block_to_entry
        block = {
            "Switchport": "enable",
            "Administrative Mode": "trunk",
            "Access Mode VLAN": "1",
            "Trunking Native Mode VLAN": "99",
            "Trunking VLANs Enabled": "all",
        }
        result = _s300_switchport_block_to_entry(block)
        assert result == {"mode": "trunk-all", "tagged": [], "untagged": 99}
