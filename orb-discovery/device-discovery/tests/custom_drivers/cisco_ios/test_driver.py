"""Unit tests for custom_napalm.ios.IOSDriver."""

from pathlib import Path

from custom_napalm.ios import IOSDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestIOSDriver(BaseDriverTest):
    """Unit tests for our IOSDriver using file-based CLI mocks."""

    driver_cls = IOSDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"

    def test_get_interfaces_vlans_canonicalizes_keys(self) -> None:
        """
        get_interfaces_vlans() always returns canonical interface names.

        NAPALM IOS get_interfaces() returns long-form names ("GigabitEthernet...")
        in its default configuration, so the keys here must match unconditionally
        — otherwise apply_interface_vlans() drops associations on exact-name match.
        """
        mock_dir = self.mock_data_root / "test_get_interfaces_vlans" / "access_only"
        driver = self._build_driver(mock_dir)
        # use_canonical_interface=False is the default — canonicalization must
        # still happen for keys to align with get_interfaces().
        assert getattr(driver, "use_canonical_interface", False) is False
        result = driver.get_interfaces_vlans()
        assert "GigabitEthernet1/0/1" in result, f"expected canonical key, got {sorted(result)}"
        assert result["GigabitEthernet1/0/1"]["mode"] == "access"
        assert result["GigabitEthernet1/0/1"]["untagged"] == 10

    def test_expand_ios_vlan_list_clamps_huge_range(self) -> None:
        """A range like 1-100000 is clamped to 1..4094 (then collapsed to wildcard)."""
        from custom_napalm.ios import _expand_ios_vlan_list
        # Single huge range whose hi is clamped to 4094 and lo is 1 → wildcard.
        assert _expand_ios_vlan_list(["1-100000"]) == ([], True)
        # Plain explicit list → not a wildcard, returns expanded VIDs.
        assert _expand_ios_vlan_list(["10-12"]) == ([10, 11, 12], False)
        # Out-of-range-only input → empty list, NOT a wildcard.
        assert _expand_ios_vlan_list(["5000-9000"]) == ([], False)

    def test_get_interfaces_vlans_trunk_all_emits_distinct_mode(self) -> None:
        """A trunk advertising ALL VLANs emits mode='trunk-all', not 'trunk'."""
        mock_dir = self.mock_data_root / "test_get_interfaces_vlans" / "trunk_all"
        driver = self._build_driver(mock_dir)
        result = driver.get_interfaces_vlans()
        assert "GigabitEthernet1/0/48" in result
        assert result["GigabitEthernet1/0/48"]["mode"] == "trunk-all"
        assert result["GigabitEthernet1/0/48"]["tagged"] == []
        assert result["GigabitEthernet1/0/48"]["untagged"] == 99

    def test_get_interfaces_vlans_numeric_full_range_is_trunk_all(self) -> None:
        """A numeric full-range trunk (e.g. 1-4094) collapses to trunk-all, same as literal ALL."""
        from custom_napalm.ios import _classify_ios_switchport_row
        row = {
            "interface": "Gi1/0/48",
            "switchport": "Enabled",
            "admin_mode": "trunk",
            "mode": "trunk",
            "access_vlan": "1",
            "native_vlan": "99",
            "voice_vlan": "none",
            "trunking_vlans": ["1-4094"],
        }
        result = _classify_ios_switchport_row(row)
        assert result == {"mode": "trunk-all", "tagged": [], "untagged": 99}

    def test_get_interfaces_vlans_explicit_none_stays_plain_trunk(self) -> None:
        """A trunk explicitly with NONE allowed stays mode=trunk, not trunk-all."""
        from custom_napalm.ios import _classify_ios_switchport_row
        row = {
            "interface": "Gi1/0/48",
            "switchport": "Enabled",
            "admin_mode": "trunk",
            "mode": "trunk",
            "access_vlan": "1",
            "native_vlan": "1",
            "voice_vlan": "none",
            "trunking_vlans": ["NONE"],
        }
        result = _classify_ios_switchport_row(row)
        assert result == {"mode": "trunk", "tagged": [], "untagged": 1}

    def test_get_interfaces_vlans_malformed_trunk_does_not_promote(self, caplog) -> None:
        """Junk trunking_vlans input must NOT silently widen the trunk to all VLANs."""
        import logging

        from custom_napalm.ios import _classify_ios_switchport_row
        row = {
            "interface": "Gi1/0/48",
            "switchport": "Enabled",
            "admin_mode": "trunk",
            "mode": "trunk",
            "access_vlan": "1",
            "native_vlan": "99",
            "voice_vlan": "none",
            "trunking_vlans": ["5000-9000"],  # all out of range after clamp
        }
        with caplog.at_level(logging.WARNING, logger="custom_napalm.ios"):
            result = _classify_ios_switchport_row(row)
        # NOT trunk-all — falls back to plain trunk with empty tagged list.
        assert result == {"mode": "trunk", "tagged": [], "untagged": 99}
        assert any("could not be parsed" in r.message for r in caplog.records)

    def test_get_interfaces_vlans_explicit_all_still_trunk_all(self) -> None:
        """Sanity: literal ALL still maps to trunk-all even with the typed-signal refactor."""
        from custom_napalm.ios import _classify_ios_switchport_row
        row = {
            "interface": "Gi1/0/48",
            "switchport": "Enabled",
            "admin_mode": "trunk",
            "mode": "trunk",
            "access_vlan": "1",
            "native_vlan": "99",
            "voice_vlan": "none",
            "trunking_vlans": ["ALL"],
        }
        result = _classify_ios_switchport_row(row)
        assert result == {"mode": "trunk-all", "tagged": [], "untagged": 99}

    def test_get_interfaces_vlans_voice_equal_access_stays_access(self) -> None:
        """When voice VLAN equals access VLAN, keep mode=access (don't promote)."""
        from custom_napalm.ios import _classify_ios_switchport_row
        row = {
            "interface": "Gi1/0/5",
            "switchport": "Enabled",
            "admin_mode": "static access",
            "mode": "static access",
            "access_vlan": "10",
            "native_vlan": "1",
            "voice_vlan": "10",  # same as access_vlan — operator quirk
            "trunking_vlans": ["ALL"],
        }
        result = _classify_ios_switchport_row(row)
        # NOT mode=trunk — promotion is suppressed when voice == access.
        assert result == {"mode": "access", "tagged": [], "untagged": 10}
