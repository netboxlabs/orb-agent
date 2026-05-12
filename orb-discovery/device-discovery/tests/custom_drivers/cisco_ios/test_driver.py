"""Unit tests for custom_napalm.ios.IOSDriver."""

from pathlib import Path

from custom_napalm.ios import IOSDriver, _maybe_int
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


def test_ios_maybe_int_rejects_bool_true():
    """Reject ``bool`` (int subclass) so it does not coerce to VID 1."""
    assert _maybe_int(True) is None


def test_ios_maybe_int_rejects_bool_false():
    """Mirrors True case: False must not coerce to VID 0."""
    assert _maybe_int(False) is None


def test_ios_maybe_int_passes_through_string_int():
    """Plain string-int still coerces normally."""
    assert _maybe_int("42") == 42


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

    def test_get_interfaces_vlans_fi_shortform_expands_to_fivegig(self) -> None:
        """
        ``Fi*`` short-form expands to FiveGigabitEthernet, not FiftyGigabitEthernet.

        Regression for ENGHLP-1279: netutils.BASE_INTERFACES maps ``"Fi"`` to
        ``"FiftyGigabitEthernet"``, which is wrong for Cisco IOS Catalyst
        multigig hardware. Without the IOS-specific ``addl_name_map`` override,
        every ``Fi*`` port returned by ``show interfaces switchport`` ended up
        with a key that didn't match the ``FiveGigabitEthernet*`` long form
        emitted by ``get_interfaces()``, and ``apply_interface_vlans()``
        silently dropped the association for every 5G port on the device.
        """
        mock_dir = self.mock_data_root / "test_get_interfaces_vlans" / "multigig_fivegig"
        driver = self._build_driver(mock_dir)
        result = driver.get_interfaces_vlans()
        # The buggy expansion would have produced "FiftyGigabitEthernet3/0/1".
        # Assert both the positive (correct expansion present) and negative
        # (wrong expansion absent) so a future regression on the netutils
        # mapping is caught even if FiveGig happens to also be inserted.
        assert "FiveGigabitEthernet3/0/1" in result, (
            f"expected FiveGigabitEthernet3/0/1 key, got {sorted(result)}"
        )
        assert "FiveGigabitEthernet3/0/2" in result
        assert not any(k.startswith("FiftyGigabitEthernet") for k in result), (
            f"unexpected FiftyGigabitEthernet key in {sorted(result)}"
        )
        assert result["FiveGigabitEthernet3/0/1"] == {
            "mode": "access", "tagged": [], "untagged": 148,
        }
        assert result["FiveGigabitEthernet3/0/2"] == {
            "mode": "trunk", "tagged": [190, 191, 251, 261], "untagged": 999,
        }
        # Sanity: other short-forms (Tw, Gi) keep working alongside the override.
        assert result["TwoGigabitEthernet2/0/1"]["untagged"] == 20
        assert result["GigabitEthernet1/0/1"]["untagged"] == 10

    def test_canonical_interface_name_fi_override(self) -> None:
        """
        Lock the BASE_INTERFACES override at the function-call level.

        If netutils ever flips ``"Fi"`` to mean something else, or a future
        refactor drops ``addl_name_map`` from the driver call site, this
        narrower assertion fires before the integration test does — making
        the root cause obvious from the failure alone.
        """
        from napalm.base.helpers import canonical_interface_name

        from custom_napalm.ios import _IOS_ADDL_NAME_MAP

        assert canonical_interface_name(
            "Fi3/0/1", addl_name_map=_IOS_ADDL_NAME_MAP
        ) == "FiveGigabitEthernet3/0/1"
        assert canonical_interface_name(
            "FI3/0/1", addl_name_map=_IOS_ADDL_NAME_MAP
        ) == "FiveGigabitEthernet3/0/1"
        assert canonical_interface_name(
            "fi3/0/1", addl_name_map=_IOS_ADDL_NAME_MAP
        ) == "FiveGigabitEthernet3/0/1"
        # Sanity: prefixes we did NOT override still resolve via BASE_INTERFACES.
        assert canonical_interface_name(
            "Gi1/0/1", addl_name_map=_IOS_ADDL_NAME_MAP
        ) == "GigabitEthernet1/0/1"
        assert canonical_interface_name(
            "Twe1/0/1", addl_name_map=_IOS_ADDL_NAME_MAP
        ) == "TwentyFiveGigE1/0/1"

    def test_expand_vlan_range_string_clamps_huge_range(self) -> None:
        """A range like 1-100000 is clamped to 1..4094 (then collapsed to wildcard)."""
        from custom_napalm._vlan import parse_vlan_range_string
        # Single huge range whose hi is clamped to 4094 and lo is 1 → wildcard.
        assert parse_vlan_range_string("1-100000") == ([], True)
        # Plain explicit list → not a wildcard, returns expanded VIDs.
        assert parse_vlan_range_string("10-12") == ([10, 11, 12], False)
        # Out-of-range-only input → empty list, NOT a wildcard.
        assert parse_vlan_range_string("5000-9000") == ([], False)

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
        from custom_napalm._vlan import classify_switchport
        from custom_napalm.ios import _ios_row_to_switchport_info
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
        result = classify_switchport(_ios_row_to_switchport_info(row))
        assert result == {"mode": "trunk-all", "tagged": [], "untagged": 99}

    def test_get_interfaces_vlans_explicit_none_stays_plain_trunk(self) -> None:
        """A trunk explicitly with NONE allowed stays mode=trunk, not trunk-all."""
        from custom_napalm._vlan import classify_switchport
        from custom_napalm.ios import _ios_row_to_switchport_info
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
        result = classify_switchport(_ios_row_to_switchport_info(row))
        assert result == {"mode": "trunk", "tagged": [], "untagged": 1}

    def test_get_interfaces_vlans_malformed_trunk_does_not_promote(self, caplog) -> None:
        """Junk trunking_vlans input must NOT silently widen the trunk to all VLANs."""
        import logging

        from custom_napalm._vlan import classify_switchport
        from custom_napalm.ios import _ios_row_to_switchport_info
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
            result = classify_switchport(_ios_row_to_switchport_info(row))
        # NOT trunk-all — falls back to plain trunk with empty tagged list.
        assert result == {"mode": "trunk", "tagged": [], "untagged": 99}
        assert any("could not be parsed" in r.message for r in caplog.records)

    def test_get_interfaces_vlans_explicit_all_still_trunk_all(self) -> None:
        """Sanity: literal ALL still maps to trunk-all even with the typed-signal refactor."""
        from custom_napalm._vlan import classify_switchport
        from custom_napalm.ios import _ios_row_to_switchport_info
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
        result = classify_switchport(_ios_row_to_switchport_info(row))
        assert result == {"mode": "trunk-all", "tagged": [], "untagged": 99}

    def test_get_interfaces_vlans_voice_equal_access_stays_access(self) -> None:
        """When voice VLAN equals access VLAN, keep mode=access (don't promote)."""
        from custom_napalm._vlan import classify_switchport
        from custom_napalm.ios import _ios_row_to_switchport_info
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
        result = classify_switchport(_ios_row_to_switchport_info(row))
        # NOT mode=trunk — promotion is suppressed when voice == access.
        assert result == {"mode": "access", "tagged": [], "untagged": 10}
