"""Unit tests for custom_napalm.ios.IOSDriver."""

import re
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

        Regression test: netutils.BASE_INTERFACES maps ``"Fi"`` to
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

    def test_get_modules_short_form_transceiver_canonicalized(self) -> None:
        """``Te2/0/2`` in show inventory becomes ``TenGigabitEthernet2/0/2`` in the sub-bay."""
        mock_dir = self.mock_data_root / "test_get_modules" / "modular_9404r_with_transceivers"
        driver = self._build_driver(mock_dir)
        result = driver.get_modules()
        assert result is not None
        member = result["members"][None]
        bay_2 = next(b for b in member["bays"] if b["name"] == "2")
        sub_names = [s["name"] for s in bay_2["module"]["sub_bays"]]
        # Both rows canonicalize to TenGigabitEthernet, even the short-form Te2/0/2.
        assert sub_names == [
            "TenGigabitEthernet2/0/1",
            "TenGigabitEthernet2/0/2",
        ]
        # Full-mode deepest-wins routing pre-populates the self-mapping.
        assert member["interfaces_by_bay"]["TenGigabitEthernet2/0/2"] == [
            "TenGigabitEthernet2/0/2",
        ]

    def test_get_modules_does_not_match_subslot_rows(self) -> None:
        """
        ``Slot 0/0`` and ``Slot 2/1/0`` (sub-slot/controller rows) must not match.

        Some IOS-XE platforms emit sub-slot rows in ``show inventory``
        with a slot prefix that includes ``/``. Without the negative
        lookahead, the regex partial-matched the leading digit and
        materialized a phantom top-level slot.
        """
        from custom_napalm.ios import _INVENTORY_SLOT_RE
        assert _INVENTORY_SLOT_RE.match("Slot 0/0") is None
        assert _INVENTORY_SLOT_RE.match("Slot 2/1/0") is None
        assert _INVENTORY_SLOT_RE.match("slot 0 /0") is None  # space-then-slash
        # Sanity: well-formed top-level slot rows still match.
        assert _INVENTORY_SLOT_RE.match("Slot 1 Supervisor") is not None
        assert _INVENTORY_SLOT_RE.match("Slot 1") is not None  # role optional

    def test_get_modules_does_not_match_isr_asr_module_zero(self) -> None:
        """
        ``NAME: "module 0"`` from ISR/ASR route-processor rows is ignored.

        Earlier the regex matched the lowercase ``module N`` form too,
        which falsely materialized a phantom slot-0 ModuleBay on every
        non-modular IOS-XE device whose chassis NAME starts with
        ``module 0``. Restricting the matcher to ``Slot N`` avoids the
        false positive while keeping coverage of every real modular
        Cisco chassis observed today (Catalyst 9400 / 9600).
        """
        from custom_napalm.ios import _INVENTORY_SLOT_RE
        assert _INVENTORY_SLOT_RE.match("module 0") is None
        assert _INVENTORY_SLOT_RE.match("Module 0") is None
        assert _INVENTORY_SLOT_RE.match("module 1 Route Processor") is None
        # Sanity: actual modular slot rows still match.
        assert _INVENTORY_SLOT_RE.match("Slot 1 Supervisor") is not None
        assert _INVENTORY_SLOT_RE.match("slot 2 Linecard") is not None

    def test_get_modules_hyphenated_slot_role_classified(self) -> None:
        """
        ``Slot 3 - Supervisor`` (hyphenated form) classifies as supervisor.

        Some Catalyst IOS-XE versions emit the hyphenated form. The
        previous regex captured only the slot number and missed the
        role word, causing supervisors to emit as ``linecard`` (the
        PID-based fallback).
        """
        from custom_napalm.ios import _INVENTORY_SLOT_RE, _classify_slot_module
        m = _INVENTORY_SLOT_RE.match("Slot 3 - Supervisor")
        assert m is not None
        assert m.group(1) == "3"
        assert (m.group(2) or "").lower() == "supervisor"
        assert _classify_slot_module("C9600-SUP-1", m.group(2) or "") == "supervisor"
        # Sanity: legacy non-hyphenated form still works.
        m2 = _INVENTORY_SLOT_RE.match("Slot 1 Supervisor")
        assert m2 is not None
        assert (m2.group(2) or "").lower() == "supervisor"

    def test_inventory_vc_slot_regex_matches_9400_svl(self) -> None:
        """`Switch 1 Slot 2 Linecard` captures member=1, slot=2, role=Linecard."""
        from custom_napalm.ios import _INVENTORY_VC_SLOT_RE
        m = _INVENTORY_VC_SLOT_RE.match("Switch 1 Slot 2 Linecard")
        assert m is not None
        assert m.group(1) == "1"
        assert m.group(2) == "2"
        assert m.group(3).lower() == "linecard"

    def test_inventory_vc_slot_regex_handles_hyphenated_form(self) -> None:
        """`Switch 2 Slot 3 - Supervisor` (hyphenated) still captures the role."""
        from custom_napalm.ios import _INVENTORY_VC_SLOT_RE
        m = _INVENTORY_VC_SLOT_RE.match("Switch 2 Slot 3 - Supervisor")
        assert m is not None
        assert m.group(1) == "2"
        assert m.group(2) == "3"
        assert m.group(3).lower() == "supervisor"

    def test_inventory_vc_slot_regex_rejects_subslot(self) -> None:
        """`Switch 1 Slot 2/0` is a sub-slot row and must not match."""
        from custom_napalm.ios import _INVENTORY_VC_SLOT_RE
        assert _INVENTORY_VC_SLOT_RE.match("Switch 1 Slot 2/0") is None

    def test_inventory_vc_fru_regex_matches_9300_uplink(self) -> None:
        """`Switch 1 FRU Uplink Module 1` captures member=1, slot=1."""
        from custom_napalm.ios import _INVENTORY_VC_FRU_RE
        m = _INVENTORY_VC_FRU_RE.match("Switch 1 FRU Uplink Module 1")
        assert m is not None
        assert m.group(1) == "1"
        assert m.group(2) == "1"

    def test_inventory_vc_fru_regex_rejects_power_supply(self) -> None:
        """`Switch 1 - Power Supply A` is not a FRU uplink module — no match."""
        from custom_napalm.ios import _INVENTORY_VC_FRU_RE
        assert _INVENTORY_VC_FRU_RE.match("Switch 1 - Power Supply A") is None

    def test_count_distinct_switch_ids_drives_vc_vs_single_chassis(self) -> None:
        """
        VC mode requires at least 2 distinct Switch ids in inventory.

        Single-chassis IOS-XE inventories that prefix `Switch 1` (Cat 9500
        etc.) must report count=1 so the caller treats them as standalone
        — matches what translate_chassis itself uses to decide stack vs
        standalone via validate_chassis_payload.
        """
        from custom_napalm.ios import _count_distinct_switch_ids
        # Single chassis with Switch 1 prefix everywhere → count=1 → standalone.
        assert _count_distinct_switch_ids([
            {"name": "Switch 1 Chassis"},
            {"name": "Switch 1 Slot 1 Supervisor"},
            {"name": "Switch 1 - Power Supply A"},
        ]) == 1
        # Real VC stack: 2 distinct ids → VC.
        assert _count_distinct_switch_ids([
            {"name": "Switch 1"},
            {"name": "Switch 2"},
        ]) == 2
        # Mixed prefix patterns, still ≥2 distinct ids → VC.
        assert _count_distinct_switch_ids([
            {"name": "Switch 1 Chassis"},
            {"name": "Switch 2 Slot 1 Supervisor"},
        ]) == 2
        # No Switch rows → standalone.
        assert _count_distinct_switch_ids([
            {"name": "Chassis"},
            {"name": "Slot 1 Supervisor"},
        ]) == 0
        # Empty / None → standalone.
        assert _count_distinct_switch_ids([]) == 0
        assert _count_distinct_switch_ids(None) == 0  # type: ignore[arg-type]
        # No-space form (some IOS-XE versions): `Switch1` / `Switch2`.
        assert _count_distinct_switch_ids([
            {"name": "Switch1 Chassis"},
            {"name": "Switch1 Slot 1 Supervisor"},
        ]) == 1
        assert _count_distinct_switch_ids([
            {"name": "Switch1"},
            {"name": "Switch2"},
        ]) == 2
        # Garbage `SwitchXabc` should NOT match — word-boundary guard.
        assert _count_distinct_switch_ids([
            {"name": "SwitchPort1/1"},
        ]) == 0

    def test_inventory_vc_slot_regex_no_space_form(self) -> None:
        """`Switch1 Slot 2 Linecard` (no space after Switch) is supported too."""
        from custom_napalm.ios import _INVENTORY_VC_FRU_RE, _INVENTORY_VC_SLOT_RE
        m = _INVENTORY_VC_SLOT_RE.match("Switch1 Slot 2 Linecard")
        assert m is not None
        assert m.group(1) == "1"
        assert m.group(2) == "2"
        assert m.group(3).lower() == "linecard"
        m = _INVENTORY_VC_FRU_RE.match("Switch2 FRU Uplink Module 1")
        assert m is not None
        assert m.group(1) == "2"
        assert m.group(2) == "1"

    def test_inventory_slot_regex_still_rejects_vc_form(self) -> None:
        """Standalone Slot N regex must NOT match `Switch 1 Slot 2 ...` (that's VC territory)."""
        from custom_napalm.ios import _INVENTORY_SLOT_RE
        assert _INVENTORY_SLOT_RE.match("Switch 1 Slot 2 Linecard") is None

    def test_get_modules_supervisor_classified_by_name_hint(self) -> None:
        """``Slot N Supervisor`` rows emit type=supervisor, not type=linecard."""
        mock_dir = self.mock_data_root / "test_get_modules" / "supervisor_only"
        driver = self._build_driver(mock_dir)
        result = driver.get_modules()
        assert result is not None
        member = result["members"][None]
        assert len(member["bays"]) == 1
        assert member["bays"][0]["module"]["type"] == "supervisor"

    def test_get_modules_interface_brief_shortform_canonicalized(self) -> None:
        """
        Short-form ifnames in show ip interface brief are canonicalized.

        ``Gi2/0/1`` and ``Te2/0/1`` become ``GigabitEthernet2/0/1`` and
        ``TenGigabitEthernet2/0/1``, matching the long form
        ``get_interfaces()`` emits. Without this normalization the
        translator's iface_module_map keys diverge from the Interface
        entity names and module ownership silently fails to attach.
        """
        mock_dir = self.mock_data_root / "test_get_modules" / "modular_9400r_shortform_ifnames"
        driver = self._build_driver(mock_dir)
        result = driver.get_modules()
        assert result is not None
        member = result["members"][None]
        slot2 = member["interfaces_by_bay"]["2"]
        slot3 = member["interfaces_by_bay"]["3"]
        # Positive: every name starts with a long-form prefix.
        long_form_prefixes = ("GigabitEthernet", "TenGigabitEthernet")
        for name in slot2 + slot3:
            assert name.startswith(long_form_prefixes), f"non-canonical: {name!r}"
        # Negative: no raw short-form names like "Gi2/0/1" or "Te2/0/1" leak.
        short_form_pattern = re.compile(r"^(Gi|Te|Fa)\d")
        for name in slot2 + slot3:
            assert not short_form_pattern.match(name), f"short-form leaked: {name!r}"
        # Exact expected canonicalization spot-checks.
        assert "GigabitEthernet2/0/1" in slot2
        assert "TenGigabitEthernet2/0/1" in slot2
        assert "GigabitEthernet3/0/1" in slot3

    def test_get_modules_inventory_failure_returns_none(self) -> None:
        """A raised exception from send_command propagates as a None result + WARNING."""
        import logging
        mock_dir = self.mock_data_root / "test_get_modules" / "modular_9404r_with_transceivers"
        driver = self._build_driver(mock_dir)

        def boom(*_a, **_kw):
            raise RuntimeError("connection reset")
        driver.device.send_command = boom  # type: ignore[method-assign]
        import custom_napalm.ios as ios_mod
        with self._caplog(ios_mod.logger, logging.WARNING) as records:
            assert driver.get_modules() is None
        assert any("show inventory failed" in r.getMessage() for r in records)

    def test_get_modules_interface_brief_failure_keeps_bays_no_iface_map(self) -> None:
        """If show ip interface brief fails, bays still emit but interfaces_by_bay stays empty."""
        mock_dir = self.mock_data_root / "test_get_modules" / "modular_9404r_with_transceivers"
        driver = self._build_driver(mock_dir)

        original = driver.device.send_command

        def selective(cmd, *a, **kw):  # type: ignore[no-untyped-def]
            if "ip interface brief" in cmd:
                raise RuntimeError("ip-brief unavailable")
            return original(cmd, *a, **kw)
        driver.device.send_command = selective  # type: ignore[method-assign]

        result = driver.get_modules()
        assert result is not None
        member = result["members"][None]
        # The transceiver self-mapping survives (it's added after the
        # interfaces_by_bay scaffold), but the per-slot lists stay empty.
        assert member["interfaces_by_bay"]["1"] == []
        assert member["interfaces_by_bay"]["2"] == []
        assert member["interfaces_by_bay"]["3"] == []
        assert member["interfaces_by_bay"]["TenGigabitEthernet2/0/1"] == [
            "TenGigabitEthernet2/0/1",
        ]

    def test_get_modules_9300_stack_emits_per_member_envelope(self) -> None:
        """
        9300 stack with NM uplinks emits {members: {1: ..., 2: ...}}.

        Each member's bay carries its FRU uplink module; each member's
        transceiver attaches as a sub-bay under its own NM. Interfaces
        bin by leading integer (member id), then by slot (second
        integer = NM slot ``1``).
        """
        mock_dir = self.mock_data_root / "test_get_modules" / "cat9300_stack_with_nm_uplinks"
        driver = self._build_driver(mock_dir)
        result = driver.get_modules()
        assert result is not None
        assert set(result["members"].keys()) == {1, 2}
        m1 = result["members"][1]
        m2 = result["members"][2]
        # Each member has the NM uplink bay with its own serial.
        assert len(m1["bays"]) == 1
        assert m1["bays"][0]["module"]["model"] == "C9300-NM-8X"
        assert m1["bays"][0]["module"]["serial"] == "FOC2501NM01"
        assert m2["bays"][0]["module"]["serial"] == "FOC2501NM02"
        # Each member's NM has a transceiver sub-bay with the right serial.
        m1_sub = m1["bays"][0]["module"]["sub_bays"]
        m2_sub = m2["bays"][0]["module"]["sub_bays"]
        assert len(m1_sub) == 1
        assert m1_sub[0]["module"]["serial"] == "FNS2501TR01"
        assert len(m2_sub) == 1
        assert m2_sub[0]["module"]["serial"] == "FNS2501TR02"
        # Interface routing: each member's slot-1 ifname bins under its own NM.
        assert "TenGigabitEthernet1/1/1" in m1["interfaces_by_bay"]["1"]
        assert "TenGigabitEthernet2/1/1" in m2["interfaces_by_bay"]["1"]

    def test_get_modules_9400_svl_emits_per_member_envelope(self) -> None:
        """
        9400 SVL emits per-member envelope with supervisors and linecards.

        Each member's chassis has slots 1 (supervisor) and 2 (linecard);
        4-tuple ifnames bin into the right member's correct slot.
        """
        mock_dir = self.mock_data_root / "test_get_modules" / "cat9400_stackwise_virtual"
        driver = self._build_driver(mock_dir)
        result = driver.get_modules()
        assert result is not None
        assert set(result["members"].keys()) == {1, 2}
        m1_models = {b["module"]["model"] for b in result["members"][1]["bays"]}
        assert m1_models == {"C9400-SUP-1", "C9400-LC-48U"}
        m2_models = {b["module"]["model"] for b in result["members"][2]["bays"]}
        assert m2_models == {"C9400-SUP-1", "C9400-LC-48P"}
        # Supervisor classifies as 'supervisor' (NAME hint), not linecard.
        sup_bay = next(
            b for b in result["members"][1]["bays"] if b["module"]["model"] == "C9400-SUP-1"
        )
        assert sup_bay["module"]["type"] == "supervisor"
        # 4-tuple ifname routes to member 1 slot 2 (canonicalized long form).
        m1_slot2 = result["members"][1]["interfaces_by_bay"].get("2", [])
        assert "HundredGigabitEthernet1/2/0/1" in m1_slot2
        # And member 2 slot 1 carries its supervisor's port too.
        m2_slot1 = result["members"][2]["interfaces_by_bay"].get("1", [])
        assert "HundredGigabitEthernet2/1/0/1" in m2_slot1

    def _caplog(self, logger, level):
        """Context manager that captures records from a specific logger at ``level``."""
        import logging
        records: list[logging.LogRecord] = []

        class _H(logging.Handler):
            def emit(self, record):
                records.append(record)

        handler = _H(level=level)

        class _Ctx:
            def __enter__(self):
                logger.addHandler(handler)
                return records

            def __exit__(self, *exc):
                logger.removeHandler(handler)
                return False

        return _Ctx()

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
