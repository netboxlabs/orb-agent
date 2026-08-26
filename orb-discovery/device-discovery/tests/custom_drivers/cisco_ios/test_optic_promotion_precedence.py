#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
Unit tests for what outranks what when an optic looks for its parent.

Exercised at the helper level rather than through a mock_data scenario on
purpose. Two of these states cannot exist on real hardware — a chassis whose
uplinks are fixed never reports a removable uplink module, and never has a
slot claimed by a card row. They are asserted anyway because they are the
invariants that keep the fixed-uplink allowlist from overriding evidence, and
a driver fixture claiming such a device exists would be a lie about the
hardware.
"""

from custom_napalm._modules import ModuleBay, ModuleEntry
from custom_napalm.ios import _attach_transceivers


def _optic(serial: str) -> ModuleEntry:
    return ModuleEntry(
        model="SFP-10G-LR", serial=serial, type="transceiver",
        description="SFP-10GBase-LR",
    )


def _uplink_card_bay() -> ModuleBay:
    return ModuleBay(
        name="1", position="1",
        module=ModuleEntry(
            model="C9200-NM-4X", serial="FRU0000001", type="linecard",
            description="4x10GE Network Module",
        ),
    )


def _attach(bays, *, claimed_slots=frozenset(), fixed_uplink_chassis):
    """Run _attach_transceivers over a single Te1/1/1 optic in standalone mode."""
    transceivers = {None: {"Te1/1/1": _optic("OPT0001111")}}
    interfaces: dict = {}
    _attach_transceivers(
        bays, transceivers, interfaces,
        switch_prefixed=True,
        claimed_slots=set(claimed_slots),
        non_prefixed_modular_veto=False,
        fixed_uplink_chassis=fixed_uplink_chassis,
    )
    return bays.get(None, {})


def test_reported_parent_bay_outranks_the_fixed_uplink_allowlist():
    """
    A bay built from a real card row wins even on an allowlisted chassis.

    The allowlist exists only to cover the gap where a chassis ships no row
    for uplinks it cannot remove. Promoting when a parent was actually
    reported would invent a chassis-level parent for hardware that already
    has one, and would emit the card and the optic as siblings.
    """
    result = _attach({None: {"1": _uplink_card_bay()}}, fixed_uplink_chassis=True)

    assert sorted(result) == ["1"], (
        f"the optic must not become a device-rooted bay, got {sorted(result)}"
    )
    sub_bays = result["1"].module.sub_bays
    assert [bay.name for bay in sub_bays] == ["TenGigabitEthernet1/1/1"]
    assert sub_bays[0].module.serial == "OPT0001111"


def test_claimed_but_unusable_slot_outranks_the_fixed_uplink_allowlist():
    """
    A slot claimed by an unusable row declines the optic, allowlist or not.

    ``claimed_slots`` records slots the raw inventory named before the
    pid/sn usability filter. The parent exists in hardware; its row simply
    failed to describe it. Promotion there would replace a real modular
    topology with an invented chassis-level one.
    """
    result = _attach({}, claimed_slots={(None, "1")}, fixed_uplink_chassis=True)

    assert result == {}, f"a claimed slot must decline promotion, got {sorted(result)}"


def test_parentless_unclaimed_optic_promotes_only_on_an_allowlisted_chassis():
    """With no parent bay and no claim, the chassis PID is the only signal."""
    on_allowlist = _attach({}, fixed_uplink_chassis=True)
    assert sorted(on_allowlist) == ["TenGigabitEthernet1/1/1"]

    off_allowlist = _attach({}, fixed_uplink_chassis=False)
    assert off_allowlist == {}, (
        "a non-zero module on an unrecognized chassis must still decline"
    )
