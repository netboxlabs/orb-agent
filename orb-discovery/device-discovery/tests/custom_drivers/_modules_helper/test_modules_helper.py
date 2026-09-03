# Copyright 2026 NetBox Labs Inc
"""Unit tests for custom_napalm._modules helper."""

from __future__ import annotations

import logging

from custom_napalm._modules import (
    MAX_BAY_DEPTH,
    MemberModules,
    ModuleBay,
    ModuleEntry,
    orphan_optic_bay,
    to_payload,
)

# ---- to_payload validation ----------------------------------------------


def _bay(name: str, *, serial: str = "S1", mtype: str = "linecard",
         model: str = "M1", description: str = "",
         sub_bays: list[ModuleBay] | None = None) -> ModuleBay:
    """Build a ModuleBay with sane defaults."""
    return ModuleBay(
        name=name,
        position=name,
        module=ModuleEntry(
            model=model,
            serial=serial,
            type=mtype,  # type: ignore[arg-type]
            description=description,
            sub_bays=sub_bays or [],
        ),
    )


def test_to_payload_empty_input_returns_none() -> None:
    """Empty members dict → None (no payload to emit)."""
    assert to_payload({}) is None


def test_to_payload_all_invalid_bays_returns_none() -> None:
    """When every member's bays fail validation, the helper returns None."""
    assert to_payload({None: MemberModules(bays=[_bay("1", serial="")])}) is None


def test_to_payload_drops_bay_with_empty_serial() -> None:
    """A bay whose module.serial is empty is dropped; valid bays survive."""
    payload = to_payload({
        None: MemberModules(bays=[_bay("1", serial=""), _bay("2", serial="OK2")]),
    })
    assert payload is not None
    names = [b["name"] for b in payload["members"][None]["bays"]]
    assert names == ["2"]


def test_to_payload_drops_bay_with_whitespace_only_serial() -> None:
    """A bay whose serial is whitespace-only is treated as empty."""
    payload = to_payload({
        None: MemberModules(bays=[_bay("1", serial="   "), _bay("2", serial="OK2")]),
    })
    assert payload is not None
    assert [b["name"] for b in payload["members"][None]["bays"]] == ["2"]


def test_to_payload_drops_bay_with_unknown_type() -> None:
    """A bay whose module.type is outside the enum is dropped."""
    bay = ModuleBay(
        name="1", position="1",
        module=ModuleEntry(model="M1", serial="S1", type="bogus"),  # type: ignore[arg-type]
    )
    assert to_payload({None: MemberModules(bays=[bay])}) is None


def test_to_payload_drops_bay_with_no_module() -> None:
    """An empty bay (module is None) is not emitted today."""
    bay = ModuleBay(name="1", position="1", module=None)
    assert to_payload({None: MemberModules(bays=[bay])}) is None


def test_to_payload_dedupes_interfaces_by_bay() -> None:
    """Duplicate ifnames in interfaces_by_bay collapse to first occurrence."""
    payload = to_payload({
        None: MemberModules(
            bays=[_bay("1")],
            interfaces_by_bay={"1": ["Te1/0/1", "Te1/0/1", "Te1/0/2", "Te1/0/1"]},
        ),
    })
    assert payload is not None
    assert payload["members"][None]["interfaces_by_bay"]["1"] == ["Te1/0/1", "Te1/0/2"]


def test_to_payload_accepts_4tuple_ifnames() -> None:
    """
    SVL ifnames like HundredGigE1/2/0/1 are preserved (no longer rejected).

    The 4-tuple rejection that lived in _validate_interfaces_by_bay during
    the standalone-only revision is gone — SVL deployments emit those
    ifnames as valid input.
    """
    payload = to_payload({
        1: MemberModules(
            bays=[_bay("2", serial="LC1", model="C9400-LC-48U")],
            interfaces_by_bay={"2": ["HundredGigE1/2/0/1", "HundredGigE1/2/0/2"]},
        ),
    })
    assert payload is not None
    assert payload["members"][1]["interfaces_by_bay"]["2"] == [
        "HundredGigE1/2/0/1", "HundredGigE1/2/0/2",
    ]


def test_to_payload_rejects_non_string_ifname_warn_and_drop() -> None:
    """Non-string entries in interfaces_by_bay are warn-dropped, never raised."""
    payload = to_payload({
        None: MemberModules(
            bays=[_bay("1")],
            interfaces_by_bay={"1": [None, 42, "Te1/0/1"]},  # type: ignore[list-item]
        ),
    })
    assert payload is not None
    assert payload["members"][None]["interfaces_by_bay"]["1"] == ["Te1/0/1"]


def test_to_payload_rejects_non_iterable_ifnames_value() -> None:
    """A non-list value in interfaces_by_bay is warn-dropped to an empty list."""
    payload = to_payload({
        None: MemberModules(
            bays=[_bay("1")],
            interfaces_by_bay={"1": None, "2": 42, "3": ["Te3/0/1"]},  # type: ignore[dict-item]
        ),
    })
    assert payload is not None
    assert payload["members"][None]["interfaces_by_bay"] == {
        "1": [], "2": [], "3": ["Te3/0/1"],
    }


def test_to_payload_keeps_subbay_at_depth_2() -> None:
    """Cisco shape: chassis → linecard → transceiver. Depth 2."""
    transceiver = _bay("Te1/0/1", serial="SFP_SN", mtype="transceiver", model="SFP-10G-LR")
    linecard = _bay("1", serial="LC_SN", model="C9400-LC", sub_bays=[transceiver])
    payload = to_payload({None: MemberModules(bays=[linecard])})
    assert payload is not None
    member = payload["members"][None]
    assert member["bays"][0]["module"]["sub_bays"][0]["module"]["type"] == "transceiver"


def test_to_payload_keeps_subbay_at_depth_3() -> None:
    """Junos shape: chassis → FPC → PIC → transceiver. Depth 3."""
    transceiver = _bay("xe-0/0/0", serial="SFP_SN", mtype="transceiver")
    pic = _bay("PIC 0", serial="PIC_SN", sub_bays=[transceiver])
    fpc = _bay("FPC 0", serial="FPC_SN", sub_bays=[pic])
    payload = to_payload({None: MemberModules(bays=[fpc])})
    assert payload is not None
    fpc_p = payload["members"][None]["bays"][0]
    pic_p = fpc_p["module"]["sub_bays"][0]
    trans_p = pic_p["module"]["sub_bays"][0]
    assert trans_p["module"]["type"] == "transceiver"


def test_to_payload_drops_subbay_deeper_than_max_depth() -> None:
    """Anything below depth 3 gets warn-dropped at the offending level."""
    too_deep = _bay("level4", serial="X")  # would be at depth 4
    leaf = _bay("level3", serial="L3", sub_bays=[too_deep])
    mid = _bay("level2", serial="L2", sub_bays=[leaf])
    top = _bay("level1", serial="L1", sub_bays=[mid])
    payload = to_payload({None: MemberModules(bays=[top])})
    assert payload is not None
    top_p = payload["members"][None]["bays"][0]
    mid_p = top_p["module"]["sub_bays"][0]
    leaf_p = mid_p["module"]["sub_bays"][0]
    assert leaf_p["module"]["sub_bays"] == []


def test_to_payload_happy_path_serialized_shape_standalone() -> None:
    """End-to-end shape for a standalone payload (None member key)."""
    transceiver = _bay("Te1/0/1", serial="FNS1", mtype="transceiver", model="SFP-10G-LR",
                       description="10GBASE-LR")
    linecard = _bay("1", serial="FOC1", model="C9400-LC-48U",
                    description="48-port UPOE+ line card", sub_bays=[transceiver])
    payload = to_payload({
        None: MemberModules(
            bays=[linecard],
            interfaces_by_bay={"1": ["Te1/0/1", "Te1/0/2"]},
        ),
    })
    assert payload == {
        "members": {
            None: {
                "bays": [
                    {
                        "name": "1",
                        "position": "1",
                        "module": {
                            "model": "C9400-LC-48U",
                            "serial": "FOC1",
                            "description": "48-port UPOE+ line card",
                            "type": "linecard",
                            "sub_bays": [
                                {
                                    "name": "Te1/0/1",
                                    "position": "Te1/0/1",
                                    "module": {
                                        "model": "SFP-10G-LR",
                                        "serial": "FNS1",
                                        "description": "10GBASE-LR",
                                        "type": "transceiver",
                                        "sub_bays": [],
                                    },
                                },
                            ],
                        },
                    },
                ],
                "interfaces_by_bay": {"1": ["Te1/0/1", "Te1/0/2"]},
            },
        },
    }


def test_to_payload_vc_two_members_each_with_bays() -> None:
    """VC envelope with two members, each carrying one valid bay."""
    payload = to_payload({
        1: MemberModules(
            bays=[_bay("1", serial="SN1", model="C9300-NM-8X")],
            interfaces_by_bay={"1": ["Te1/1/1", "Te1/1/2"]},
        ),
        2: MemberModules(
            bays=[_bay("1", serial="SN2", model="C9300-NM-8X")],
            interfaces_by_bay={"1": ["Te2/1/1", "Te2/1/2"]},
        ),
    })
    assert payload is not None
    assert set(payload["members"].keys()) == {1, 2}
    assert payload["members"][1]["bays"][0]["module"]["serial"] == "SN1"
    assert payload["members"][2]["bays"][0]["module"]["serial"] == "SN2"
    assert payload["members"][1]["interfaces_by_bay"]["1"] == ["Te1/1/1", "Te1/1/2"]
    assert payload["members"][2]["interfaces_by_bay"]["1"] == ["Te2/1/1", "Te2/1/2"]


def test_to_payload_vc_drops_member_with_no_valid_bays() -> None:
    """A VC member whose every bay is invalid is dropped; siblings survive."""
    payload = to_payload({
        1: MemberModules(bays=[_bay("1", serial="")]),  # all invalid
        2: MemberModules(bays=[_bay("1", serial="OK2")]),
    })
    assert payload is not None
    assert list(payload["members"].keys()) == [2]


def test_to_payload_vc_returns_none_when_no_member_survives() -> None:
    """Every member's bays drop → returns None."""
    payload = to_payload({
        1: MemberModules(bays=[_bay("1", serial="")]),
        2: MemberModules(bays=[_bay("1", serial="")]),
    })
    assert payload is None


def test_max_bay_depth_is_three() -> None:
    """Sanity-pin the depth-3 contract — change with intent."""
    assert MAX_BAY_DEPTH == 3


# ---- _load_expected normalizer ------------------------------------------
#
# The base test harness rewrites JSON's string ``"null"`` member keys back
# to Python ``None`` so fixture comparisons work. Pinned here because the
# normalizer exists to make module-discovery fixtures round-trip.


def test_load_expected_normalizes_null_member_key(tmp_path):
    """Loader rewrites JSON's string `"null"` member key back to Python None."""
    from tests.custom_drivers.base_test import _load_expected
    fixture = tmp_path / "test_x" / "scenario_y"
    fixture.mkdir(parents=True)
    (fixture / "expected_result.json").write_text(
        '{"members": {"null": {"bays": []}}}', encoding="utf-8",
    )
    loaded = _load_expected(fixture)
    assert None in loaded["members"]
    assert "null" not in loaded["members"]


def test_normalize_null_member_keys_handles_nested_list_of_dicts():
    """The recursive walk descends through lists-of-dicts; rewriting is scoped to members."""
    from tests.custom_drivers.base_test import _normalize_null_member_keys
    raw = {
        "members": {
            "null": {
                "bays": [
                    {"name": "1", "module": {"sub_bays": [{"null": "kept-as-string"}]}},
                ],
            },
            "2": {"bays": []},
        },
    }
    out = _normalize_null_member_keys(raw)
    # Member keys are normalized: "null" → None, "2" → 2.
    assert set(out["members"].keys()) == {None, 2}
    # Deep "null" keys (outside the members level) are NOT rewritten —
    # the normalization is scoped to member ids and would over-rewrite
    # genuine "null"-named keys deeper in the tree.
    deep_subbay = out["members"][None]["bays"][0]["module"]["sub_bays"][0]
    assert "null" in deep_subbay
    assert None not in deep_subbay


def test_orphan_optic_bay_is_named_and_positioned_by_interface():
    """A parentless optic becomes a bay keyed by its interface name."""
    optic = ModuleEntry(
        model="SFP-10G-LR", serial="OPT0000001", type="transceiver",
        description="SFP-10GBase-LR",
    )

    bay = orphan_optic_bay("TenGigabitEthernet1/0/1", optic)

    assert bay.name == "TenGigabitEthernet1/0/1"
    assert bay.position == "TenGigabitEthernet1/0/1"
    assert bay.module is optic


def test_orphan_optic_bay_has_no_sub_bays():
    """A transceiver is a leaf: nothing installs inside an optic."""
    optic = ModuleEntry(model="SFP-10G-SR", serial="OPT0000002", type="transceiver")

    bay = orphan_optic_bay("Ethernet1", optic)

    assert bay.module is not None
    assert bay.module.sub_bays == []


# ---- identified flag validation -----------------------------------------


def _flagged_bay(model: str, *, identified: bool = True, description: str = "d") -> ModuleBay:
    """One standalone bay carrying a module, for the validator's own checks."""
    return ModuleBay(
        name="1",
        position="1",
        module=ModuleEntry(
            model=model,
            serial="SN1",
            type="transceiver",
            description=description,
            identified=identified,
        ),
    )


def test_identified_module_with_blank_model_is_dropped_and_warned(caplog):
    """
    A driver that emits no model while claiming the part is identified has a bug.

    Before this flag existed the payload carried the blank through to
    translate, which substituted the literal "Unknown" -- collapsing every such
    part fleet-wide into one ModuleType under the real vendor's name. It must
    fail loudly at the one place all drivers funnel through.
    """
    with caplog.at_level(logging.WARNING, logger="custom_napalm._modules"):
        payload = to_payload({None: MemberModules(bays=[_flagged_bay("")], interfaces_by_bay={})})

    assert payload is None
    assert any("no model" in r.getMessage() for r in caplog.records), (
        f"the drop must say why, got {[r.getMessage() for r in caplog.records]}"
    )


def test_unidentified_module_with_blank_model_is_dropped_quietly(caplog):
    """
    Silent drop for serial with no part number or description.

    There is nothing to call the part and NetBox requires a model, so it is
    skipped. Rare, and nothing an operator can act on, so it must not warn.
    """
    with caplog.at_level(logging.WARNING, logger="custom_napalm._modules"):
        payload = to_payload(
            {None: MemberModules(bays=[_flagged_bay("", identified=False, description="")],
                                 interfaces_by_bay={})}
        )

    assert payload is None
    assert not caplog.records


def test_whitespace_only_model_counts_as_blank():
    """
    Whitespace-only model is treated as blank.

    The serial is trimmed but the model was passed through raw, so "   " was
    truthy and would have defeated both checks above.
    """
    payload = to_payload({None: MemberModules(bays=[_flagged_bay("   ")], interfaces_by_bay={})})

    assert payload is None


def test_unidentified_module_with_a_description_model_survives():
    """The whole point: a described part reaches the payload, flag intact."""
    payload = to_payload(
        {None: MemberModules(bays=[_flagged_bay("SFP-10GBase-CX1", identified=False)],
                             interfaces_by_bay={})}
    )

    assert payload is not None
    module = payload["members"][None]["bays"][0]["module"]
    assert module["model"] == "SFP-10GBase-CX1"
    assert module["identified"] is False


def test_identified_module_omits_the_flag_entirely():
    """
    Identified modules must omit the flag key entirely.

    The flag is an exception marker, not a field on every module. 132
    expected_result.json fixtures across 17 drivers deep-compare this dict, so
    a key present on identified modules would rewrite all of them to record
    something true everywhere.
    """
    payload = to_payload({None: MemberModules(bays=[_flagged_bay("SFP-10G-LR")], interfaces_by_bay={})})

    module = payload["members"][None]["bays"][0]["module"]
    assert "identified" not in module


def test_dropping_a_parent_names_the_children_lost_with_it(caplog):
    """
    Parent drop must name orphaned children in the warning.

    _validate_bay recurses and a parent returning None takes its sub-bays with
    it, so an identified optic under an unidentified linecard would vanish
    without trace. The drop must say how much usable hardware went with it.
    """
    child = ModuleBay(
        name="Te1/1/1", position="Te1/1/1",
        module=ModuleEntry(model="SFP-10G-LR", serial="OPT1", type="transceiver"),
    )
    parent = ModuleBay(
        name="1", position="1",
        module=ModuleEntry(model="", serial="SN1", type="linecard", sub_bays=[child]),
    )

    with caplog.at_level(logging.WARNING, logger="custom_napalm._modules"):
        payload = to_payload({None: MemberModules(bays=[parent], interfaces_by_bay={})})

    assert payload is None
    assert any("1 usable" in r.getMessage() for r in caplog.records), (
        f"the count of lost children must be named, got {[r.getMessage() for r in caplog.records]}"
    )


def test_unidentified_blank_model_warns_when_it_takes_sub_bays_with_it(caplog):
    """
    The quiet drop stops being quiet once usable hardware goes down with it.

    A part with neither a part number nor a description is normally skipped at
    debug: correct, and nothing an operator can act on. But _validate_bay
    recurses, so a parent returning None takes its children too. When those
    children were themselves usable, the operator has lost real inventory and
    must be told, even though the parent alone would not have been worth a
    word.
    """
    child = ModuleBay(
        name="Te1/1/1", position="Te1/1/1",
        module=ModuleEntry(model="SFP-10G-LR", serial="OPT1", type="transceiver"),
    )
    parent = ModuleBay(
        name="1", position="1",
        module=ModuleEntry(
            model="", serial="SN1", type="linecard",
            description="", identified=False, sub_bays=[child],
        ),
    )

    with caplog.at_level(logging.DEBUG, logger="custom_napalm._modules"):
        payload = to_payload({None: MemberModules(bays=[parent], interfaces_by_bay={})})

    assert payload is None
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("1 usable" in m for m in warnings), (
        f"losing a usable sub-bay must warn, not stay at debug, got {warnings}"
    )
