#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Unit tests for device_discovery.translate_modules."""

from __future__ import annotations

import logging

from netboxlabs.diode.sdk.ingester import Device, DeviceType, Entity, Manufacturer

from device_discovery.policy.models import Options
from device_discovery.translate_modules import emit_modules_if_requested


def _make_device(name: str = "test-router", vendor: str = "Cisco") -> Device:
    """Test helper: build a minimal Device with manufacturer set on its DeviceType."""
    return Device(
        name=name,
        device_type=DeviceType(model="C9606R", manufacturer=Manufacturer(name=vendor)),
    )


def _standalone(bays: list, interfaces_by_bay: dict | None = None) -> dict:
    """Wrap one member's bays into the canonical nested envelope under key None."""
    return {
        "members": {
            None: {
                "bays": bays,
                "interfaces_by_bay": interfaces_by_bay or {},
            },
        },
    }


def _devices(device: Device | None = None) -> dict:
    """Standalone device map under key None for the per-member dispatch signature."""
    return {None: device if device is not None else _make_device()}


def _linecard_payload() -> dict:
    """One-bay one-linecard happy-path payload (canonical envelope)."""
    return _standalone(
        bays=[
            {
                "name": "1",
                "position": "1",
                "module": {
                    "model": "C9400-LC-48U",
                    "serial": "FOC1",
                    "description": "48-port UPOE+",
                    "type": "linecard",
                    "sub_bays": [],
                },
            },
        ],
        interfaces_by_bay={"1": ["Te1/0/1", "Te1/0/2"]},
    )


def _linecard_with_transceiver_payload() -> dict:
    """Linecard with one nested transceiver — exercises depth-2 emission."""
    return _standalone(
        bays=[
            {
                "name": "1",
                "position": "1",
                "module": {
                    "model": "C9400-LC-48U",
                    "serial": "FOC1",
                    "description": "48-port UPOE+",
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
        interfaces_by_bay={"1": ["Te1/0/1", "Te1/0/2"]},
    )


# ---- mode gating ---------------------------------------------------------


def test_off_mode_returns_empty_map_and_does_not_touch_entities() -> None:
    """discover_modules == 'off' → no payload read, entities unchanged."""
    entities: list = []
    data = {"modules": _linecard_payload()}
    iface_module_map = emit_modules_if_requested(
        data, Options(discover_modules="off"), _devices(), entities,
    )
    assert iface_module_map == {}
    assert entities == []


def test_missing_modules_key_returns_empty_map() -> None:
    """When data['modules'] is absent, fall through cleanly."""
    entities: list = []
    iface_module_map = emit_modules_if_requested(
        {}, Options(discover_modules="linecards"), _devices(), entities,
    )
    assert iface_module_map == {}
    assert entities == []


def test_none_modules_payload_returns_empty_map() -> None:
    """data['modules'] == None (driver get_modules() returned None) → no emission."""
    entities: list = []
    iface_module_map = emit_modules_if_requested(
        {"modules": None}, Options(discover_modules="linecards"), _devices(), entities,
    )
    assert iface_module_map == {}
    assert entities == []


def test_empty_bays_returns_empty_map() -> None:
    """Payload with one member whose bays=[] → no emission."""
    entities: list = []
    iface_module_map = emit_modules_if_requested(
        {"modules": _standalone(bays=[])},
        Options(discover_modules="linecards"),
        _devices(),
        entities,
    )
    assert iface_module_map == {}
    assert entities == []


def test_empty_members_dict_returns_empty_map() -> None:
    """Payload with members={} → no emission (no buckets to dispatch)."""
    entities: list = []
    iface_module_map = emit_modules_if_requested(
        {"modules": {"members": {}}},
        Options(discover_modules="linecards"),
        _devices(),
        entities,
    )
    assert iface_module_map == {}
    assert entities == []


def test_legacy_flat_shape_warns_and_skips(caplog) -> None:
    """
    A driver still emitting the old flat shape (no 'members' key) is rejected.

    Translator warns once with modules_dropped{reason="malformed"} and
    skips emission entirely, forcing drivers to migrate to the canonical
    envelope.
    """
    entities: list = []
    with caplog.at_level(logging.WARNING, logger="device_discovery.translate_modules"):
        iface_map = emit_modules_if_requested(
            {"modules": {"bays": [{"name": "1"}], "interfaces_by_bay": {}}},
            Options(discover_modules="linecards"),
            _devices(),
            entities,
        )
    assert iface_map == {}
    assert entities == []
    assert any("'members' envelope" in r.getMessage() for r in caplog.records)


# ---- linecards mode ------------------------------------------------------


def test_linecards_mode_emits_top_level_bay_and_module() -> None:
    """Linecards mode emits one ModuleBay + one Module per linecard."""
    entities: list = []
    data = {"modules": _linecard_payload()}
    iface_module_map = emit_modules_if_requested(
        data, Options(discover_modules="linecards"), _devices(), entities,
    )
    bays = [e for e in entities if e.HasField("module_bay")]
    modules = [e for e in entities if e.HasField("module")]
    assert len(bays) == 1
    assert len(modules) == 1
    assert bays[0].module_bay.name == "1"
    assert modules[0].module.serial == "FOC1"
    assert modules[0].module.module_type.model == "C9400-LC-48U"
    assert modules[0].module.module_type.manufacturer.name == "Cisco"
    # Interface routing: both ifnames in interfaces_by_bay map to the linecard.
    assert set(iface_module_map.keys()) == {"Te1/0/1", "Te1/0/2"}


def test_linecards_mode_drops_transceiver_subbays() -> None:
    """Linecards mode emits the parent linecard but NOT the nested transceiver."""
    entities: list = []
    data = {"modules": _linecard_with_transceiver_payload()}
    iface_module_map = emit_modules_if_requested(
        data, Options(discover_modules="linecards"), _devices(), entities,
    )
    modules = [e.module for e in entities if e.HasField("module")]
    assert len(modules) == 1  # only the linecard, transceiver dropped
    assert modules[0].module_type.model == "C9400-LC-48U"
    # Interfaces still get attached — to the parent linecard, not transceiver.
    assert iface_module_map["Te1/0/1"].module_type.model == "C9400-LC-48U"


def test_linecards_mode_skips_top_level_transceiver_bay() -> None:
    """A top-level transceiver bay (rare, but possible) is dropped in linecards mode."""
    payload = {
        "bays": [
            {
                "name": "1",
                "position": "1",
                "module": {
                    "model": "SFP-10G-LR",
                    "serial": "FNS1",
                    "description": "",
                    "type": "transceiver",
                    "sub_bays": [],
                },
            },
        ],
        "interfaces_by_bay": {},
    }
    entities: list = []
    iface_module_map = emit_modules_if_requested(
        {"modules": {"members": {None: payload}}}, Options(discover_modules="linecards"),
        _devices(), entities,
    )
    assert entities == []
    assert iface_module_map == {}


def test_linecards_mode_emits_nothing_for_device_rooted_optics() -> None:
    """
    A fixed-port device has only transceiver bays, so linecards mode is silent.

    Fixed-port platforms (and the fixed ports of a chassis whose only module
    is an uplink) have no slot/linecard/FRU parent for their optics, so the
    driver promotes each one to a device-rooted bay named after its
    interface — the same shape a sub-bay collapses to once a parent link is
    stripped. Mode filtering doesn't care where the bay is rooted, only that
    its module classifies as a transceiver, so this is shared by every
    driver that implements get_modules() and one test covers all of them.
    """
    entities: list = []
    data = {
        "modules": _standalone(
            bays=[
                {
                    "name": "Ethernet1",
                    "position": "Ethernet1",
                    "module": {
                        "model": "QSFP-40G-SR4",
                        "serial": "OPT0000001",
                        "type": "transceiver",
                        "description": "",
                        "sub_bays": [],
                    },
                },
            ],
            interfaces_by_bay={"Ethernet1": ["Ethernet1"]},
        ),
    }
    iface_module_map = emit_modules_if_requested(
        data, Options(discover_modules="linecards"), _devices(), entities,
    )
    assert entities == [], "linecards mode must not emit a device-rooted transceiver bay"
    assert iface_module_map == {}


# ---- full mode -----------------------------------------------------------


def test_full_mode_emits_transceiver_subbay_without_module_parent() -> None:
    """
    Full mode emits the linecard, the sub-bay, AND the transceiver Module.

    Sub-bays are intentionally device-rooted (no ``module=parent`` link).
    Setting ``module=parent`` would let NetBox render the bay nested
    under its linecard, but the current per-entity reconciler then
    re-emits the parent Module inside the sub-bay's own changeset and
    conflicts at apply with the linecard created by the prior top-level
    Module entity. The transceiver still installs in the sub-bay via
    ``Module.module_bay``; only the bay-under-linecard rendering is
    lost.

    TODO: restore ``module=parent`` on sub-bays once the reconciler
    resolves nested parent-module refs against committed sibling
    entities in a single ingest call.
    """
    entities: list = []
    data = {"modules": _linecard_with_transceiver_payload()}
    emit_modules_if_requested(
        data, Options(discover_modules="full"), _devices(), entities,
    )
    bays = [e.module_bay for e in entities if e.HasField("module_bay")]
    modules = [e.module for e in entities if e.HasField("module")]
    assert len(bays) == 2  # top-level linecard bay + sub transceiver bay
    assert len(modules) == 2  # linecard + transceiver
    # Top-level bay: device-rooted, no module parent.
    top_bay = bays[0]
    assert top_bay.name == "1"
    assert top_bay.device.name == "test-router"
    assert not top_bay.HasField("module")
    # Sub-bay: device-rooted, NO module parent (see docstring).
    sub_bay = bays[1]
    assert sub_bay.name == "Te1/0/1"
    assert sub_bay.device.name == "test-router"
    assert not sub_bay.HasField("module")
    # Transceiver module still carries the chassis device + its sub-bay.
    transceiver = modules[1]
    assert transceiver.module_type.model == "SFP-10G-LR"
    assert transceiver.device.name == "test-router"
    assert transceiver.module_bay.name == "Te1/0/1"
    assert transceiver.serial == "FNS1"


# ---- malformed-payload fallthrough --------------------------------------


def test_malformed_bay_logged_and_other_bays_continue(caplog) -> None:
    """A bay that raises during emission is logged and other bays still emit."""
    payload = {
        "bays": [
            {  # Missing "module" key → will raise inside _emit_bay_recursive.
                "name": "broken",
                "position": "broken",
            },
            {  # Valid sibling — must still emit.
                "name": "1",
                "position": "1",
                "module": {
                    "model": "C9400-LC-48U",
                    "serial": "FOC1",
                    "description": "",
                    "type": "linecard",
                    "sub_bays": [],
                },
            },
        ],
        "interfaces_by_bay": {},
    }
    entities: list = []
    with caplog.at_level(logging.WARNING, logger="device_discovery.translate_modules"):
        emit_modules_if_requested(
            {"modules": {"members": {None: payload}}}, Options(discover_modules="linecards"),
            _devices(), entities,
        )
    modules = [e for e in entities if e.HasField("module")]
    assert len(modules) == 1
    assert modules[0].module.serial == "FOC1"
    assert any("malformed module payload" in r.message for r in caplog.records)


def test_non_dict_payload_returns_empty_map() -> None:
    """data['modules'] of a wrong type (e.g. a list) is treated as no payload."""
    entities: list = []
    iface_module_map = emit_modules_if_requested(
        {"modules": ["not", "a", "dict"]},
        Options(discover_modules="linecards"),
        _devices(),
        entities,
    )
    assert iface_module_map == {}
    assert entities == []


def test_malformed_sub_bay_does_not_drop_parent_bay(caplog) -> None:
    """
    One bad sub-bay must not take down the parent linecard's emission.

    Earlier the recursive call lived inside the top-level bay's
    try/except, so any exception raised inside _emit_bay_recursive
    while processing a sub-bay would skip the whole parent bay (and
    its already-emitted Module). The fix wraps each sub-bay in its
    own guard.
    """
    payload = {
        "bays": [
            {
                "name": "1", "position": "1",
                "module": {
                    "model": "C9400-LC-48U", "serial": "FOC1", "description": "",
                    "type": "linecard",
                    "sub_bays": [
                        # Missing "module" key → AttributeError inside recursion.
                        {"name": "BROKEN", "position": "BROKEN"},
                        {
                            "name": "Te1/0/2", "position": "Te1/0/2",
                            "module": {
                                "model": "SFP-10G-LR", "serial": "FNS2",
                                "description": "", "type": "transceiver",
                                "sub_bays": [],
                            },
                        },
                    ],
                },
            },
        ],
        "interfaces_by_bay": {},
    }
    entities: list = []
    with caplog.at_level(logging.WARNING, logger="device_discovery.translate_modules"):
        emit_modules_if_requested(
            {"modules": {"members": {None: payload}}}, Options(discover_modules="full"),
            _devices(), entities,
        )
    modules = [e.module for e in entities if e.HasField("module")]
    # Linecard + the sibling transceiver survive; broken sub-bay is dropped.
    serials = sorted(m.serial for m in modules)
    assert serials == ["FNS2", "FOC1"]
    assert any("sub-bay" in r.message for r in caplog.records)


def test_non_dict_sub_bay_logged_and_skipped(caplog) -> None:
    """A non-dict element in sub_bays is logged and skipped without raising."""
    payload = {
        "bays": [
            {
                "name": "1", "position": "1",
                "module": {
                    "model": "C9400-LC-48U", "serial": "FOC1", "description": "",
                    "type": "linecard",
                    "sub_bays": ["garbage-not-a-dict"],
                },
            },
        ],
        "interfaces_by_bay": {},
    }
    entities: list = []
    with caplog.at_level(logging.WARNING, logger="device_discovery.translate_modules"):
        emit_modules_if_requested(
            {"modules": {"members": {None: payload}}}, Options(discover_modules="full"),
            _devices(), entities,
        )
    modules = [e.module for e in entities if e.HasField("module")]
    assert len(modules) == 1  # parent linecard still emits
    assert any("not a dict" in r.message for r in caplog.records)


def test_non_list_per_bay_ifnames_does_not_drop_parent_bay(caplog) -> None:
    """
    A non-list per-bay value is treated as empty, not iterated blindly.

    The previous code path iterated whatever ``interfaces_by_bay[name]``
    returned. If a driver passed a string, Python iterates it
    character-by-character (silently bogus). If it passed an int, the
    iteration raises and the outer try/except drops the entire parent
    Module. The per-bay guard now logs at WARNING and treats non-list
    values as empty so the bay and its Module still emit cleanly.
    """
    payload = {
        "bays": [
            {
                "name": "1", "position": "1",
                "module": {
                    "model": "C9400-LC-48U", "serial": "FOC1", "description": "",
                    "type": "linecard",
                    "sub_bays": [],
                },
            },
        ],
        "interfaces_by_bay": {"1": "Te1/0/1"},  # type: ignore[dict-item]
    }
    entities: list = []
    with caplog.at_level(logging.WARNING, logger="device_discovery.translate_modules"):
        emit_modules_if_requested(
            {"modules": {"members": {None: payload}}}, Options(discover_modules="linecards"),
            _devices(), entities,
        )
    modules = [e for e in entities if e.HasField("module")]
    bays = [e for e in entities if e.HasField("module_bay")]
    # Parent linecard still emits despite the malformed routing entry —
    # iterating the string by character would have populated bogus
    # ifnames in iface_module_map; the guard prevents that.
    assert len(modules) == 1
    assert len(bays) == 1
    assert any("expected list" in r.getMessage() for r in caplog.records)


def test_malformed_interfaces_by_bay_does_not_block_emission(caplog) -> None:
    """
    A non-dict ``interfaces_by_bay`` must not crash bay/module emission.

    The translator normalizes it to ``{}`` so per-interface routing is
    simply empty; the rest of the payload still emits cleanly.
    """
    payload = {
        "bays": [
            {
                "name": "1", "position": "1",
                "module": {
                    "model": "C9400-LC-48U", "serial": "FOC1", "description": "",
                    "type": "linecard",
                    "sub_bays": [],
                },
            },
        ],
        # A driver returning None here used to AttributeError inside the loop.
        "interfaces_by_bay": None,
    }
    entities: list = []
    iface_module_map = emit_modules_if_requested(
        {"modules": {"members": {None: payload}}}, Options(discover_modules="linecards"),
        _devices(), entities,
    )
    modules = [e for e in entities if e.HasField("module")]
    assert len(modules) == 1
    assert iface_module_map == {}


def test_non_dict_bay_in_payload_logged_and_skipped(caplog) -> None:
    """A non-dict element inside payload['bays'] must not crash the loop."""
    payload = {
        "bays": [
            "garbage-not-a-dict",
            {
                "name": "1",
                "position": "1",
                "module": {
                    "model": "C9400-LC-48U",
                    "serial": "FOC1",
                    "description": "",
                    "type": "linecard",
                    "sub_bays": [],
                },
            },
        ],
        "interfaces_by_bay": {},
    }
    entities: list = []
    with caplog.at_level(logging.WARNING, logger="device_discovery.translate_modules"):
        emit_modules_if_requested(
            {"modules": {"members": {None: payload}}}, Options(discover_modules="linecards"),
            _devices(), entities,
        )
    modules = [e for e in entities if e.HasField("module")]
    assert len(modules) == 1
    assert any("not a dict" in r.message for r in caplog.records)


def test_linecards_mode_drops_non_transceiver_sub_bays() -> None:
    """
    Linecards mode drops ALL sub_bays regardless of type, not just transceivers.

    A nested fan / psu / supervisor sub-bay (rare in real chassis but
    representable in the payload) must also be filtered out so that
    operator dashboards show only the top-level inventory.
    """
    payload = {
        "bays": [
            {
                "name": "1", "position": "1",
                "module": {
                    "model": "C9400-LC-48U", "serial": "FOC1", "description": "",
                    "type": "linecard",
                    "sub_bays": [
                        {
                            "name": "FAN-1", "position": "FAN-1",
                            "module": {
                                "model": "C9400-FAN", "serial": "FAN_SN",
                                "description": "", "type": "fan",
                                "sub_bays": [],
                            },
                        },
                    ],
                },
            },
        ],
        "interfaces_by_bay": {},
    }
    entities: list = []
    emit_modules_if_requested(
        {"modules": {"members": {None: payload}}}, Options(discover_modules="linecards"),
        _devices(), entities,
    )
    modules = [e.module for e in entities if e.HasField("module")]
    # Only the linecard emits — the nested fan sub-bay is dropped.
    assert len(modules) == 1
    assert modules[0].module_type.model == "C9400-LC-48U"


def test_full_mode_module_reuses_device_manufacturer_reference() -> None:
    """
    Module ModuleType.manufacturer must value-equal the Device's manufacturer.

    v1 inherits the device's manufacturer for every installed Module —
    constructing a fresh Manufacturer(name=...) here would lose any extra
    fields the upstream driver populated (slug, custom_field_data, etc.).
    """
    entities: list = []
    data = {"modules": _linecard_payload()}
    device = _make_device(vendor="Cisco")
    emit_modules_if_requested(
        data, Options(discover_modules="linecards"), {None: device}, entities,
    )
    module = next(e.module for e in entities if e.HasField("module"))
    # Same name, and the manufacturer message round-trips via SerializeToString
    # to the same bytes as the device's. Protobuf messages are equal iff their
    # serialized bytes are equal, so this catches drift in any non-name field.
    assert (
        module.module_type.manufacturer.SerializeToString()
        == device.device_type.manufacturer.SerializeToString()
    )


# ---- iface_module_map deepest-wins --------------------------------------


def test_metric_counters_invoked_when_enabled(monkeypatch) -> None:
    """
    Module / bay emission each bump their counters with vendor + type attributes.

    Stubs ``get_metric`` to a recording fake so we don't depend on the
    OTel SDK being wired up in the test environment. The vc_of_modular
    drop counter is fired upstream in
    ``policy.runner._collect_modules`` and is covered there.
    """
    import device_discovery.translate_modules as tm

    calls: list[tuple[str, int, dict]] = []

    class _FakeCounter:
        def __init__(self, name):
            self.name = name

        def add(self, value, attrs):
            calls.append((self.name, value, dict(attrs)))

    counters: dict[str, _FakeCounter] = {}

    def fake_get_metric(name: str):
        counters.setdefault(name, _FakeCounter(name))
        return counters[name]
    monkeypatch.setattr(tm, "get_metric", fake_get_metric)

    entities: list = []
    data = {"modules": _linecard_with_transceiver_payload()}
    emit_modules_if_requested(
        data, Options(discover_modules="full"), _devices(), entities,
    )
    bay_counts = [c for c in calls if c[0] == "module_bays_emitted"]
    mod_counts = [c for c in calls if c[0] == "modules_emitted"]
    assert len(bay_counts) == 2  # parent bay + transceiver sub-bay
    assert len(mod_counts) == 2  # linecard + transceiver
    # Linecard emits with type=linecard; transceiver with type=transceiver.
    assert {m[2].get("type") for m in mod_counts} == {"linecard", "transceiver"}
    assert all(c[2].get("vendor") == "Cisco" for c in mod_counts + bay_counts)


def test_metric_counters_noop_when_disabled(monkeypatch) -> None:
    """get_metric() returns None when OTel export was never configured — no AttributeError."""
    import device_discovery.translate_modules as tm
    monkeypatch.setattr(tm, "get_metric", lambda _name: None)
    entities: list = []
    iface_module_map = emit_modules_if_requested(
        {"modules": _linecard_payload()}, Options(discover_modules="linecards"),
        _devices(), entities,
    )
    # Emission still succeeds with metrics disabled (the production default).
    assert any(e.HasField("module") for e in entities)
    assert iface_module_map  # interfaces routed


def test_full_mode_iface_map_uses_deepest_bay_when_payload_specifies() -> None:
    """When the driver maps an ifname to a sub-bay key, that sub-bay wins."""
    payload = _linecard_with_transceiver_payload()
    # Driver populates the sub-bay key as well as the parent — deepest wins.
    payload["members"][None]["interfaces_by_bay"]["Te1/0/1"] = ["Te1/0/1"]
    entities: list = []
    iface_module_map = emit_modules_if_requested(
        {"modules": payload}, Options(discover_modules="full"),
        _devices(), entities,
    )
    # The transceiver module wins for Te1/0/1.
    assert iface_module_map["Te1/0/1"].module_type.model == "SFP-10G-LR"
    # Te1/0/2 wasn't in the sub-bay map; it stays on the parent linecard.
    assert iface_module_map["Te1/0/2"].module_type.model == "C9400-LC-48U"


# ---- VC dispatch ---------------------------------------------------------


def test_emit_vc_two_members_each_get_their_own_bays() -> None:
    """A two-member VC payload emits per-member Module + ModuleBay under that member's Device."""
    member1_dev = _make_device(name="sw1")
    member2_dev = _make_device(name="sw2")
    payload = {
        "modules": {
            "members": {
                1: {
                    "bays": [{
                        "name": "1", "position": "1",
                        "module": {
                            "model": "C9300-NM-8X", "serial": "NM1",
                            "description": "", "type": "linecard",
                            "sub_bays": [],
                        },
                    }],
                    "interfaces_by_bay": {"1": ["Te1/1/1"]},
                },
                2: {
                    "bays": [{
                        "name": "1", "position": "1",
                        "module": {
                            "model": "C9300-NM-8X", "serial": "NM2",
                            "description": "", "type": "linecard",
                            "sub_bays": [],
                        },
                    }],
                    "interfaces_by_bay": {"1": ["Te2/1/1"]},
                },
            },
        },
    }
    entities: list = []
    iface_module_map = emit_modules_if_requested(
        payload, Options(discover_modules="linecards"),
        {1: member1_dev, 2: member2_dev}, entities,
    )
    modules = [e.module for e in entities if e.HasField("module")]
    assert {m.serial for m in modules} == {"NM1", "NM2"}
    # Module sn=NM1 lives on member1_dev; sn=NM2 on member2_dev.
    nm1 = next(m for m in modules if m.serial == "NM1")
    nm2 = next(m for m in modules if m.serial == "NM2")
    assert nm1.device.name == "sw1"
    assert nm2.device.name == "sw2"
    # Iface routing: each member's ifname → that member's module.
    assert iface_module_map["Te1/1/1"].serial == "NM1"
    assert iface_module_map["Te2/1/1"].serial == "NM2"


def test_empty_envelope_does_not_log_malformed(caplog, monkeypatch) -> None:
    """
    An empty but well-formed envelope is a silent no-op.

    Pre-fix, the malformed-vs-empty paths shared one helper, so a payload
    like ``{"members": {}}`` or ``{"members": {None: {"bays": []}}}``
    triggered both a WARNING and a ``modules_dropped{reason="malformed"}``
    counter even though the shape was valid. The split helpers separate
    those concerns; this test pins the silent path.
    """
    import device_discovery.translate_modules as tm
    counter_calls: list[tuple[int, dict]] = []

    class _FakeCounter:
        def add(self, value, attrs):
            counter_calls.append((value, dict(attrs)))

    monkeypatch.setattr(
        tm, "get_metric",
        lambda name: _FakeCounter() if name == "modules_dropped" else None,
    )
    entities: list = []
    with caplog.at_level(logging.WARNING, logger="device_discovery.translate_modules"):
        # Variant 1: members dict is empty.
        emit_modules_if_requested(
            {"modules": {"members": {}}},
            Options(discover_modules="linecards"),
            _devices(), entities,
        )
        # Variant 2: well-formed members entry with empty bays.
        emit_modules_if_requested(
            {"modules": {"members": {None: {"bays": [], "interfaces_by_bay": {}}}}},
            Options(discover_modules="linecards"),
            _devices(), entities,
        )
    assert entities == []
    # No malformed warning and no counter bump on either variant.
    assert not any("malformed" in r.getMessage() for r in caplog.records)
    assert counter_calls == []


def test_emit_vc_member_with_non_list_bays_warn_dropped(caplog, monkeypatch) -> None:
    """A member whose `bays` is non-list (None/int/string) is warn-dropped."""
    import device_discovery.translate_modules as tm
    counter_calls: list[tuple[int, dict]] = []

    class _FakeCounter:
        def add(self, value, attrs):
            counter_calls.append((value, dict(attrs)))

    monkeypatch.setattr(
        tm, "get_metric",
        lambda name: _FakeCounter() if name == "modules_dropped" else None,
    )
    payload = {
        "modules": {
            "members": {
                1: {"bays": None, "interfaces_by_bay": {}},  # type: ignore[dict-item]
                2: {
                    "bays": [{
                        "name": "1", "position": "1",
                        "module": {
                            "model": "M", "serial": "S2", "description": "",
                            "type": "linecard", "sub_bays": [],
                        },
                    }],
                    "interfaces_by_bay": {},
                },
            },
        },
    }
    entities: list = []
    with caplog.at_level(logging.WARNING, logger="device_discovery.translate_modules"):
        emit_modules_if_requested(
            payload, Options(discover_modules="linecards"),
            {1: _make_device(name="sw1"), 2: _make_device(name="sw2")}, entities,
        )
    modules = [e.module for e in entities if e.HasField("module")]
    # Member 2 still emits; member 1's bad bays warn-drops the whole member.
    assert {m.serial for m in modules} == {"S2"}
    assert any("bays is not a list" in r.getMessage() for r in caplog.records)
    assert counter_calls == [(1, {"reason": "malformed"})]


def test_emit_vc_skips_malformed_member_payload(caplog, monkeypatch) -> None:
    """
    A non-dict member entry is skipped; sibling valid members still emit.

    ``_payload_has_members`` only proves at least one member entry has bays;
    a mixed payload where one member is a string/None/list slipped through
    in the past and AttributeError'd on the next iteration. The isinstance
    guard now warn-drops the bad entry with ``modules_dropped{reason=
    malformed}`` and lets sibling members through.
    """
    import device_discovery.translate_modules as tm
    counter_calls: list[tuple[int, dict]] = []

    class _FakeCounter:
        def add(self, value, attrs):
            counter_calls.append((value, dict(attrs)))

    monkeypatch.setattr(
        tm, "get_metric",
        lambda name: _FakeCounter() if name == "modules_dropped" else None,
    )
    payload = {
        "modules": {
            "members": {
                1: "garbage-not-a-dict",  # type: ignore[dict-item]
                2: {
                    "bays": [{
                        "name": "1", "position": "1",
                        "module": {
                            "model": "M", "serial": "S2", "description": "",
                            "type": "linecard", "sub_bays": [],
                        },
                    }],
                    "interfaces_by_bay": {},
                },
            },
        },
    }
    entities: list = []
    with caplog.at_level(logging.WARNING, logger="device_discovery.translate_modules"):
        emit_modules_if_requested(
            payload, Options(discover_modules="linecards"),
            {1: _make_device(name="sw1"), 2: _make_device(name="sw2")}, entities,
        )
    modules = [e.module for e in entities if e.HasField("module")]
    assert {m.serial for m in modules} == {"S2"}
    assert any("not a dict" in r.getMessage() for r in caplog.records)
    assert counter_calls == [(1, {"reason": "malformed"})]


def test_emit_vc_orphan_member_id_warn_dropped(caplog, monkeypatch) -> None:
    """A member id with no matching device → modules_dropped{reason=orphan_member}, warn, skip."""
    import device_discovery.translate_modules as tm
    counter_calls: list[tuple[int, dict]] = []

    class _FakeCounter:
        def add(self, value, attrs):
            counter_calls.append((value, dict(attrs)))

    monkeypatch.setattr(
        tm, "get_metric",
        lambda name: _FakeCounter() if name == "modules_dropped" else None,
    )
    payload = {
        "modules": {
            "members": {
                1: {
                    "bays": [{
                        "name": "1", "position": "1",
                        "module": {
                            "model": "M", "serial": "S1", "description": "",
                            "type": "linecard", "sub_bays": [],
                        },
                    }],
                    "interfaces_by_bay": {},
                },
                # Member 3 has no matching device → orphan.
                3: {
                    "bays": [{
                        "name": "1", "position": "1",
                        "module": {
                            "model": "M", "serial": "S3", "description": "",
                            "type": "linecard", "sub_bays": [],
                        },
                    }],
                    "interfaces_by_bay": {},
                },
            },
        },
    }
    entities: list = []
    with caplog.at_level(logging.WARNING, logger="device_discovery.translate_modules"):
        emit_modules_if_requested(
            payload, Options(discover_modules="linecards"),
            {1: _make_device(name="sw1")}, entities,
        )
    modules = [e.module for e in entities if e.HasField("module")]
    # Member 1 still emits; member 3 is dropped.
    assert {m.serial for m in modules} == {"S1"}
    assert any("orphan" in r.getMessage() for r in caplog.records)
    assert counter_calls == [(1, {"reason": "orphan_member"})]


def test_emit_vc_boolean_member_id_warn_dropped(caplog, monkeypatch) -> None:
    """
    Boolean member_id (True/False) is dropped before the devices.get() lookup.

    Because ``bool`` is a subclass of ``int`` in Python, ``devices.get(True)``
    silently resolves to the device keyed by ``1``. Without the explicit
    guard the bad payload would misattribute the bay/module to member 1
    instead of being warn-dropped as malformed.

    Note we can't put both ``True`` and ``1`` in the same dict literal —
    Python collapses them (``hash(True) == hash(1)`` and ``True == 1``).
    Test the bool-only case directly.
    """
    import device_discovery.translate_modules as tm
    counter_calls: list[tuple[int, dict]] = []

    class _FakeCounter:
        def add(self, value, attrs):
            counter_calls.append((value, dict(attrs)))

    monkeypatch.setattr(
        tm, "get_metric",
        lambda name: _FakeCounter() if name == "modules_dropped" else None,
    )
    members: dict = {}
    members[True] = {
        "bays": [{
            "name": "1", "position": "1",
            "module": {
                "model": "M", "serial": "S_TRUE", "description": "",
                "type": "linecard", "sub_bays": [],
            },
        }],
        "interfaces_by_bay": {},
    }
    payload = {"modules": {"members": members}}
    entities: list = []
    with caplog.at_level(logging.WARNING, logger="device_discovery.translate_modules"):
        emit_modules_if_requested(
            payload, Options(discover_modules="linecards"),
            {1: _make_device(name="sw1")}, entities,
        )
    modules = [e.module for e in entities if e.HasField("module")]
    # bool-True payload is dropped; nothing emitted even though devices has
    # an entry for int-1 (which would otherwise silently match True).
    assert modules == []
    assert any("boolean" in r.getMessage() for r in caplog.records)
    assert (1, {"reason": "malformed"}) in counter_calls
