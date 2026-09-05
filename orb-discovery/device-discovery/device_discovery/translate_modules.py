#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
Translate vendor-neutral module payloads into Module + ModuleBay entities.

Reads the per-member nested envelope produced by a driver's optional
``get_modules()`` and dispatches each member's bays under the right
Device. Standalone callers pass ``{None: device}``; virtual-chassis
callers pass ``{member_id: member_device, ...}``.

Public entry point: ``emit_modules_if_requested(...)``. Returns an
``iface_module_map: dict[str, pb.Module]`` that the interface builder
consumes to attach ``module=`` on each interface alongside ``device=``.
The ingester ``Module(...)`` constructor returns a ``pb.Module`` proto
directly (the ingester names are factories, not wrapper classes), so
the map values are protobuf messages even though they're created
through the SDK wrapper.
"""

from __future__ import annotations

import logging
from typing import Any

from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb
from netboxlabs.diode.sdk.ingester import Entity, Module, ModuleBay, ModuleType

from device_discovery.metrics import get_metric
from device_discovery.policy.models import Options
from device_discovery.proto_presence import blank_to_none

logger = logging.getLogger(__name__)

#: Manufacturer for a part the device could not name. Segregates guessed parts
#: from genuine ones, because dcim.moduletype matches on (manufacturer, model):
#: filed under the chassis vendor they would interleave with real parts and be
#: unpickable later. The string matches _manufacturer_from_device's own
#: fallback, which is correct -- both mean the same thing.
UNIDENTIFIED_MANUFACTURER = "Unknown"


def emit_modules_if_requested(
    data: dict[str, Any],
    options: Options,
    devices: dict[int | None, pb.Device],
    entities: list[Entity],
) -> dict[str, pb.Module]:
    """
    Maybe-emit Module / ModuleBay entities for the discovered device(s).

    ``devices`` maps member id to the Device proto each member's modules
    should be attached to. Standalone callers pass ``{None: device}``;
    virtual-chassis callers pass ``{1: member_dev_1, 2: member_dev_2, ...}``.

    Reads ``data["modules"]`` (the nested envelope produced by the driver's
    optional get_modules() extension). Mutates ``entities`` in place to
    append ModuleBay and Module entries. Returns a flat ifname → Module
    map so the interface builder can attach ``module=`` per entity.

    Returns an empty dict when:
      - ``options.discover_modules == "off"`` (default; zero behavior change).
      - ``data["modules"]`` is missing, ``None``, or has no surviving member bays.
      - The payload is malformed (missing 'members' envelope, etc.).
    """
    if options.discover_modules == "off":
        return {}
    payload = data.get("modules")
    if payload is None:
        return {}
    # Separate envelope-validation from "has any bays" — an empty but
    # well-formed envelope (e.g. {"members": {None: {"bays": []}}}) is
    # a valid no-op and must NOT log/bump the malformed counter. Only
    # payloads that DON'T match the canonical shape are flagged.
    if not _payload_is_envelope(payload):
        if isinstance(payload, dict) and payload:
            logger.warning(
                "module payload malformed — expected 'members' envelope",
                extra={"keys": sorted(payload.keys())[:6]},
            )
            _bump("modules_dropped", 1, {"reason": "malformed"})
        return {}
    if not _payload_has_any_bay(payload):
        return {}

    mode = options.discover_modules
    iface_module_map: dict[str, pb.Module] = {}
    for member_id, member_payload in payload["members"].items():
        _emit_one_member(
            member_id=member_id,
            member_payload=member_payload,
            devices=devices,
            mode=mode,
            entities=entities,
            iface_module_map=iface_module_map,
        )
    return iface_module_map


def _emit_one_member(
    *,
    member_id: int | None,
    member_payload: Any,
    devices: dict[int | None, pb.Device],
    mode: str,
    entities: list[Entity],
    iface_module_map: dict[str, pb.Module],
) -> None:
    """Emit one member's bays under that member's Device, or warn-drop the member."""
    # _payload_is_envelope only checks shape at the outer level; it does
    # not guarantee every member value is a dict. Guard here so one
    # malformed member (string / None / list) cannot AttributeError the
    # outer loop and abort emission for the rest of the device.
    if not isinstance(member_payload, dict):
        logger.warning(
            "malformed module member payload — skipping (not a dict)",
            extra={"member_id": member_id, "payload": repr(member_payload)[:80]},
        )
        _bump("modules_dropped", 1, {"reason": "malformed"})
        return
    # bool is a subclass of int — devices.get(True) would resolve to the
    # member keyed by 1 and silently misattribute the module entities.
    # Reject boolean ids as malformed before the lookup.
    if isinstance(member_id, bool):
        logger.warning(
            "malformed module member payload — boolean member_id",
            extra={"member_id": member_id},
        )
        _bump("modules_dropped", 1, {"reason": "malformed"})
        return
    device = devices.get(member_id)
    if device is None:
        logger.warning(
            "module discovery dropped orphan member with no matching chassis device",
            extra={"member_id": member_id},
        )
        _bump("modules_dropped", 1, {"reason": "orphan_member"})
        return
    manufacturer = _manufacturer_from_device(device)
    raw_ifaces = member_payload.get("interfaces_by_bay")
    interfaces_by_bay = raw_ifaces if isinstance(raw_ifaces, dict) else {}
    # Per-member ``bays`` is expected to be a list; guard against
    # ``bays=None``/int/string so a buggy driver payload doesn't
    # TypeError or iterate a string character-by-character.
    raw_bays = member_payload.get("bays", [])
    if not isinstance(raw_bays, list):
        logger.warning(
            "malformed module member payload — bays is not a list",
            extra={"member_id": member_id, "bays": repr(raw_bays)[:80]},
        )
        _bump("modules_dropped", 1, {"reason": "malformed"})
        return
    for bay_data in raw_bays:
        if not isinstance(bay_data, dict):
            logger.warning(
                "malformed module payload bay — skipping (not a dict)",
                extra={"bay": repr(bay_data)[:80], "member_id": member_id},
            )
            _bump("modules_dropped", 1, {"reason": "malformed"})
            continue
        try:
            _emit_bay_recursive(
                bay_data=bay_data,
                device=device,
                mode=mode,
                manufacturer=manufacturer,
                entities=entities,
                iface_module_map=iface_module_map,
                interfaces_by_bay=interfaces_by_bay,
            )
        except Exception:
            logger.warning(
                "malformed module payload bay — skipping",
                extra={"bay": bay_data.get("name"), "member_id": member_id},
                exc_info=True,
            )
            _bump("modules_dropped", 1, {"reason": "malformed"})


def _bump(metric_name: str, value: int, attrs: dict[str, str]) -> None:
    """
    Increment an OTel counter when metrics are enabled; otherwise no-op.

    Kept narrow on purpose: ``get_metric`` returns ``None`` whenever
    ``setup_metrics_export`` has not been called (every test and the dry-
    run mode both leave it unconfigured), so wrapping the .add() call
    here saves every caller from writing the same guard.
    """
    counter = get_metric(metric_name)
    if counter is not None:
        counter.add(value, attrs)


def _payload_is_envelope(payload: Any) -> bool:
    """
    Defensive shape check: payload IS the canonical envelope.

    True for ``{"members": {...}}`` with any (possibly empty) dict of
    members — including ``{"members": {}}`` and member buckets with
    ``bays=[]``. Those are valid no-ops, not malformed.
    """
    if not isinstance(payload, dict):
        return False
    return isinstance(payload.get("members"), dict)


def _payload_has_any_bay(payload: dict) -> bool:
    """True when at least one member entry in the envelope carries a non-empty bays list."""
    for entry in payload["members"].values():
        if isinstance(entry, dict) and entry.get("bays"):
            return True
    return False


def _manufacturer_from_device(device: pb.Device) -> pb.Manufacturer:
    """
    Return the device's Manufacturer message, falling back to a placeholder.

    Modules / ModuleTypes need a Manufacturer reference. v1 reuses the
    device's manufacturer message directly so any extra fields the
    upstream driver populated (custom_field_data, slug, etc.) propagate
    to the Module without re-deriving from just the name string.
    """
    if device.HasField("device_type") and device.device_type.HasField("manufacturer"):
        return device.device_type.manufacturer
    return pb.Manufacturer(name="Unknown")


def _emit_bay_recursive(
    *,
    bay_data: dict,
    device: pb.Device,
    mode: str,
    manufacturer: pb.Manufacturer,
    entities: list[Entity],
    iface_module_map: dict[str, pb.Module],
    interfaces_by_bay: dict[str, list[str]],
) -> None:
    """
    Recursively emit a ModuleBay + Module + their nested sub-bays.

    NetBox requires ``device=`` on every ModuleBay and Module — including
    nested sub-bays — because the chassis device is the matching scope
    for both. The Diode reconciler rejects bays/modules emitted without
    ``device=`` with ``Field device is required``.

    Sub-bays are emitted as device-rooted bays (no ``module=parent``
    link). Setting ``module=parent_module`` would let NetBox render the
    bay nested under its linecard, but in the current reconciler that
    field forces the parent Module to be re-emitted inside the sub-bay's
    own changeset, which conflicts at apply time with the linecard
    created by the earlier top-level Module entity
    (``dcim_module_module_bay_id_key`` unique-constraint violation). The
    transceiver Module still installs in the sub-bay correctly via
    ``Module.module_bay``; only the bay-under-linecard rendering is
    lost.

    TODO: restore ``module=parent_module`` on sub-bays once the
    reconciler resolves nested parent-module refs against committed
    sibling entities in a single ingest call.

    ``linecards`` mode short-circuits: any bay whose module.type is
    ``"transceiver"`` is skipped entirely (including its sub_bays);
    interfaces that would have routed to a skipped sub-bay fall back to
    the nearest emitted ancestor in ``iface_module_map``.
    """
    module_data = bay_data["module"]
    if mode == "linecards" and module_data["type"] == "transceiver":
        return

    bay = ModuleBay(
        device=device,
        name=bay_data["name"],
        # ModuleBay.position and Module.serial declare presence. custom_napalm
        # normally drops blank-serial bays, but a driver assembling the envelope
        # without to_payload must not be able to emit an explicit empty value.
        position=blank_to_none(bay_data.get("position") or bay_data["name"]),
    )
    entities.append(Entity(module_bay=bay))
    _bump("module_bays_emitted", 1, {"vendor": manufacturer.name})

    identified = module_data.get("identified", True)
    module_manufacturer = (
        manufacturer if identified else pb.Manufacturer(name=UNIDENTIFIED_MANUFACTURER)
    )
    # No `or "Unknown"` fallback: _validate_bay guarantees a non-blank model
    # reaches here, and substituting a placeholder is what collapsed every
    # unidentifiable part into a single ModuleType.
    module_type = ModuleType(
        manufacturer=module_manufacturer,
        model=module_data["model"],
    )
    module_kwargs: dict[str, Any] = {
        "device": device,
        "module_bay": bay,
        "module_type": module_type,
        "serial": blank_to_none(module_data["serial"]),
    }
    if module_data.get("description"):
        module_kwargs["description"] = module_data["description"]
    module = Module(**module_kwargs)
    entities.append(Entity(module=module))
    _bump(
        "modules_emitted", 1,
        {
            "vendor": module_manufacturer.name,
            "type": module_data["type"],
            "identified": "true" if identified else "false",
        },
    )

    # Map interfaces owned by THIS bay (top-level or sub) to this module.
    # Deepest match wins because we walk parent first then sub-bays — a
    # later assignment for a deeper bay overwrites the earlier one.
    # Per-bay value is guarded: a buggy driver returning
    # ``{"1": None}`` (or a string) would otherwise iterate
    # character-by-character or TypeError, and the outer try/except
    # would silently drop this otherwise-valid bay's parent module.
    bay_ifnames = interfaces_by_bay.get(bay_data["name"])
    if bay_ifnames is not None and not isinstance(bay_ifnames, list):
        logger.warning(
            "interfaces_by_bay value ignored: expected list, got %s",
            type(bay_ifnames).__name__,
            extra={"bay": bay_data["name"]},
        )
        bay_ifnames = None
    for ifname in bay_ifnames or []:
        iface_module_map[ifname] = module

    if mode == "linecards":
        # Drop all sub_bays in linecards mode regardless of type. The
        # interfaces that would have routed to those sub-bays stay on
        # the parent linecard module via the assignment loop above.
        return

    for sub_bay in module_data.get("sub_bays", []):
        if not isinstance(sub_bay, dict):
            logger.warning(
                "malformed module sub-bay — skipping (not a dict)",
                extra={"parent_bay": bay_data.get("name"), "sub_bay": repr(sub_bay)[:80]},
            )
            _bump("modules_dropped", 1, {"reason": "malformed"})
            continue
        # Each sub-bay is guarded on its own so a single bad child cannot
        # drop the parent bay/module that the outer loop already emitted.
        try:
            _emit_bay_recursive(
                bay_data=sub_bay,
                device=device,
                mode=mode,
                manufacturer=manufacturer,
                entities=entities,
                iface_module_map=iface_module_map,
                interfaces_by_bay=interfaces_by_bay,
            )
        except Exception:
            logger.warning(
                "malformed module sub-bay — skipping",
                extra={"parent_bay": bay_data.get("name"), "sub_bay": sub_bay.get("name")},
                exc_info=True,
            )
            _bump("modules_dropped", 1, {"reason": "malformed"})
