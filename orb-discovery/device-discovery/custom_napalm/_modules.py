# Copyright 2026 NetBox Labs Inc
"""
Generic, vendor-neutral helper for modular-chassis module / module-bay discovery.

Each driver's optional ``get_modules()`` returns a single canonical envelope
keyed by member id. Standalone modular chassis use one bucket keyed ``None``;
virtual-chassis-of-modular deployments use one bucket per validated member id.

Envelope shape::

    {
        "members": {
            member_id_or_None: {
                "bays": [
                    {
                        "name": "1", "position": "1",
                        "module": {
                            "model": "...", "serial": "...",
                            "description": "...", "type": "linecard",
                            "sub_bays": [...],            # recursive, depth-3 cap
                        },
                    },
                    ...
                ],
                "interfaces_by_bay": {"1": ["Te1/0/1", ...]},
            },
            ...
        },
    }

Returning ``None`` (no surviving member) signals the translate layer to keep
the existing single-Device path. The helper never raises on data shape — bad
rows are warn-dropped, matching the forgiving behavior of ``_chassis.py``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Literal

logger = logging.getLogger(__name__)


ModuleType = Literal["linecard", "supervisor", "fan", "psu", "transceiver"]
_VALID_TYPES: frozenset[str] = frozenset(
    {"linecard", "supervisor", "fan", "psu", "transceiver"}
)

#: Hard depth cap for recursive sub-bay nesting. Cisco modular chassis are
#: depth 2 (chassis → linecard → transceiver); Junos is depth 3 (chassis
#: → FPC → PIC → transceiver). Anything deeper is rejected with a warning.
MAX_BAY_DEPTH = 3


@dataclass
class ModuleEntry:
    """One physical module installed in a bay."""

    model: str
    serial: str
    type: ModuleType
    description: str = ""
    sub_bays: list[ModuleBay] = field(default_factory=list)


@dataclass
class ModuleBay:
    """
    One slot in a chassis (or in a parent module) that holds a Module.

    Empty bays (``module is None``) are not emitted — operators wanting
    empty-bay layouts pre-populate via the devicetype-library templates.
    """

    name: str
    position: str
    module: ModuleEntry | None


def orphan_optic_bay(ifname: str, optic: ModuleEntry) -> ModuleBay:
    """
    A transceiver with no parent module, as a device-rooted bay.

    Fixed-port platforms report optics with no slot, linecard or FRU module
    above them. A bay rooted on the device is the accurate representation
    there rather than a workaround, because no parent module exists to nest
    under. The emitted result is identical to an optic sub-bay: translate
    emits sub-bays device-rooted too, stripping the parent link.

    Callers own their own bay container and their own interface self-route;
    the containers differ too much between drivers to share. This exists so
    the contract is stated once and every promotion site is greppable.
    """
    return ModuleBay(name=ifname, position=ifname, module=optic)


@dataclass
class MemberModules:
    """Per-member bundle: the bays installed in this member and how to route ifnames into them."""

    bays: list[ModuleBay]
    interfaces_by_bay: dict[str, list[str]] = field(default_factory=dict)


# ---- vendor-neutral optic recognition --------------------------------------
#
# MSA / SFF prefixes are industry-standardized — they're the same across
# Cisco, Arista, Juniper, Nokia, etc. Linecard / supervisor / fan / psu
# PID prefixes are vendor-specific and live in each driver's private
# classifier (see ios.py, eos.py, junos.py, nxos.py, nxos_ssh.py).


_OPTIC_PREFIXES = (
    "SFP-",
    "SFP+",
    "SFP28-",
    "SFP56-",
    "QSFP-",
    "QSFP+",
    "QSFP28",
    "QSFP56-",
    "QSFP-DD",
    "QDD-",  # Cisco 400G QSFP-DD optics (QDD-400G-DR4-S) — not a QSFP-DD literal prefix
    "OSFP-",
    "GLC-",
    "X2-",
    "CFP-",
    "CFP2-",
    "XENPAK-",
    "XFP-",
    "CVR-",
)


def is_optic_pid(pid: str) -> bool:
    """
    Return True when ``pid`` starts with a standardized optic PID prefix.

    Recognizes MSA/SFF transceiver designators that are shared across
    every vendor. Driver classifiers should call this first; only if it
    returns False should they consult vendor-specific linecard /
    supervisor / chassis prefixes.
    """
    if not pid or not pid.strip():
        return False
    return pid.strip().upper().startswith(_OPTIC_PREFIXES)


# ---- payload assembly ----------------------------------------------------


def to_payload(members: dict[int | None, MemberModules]) -> dict | None:
    """
    Validate and serialize a per-member envelope. Returns None if no member survives.

    Each member's bays are independently validated (serial / type / depth-3
    cap). A member whose every bay is dropped is itself dropped from the
    result. When every member drops, returns None — the driver passes that
    straight through.
    """
    out_members: dict[int | None, dict] = {}
    for member_id, payload in members.items():
        validated = [b for b in (_validate_bay(bay, depth=1) for bay in payload.bays) if b]
        if not validated:
            continue
        cleaned_ifaces = _validate_interfaces_by_bay(payload.interfaces_by_bay or {})
        out_members[member_id] = {
            "bays": validated,
            "interfaces_by_bay": cleaned_ifaces,
        }
    if not out_members:
        return None
    return {"members": out_members}


def _validate_bay(bay: ModuleBay, *, depth: int) -> dict | None:
    """Recursively validate one ModuleBay. Returns serialized dict or None."""
    if depth > MAX_BAY_DEPTH:
        logger.warning(
            "module bay dropped: nested deeper than depth %d",
            MAX_BAY_DEPTH,
            extra={"bay_name": bay.name, "depth": depth},
        )
        return None
    if bay.module is None:
        logger.warning("module bay dropped: empty bay", extra={"bay_name": bay.name})
        return None
    serial = (bay.module.serial or "").strip()
    if not serial:
        logger.warning("module bay dropped: empty serial", extra={"bay_name": bay.name})
        return None
    if bay.module.type not in _VALID_TYPES:
        logger.warning(
            "module bay dropped: invalid type %r",
            bay.module.type,
            extra={"bay_name": bay.name},
        )
        return None
    sub_bays: list[dict] = []
    for sub in bay.module.sub_bays:
        validated_sub = _validate_bay(sub, depth=depth + 1)
        if validated_sub is not None:
            sub_bays.append(validated_sub)
    return {
        "name": bay.name,
        "position": bay.position,
        "module": {
            "model": bay.module.model,
            "serial": serial,
            "description": bay.module.description,
            "type": bay.module.type,
            "sub_bays": sub_bays,
        },
    }


def _validate_interfaces_by_bay(
    interfaces_by_bay: dict[str, list[str]],
) -> dict[str, list[str]]:
    """
    Dedupe ifnames within each bay; warn-drop non-list values and non-string entries.

    The 4-tuple ifname rejection that lived here in the standalone-only
    revision is removed — SVL deployments emit ifnames like
    ``HundredGigE1/2/0/1`` whose leading integer is the member id, and
    those are valid input now. Translator-side routing parses the member
    id at emission time.
    """
    cleaned: dict[str, list[str]] = {}
    for bay_name, ifnames in interfaces_by_bay.items():
        if not isinstance(ifnames, list):
            logger.warning(
                "interfaces_by_bay value dropped: expected list, got %s",
                type(ifnames).__name__,
                extra={"bay_name": bay_name},
            )
            cleaned[bay_name] = []
            continue
        seen: set[str] = set()
        keep: list[str] = []
        for name in ifnames:
            if not isinstance(name, str):
                logger.warning(
                    "interfaces_by_bay entry dropped: non-string ifname",
                    extra={"bay_name": bay_name, "ifname": repr(name)[:80]},
                )
                continue
            if name in seen:
                continue
            seen.add(name)
            keep.append(name)
        cleaned[bay_name] = keep
    return cleaned
