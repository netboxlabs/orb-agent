# Copyright 2026 NetBox Labs Inc
"""
Generic, vendor-neutral interface↔VLAN classifier for custom NAPALM drivers.

Each driver's ``get_interfaces_vlans()`` extracts native fields per interface,
builds a :class:`SwitchportInfo`, and calls :func:`classify_switchport`. The
classifier is the only place that encodes voice-VLAN promotion, DTP fallback,
wildcard handling, VID range clamping, and the routed/access/trunk/trunk-all
output enum consumed by ``device_discovery.translate.apply_interface_vlans``.

Output shape (per interface)::

    {
        "mode":     "access" | "trunk" | "trunk-all" | "routed",
        "tagged":   list[int],          # VIDs in 1..4094, never the untagged VID
        "untagged": int | None,         # VID in 1..4094, or None when no valid VID
    }

NetBox mapping is owned by ``device_discovery.translate``:
``access`` → ``access``, ``trunk`` → ``tagged``, ``trunk-all`` → ``tagged-all``,
``routed`` → ``null`` (no NetBox change applied).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass
class SwitchportInfo:
    """Vendor-neutral normalized intermediate. One per interface."""

    enabled: bool
    admin_mode: Literal["access", "trunk", "dynamic"] | None
    oper_mode: Literal["access", "trunk", "routed"] | None
    access_vlan: int | None
    native_vlan: int | None
    allowed_vlans: list[int] | Literal["all"] | None
    voice_vlan: int | None = None


def coerce_vid(value: object) -> int | None:
    """Coerce a value to an int in [1, 4094]. Reject bools (subclass of int)."""
    if isinstance(value, bool):
        return None
    if not isinstance(value, (int, str)):
        return None
    try:
        v = int(value)
    except ValueError:
        return None
    return v if 1 <= v <= 4094 else None


def _is_full_vlan_range(vids: list[int]) -> bool:
    """Return True iff ``vids`` covers the full 1..4094 dot1q range."""
    return (
        bool(vids)
        and min(vids) <= 1
        and max(vids) >= 4094
        and len(set(vids)) >= 4094
    )


def _expand_range_chunk(chunk: str) -> list[int]:
    """Expand one range or single VID chunk into a list of VIDs (clamped to 1..4094)."""
    chunk = chunk.strip()
    if not chunk:
        return []
    if "-" in chunk:
        lo_s, hi_s = chunk.split("-", 1)
        try:
            lo, hi = int(lo_s), int(hi_s)
        except ValueError:
            return []
        lo = max(lo, 1)
        hi = min(hi, 4094)
        if lo > hi:
            return []
        return list(range(lo, hi + 1))
    try:
        return [int(chunk)]
    except ValueError:
        return []


def parse_vlan_range_string(spec: str) -> tuple[list[int], bool]:
    """
    Expand a comma-separated VLAN list/range spec into ``(vids, is_wildcard)``.

    Examples::

        "1,10-12,20"   → ([1, 10, 11, 12, 20], False)
        "all" / "ALL"  → ([], True)        # genuine wildcard
        "1-4094"       → ([], True)        # full-range expansion → wildcard
        "none"         → ([], False)
        ""             → ([], False)
        "5000-9000"    → ([], False)       # clamped out, NOT a wildcard
        "junk,10"      → ([10], False)     # junk dropped, valid kept

    Callers MUST NOT treat the ``([], False)`` return as a wildcard — that path
    is reached by empty input AND by all-junk input. Promotion to ``trunk-all``
    only happens when ``is_wildcard`` is True.
    """
    if not spec:
        return [], False
    raw = spec.strip().lower()
    if raw == "all":
        return [], True
    if raw == "none":
        return [], False

    out: list[int] = []
    for chunk in spec.split(","):
        out.extend(_expand_range_chunk(chunk))

    out = [v for v in out if 1 <= v <= 4094]
    if _is_full_vlan_range(out):
        return [], True
    return out, False


def _resolve_effective_mode(info: SwitchportInfo) -> Literal["access", "trunk"] | None:
    """
    Decide which mode to use, resolving DTP-negotiated ports via oper_mode.

    Returns None to signal "routed/unknown"; classify_switchport converts
    that to a routed entry.
    """
    if not info.enabled:
        return None
    admin = info.admin_mode
    if admin in ("access", "trunk"):
        return admin
    # dynamic / None — fall back to oper_mode
    oper = info.oper_mode
    if oper in ("access", "trunk"):
        return oper
    return None  # routed / unknown


def _normalize_allowed(
    allowed: list[int] | str | None,
) -> tuple[list[int], bool]:
    """
    Normalize a SwitchportInfo.allowed_vlans value into ``(vids, is_wildcard)``.

    Accepts the literal ``"all"`` token (case-insensitive), a list of ints
    (with bool/oob entries dropped), or None. List input is clamped to 1..4094
    and de-booled. Empty list → ([], False) — NOT a wildcard.
    """
    if allowed is None:
        return [], False
    if isinstance(allowed, str):
        if allowed.strip().lower() == "all":
            return [], True
        # any other string is treated as a comma-separated spec
        return parse_vlan_range_string(allowed)
    if isinstance(allowed, list):
        cleaned = [coerce_vid(v) for v in allowed]
        out = [v for v in cleaned if v is not None]
        return ([], True) if _is_full_vlan_range(out) else (out, False)
    return [], False


def classify_switchport(info: SwitchportInfo) -> dict:
    """
    Map a SwitchportInfo to a switchport entry dict.

    See module docstring for output shape and NetBox mapping.
    """
    effective = _resolve_effective_mode(info)
    if effective is None:
        return {"mode": "routed", "tagged": [], "untagged": None}

    if effective == "access":
        access = coerce_vid(info.access_vlan)
        voice = coerce_vid(info.voice_vlan)
        if voice is not None and voice != access:
            # Voice-VLAN promotion: NetBox 'access' mode disallows tagged
            # VLANs. Promote to trunk with the voice VLAN tagged + access
            # as untagged. When voice == access (operator misconfig) keep
            # plain access.
            return {"mode": "trunk", "tagged": [voice], "untagged": access}
        return {"mode": "access", "tagged": [], "untagged": access}

    # effective == "trunk"
    native = coerce_vid(info.native_vlan)
    vids, is_wildcard = _normalize_allowed(info.allowed_vlans)
    if is_wildcard:
        return {"mode": "trunk-all", "tagged": [], "untagged": native}
    tagged = [v for v in vids if v != native]
    return {"mode": "trunk", "tagged": tagged, "untagged": native}
