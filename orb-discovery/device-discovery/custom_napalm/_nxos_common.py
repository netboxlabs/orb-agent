# Copyright 2026 NetBox Labs Inc
"""
Shared NX-OS field mapper for the nxos (NX-API) and nxos_ssh subclass drivers.

Both drivers ultimately produce the same per-interface row shape — NX-API
emits it as JSON, ntc-templates emits it as a dict from CLI parsing.

Field-name reconciliation
-------------------------
NX-API JSON fields:
    interface, switchport, admin_mode, oper_mode, access_vlan, native_vlan,
    voice_vlan, trunk_vlans

ntc-templates ``cisco_nxos_show_interface_switchport`` template fields
(observed in ntc-templates 7.x as installed in this venv):
    interface, switchport, mode (= operational mode only — admin_mode is NOT
    parsed by the template), access_vlan, access_vlan_name, native_vlan,
    native_vlan_name, trunking_vlans, voice_vlan

The mapper accepts BOTH naming conventions and normalizes them. NX-OS-SSH
rows lack ``admin_mode`` because ``show interface switchport`` does not
print it on every NX-OS release; the operational ``mode`` field is the
only signal available, so we use it as both admin and oper. This is
correct for NX-OS in practice — DTP (the reason IOS distinguishes admin
vs oper) is rarely used on NX-OS, and when it IS used the operational
mode reflects the negotiated state.
"""

from __future__ import annotations

from custom_napalm._vlan import SwitchportInfo, parse_vlan_range_string


def _maybe_int(value: object) -> int | None:
    """
    Coerce to int or None.

    Returns None for the NX-OS sentinels (``None``, empty string, ``"none"``
    / ``"None"`` / ``"NONE"``). Also rejects ``bool`` explicitly — ``bool``
    is a subclass of ``int`` in Python (``int(True) == 1``), so without the
    guard a buggy upstream parser passing a bool would slip past the
    classifier's bool-rejection in ``_vlan.coerce_vid``.
    """
    if isinstance(value, bool):
        return None
    if value in (None, "", "none", "None", "NONE"):
        return None
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _normalize_admin(value: str) -> str | None:
    """Normalize a raw admin-mode string to 'access', 'trunk', 'dynamic', or None."""
    raw = (value or "").lower()
    if "access" in raw:
        return "access"
    if "trunk" in raw:
        return "trunk"
    if "dynamic" in raw:
        return "dynamic"
    return None


def _normalize_oper(value: str) -> str | None:
    """Normalize a raw oper-mode string to 'access', 'trunk', 'routed', or None."""
    raw = (value or "").lower()
    if "access" in raw:
        return "access"
    if "trunk" in raw:
        return "trunk"
    if "routed" in raw:
        return "routed"
    return None


def _read_admin_mode(row: dict) -> str:
    """Return raw admin_mode string, falling back to ``mode`` (ntc-templates alias)."""
    return row.get("admin_mode") or row.get("mode") or ""


def _read_oper_mode(row: dict) -> str:
    """Return raw oper_mode string, falling back to ``mode`` (ntc-templates alias)."""
    return row.get("oper_mode") or row.get("mode") or ""


def _read_trunk_vlans(row: dict) -> str:
    """Return raw trunk_vlans, accepting NX-API key ``trunk_vlans`` or ntc alias ``trunking_vlans``."""
    return row.get("trunk_vlans") or row.get("trunking_vlans") or ""


def nxos_row_to_switchport_info(row: dict) -> SwitchportInfo:
    """
    Build a SwitchportInfo from a normalized NX-OS row dict.

    Accepts BOTH NX-API (JSON) and ntc-templates (CLI-parsed) shapes::

        NX-API:     {"interface", "switchport", "admin_mode", "oper_mode",
                     "access_vlan", "native_vlan", "voice_vlan", "trunk_vlans"}
        ntc:        {"interface", "switchport", "mode",
                     "access_vlan", "native_vlan", "voice_vlan", "trunking_vlans"}

    NX-API uses "Enabled"/"Disabled" for ``switchport``; ntc-templates may
    emit "Enabled"/"Disabled" or other casing. Both are tolerated.

    When ntc-templates rows lack a separate ``admin_mode``, the ``mode``
    field (operational) is used as both admin AND oper signals — which
    keeps DTP-fallback correctness on the rare NX-OS deployment that
    actually negotiates DTP, and is exactly equivalent to "admin = oper"
    on the common case where DTP is disabled.
    """
    if (row.get("switchport") or "").lower() == "disabled":
        return SwitchportInfo(
            enabled=False, admin_mode=None, oper_mode=None,
            access_vlan=None, native_vlan=None, allowed_vlans=None,
        )

    trunk_vlans_raw = _read_trunk_vlans(row)
    if trunk_vlans_raw:
        vids, is_wildcard = parse_vlan_range_string(trunk_vlans_raw)
        allowed: list[int] | str | None = "all" if is_wildcard else vids
    else:
        allowed = None

    admin = _normalize_admin(_read_admin_mode(row))
    oper = _normalize_oper(_read_oper_mode(row))

    # NX-OS SSH oper-down inference.
    #
    # ntc-templates' ``cisco_nxos_show_interface_switchport`` parser does NOT
    # capture the ``Administrative Mode`` line — only ``Operational Mode``.
    # Both ``_read_admin_mode`` and ``_read_oper_mode`` therefore fall back
    # to the same ``mode`` field, and a down link reports ``mode: down`` →
    # both normalize to ``None`` → ``classify_switchport`` would emit
    # ``routed``, dropping the configured VLAN data on every disconnected
    # interface at collection time.
    #
    # Default ``admin`` to ``"access"`` when ``Switchport: Enabled`` and
    # neither admin nor oper resolves to a known mode. Access is the
    # most common default for an enabled switchport with no other signal,
    # and the access_vlan field is still populated by NX-OS even on down
    # ports. Trunks that happen to be down are misclassified as access
    # using their trunk's access_vlan field (typically VID 1) — corrected
    # automatically on the next discovery cycle once the link is up.
    # NX-API rows are unaffected because they emit ``admin_mode`` and
    # ``oper_mode`` separately, so ``admin`` is non-None and this branch
    # does not fire.
    if admin is None and oper is None:
        admin = "access"

    return SwitchportInfo(
        enabled=True,
        admin_mode=admin,  # type: ignore[arg-type]
        oper_mode=oper,    # type: ignore[arg-type]
        access_vlan=_maybe_int(row.get("access_vlan")),
        native_vlan=_maybe_int(row.get("native_vlan")),
        allowed_vlans=allowed,
        voice_vlan=_maybe_int(row.get("voice_vlan")),
    )
