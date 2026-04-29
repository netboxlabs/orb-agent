# Copyright 2026 NetBox Labs Inc
"""IOS NAPALM driver subclass adding get_interfaces_vlans()."""

import logging

from napalm.base.helpers import canonical_interface_name
from napalm.ios.ios import IOSDriver as NapalmIOSDriver
from ntc_templates.parse import parse_output

logger = logging.getLogger(__name__)


def _expand_ios_vlan_list(items: list[str]) -> tuple[list[int], bool]:
    """
    Expand ntc-templates trunking_vlans list into ``(vids, is_wildcard)``.

    Each item is a digit ("10"), a range ("20-30"), "ALL", or "NONE".
    Returns ``([], True)`` for genuine wildcards (literal ``ALL`` or any
    expansion that covers the full 1-4094 dot1q range). Returns
    ``([...], False)`` for explicit lists, ``([], False)`` for empty/NONE
    input, and ``([], False)`` for unparseable input — callers must NOT
    treat the False-with-empty-list case as a wildcard, since that path
    can be entered by junk tokens (e.g. "5000-9000" clamped out, "junk"
    failing int()).
    """
    if not items:
        return [], False
    has_explicit_all = any((tok or "").strip().upper() == "ALL" for tok in items)
    out: list[int] = []
    for item in items:
        token = (item or "").strip().upper()
        if not token or token in {"ALL", "NONE"}:
            continue
        if "-" in token:
            lo_s, hi_s = token.split("-", 1)
            try:
                lo, hi = int(lo_s), int(hi_s)
            except ValueError:
                continue
            lo = max(lo, 1)
            hi = min(hi, 4094)
            if lo > hi:
                continue
            out.extend(range(lo, hi + 1))
        else:
            try:
                out.append(int(token))
            except ValueError:
                continue
    out = [v for v in out if 1 <= v <= 4094]
    is_full_range = (
        bool(out) and min(out) <= 1 and max(out) >= 4094 and len(set(out)) >= 4094
    )
    if has_explicit_all or is_full_range:
        return [], True
    return out, False


def _classify_ios_trunk(raw_trunking: list, native_vid: int | None) -> dict:
    """
    Classify the trunking_vlans portion of a trunk row into the jobec shape.

    Returns the appropriate mode (``trunk`` / ``trunk-all``) based on the
    typed wildcard signal from :func:`_expand_ios_vlan_list`. Logs a
    warning when a non-empty, non-NONE input parses to an empty list
    (likely malformed input), but does NOT promote to ``trunk-all`` in
    that case — bad CLI rows yield a plain trunk with no tagged VLANs.
    """
    expanded, is_wildcard = _expand_ios_vlan_list(raw_trunking)
    if is_wildcard:
        return {"mode": "trunk-all", "tagged": [], "untagged": native_vid}
    has_input = any((tok or "").strip() for tok in (raw_trunking or []))
    has_none = any((tok or "").strip().upper() == "NONE" for tok in (raw_trunking or []))
    if has_input and not has_none and not expanded:
        logger.warning(
            "trunking_vlans=%r could not be parsed; "
            "treating as plain trunk with no tagged VLANs",
            raw_trunking,
        )
    if native_vid is not None:
        expanded = [v for v in expanded if v != native_vid]
    return {"mode": "trunk", "tagged": expanded, "untagged": native_vid}


def _classify_ios_switchport_row(row: dict) -> dict:
    """
    Map one ntc-templates parsed row to NAPALM #919 jobec shape.

    Returns ``{"mode": "access"|"trunk"|"trunk-all"|"routed",
    "tagged": list[int], "untagged": int | None}``.

    Voice-VLAN promotion: an access port with a configured voice VLAN is
    reported as ``mode=trunk, untagged=access_vid, tagged=[voice_vid]``
    because NetBox's ``access`` mode disallows tagged VLANs.

    DTP-negotiated ports (admin_mode = "dynamic auto" / "dynamic desirable")
    fall back to operational ``mode`` for classification, since the admin
    string itself contains neither "access" nor "trunk".
    """
    switchport = (row.get("switchport") or "").lower()
    admin_mode = (row.get("admin_mode") or "").lower()
    oper_mode = (row.get("mode") or "").lower()

    if "disabled" in switchport:
        return {"mode": "routed", "tagged": [], "untagged": None}

    # Pick the most useful mode signal. Admin tells us the user's intent;
    # operational tells us what the port actually negotiated to. For DTP
    # modes ("dynamic auto", "dynamic desirable") admin_mode is unhelpful,
    # so fall back to oper_mode. If both are empty, treat as routed.
    effective = admin_mode if (
        "access" in admin_mode or "trunk" in admin_mode
    ) else oper_mode

    if not effective or "routed" in effective:
        return {"mode": "routed", "tagged": [], "untagged": None}

    def _to_int(value: str) -> int | None:
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    access_vid = _to_int(row.get("access_vlan", ""))
    native_vid = _to_int(row.get("native_vlan", ""))
    voice_vid = _to_int(row.get("voice_vlan", ""))

    if "access" in effective:
        # Voice-VLAN promotion: an access port with a *distinct* voice VLAN
        # is reported as mode=trunk with the voice VLAN tagged. NetBox's
        # `access` mode disallows tagged VLANs. When voice_vid equals
        # access_vid (operator misconfiguration or coincidence), keep the
        # interface as plain access — promoting would produce mode=tagged
        # with an empty tagged list after the translator's defensive
        # native-stripped-from-tagged filter.
        if voice_vid and voice_vid != access_vid:
            return {
                "mode": "trunk",
                "tagged": [voice_vid],
                "untagged": access_vid,
            }
        return {
            "mode": "access",
            "tagged": [],
            "untagged": access_vid,
        }
    if "trunk" in effective:
        return _classify_ios_trunk(row.get("trunking_vlans") or [], native_vid)
    return {"mode": "routed", "tagged": [], "untagged": None}


class IOSDriver(NapalmIOSDriver):
    """Cisco IOS NAPALM driver with VLAN-interface association support."""

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """
        Return per-interface VLAN config (NAPALM #919 jobec shape).

        Parses ``show interfaces switchport`` via ntc-templates.
        """
        output = self._send_command("show interfaces switchport")
        if not output:
            return {}

        try:
            rows = parse_output(
                platform="cisco_ios",
                command="show interfaces switchport",
                data=output,
            )
        except Exception:
            logger.debug(
                "ntc-templates failed to parse 'show interfaces switchport'",
                exc_info=True,
            )
            return {}

        result: dict[str, dict] = {}
        for row in rows or []:
            ifname = row.get("interface")
            if not ifname:
                continue
            # Always canonicalize: NAPALM IOS's default get_interfaces() returns
            # long-form names (GigabitEthernet1/0/1) parsed from `show interfaces`,
            # but `show interfaces switchport` emits short-form (Gi1/0/1). Without
            # this, apply_interface_vlans()'s exact-name match silently misses
            # associations in the common default configuration.
            ifname = canonical_interface_name(ifname)
            result[ifname] = _classify_ios_switchport_row(row)
        return result
