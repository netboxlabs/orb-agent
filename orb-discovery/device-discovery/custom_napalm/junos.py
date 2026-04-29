# Copyright 2026 NetBox Labs Inc
"""
Juniper Junos NAPALM driver subclass adding ``get_interfaces_vlans()``.

Fetches via PyEZ NETCONF RPC. Targets EX/QFX switching products.
Handles both ELS and non-ELS configuration models. v1 skips voice VLAN
(Junos voip semantics differ from the Cisco family).

XML parsing notes
-----------------
- ``Element.find()`` / ``Element.findall()`` use ElementPath, a simplified
  subset of XPath that does NOT accept arbitrary predicates such as
  ``local-name()``. (Full XPath 1.0 — including ``local-name()`` — is
  available via ``Element.xpath()``, but it's heavier and namespace-aware
  in ways that complicate ELS/non-ELS handling.) We compare
  ``etree.QName(child.tag).localname`` directly instead — namespace-agnostic,
  works on every element lxml can produce, and avoids the XPath dependency
  altogether.
- ELS responses wrap the per-interface list in
  ``<l2ng-l2ald-iff-information>`` and use ``<interface-mode>``.
- Non-ELS responses wrap in ``<ethernet-switching-interface-information>``
  and use ``<interface-port-mode>``.
- Both share the per-``<interface>`` child shape, so the parser only needs
  to recurse into direct ``interface`` children regardless of wrapper.
"""

import logging

from lxml import etree
from napalm.junos.junos import JunOSDriver as NapalmJunOSDriver

from custom_napalm._vlan import SwitchportInfo, classify_switchport

logger = logging.getLogger(__name__)


def _localname(elem) -> str:
    """Return the namespace-stripped local name of an element."""
    return etree.QName(elem.tag).localname


def _find_child(parent, name: str):
    """Find the first direct child whose local-name matches ``name``."""
    if parent is None:
        return None
    for child in parent:
        if _localname(child) == name:
            return child
    return None


def _find_children(parent, name: str) -> list:
    """Return all direct children whose local-name matches ``name``."""
    if parent is None:
        return []
    return [child for child in parent if _localname(child) == name]


def _text(elem) -> str:
    """Return stripped text or empty string."""
    if elem is None or elem.text is None:
        return ""
    return elem.text.strip()


def _maybe_int(s: str) -> int | None:
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


def _interface_to_switchport_info(intf_elem) -> SwitchportInfo:
    """
    Build a SwitchportInfo from one ``<interface>`` element.

    Tolerates both ELS (``<interface-mode>``) and non-ELS
    (``<interface-port-mode>``) shapes — Junos emits one or the other but
    never both, so we read whichever is present.

    VLAN membership is in ``<interface-vlan-member-list>`` containing
    ``<interface-vlan-member>`` entries with
    ``<interface-vlan-member-tagid>`` and
    ``<interface-vlan-member-tagness>`` ("tagged"|"untagged"). Members
    with only a name (no tagid) are dropped with a warning log — VLAN-name
    resolution against ``self.get_vlans()`` is out-of-scope for v1.
    """
    # Mode — read whichever element is present
    mode_text = (
        _text(_find_child(intf_elem, "interface-mode"))
        or _text(_find_child(intf_elem, "interface-port-mode"))
    ).lower()

    if "trunk" in mode_text:
        admin: str | None = "trunk"
    elif "access" in mode_text:
        admin = "access"
    else:
        admin = None

    native_vid = _maybe_int(_text(_find_child(intf_elem, "interface-native-vlan-id")))

    member_list = _find_child(intf_elem, "interface-vlan-member-list")
    members = _find_children(member_list, "interface-vlan-member") if member_list is not None else []

    untagged_vid: int | None = None
    tagged_vids: list[int] = []
    has_all_member = False
    for m in members:
        name = _text(_find_child(m, "interface-vlan-name"))
        if name.lower() == "all":
            has_all_member = True
            continue
        vid = _maybe_int(_text(_find_child(m, "interface-vlan-member-tagid")))
        tagness = _text(_find_child(m, "interface-vlan-member-tagness")).lower()
        if vid is None:
            # Member emitted with only a name (no tagid). v1 doesn't resolve
            # names → IDs via self.get_vlans(); warn so operators see the
            # missing association at default log levels.
            logger.warning(
                "Junos interface-vlan-member %r has no tagid; skipping (name resolution out-of-scope for v1)",
                name,
            )
            continue
        if "untagged" in tagness:
            untagged_vid = vid
        else:
            tagged_vids.append(vid)

    if admin == "trunk":
        allowed: list[int] | str | None = "all" if has_all_member else tagged_vids
        # Native VLAN preferred over untagged-from-membership
        native_resolved = native_vid if native_vid is not None else untagged_vid
        return SwitchportInfo(
            enabled=True,
            admin_mode="trunk",
            oper_mode=None,
            access_vlan=None,
            native_vlan=native_resolved,
            allowed_vlans=allowed,
        )
    if admin == "access":
        return SwitchportInfo(
            enabled=True,
            admin_mode="access",
            oper_mode=None,
            access_vlan=untagged_vid,
            native_vlan=None,
            allowed_vlans=None,
        )

    # No VLAN config at all → routed
    return SwitchportInfo(
        enabled=False,
        admin_mode=None,
        oper_mode=None,
        access_vlan=None,
        native_vlan=None,
        allowed_vlans=None,
    )


class JunOSDriver(NapalmJunOSDriver):
    """Juniper Junos NAPALM driver with VLAN-interface association support."""

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """
        Return per-interface VLAN config (PyEZ NETCONF path).

        Wraps the entire RPC + parse pipeline in try/except — any unexpected
        XML shape returns an empty dict rather than crashing the discovery
        cycle. This deliberately swallows exceptions because Junos releases
        emit subtly-different XML and we'd rather skip VLAN ingest than fail
        the whole device.
        """
        try:
            reply = self.device.rpc.get_ethernet_switching_interface_information()
        except Exception:
            logger.debug("Junos get-ethernet-switching-interface-information failed", exc_info=True)
            return {}

        if reply is None:
            return {}

        # Wrapper element is <ethernet-switching-interface-information> (non-ELS)
        # or <l2ng-l2ald-iff-information> (ELS). Each <interface> child has the
        # same shape regardless of wrapper.
        try:
            result: dict[str, dict] = {}
            for intf in _find_children(reply, "interface"):
                ifname = _text(_find_child(intf, "interface-name"))
                if not ifname:
                    continue
                info = _interface_to_switchport_info(intf)
                result[ifname] = classify_switchport(info)
            return result
        except Exception:
            logger.debug("Junos VLAN XML parse failed", exc_info=True)
            return {}
