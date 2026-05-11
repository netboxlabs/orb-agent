# Copyright 2026 NetBox Labs Inc
"""
Juniper Junos NAPALM driver subclass.

Adds two optional extension methods on top of upstream NAPALM Junos:

- ``get_interfaces_vlans()``: per-interface VLAN classification from the
  ``<get-ethernet-switching-interface-information>`` RPC, tolerating both
  ELS and non-ELS XML wrappers. v1 skips voice VLAN (Junos voip semantics
  differ from the Cisco family).
- ``get_chassis_members()``: Virtual Chassis topology from the
  ``<get-virtual-chassis-information>`` RPC, returning the vendor-neutral
  payload consumed by ``device_discovery.translate_chassis``. Standalone
  EX/QFX devices (no VC configured) return ``None``.

Both fetch via PyEZ NETCONF RPC and target EX / QFX switching products.

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

from jnpr.junos.exception import RpcError
from lxml import etree
from napalm.junos.junos import JunOSDriver as NapalmJunOSDriver

from custom_napalm._chassis import ChassisMember, normalize_role, to_payload
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


def _junos_get_chassis_members_impl(driver) -> dict | None:
    """
    Implementation of JunOSDriver.get_chassis_members (factored for testability).

    Junos exposes Virtual Chassis topology via the
    ``<get-virtual-chassis-information>`` RPC. The reply shape is::

        <virtual-chassis-information>
          <member-list>
            <member>
              <member-id>0</member-id>
              <member-status>Prsnt</member-status>
              <member-model>EX4300-48T</member-model>
              <member-serial-number>PE3714410232</member-serial-number>
              <member-mac-address>2c:6b:f5:a8:33:c0</member-mac-address>
              <member-priority>129</member-priority>
              <member-role>Master*</member-role>
            </member>
            ...
          </member-list>
        </virtual-chassis-information>

    Standalone EX/QFX (no VC configured) raises ``RpcError`` or returns no
    members; both produce ``None`` so translate falls through to the
    single-Device path. ``NotPrsnt`` slots are filtered out before
    ``to_payload`` so empty stack positions don't pollute the payload.

    Logging policy: ``RpcError`` is the *expected* signal that the device
    is not in VC mode, so it is logged at DEBUG only — otherwise every
    standalone Junos device would emit a WARNING per discovery cycle.
    Any other exception is unexpected and stays at WARNING so operators
    see real driver / transport problems.
    """
    try:
        reply = driver.device.rpc.get_virtual_chassis_information()
    except RpcError as e:
        logger.debug("junos.get_chassis_members: RPC not supported (likely standalone, not in VC mode): %s", e)
        return None
    except Exception as e:
        # exc_info=True so the traceback survives — without it operators
        # only see the exception string, which is rarely enough to root-cause
        # transport / PyEZ failures.
        logger.warning(
            "junos.get_chassis_members: unexpected RPC failure: %s", e, exc_info=True,
        )
        return None

    if reply is None:
        return None

    # Some Junos releases wrap members under <member-list>; older releases emit
    # <member> directly under <virtual-chassis-information>. Try both.
    member_list = _find_child(reply, "member-list")
    members_xml = (
        _find_children(member_list, "member") if member_list is not None
        else _find_children(reply, "member")
    )

    if not members_xml:
        return None

    members: list[ChassisMember] = []
    for m in members_xml:
        mid = _maybe_int(_text(_find_child(m, "member-id")))
        if mid is None:
            continue

        # Skip absent slots — Junos can list reserved member ids as NotPrsnt.
        status = _text(_find_child(m, "member-status"))
        if status and "notprsnt" in status.lower().replace("-", ""):
            continue

        # Role often comes with a trailing asterisk on the active master ("Master*").
        # Strip it so normalize_role's lookup ("master" → "active") works.
        raw_role = _text(_find_child(m, "member-role")).rstrip("*").strip()

        members.append(
            ChassisMember(
                id=mid,
                serial=_text(_find_child(m, "member-serial-number")),
                model=_text(_find_child(m, "member-model")) or None,
                role=normalize_role(raw_role),
                priority=_maybe_int(_text(_find_child(m, "member-priority"))),
                mac=_text(_find_child(m, "member-mac-address")) or None,
                state=status or None,
            )
        )

    return to_payload(members, domain=None)


class JunOSDriver(NapalmJunOSDriver):
    """
    Juniper Junos NAPALM driver.

    Adds two optional extension methods on top of the upstream NAPALM driver:

    - ``get_interfaces_vlans()``: per-interface VLAN classification from the
      ``<get-ethernet-switching-interface-information>`` RPC, tolerating
      both ELS and non-ELS XML wrappers.
    - ``get_chassis_members()``: Virtual Chassis topology from the
      ``<get-virtual-chassis-information>`` RPC, returning the vendor-
      neutral payload consumed by ``device_discovery.translate_chassis``.
    """

    def get_chassis_members(self) -> dict | None:
        """
        Return Junos Virtual Chassis member info (EX/QFX).

        Standalone (non-VC) EX/QFX returns None; VC of N populated members
        returns the payload shape consumed by translate's VC emission path.
        """
        return _junos_get_chassis_members_impl(self)

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
