# Copyright 2026 NetBox Labs Inc
"""
Juniper Junos NAPALM driver subclass.

Adds three optional extension methods on top of upstream NAPALM Junos:

- ``get_interfaces_vlans()``: per-interface VLAN classification from the
  ``<get-ethernet-switching-interface-information>`` RPC, tolerating both
  ELS and non-ELS XML wrappers. v1 skips voice VLAN (Junos voip semantics
  differ from the Cisco family).
- ``get_chassis_members()``: Virtual Chassis topology from the
  ``<get-virtual-chassis-information>`` RPC, returning the vendor-neutral
  payload consumed by ``device_discovery.translate_chassis``. Standalone
  EX/QFX devices (no VC configured) return ``None``.
- ``get_modules()``: Module / module-bay discovery for Junos modular
  chassis + VC-of-modular.

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
import re
from ipaddress import ip_address

from jnpr.junos.exception import RpcError
from lxml import etree
from napalm.junos.junos import JunOSDriver as NapalmJunOSDriver

from custom_napalm._chassis import ChassisMember, normalize_role, to_payload
from custom_napalm._modules import (
    MemberModules as _MemberModules,
)
from custom_napalm._modules import (
    ModuleBay as _ModuleBay,
)
from custom_napalm._modules import (
    ModuleEntry as _ModuleEntry,
)
from custom_napalm._modules import (
    is_optic_pid,
)
from custom_napalm._modules import (
    to_payload as _modules_to_payload,
)
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


def classify_module_type_junos(part_number: str, description: str, name: str = "") -> str:
    """
    Map a Junos chassis-inventory row to a ModuleType.

    Optic signal is the element NAME (Junos reports transceivers as
    "Xcvr N" leaf elements) plus MSA part-number prefixes — NOT the
    description, because FPC/PIC descriptions advertise port capabilities
    ("48x SFP/SFP+ ports", "4x 40GE QSFP+") that would false-match an
    SFP/QSFP keyword check and drop the linecard bay in linecards mode.
    Routing Engine descriptions map to supervisor (Junos uses RE rather
    than "supervisor" terminology). PSU / fan are classified so they don't
    fall through to ``linecard``, but are filtered upstream and never reach
    Diode emission.
    """
    if is_optic_pid(part_number):
        return "transceiver"
    if name.strip().lower().startswith("xcvr"):
        return "transceiver"
    # Name-based RE detection (robust against terse/absent descriptions),
    # consistent with Xcvr name-gating; description check stays as fallback.
    if name.strip().lower().startswith("routing engine"):
        return "supervisor"
    descr_lower = (description or "").lower()
    if "routing engine" in descr_lower or descr_lower.startswith("re-"):
        return "supervisor"
    if "power supply" in descr_lower or "psu" in descr_lower:
        return "psu"
    if "fan" in descr_lower:
        return "fan"
    return "linecard"


def _junos_extract_module_from_elem(elem) -> _ModuleEntry | None:
    """
    Build a ModuleEntry from a chassis-module / sub-module / sub-sub element.

    Returns None when the element has no part-number AND no serial-number
    (Junos sometimes reports placeholder entries with both fields empty).
    """
    name = _text(_find_child(elem, "name")).strip()
    part = _text(_find_child(elem, "part-number")).strip()
    serial = _text(_find_child(elem, "serial-number")).strip()
    descr = _text(_find_child(elem, "description")).strip()
    if not (part and serial):
        return None
    mtype = classify_module_type_junos(part, descr, name)
    if mtype in ("psu", "fan"):
        return None  # filtered — not emitted
    return _ModuleEntry(model=part, serial=serial, type=mtype, description=descr)


def _junos_optic_bay_name(
    position: str,
    *,
    fpc: int | None,
    pic: int | None,
    coord_to_ifname: dict[tuple[int, int, int], str],
    self_routes: list[tuple[int, str]],
) -> str:
    """
    Name an Xcvr sub-bay by its canonical ifname when correlated, else "Xcvr N".

    The (fpc,pic,port) coordinate is matched against the ``show interfaces
    terse`` rows. The translator looks up ``interfaces_by_bay[bay.name]`` — there is never
    an ``"Xcvr N"`` entry (and it would be ambiguous across PICs anyway), so
    a transceiver named ``"Xcvr 0"`` never receives its interface in full
    mode. Naming the sub-bay by the canonical ifname + self-routing it lets
    the translator's deepest-wins logic link the interface to the optic —
    parity with the eos/nxos drivers. When no terse row matches (port not in
    terse output), keep ``"Xcvr N"`` and do NOT self-route.

    Records ``(fpc, ifname)`` in ``self_routes`` so the caller can route the
    self-route into the member that owns that FPC (preserving VC offset-FPC
    member mapping).
    """
    port = _maybe_int(position)
    if fpc is None or pic is None or port is None:
        return f"Xcvr {position}"
    ifname = coord_to_ifname.get((fpc, pic, port))
    if not ifname:
        return f"Xcvr {position}"
    self_routes.append((fpc, ifname))
    return ifname


def _junos_walk_sub_bays(
    parent_elem,
    *,
    depth: int,
    fpc: int | None,
    pic: int | None,
    coord_to_ifname: dict[tuple[int, int, int], str],
    self_routes: list[tuple[int, str]],
) -> list[_ModuleBay]:
    """
    Recurse into chassis-sub-module / chassis-sub-sub-module children.

    Threads FPC + PIC context and the (fpc,pic,port)→ifname map so each Xcvr
    can name its sub-bay by the canonical ifname (see _junos_optic_bay_name).
    At depth 2 the child is a PIC (parse its position into ``pic``); at depth
    3 it is an Xcvr (the leaf optic).
    """
    if depth > 3:
        return []
    tag = "chassis-sub-module" if depth == 2 else "chassis-sub-sub-module"
    out: list[_ModuleBay] = []
    for child in _find_children(parent_elem, tag):
        name = _text(_find_child(child, "name")).strip()
        if not name:
            continue
        # PIC N / Xcvr N — position is the trailing integer.
        position = name.split()[-1] if name.split() else name
        # At depth 2 this child is a PIC: parse its slot so the optic leaf
        # below knows its (fpc,pic,port) coordinate.
        child_pic = _maybe_int(position) if depth == 2 else pic
        module = _junos_extract_module_from_elem(child)
        if module is None:
            # Serial-less intermediate container (e.g. a built-in PIC/MIC
            # with a part-number but empty serial): _validate_bay would drop
            # it anyway, but its optic CHILDREN do have serials. Recurse and
            # HOIST those children to the nearest emittable ancestor (the FPC)
            # rather than dropping the whole subtree. A serial-less LEAF (no
            # recursable children) stays skipped. Hoisting up a level keeps
            # the optics within MAX_BAY_DEPTH.
            hoisted = _junos_walk_sub_bays(
                child, depth=depth + 1, fpc=fpc, pic=child_pic,
                coord_to_ifname=coord_to_ifname, self_routes=self_routes,
            )
            if hoisted:
                out.extend(hoisted)
            continue
        module.sub_bays = _junos_walk_sub_bays(
            child, depth=depth + 1, fpc=fpc, pic=child_pic,
            coord_to_ifname=coord_to_ifname, self_routes=self_routes,
        )
        # At depth 3 the child is the Xcvr optic — name it by canonical ifname
        # when its coordinate correlates to a terse row (self-routed there).
        if depth == 3:
            bay_name = _junos_optic_bay_name(
                position, fpc=fpc, pic=pic,
                coord_to_ifname=coord_to_ifname, self_routes=self_routes,
            )
        else:
            bay_name = name
        out.append(_ModuleBay(name=bay_name, position=position, module=module))
    return out


def _junos_parse_chassis(
    chassis_elem,
    coord_to_ifname: dict[tuple[int, int, int], str],
    self_routes: list[tuple[int, str]],
) -> list[_ModuleBay]:
    """
    Top-level: enumerate FPC / Routing Engine modules under one <chassis>.

    For each FPC bay at slot F, threads ``fpc=F`` into the sub-bay walk so
    optic sub-bays can be named by their canonical ifname. ``self_routes``
    accumulates ``(fpc, ifname)`` pairs the caller routes into the owning
    member's interfaces_by_bay.
    """
    bays: list[_ModuleBay] = []
    for module_elem in _find_children(chassis_elem, "chassis-module"):
        name = _text(_find_child(module_elem, "name")).strip()
        if not name:
            continue
        # Only FPC line cards and Routing Engines are slot bays we emit.
        # get-chassis-inventory also lists chassis infrastructure FRUs at the
        # top level (Midplane / CB / SCB / FPM / PEM / PDM / Fan Tray); those
        # are not module bays and would otherwise default to a bogus linecard.
        lname = name.lower()
        if not (lname.startswith("fpc ") or lname.startswith("routing engine ")):
            continue
        position = name.split()[-1] if name.split() else name
        # Only FPC bays carry optics with (fpc,pic,port) coords; a Routing
        # Engine bay's position is not an FPC slot, so leave fpc=None there.
        fpc = _maybe_int(position) if name.startswith("FPC ") else None
        module = _junos_extract_module_from_elem(module_elem)
        if module is None:
            continue
        module.sub_bays = _junos_walk_sub_bays(
            module_elem, depth=2, fpc=fpc, pic=None,
            coord_to_ifname=coord_to_ifname, self_routes=self_routes,
        )
        bays.append(_ModuleBay(name=name, position=position, module=module))
    return bays


# Junos ifname: <media>-<fpc>/<pic>/<port>(.unit)? — e.g. xe-0/1/3, et-12/0/0.
_JUNOS_IFNAME_RE = re.compile(r"^[a-z]+-(\d+)/(\d+)/(\d+)(?:\.\d+)?$")


def _junos_terse_coords(raw: str) -> dict[tuple[int, int, int], str]:
    """
    Parse ``show interfaces terse`` into a (fpc,pic,port)→base-ifname map.

    The base ifname strips any ``.unit`` so an optic correlates to the
    physical interface (``xe-0/1/3``) rather than a logical unit
    (``xe-0/1/3.0``). The first physical match for a coordinate wins; later
    logical-unit lines for the same physical port don't overwrite it.
    """
    coords: dict[tuple[int, int, int], str] = {}
    for line in (raw or "").splitlines():
        token = line.split(" ", 1)[0].strip()
        m = _JUNOS_IFNAME_RE.match(token)
        if not m:
            continue
        fpc, pic, port = int(m.group(1)), int(m.group(2)), int(m.group(3))
        base = token.split(".", 1)[0]
        coords.setdefault((fpc, pic, port), base)
    return coords


def _junos_terse_fpc_ifnames(
    raw: str, fpc_to_member: dict[int, int] | None
) -> dict[int | None, dict[str, list[str]]]:
    """
    Group terse ifnames by (member_id, ``"FPC <slot>"``) for the FPC linecard.

    In Junos the ifname like ``ge-1/0/3`` encodes (FPC slot 1, PIC 0, port
    3). The leading integer is the GLOBAL FPC slot in both modes — it is NOT
    the VC member id. Real Junos VCs use offset FPC numbering (member 0: FPC
    0-11, member 1: FPC 12-23, ...), so ``xe-12/0/0`` is member 1's line
    card, not member 12.

    ``fpc_to_member is None`` selects standalone mode: a single chassis keyed
    ``None``. ``fpc_to_member`` (FPC slot -> VC member id) selects VC mode:
    each interface is routed to the member that owns its FPC; an interface
    whose FPC is in no member's inventory (empty slot) is SKIPPED rather than
    attached to a phantom member.

    The returned bay key is the ACTUAL ``"FPC <slot>"``, matching the ``name``
    field on the top-level ``_ModuleBay``. The translator keys
    ``interfaces_by_bay`` lookups by ``bay_data["name"]``, so a mismatched key
    silently produces zero interface-to-module links.
    """
    vc_mode = fpc_to_member is not None
    ifaces_by_member: dict[int | None, dict[str, list[str]]] = {}
    for line in (raw or "").splitlines():
        token = line.split(" ", 1)[0].strip()
        # Junos ifname pattern: <media>-<num>/<num>/<num>(.unit)?
        if not token or "-" not in token or "/" not in token:
            continue
        try:
            slot = int(token.split("-", 1)[1].split("/", 1)[0])
        except (ValueError, IndexError):
            continue
        if vc_mode:
            member_key = fpc_to_member.get(slot)
            # FPC not in any member's inventory (empty slot / parse gap):
            # don't attach to a phantom member.
            if member_key is None:
                continue
        else:
            member_key = None
        bay_name = f"FPC {slot}"
        ifaces_by_member.setdefault(member_key, {}).setdefault(bay_name, []).append(token)
    return ifaces_by_member


def _junos_fetch_terse(driver) -> str:
    """Run ``show interfaces terse``; return raw text ("" on failure)."""
    try:
        return driver.device.cli("show interfaces terse") or ""
    except Exception as e:
        logger.warning("junos.get_modules: show interfaces terse failed: %s", e)
        return ""


def _junos_merge_self_routes(
    ifaces_by_member: dict[int | None, dict[str, list[str]]],
    self_routes: list[tuple[int, str]],
    fpc_to_member: dict[int, int] | None,
) -> None:
    """
    Add ``ifname -> [ifname]`` self-routes into the owning member's bucket.

    Each self-route carries the optic's FPC. In standalone mode every route
    lands in the ``None`` bucket; in VC mode it routes to
    ``fpc_to_member[fpc]`` so an optic on FPC 12 lands in member 1 (offset-FPC
    member mapping preserved). The translator's deepest-wins logic then links
    the interface to the transceiver rather than the FPC linecard.
    """
    for fpc, ifname in self_routes:
        if fpc_to_member is None:
            member_key: int | None = None
        else:
            member_key = fpc_to_member.get(fpc)
            if member_key is None:
                continue
        ifaces_by_member.setdefault(member_key, {})[ifname] = [ifname]


def _junos_fpc_to_member(member_bays: dict[int, list[_ModuleBay]]) -> dict[int, int]:
    """
    Map global FPC slot -> VC member id from each member's chassis bays.

    ``bay.position`` is the trailing FPC integer (``_junos_parse_chassis``
    sets it via ``name.split()[-1]``). Gate on "FPC " so a Routing Engine
    bay (position like "0") is never mistaken for an FPC slot.
    """
    fpc_to_member: dict[int, int] = {}
    for member_id, bays in member_bays.items():
        for bay in bays:
            if bay.name.startswith("FPC "):
                try:
                    fpc_to_member[int(bay.position)] = member_id
                except (ValueError, TypeError):
                    continue
    return fpc_to_member


def _junos_modules_from_vc(driver, rpc_root) -> dict | None:
    """
    Build the module envelope for the VC-of-modular path.

    Iterates ``<multi-routing-engine-item>`` children; each carries its
    own ``<chassis-inventory><chassis>`` subtree and an ``<re-name>``
    (``fpcN``) whose trailing integer is the dispatch member id.
    """
    # Parse terse FIRST so the chassis walk can name optic sub-bays by their
    # canonical ifname (the coord map doesn't depend on fpc_to_member).
    raw = _junos_fetch_terse(driver)
    coord_to_ifname = _junos_terse_coords(raw)
    self_routes: list[tuple[int, str]] = []
    member_bays: dict[int, list[_ModuleBay]] = {}
    for item in _find_children(rpc_root, "multi-routing-engine-item"):
        re_name = _text(_find_child(item, "re-name")).strip()
        # Pattern: "fpc0" / "fpc1" / ...; the trailing integer is the
        # member id we'll use as the dispatch key.
        try:
            member_id = int(re_name.removeprefix("fpc"))
        except ValueError:
            continue
        ci = _find_child(item, "chassis-inventory")
        if ci is None:
            continue
        chassis = _find_child(ci, "chassis")
        if chassis is None:
            continue
        bays = _junos_parse_chassis(chassis, coord_to_ifname, self_routes)
        if bays:
            member_bays[member_id] = bays
    if not member_bays:
        return None
    fpc_to_member = _junos_fpc_to_member(member_bays)
    ifaces_by_member = _junos_terse_fpc_ifnames(raw, fpc_to_member)
    _junos_merge_self_routes(ifaces_by_member, self_routes, fpc_to_member)
    return _modules_to_payload({
        member_id: _MemberModules(
            bays=bays,
            interfaces_by_bay=ifaces_by_member.get(member_id, {}),
        )
        for member_id, bays in member_bays.items()
    })


def _junos_modules_from_standalone(driver, rpc_root) -> dict | None:
    """
    Build the module envelope for the standalone path.

    ``rpc_root`` IS the ``<chassis-inventory>``; its ``<chassis>`` child
    carries the FPC / RE tree. Emits a single bucket keyed ``None``.
    """
    chassis = _find_child(rpc_root, "chassis")
    if chassis is None:
        return None
    # Parse terse FIRST so optic sub-bays can be named by canonical ifname.
    raw = _junos_fetch_terse(driver)
    coord_to_ifname = _junos_terse_coords(raw)
    self_routes: list[tuple[int, str]] = []
    bays = _junos_parse_chassis(chassis, coord_to_ifname, self_routes)
    if not bays:
        return None
    ifaces_by_member = _junos_terse_fpc_ifnames(raw, None)
    _junos_merge_self_routes(ifaces_by_member, self_routes, None)
    return _modules_to_payload({
        None: _MemberModules(
            bays=bays,
            interfaces_by_bay=ifaces_by_member.get(None, {}),
        ),
    })


def _junos_get_modules_impl(driver) -> dict | None:
    """
    Module discovery for Junos. Detects VC-of-modular automatically.

    PyEZ returns the chassis-inventory RPC payload with the outer
    ``<rpc-reply>`` stripped, so the ROOT element of ``rpc_root`` is
    either:

      - ``<multi-routing-engine-results>`` (VC mode) — iterate
        ``<multi-routing-engine-item>`` children directly.
      - ``<chassis-inventory>`` (standalone) — its ``<chassis>`` child
        carries the FPC / RE tree.

    The detection key is the root tag's local name (the leftover
    ``junos:`` namespace prefix on attributes does not matter here).
    """
    try:
        rpc_root = driver.device.rpc.get_chassis_inventory()
    except RpcError as e:
        logger.warning("junos.get_modules: RPC failed: %s", e)
        return None
    except Exception as e:
        logger.warning("junos.get_modules: unexpected RPC error: %s", e)
        return None
    if rpc_root is None:
        return None

    root_tag = etree.QName(rpc_root.tag).localname

    if root_tag == "multi-routing-engine-results":
        return _junos_modules_from_vc(driver, rpc_root)

    if root_tag != "chassis-inventory":
        # Unknown / unexpected root — bail rather than guess.
        logger.warning(
            "junos.get_modules: unexpected RPC root tag %r", root_tag,
        )
        return None

    return _junos_modules_from_standalone(driver, rpc_root)


_EXPECTED_VIRTUAL_TAG = "virtual-ip-address"

# Element names already reported, so an unrecognised spelling is logged once per
# process rather than once per address per cycle. The expected name is not
# corroborated by any published source, so on a device using a different one an
# unbounded line would be permanent noise.
_UNEXPECTED_TAGS_SEEN: set[str] = set()


def _note_unexpected_tag(ifname: str, address: str, name: str) -> None:
    """
    Log once per element name that is not the expected one.

    The element carrying a virtual address is matched by shape rather than by a
    verified name. The case worth surfacing is a match on an address the driver
    never reported as an interface address: nothing is suppressed then, so no
    other line is emitted and a wrong match would leave no trace.
    """
    if name == _EXPECTED_VIRTUAL_TAG or name in _UNEXPECTED_TAGS_SEEN:
        return
    _UNEXPECTED_TAGS_SEEN.add(name)
    logger.info(
        "%s: matched virtual address %s via unexpected element <%s>",
        ifname,
        address,
        name,
    )


def _normalise_ip(value: str) -> str:
    """Return the address without any mask, compressed, or the input unchanged."""
    bare = (value or "").split("/", 1)[0].strip()
    try:
        return ip_address(bare).compressed
    except ValueError:
        return value


# The three address roles VRRP output distinguishes: the virtual address, the
# local (this router's own) address, and the master's address. Only the first
# may be suppressed; collecting either of the others would remove a real
# interface address.
_VIRTUAL_ROLE = "vip"
_REAL_ADDRESS_ROLES = frozenset({"lcl", "mas"})


def _is_virtual_address_tag(name: str) -> bool:
    """
    Recognise a virtual address carried by the element's own name.

    No published source corroborates the exact element name, so match local
    names that contain "virtual" and end in "address", plus the bare "vip"
    form.
    """
    return name == _VIRTUAL_ROLE or ("virtual" in name and name.endswith("address"))


def _is_address_tag(name: str) -> bool:
    """Recognise a generically named address element, whatever its role."""
    return "addr" in name


def _row_role(el) -> str:
    """
    Return the address role declared beside ``el``, lowercased, or "".

    Junos can carry the role as a sibling *value* rather than in the element
    name, so a typed row looks like a generic address element next to an
    element whose text is vip, lcl or mas. Reading the role from the row is the
    only way to tell a virtual address from the interface's own on that shape.
    """
    parent = el.getparent()
    if parent is None:
        return ""
    for sibling in parent:
        if not isinstance(sibling.tag, str) or sibling is el:
            continue
        text = _text(sibling).strip().lower()
        if text == _VIRTUAL_ROLE or text in _REAL_ADDRESS_ROLES:
            return text
    return ""


def _carries_virtual_address(el, name: str) -> bool:
    """
    Decide whether ``el`` holds a virtual address, by name or by declared role.

    Two reply shapes are supported because which one Junos emits is not
    established: the role in the element name, and the role as a sibling value
    beside a generically named address element. An explicit lcl or mas role
    wins over a name match, so a row that declares itself real is never
    collected.
    """
    role = _row_role(el)
    if role in _REAL_ADDRESS_ROLES:
        return False
    if _is_virtual_address_tag(name):
        return True
    return role == _VIRTUAL_ROLE and _is_address_tag(name)


def _iter_localname(root, name: str):
    """Yield root and every descendant element whose local name matches."""
    for el in root.iter():
        if isinstance(el.tag, str) and _localname(el) == name:
            yield el


def _owned_by(el, entry) -> bool:
    """
    True when the innermost ``vrrp-interface`` enclosing ``el`` is ``entry``.

    A nested entry owns its own addresses; letting the outer one absorb them
    would suppress an address on the wrong interface. Skipping per element
    rather than breaking out of the walk matters because ``iter()`` is
    document-order depth-first, so a break would also abandon any of the outer
    entry's own addresses that appear after the nested one.

    Requires lxml's ``getparent()``, as does ``_group_for``. PyEZ and the test
    double both produce lxml trees.
    """
    if el is entry:
        return True
    node = el.getparent()
    while node is not None:
        if _localname(node) == "vrrp-interface":
            return node is entry
        node = node.getparent()
    return True


def _group_for(matched, entry) -> str:
    """
    Return the group id nearest the matched element, walking up to ``entry``.

    A per-group container would put the group above the address rather than
    beside the interface, so a direct-child lookup on ``entry`` alone would
    report every group as unknown.
    """
    node = matched
    while node is not None:
        group = _text(_find_child(node, "group"))
        if group:
            return group
        if node is entry:
            break
        node = node.getparent()
    return ""


def _vrrp_interface_name(entry) -> str:
    """
    Return the logical interface name, joining a separate unit when present.

    VRRP output can report the physical interface and its unit as two fields,
    which would otherwise produce a name that cannot match the interface keys
    upstream returns.
    """
    for tag in ("interface", "interface-name"):
        name = _text(_find_child(entry, tag))
        if not name:
            continue
        if "." not in name:
            unit = _text(_find_child(entry, "unit"))
            if unit:
                return f"{name}.{unit}"
        return name
    return ""


def _virtual_addresses_from_reply(reply) -> dict[tuple[str, str], str]:
    """
    Map (ifl, virtual address) to the VRRP group that declares it.

    Returns an empty mapping for anything that is not an element: a device with
    no VRRP configured answers with a warning that PyEZ turns into the boolean
    True, which is the common case rather than an error.

    Walks every descendant, so a multi-routing-engine-results wrapper needs no
    special handling. Comments and processing instructions are skipped because
    their tag is a callable and ncclient copies them through from real devices.

    Anything that does not yield both an interface and an address is skipped
    rather than raising, so an unanticipated reply shape degrades to
    "suppress nothing".
    """
    out: dict[tuple[str, str], str] = {}
    if reply is None or not hasattr(reply, "tag"):
        return out
    for entry in _iter_localname(reply, "vrrp-interface"):
        ifname = _vrrp_interface_name(entry)
        if not ifname:
            continue
        for el in entry.iter():
            if not isinstance(el.tag, str):
                continue
            name = _localname(el)
            if not _carries_virtual_address(el, name) or not _owned_by(el, entry):
                continue
            address = _normalise_ip(_text(el))
            try:
                ip_address(address)
            except ValueError:
                continue
            _note_unexpected_tag(ifname, address, name)
            out[(ifname, address)] = _group_for(el, entry)
    return out


def _suppress_virtual(
    interfaces_ip: dict,
    virtual: dict[tuple[str, str], str],
) -> tuple[dict, list[tuple[str, str, str]]]:
    """
    Remove addresses the device reports as first-hop-redundancy virtual addresses.

    Only address entries are removed. Family and interface keys are left in
    place because an interface may be known only through this mapping.
    """
    dropped: list[tuple[str, str, str]] = []
    if not virtual:
        return interfaces_ip, dropped
    for ifname, families in interfaces_ip.items():
        for addresses in families.values():
            for ip in list(addresses):
                group = virtual.get((ifname, _normalise_ip(ip)))
                if group is None:
                    continue
                del addresses[ip]
                dropped.append((ifname, ip, group))
    return interfaces_ip, dropped


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

    def get_modules(self) -> dict | None:
        """
        Return Module / ModuleBay inventory for Junos modular chassis.

        Standalone modular chassis (MX480, EX9214) emit a single bucket
        keyed None. VC-of-modular (Junos VC of EX9200s) emit one bucket
        per VC member id. Standalone non-modular EX/QFX switches return
        None — the existing single-Device path is unchanged.
        """
        return _junos_get_modules_impl(self)

    def _virtual_addresses(self) -> dict[tuple[str, str], str]:
        """Ask the device which of its addresses are VRRP virtual addresses."""
        reply = self.device.rpc.get_vrrp_information(
            ignore_warning=["vrrp subsystem not running"],
        )
        return _virtual_addresses_from_reply(reply)

    def get_interfaces_ip(self) -> dict:
        """
        Return interface addresses, minus VRRP virtual addresses.

        Junos reports a virtual address as an interface address, without a mask,
        and upstream NAPALM fills that gap with a host length. Emitting it
        overwrites an operator's own record with a value the device never
        reported, and moves an address held against a redundancy group onto the
        interface. The device is asked which addresses are virtual, and those
        are left out.

        Best-effort throughout: any failure returns what upstream parsed, since
        this method is called without a guard and an escaping exception would
        cost the device its whole discovery cycle. A failure part-way through
        keeps the suppressions already made, which is strictly better than
        losing the device.
        """
        interfaces_ip = super().get_interfaces_ip()
        try:
            virtual = self._virtual_addresses()
            interfaces_ip, dropped = _suppress_virtual(interfaces_ip, virtual)
            for ifname, address, group in dropped:
                logger.info(
                    "%s: not emitting %s, reported as a virtual address of group %s",
                    ifname,
                    address,
                    group or "unknown",
                )
        except Exception:
            logger.debug("Junos virtual-address suppression failed", exc_info=True)
        return interfaces_ip

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
