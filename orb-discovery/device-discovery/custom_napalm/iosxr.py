"""
Custom IOS-XR driver shim adding get_modules() to napalm.iosxr.IOSXRDriver.

Only get_modules and its private helpers are added; all other getters are
inherited from the upstream class. Inventory is fetched via the pyIOSXR
private _execute_show("show inventory") API (returns plain text wrapped
through the XR <CLI><Exec> XML-Agent), then parsed via the cisco_nxos
ntc-template because XR show inventory shares the NAME/DESCR/PID/VID/SN
block layout with NX-OS / IOS / FXOS.
"""

import logging
import re

from napalm.iosxr.iosxr import IOSXRDriver as _UpstreamIOSXRDriver
from napalm.pyIOSXR.exceptions import (
    ConnectError,
    InvalidInputError,
    XMLCLIError,
)
from napalm.pyIOSXR.exceptions import (
    TimeoutError as IOSXRTimeoutError,
)
from ntc_templates.parse import ParsingException, parse_output
from textfsm.parser import TextFSMError

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
    orphan_optic_bay,
)
from custom_napalm._modules import (
    to_payload as _modules_to_payload,
)

logger = logging.getLogger(__name__)

# Catch both classes so an ntc_templates ParsingException doesn't propagate
# as an unhandled exception — same defensive pattern as cisco_fxos.py:41.
_IOSXR_PARSE_ERRORS = (TextFSMError, ParsingException)

# Slot-bay NAME patterns. Per spec: RP/RSP -> supervisor, slot-only -> linecard,
# FC/SC -> fabric/switch (emit as linecard, no NetBox fabric type today).
_IOSXR_RP_RE = re.compile(r"^(?P<rack>\d+)/(?:RP|RSP)\d+/CPU\d+$")
_IOSXR_LC_RE = re.compile(r"^(?P<rack>\d+)/\d+/CPU\d+$")
_IOSXR_FAB_RE = re.compile(r"^(?P<rack>\d+)/(?:FC|SC)\d+$")
# The chassis's own top-level inventory row, e.g. NAME: "Rack 0". Its PID is
# the chassis identity an RP/RSP row is compared against for the fixed-port
# positive-evidence gate (see _iosxr_rack_is_fixed_port).
_IOSXR_RACK_RE = re.compile(r"^Rack\s+(?P<rack>\d+)$", re.IGNORECASE)
# Port-slot pattern. Accepts both the 3-tuple form (`0/0/0`) and the 4-tuple
# form (`0/0/CPU0/2`, `0/0/0/14`) — the latter appears for transceiver
# positions on many ASR9k releases. Optional `:<sub>` suffix covers breakout
# ports.
_IOSXR_PORT_RE = re.compile(
    r"^(?P<rack>\d+)/(?P<slot>\d+)/"
    r"(?:[A-Za-z]*\d+/)?"
    r"\d+(?::\d+)?$",
)

# Strip the optional XR inventory-object prefix so the slot regexes see the
# bare identifier. Real show inventory varies across XR releases between
# bare ("0/RSP0/CPU0"), single-prefix ("module 0/RSP0/CPU0"), and
# multi-prefix ("module mau 0/1/CPU0/2") forms; allow one or more prefix
# words before the leading digit.
_IOSXR_NAME_PREFIX_RE = re.compile(
    r"^(?:(?:module|slot|port|card|mau)\s+)+(?=\d)",
    re.IGNORECASE,
)


def _iosxr_strip_inventory_prefix(name: str) -> str:
    """Strip XR inventory-object prefix ('module 0/...', 'Slot 0/0', ...)."""
    return _IOSXR_NAME_PREFIX_RE.sub("", name or "")


# The same NAME patterns _iosxr_build_top_bays uses to recognize a card row
# (linecard, RP/RSP, fabric/switch) — matched here unconditionally, before
# the pid/sn usability filter, so a card whose own row is unusable still
# claims its slot. See _iosxr_claimed_slot_prefix.
_IOSXR_CARD_ROW_RES = (_IOSXR_LC_RE, _IOSXR_RP_RE, _IOSXR_FAB_RE)


def _iosxr_claimed_slot_prefix(name: str) -> str | None:
    """
    Return the ``<rack>/<slot>/`` prefix a card-identifying NAME claims, or None.

    Tested against the RAW name, ahead of any pid/sn or classification
    filter, so a card row that later turns out unusable (blank PID or
    serial) still claims its slot. Only rows that identify a card by NAME
    (linecard, RP/RSP, fabric/switch) claim a prefix; port and PSU/fan rows
    return None.
    """
    if not any(pattern.match(name) for pattern in _IOSXR_CARD_ROW_RES):
        return None
    parts = name.split("/")
    if len(parts) < 2:
        return None
    return f"{parts[0]}/{parts[1]}/"


def classify_module_type_iosxr(pid: str, name: str) -> str:
    """
    Classify an IOS-XR inventory row into a Module type.

    NAME drives slot-vs-port disambiguation (RP/RSP/FC/SC vs LC vs port);
    PID is consulted only for the optic check and the defensive PSU/fan
    fallback. Unknown rows that nonetheless match a slot-NAME regex emit
    as linecard.
    """
    upper_pid = (pid or "").strip().upper()
    if is_optic_pid(pid):
        return "transceiver"
    if _IOSXR_RP_RE.match(name or ""):
        return "supervisor"
    if _IOSXR_LC_RE.match(name or ""):
        return "linecard"
    if _IOSXR_FAB_RE.match(name or ""):
        return "linecard"
    if upper_pid.startswith("PWR-") or "-PS-" in upper_pid or "PSU" in upper_pid:
        return "psu"
    if "FAN" in upper_pid or (name or "").startswith("Fan") or "/FT" in (name or ""):
        return "fan"
    return "other"


def _iosxr_member_of(name: str) -> int | None:
    """Return the integer rack id parsed from the leading element of NAME."""
    head, _, _ = (name or "").partition("/")
    try:
        return int(head)
    except ValueError:
        return None


def _iosxr_build_top_bays(
    rows: list[dict],
) -> tuple[dict[int, list[_ModuleBay]], set[str]]:
    """
    First pass: build top-level slot bays keyed by rack id.

    Also returns ``claimed_slot_prefixes``: every ``<rack>/<slot>/`` prefix
    a RAW row claims by NAME alone (see ``_iosxr_claimed_slot_prefix`),
    collected before the ``pid and sn`` usability filter below and before
    any type/classification filter. A prefix lands in this set even when
    its own row turns out unusable (blank PID or serial); the promotion
    pass must then decline any optic under that prefix, because the slot's
    parent exists in hardware — this row simply failed to describe it
    usably. Promoting the optic to a device-rooted bay in that case would
    invent a chassis-level parent for hardware that already has one.
    """
    bays_by_rack: dict[int, list[_ModuleBay]] = {}
    claimed_slot_prefixes: set[str] = set()
    for row in rows:
        name = _iosxr_strip_inventory_prefix(
            (row.get("name") or "").strip().strip('"'),
        )
        prefix = _iosxr_claimed_slot_prefix(name)
        if prefix:
            claimed_slot_prefixes.add(prefix)
        pid = (row.get("pid") or "").strip()
        sn = (row.get("sn") or "").strip()
        descr = (row.get("descr") or "").strip().strip('"')
        if not (pid and sn):
            continue
        mtype = classify_module_type_iosxr(pid, name)
        if mtype in ("psu", "fan", "transceiver", "other"):
            continue  # PSU/fan filtered; transceivers attach as sub-bays below
        rack = _iosxr_member_of(name)
        if rack is None:
            continue  # row whose NAME doesn't start with an int rack id
        bays_by_rack.setdefault(rack, []).append(_ModuleBay(
            name=name, position=name,
            module=_ModuleEntry(model=pid, serial=sn, type=mtype, description=descr),
        ))
    return bays_by_rack, claimed_slot_prefixes


def _iosxr_rack_chassis_pids(rows: list[dict]) -> dict[int, str]:
    """
    Return each rack's own "Rack <n>" row PID, keyed by rack id, from the RAW rows.

    Read unconditionally, ahead of any pid/sn usability filter — this is
    the chassis identity an RP/RSP row is compared against for
    ``_iosxr_rack_is_fixed_port`` clause (A), not itself gated by whether
    the "Rack <n>" row would otherwise be usable.
    """
    pids: dict[int, str] = {}
    for row in rows:
        name = _iosxr_strip_inventory_prefix((row.get("name") or "").strip().strip('"'))
        m = _IOSXR_RACK_RE.match(name)
        if m:
            pids[int(m.group("rack"))] = (row.get("pid") or "").strip()
    return pids


def _iosxr_rp_pids_by_rack(rows: list[dict]) -> dict[int, list[str]]:
    """
    Return every RP/RSP CPU0 row's own PID, grouped by rack id, from the RAW rows.

    Read unconditionally, ahead of any pid/sn usability filter, so a rack
    whose RP row is present but was never usable still reports one here —
    ``_iosxr_rack_is_fixed_port`` clause (A) still requires PID equality
    against the chassis row to actually recognize it, so an unusable RP
    row with the wrong PID does not falsely grant fixed-port status.
    """
    out: dict[int, list[str]] = {}
    for row in rows:
        name = _iosxr_strip_inventory_prefix((row.get("name") or "").strip().strip('"'))
        m = _IOSXR_RP_RE.match(name)
        if m:
            out.setdefault(int(m.group("rack")), []).append((row.get("pid") or "").strip())
    return out


def _iosxr_row_pid_by_name(rows: list[dict]) -> dict[str, str]:
    """
    Map every RAW row's (prefix-stripped) NAME to its own PID, unfiltered.

    Used only by ``_iosxr_optic_has_mpa_parent``: a modular port adapter
    (MPA) row's NAME has the same plain ``<rack>/<slot>/<n>`` shape a port
    uses, so it never matches a card-row pattern and never claims a
    ``claimed_slot_prefixes`` entry (see ``_iosxr_claimed_slot_prefix``). A
    row existing at an optic's immediate parent path with a real,
    non-optic PID is the only positive evidence of that case.
    """
    out: dict[str, str] = {}
    for row in rows:
        name = _iosxr_strip_inventory_prefix((row.get("name") or "").strip().strip('"'))
        if name:
            out[name] = (row.get("pid") or "").strip()
    return out


def _iosxr_optic_has_mpa_parent(pname: str, row_pid_by_name: dict[str, str]) -> bool:
    """
    Return True when a raw row names the optic's immediate parent path with a real PID.

    ``pname`` is the optic's own (already prefix-stripped) NAME, e.g.
    ``0/0/1/2``. Stripping its last element gives the parent path
    (``0/0/1``) — the slot an MPA would occupy. A blank PID at that path
    is not treated as positive evidence (it reads the same as no row at
    all); only a real, non-optic PID counts.
    """
    parts = pname.split("/")
    if len(parts) < 2:
        return False
    parent_pid = row_pid_by_name.get("/".join(parts[:-1]), "")
    return bool(parent_pid) and not is_optic_pid(parent_pid)


def _iosxr_rack_is_fixed_port(
    rack: int,
    rack_pids: dict[int, str],
    rp_pids_by_rack: dict[int, list[str]],
    claimed_slot_prefixes: set[str],
) -> bool:
    """
    Positive-evidence gate: may an orphan optic on RACK be promoted to a device-rooted bay?

    (A) positive: an RP/RSP CPU0 row exists for this rack and its own PID
    equals that rack's "Rack <n>" row PID — on a fixed-port XR box the
    route processor IS the chassis, stated directly by the vendor in rows
    already fetched, not inferred from the absence of a claim.

    (B) narrowed absence: the raw rows claim no card-shaped prefix at all
    for this rack (see ``claimed_slot_prefixes`` / ``_iosxr_build_top_bays``)
    — RP/RSP and every linecard/fabric row are missing simultaneously.
    Both must-promote fixed-port fixtures report no RP row at all, so this
    clause has to stay; it is deliberately narrower than "this one slot is
    unclaimed" — a rack with ANY surviving card-shaped row fails it, even
    when the specific slot underneath the optic was itself never claimed.
    """
    chassis_pid = rack_pids.get(rack)
    if chassis_pid and any(
        pid == chassis_pid for pid in rp_pids_by_rack.get(rack, []) if pid
    ):
        return True
    return not any(prefix.startswith(f"{rack}/") for prefix in claimed_slot_prefixes)


def _iosxr_collect_all_optics(rows: list[dict]) -> dict[str, _ModuleEntry]:
    """
    Index every optic row in inventory by its port name.

    Collected independently of the bay walk so an optic on a slot with no
    linecard bay is still visible. The bay walk consumes from this map and
    whatever it leaves behind is promoted to a device-rooted bay.
    """
    optics: dict[str, _ModuleEntry] = {}
    for row in rows:
        rname = _iosxr_strip_inventory_prefix(
            (row.get("name") or "").strip().strip('"'),
        )
        if not _IOSXR_PORT_RE.match(rname):
            continue
        rpid = (row.get("pid") or "").strip()
        rsn = (row.get("sn") or "").strip()
        rdescr = (row.get("descr") or "").strip().strip('"')
        if rpid and rsn and is_optic_pid(rpid):
            optics[rname] = _ModuleEntry(
                model=rpid, serial=rsn, type="transceiver", description=rdescr,
            )
    return optics


def _iosxr_promote_orphan_optics(
    optics: dict[str, _ModuleEntry],
    consumed: set[str],
    vsf: bool,
    bays_by_rack: dict[int, list[_ModuleBay]],
    ifaces_by_member: dict[int | None, dict[str, list[str]]],
    claimed_slot_prefixes: set[str],
    rack_pids: dict[int, str],
    rp_pids_by_rack: dict[int, list[str]],
    row_pid_by_name: dict[str, str],
) -> None:
    """
    Promote optics the bay walk never claimed to device-rooted bays, in place.

    Fixed-port XR platforms report optics with no linecard above them, so
    there is no parent bay to nest under. The rack is the port name's
    leading element.

    ``bays_by_rack`` doubles as the rack roster, so the first orphan on a
    device that reported no slot bays at all mints its rack — the intended
    fixed-port case. Every orphan after that must name a rack already in
    the roster, which is why the test below reads ``bays_by_rack`` live
    rather than a pre-loop snapshot: a snapshot taken while the roster was
    empty never refuses anything, so a second, differing rack would be
    minted and then dropped without a word by the standalone tail (which
    emits one rack) or warn-dropped a layer away by translate as an orphan
    member. Refusing here is what gives the drop a name; nothing incorrect
    reaches NetBox either way. This is a different question from the two
    gates below, which ask whether a RACK is fixed-port at all, so it stays
    live on purpose while they are computed from a pre-loop snapshot.

    ``claimed_slot_prefixes`` (see ``_iosxr_build_top_bays``) names every
    ``<rack>/<slot>/`` prefix the RAW inventory already accounted for by
    NAME alone. An optic under a claimed prefix is declined even when its
    rack is otherwise in the roster (e.g. because a sibling card in the
    same rack survived) — that slot's own card exists in hardware, it just
    didn't survive the pid/sn filter, so promoting the optic here would
    invent a device-rooted parent for a slot that already has one.

    ``_iosxr_optic_has_mpa_parent`` catches the case a slot-prefix claim
    can't: a modular port adapter's NAME collides with the plain port-slot
    shape, so it never lands in ``claimed_slot_prefixes`` at all.

    ``_iosxr_rack_is_fixed_port`` (``rack_pids`` / ``rp_pids_by_rack``,
    also snapshotted before this loop runs — see ``_iosxr_build_top_bays``)
    is the positive-evidence gate on the rack overall: a rack with a
    surviving card-shaped row that isn't itself the chassis (clause A)
    fails it even when the specific slot under this optic was never
    claimed by any row.
    """
    for pname, optic in optics.items():
        if pname in consumed:
            continue
        rack = int(pname.split("/")[0])
        if bays_by_rack and rack not in bays_by_rack:
            logger.warning(
                "iosxr.get_modules: orphan optic %s rack %s not in chassis set",
                pname, rack,
            )
            continue
        if any(pname.startswith(prefix) for prefix in claimed_slot_prefixes):
            logger.debug(
                "iosxr.get_modules: declining promotion of %s (inventory claims its "
                "slot but the row was unusable)",
                pname,
            )
            continue
        if _iosxr_optic_has_mpa_parent(pname, row_pid_by_name):
            logger.debug(
                "iosxr.get_modules: declining promotion of %s (a raw inventory row "
                "names its parent path with a non-optic PID — a modular port adapter)",
                pname,
            )
            continue
        if not _iosxr_rack_is_fixed_port(rack, rack_pids, rp_pids_by_rack, claimed_slot_prefixes):
            logger.debug(
                "iosxr.get_modules: declining promotion of %s (no positive evidence "
                "rack %s's own parent is the chassis)",
                pname, rack,
            )
            continue
        member = rack if vsf else None
        bays_by_rack.setdefault(rack, []).append(orphan_optic_bay(pname, optic))
        ifaces_by_member.setdefault(member, {})[pname] = [pname]


def _iosxr_attach_sub_bays(
    rows: list[dict],
    bays_by_rack: dict[int, list[_ModuleBay]],
    vsf: bool,
    optics: dict[str, _ModuleEntry],
    consumed: set[str],
) -> dict[int | None, dict[str, list[str]]]:
    """Second pass: attach optic sub-bays + port-ifname maps to linecard bays."""
    ifaces_by_member: dict[int | None, dict[str, list[str]]] = {}
    for rack, bays in bays_by_rack.items():
        member = rack if vsf else None
        for bay in bays:
            if not _IOSXR_LC_RE.match(bay.name):
                continue
            slot = bay.name.split("/")[1]  # "0/0/CPU0" -> "0"
            slot_prefix = f"{rack}/{slot}/"
            slot_ifaces, sub_bays = _iosxr_collect_slot_ports(
                rows, slot_prefix, ifaces_by_member, member, optics, consumed,
            )
            if sub_bays:
                bay.module.sub_bays.extend(sub_bays)
            if slot_ifaces:
                ifaces_by_member.setdefault(member, {})[bay.name] = list(slot_ifaces)
    return ifaces_by_member


def _iosxr_collect_slot_ports(
    rows: list[dict],
    slot_prefix: str,
    ifaces_by_member: dict[int | None, dict[str, list[str]]],
    member: int | None,
    optics: dict[str, _ModuleEntry],
    consumed: set[str],
) -> tuple[list[str], list[_ModuleBay]]:
    """
    Collect ifnames + optic sub-bays under a single linecard's <rack>/<slot>/ prefix.

    Self-routes each optic ifname under its own sub-bay key so translate's
    deepest-match-wins routes the port to the transceiver while non-optic
    ports stay on the parent linecard.

    Optics come from the pre-built ``optics`` index rather than being
    re-derived here, and every one claimed is recorded in ``consumed`` so
    the promotion pass can tell which optics still have no parent.
    """
    slot_ifaces: list[str] = []
    sub_bays: list[_ModuleBay] = []
    for row in rows:
        rname = _iosxr_strip_inventory_prefix(
            (row.get("name") or "").strip().strip('"'),
        )
        if not _IOSXR_PORT_RE.match(rname):
            continue
        if not rname.startswith(slot_prefix):
            continue
        slot_ifaces.append(rname)
        optic = optics.get(rname)
        if optic is not None:
            sub_bays.append(_ModuleBay(name=rname, position=rname, module=optic))
            consumed.add(rname)
            ifaces_by_member.setdefault(member, {})[rname] = [rname]
    return slot_ifaces, sub_bays


def _iosxr_get_modules_impl(driver) -> dict | None:
    """
    Standalone + nV-cluster module discovery for IOS-XR via pyIOSXR.

    Reuses the cisco_nxos show inventory template because XR's block
    layout is identical. nV cluster is auto-detected from rack ids in
    slot NAMEs — no separate cluster RPC is needed.

    Fixed-port XR platforms report optics with no linecard row above them;
    those become device-rooted bays. Returns None only when neither a slot
    bay nor an optic was recognized.
    """
    try:
        # pyIOSXR's foundational show-runner; wraps the XR XML-Agent CLI
        # <Exec> envelope and returns the unwrapped text. Private API in
        # napalm.pyIOSXR but stable for years and used by every higher-
        # level pyIOSXR method (e.g. make_rpc_call delegates through it).
        inv_raw = driver.device._execute_show("show inventory")
    except (ConnectError, IOSXRTimeoutError, InvalidInputError, XMLCLIError) as e:
        logger.warning("iosxr.get_modules: show inventory failed: %s", e)
        return None
    if not inv_raw:
        return None
    try:
        rows = parse_output(platform="cisco_nxos", command="show inventory", data=inv_raw)
    except _IOSXR_PARSE_ERRORS:
        logger.warning("iosxr.get_modules: show inventory parse failed")
        return None
    if not rows:
        return None

    optics = _iosxr_collect_all_optics(rows)
    bays_by_rack, claimed_slot_prefixes = _iosxr_build_top_bays(rows)
    if not bays_by_rack and not optics:
        return None

    # Snapshotted beside claimed_slot_prefixes, from the same raw rows and
    # before the same pid/sn filter — the positive-evidence inputs for
    # _iosxr_rack_is_fixed_port / _iosxr_optic_has_mpa_parent below.
    rack_pids = _iosxr_rack_chassis_pids(rows)
    rp_pids_by_rack = _iosxr_rp_pids_by_rack(rows)
    row_pid_by_name = _iosxr_row_pid_by_name(rows)

    # Derived from slot bays only, before promotion: a fixed-port device has
    # no slot bays at all, so it stays standalone and collapses to the
    # None-bucket via the tail below rather than becoming a 1-member cluster.
    vsf = len(bays_by_rack) >= 2
    consumed: set[str] = set()
    ifaces_by_member = _iosxr_attach_sub_bays(
        rows, bays_by_rack, vsf, optics, consumed,
    )
    _iosxr_promote_orphan_optics(
        optics, consumed, vsf, bays_by_rack, ifaces_by_member, claimed_slot_prefixes,
        rack_pids, rp_pids_by_rack, row_pid_by_name,
    )
    # Re-check after promotion. The gate above runs before the claimed-slot
    # guard can refuse anything, so it cannot see the case where every card row
    # is unusable AND every optic beneath one is declined: optics is non-empty
    # so the gate passes, promotion adds nothing, and the standalone tail below
    # would call next() on an empty mapping.
    if not bays_by_rack:
        return None

    if vsf:
        return _modules_to_payload({
            rack: _MemberModules(bays=bays, interfaces_by_bay=ifaces_by_member.get(rack, {}))
            for rack, bays in bays_by_rack.items()
        })
    # Standalone: collapse the single rack to the None-bucket.
    only_rack = next(iter(bays_by_rack))
    return _modules_to_payload({
        None: _MemberModules(
            bays=bays_by_rack[only_rack],
            interfaces_by_bay=ifaces_by_member.get(None, {}),
        ),
    })


# "show vrf all detail" block headers: VRF <name>; RD <rd>; VPN ID <id>.
_IOSXR_VRF_HEADER_RE = re.compile(r"^\s*VRF (\S+); RD (.+?); VPN ID")
# Member rows under the "Interfaces:" section — one indented ifname per line,
# same character class the cisco_xr ntc-template uses for interface names.
_IOSXR_VRF_IFACE_RE = re.compile(r"^\s+([\w./-]+)\s*$")
_IOSXR_VRF_IFACES_HDR_RE = re.compile(r"^\s*Interfaces:\s*$")


def _iosxr_parse_vrf_blocks(raw: str) -> list[dict]:
    """
    Driver-local parse of "show vrf all detail" into name/rd/interfaces rows.

    Deliberately NOT the cisco_xr ntc-template: its FSM only leaves the
    Interfaces / route-target states on specific follow-up lines ("Address
    family ...", "No import route policy"), so a VRF block without an
    address family, or with an import/export route policy attached
    (`Import route policy: RPL_IN` — routine in production L3VPN),
    swallows the NEXT VRF's header and misattributes its interfaces.
    A line-stateful walk keyed on the unambiguous block header has no
    such stuck states: interface collection starts at "Interfaces:" and
    stops at the first line that isn't a lone indented interface name.
    """
    rows: list[dict] = []
    current: dict | None = None
    in_interfaces = False
    for line in raw.splitlines():
        m = _IOSXR_VRF_HEADER_RE.match(line)
        if m:
            current = {"vrf": m.group(1), "rd": m.group(2), "interfaces": []}
            rows.append(current)
            in_interfaces = False
            continue
        if current is None:
            continue
        if _IOSXR_VRF_IFACES_HDR_RE.match(line):
            in_interfaces = True
            continue
        if in_interfaces:
            m = _IOSXR_VRF_IFACE_RE.match(line)
            if m:
                current["interfaces"].append(m.group(1))
            else:
                in_interfaces = False
    return rows


def _iosxr_default_instance() -> dict:
    """
    Return the DEFAULT_INSTANCE entry for the global routing table.

    Its interface membership is intentionally left empty: enumerating
    default-table interfaces needs a second command, and the discovery
    pipeline only consumes VRF (L3VRF) memberships — every interface not
    claimed by a VRF is in the default table by definition.
    """
    return {
        "name": "default",
        "type": "DEFAULT_INSTANCE",
        "state": {"route_distinguisher": ""},
        "interfaces": {"interface": {}},
    }


def _iosxr_get_network_instances_impl(driver, name: str = "") -> dict:
    """
    VRF discovery for IOS-XR via pyIOSXR ("show vrf all detail").

    Parsed driver-locally (see _iosxr_parse_vrf_blocks for why the
    cisco_xr ntc-template is not used); each row carries the VRF name,
    its route distinguisher (the literal "not set" when unconfigured —
    normalized to ""), and the member interface list.
    """
    try:
        raw = driver.device._execute_show("show vrf all detail")
    except (ConnectError, IOSXRTimeoutError, InvalidInputError, XMLCLIError) as e:
        logger.warning("iosxr.get_network_instances: show vrf all detail failed: %s", e)
        # Deliberately {} (not the seeded default instance): a transport
        # failure means the device state is unknown, and an empty dict is
        # the unambiguous "discovery failed" signal. The seeded default is
        # returned only on paths where the device DID respond — there the
        # default table is a platform invariant, not fabricated knowledge.
        return {}

    instances: dict = {"default": _iosxr_default_instance()}
    rows = _iosxr_parse_vrf_blocks(raw) if raw else []
    for row in rows:
        vrf = (row.get("vrf") or "").strip()
        # Never let a parsed row overwrite the seeded DEFAULT_INSTANCE —
        # a row named "default" is the global table, not an L3VRF.
        if not vrf or vrf == "default":
            continue
        rd = (row.get("rd") or "").strip()
        if rd.lower() == "not set":
            rd = ""
        interfaces = {
            ifname.strip(): {}
            for ifname in (row.get("interfaces") or [])
            if ifname and ifname.strip()
        }
        instances[vrf] = {
            "name": vrf,
            "type": "L3VRF",
            "state": {"route_distinguisher": rd},
            "interfaces": {"interface": interfaces},
        }
    if name:
        return {name: instances[name]} if name in instances else {}
    return instances


class IOSXRDriver(_UpstreamIOSXRDriver):
    """Custom IOS-XR driver shim adding get_modules() to the upstream class."""

    def get_modules(self) -> dict | None:
        """
        Return per-rack module / module-bay inventory or None.

        On fixed-port platforms the optics have no linecard parent and are
        returned as device-rooted bays instead of being dropped.
        """
        return _iosxr_get_modules_impl(self)

    def get_network_instances(self, name: str = "") -> dict:
        """Return network instances (VRFs) keyed by name, NAPALM OC shape."""
        return _iosxr_get_network_instances_impl(self, name)
