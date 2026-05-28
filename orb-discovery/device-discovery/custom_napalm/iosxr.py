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


def _iosxr_build_top_bays(rows: list[dict]) -> dict[int, list[_ModuleBay]]:
    """First pass: build top-level slot bays keyed by rack id."""
    bays_by_rack: dict[int, list[_ModuleBay]] = {}
    for row in rows:
        name = _iosxr_strip_inventory_prefix(
            (row.get("name") or "").strip().strip('"'),
        )
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
    return bays_by_rack


def _iosxr_attach_sub_bays(
    rows: list[dict],
    bays_by_rack: dict[int, list[_ModuleBay]],
    vsf: bool,
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
                rows, slot_prefix, ifaces_by_member, member,
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
) -> tuple[list[str], list[_ModuleBay]]:
    """
    Collect ifnames + optic sub-bays under a single linecard's <rack>/<slot>/ prefix.

    Self-routes each optic ifname under its own sub-bay key so translate's
    deepest-match-wins routes the port to the transceiver while non-optic
    ports stay on the parent linecard.
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
        rpid = (row.get("pid") or "").strip()
        rsn = (row.get("sn") or "").strip()
        rdescr = (row.get("descr") or "").strip().strip('"')
        if rpid and rsn and is_optic_pid(rpid):
            sub_bays.append(_ModuleBay(
                name=rname, position=rname,
                module=_ModuleEntry(
                    model=rpid, serial=rsn, type="transceiver", description=rdescr,
                ),
            ))
            ifaces_by_member.setdefault(member, {})[rname] = [rname]
    return slot_ifaces, sub_bays


def _iosxr_get_modules_impl(driver) -> dict | None:
    """
    Standalone + nV-cluster module discovery for IOS-XR via pyIOSXR.

    Reuses the cisco_nxos show inventory template because XR's block
    layout is identical. nV cluster is auto-detected from rack ids in
    slot NAMEs — no separate cluster RPC is needed.
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

    bays_by_rack = _iosxr_build_top_bays(rows)
    if not bays_by_rack:
        return None

    vsf = len(bays_by_rack) >= 2
    ifaces_by_member = _iosxr_attach_sub_bays(rows, bays_by_rack, vsf)

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


class IOSXRDriver(_UpstreamIOSXRDriver):
    """Custom IOS-XR driver shim adding get_modules() to the upstream class."""

    def get_modules(self) -> dict | None:
        """Return per-rack module / module-bay inventory or None."""
        return _iosxr_get_modules_impl(self)
