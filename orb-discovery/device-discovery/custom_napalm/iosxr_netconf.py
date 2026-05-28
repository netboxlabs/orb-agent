"""
Custom IOS-XR NETCONF driver shim adding get_modules().

Subclasses napalm.iosxr_netconf.IOSXRNETCONFDriver to inherit every
other getter unchanged. Inventory is fetched via a ncclient subtree-
filtered <get> on the Cisco-IOS-XR-invmgr-oper:inventory model; lxml
walks the flat entities/entity list (mirroring the path the upstream
driver uses for get_facts) and flattens each entry into a row matching
the show-inventory shape used by custom_napalm.iosxr.
"""

import logging
import re

from lxml import etree as ETREE
from napalm.iosxr_netconf.iosxr_netconf import (
    IOSXRNETCONFDriver as _UpstreamIOSXRNetconfDriver,
)
from ncclient import NCClientError

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

_INVMGR_NS = "http://cisco.com/ns/yang/Cisco-IOS-XR-invmgr-oper"
_NS_MAP = {"imo": _INVMGR_NS}  # prefix matches upstream napalm.iosxr_netconf convention

# Focused subtree filter: just the entity name + inv-basic-bag fields we
# need. Empty leaf elements ("<name/>") mean "select all instances". Mirrors
# the upstream FACTS_RPC_REQ pattern in napalm/iosxr_netconf/constants.py.
_INV_FILTER = f"""
<inventory xmlns="{_INVMGR_NS}">
  <entities>
    <entity>
      <name/>
      <attributes>
        <inv-basic-bag>
          <description/>
          <model-name/>
          <serial-number/>
        </inv-basic-bag>
      </attributes>
    </entity>
  </entities>
</inventory>
"""

# Same slot-NAME regexes as custom_napalm.iosxr (per-driver-bespoke duplication).
_IOSXR_RP_RE = re.compile(r"^(?P<rack>\d+)/(?:RP|RSP)\d+/CPU\d+$")
_IOSXR_LC_RE = re.compile(r"^(?P<rack>\d+)/\d+/CPU\d+$")
_IOSXR_FAB_RE = re.compile(r"^(?P<rack>\d+)/(?:FC|SC)\d+$")
_IOSXR_PORT_RE = re.compile(
    r"^(?P<rack>\d+)/(?P<slot>\d+)/"
    r"(?:[A-Za-z]*\d+/)?"
    r"\d+(?::\d+)?$",
)

# Strip leading inventory-object prefix; allow one or more words before the
# rack digit so forms like "module mau 0/1/CPU0/2" reduce to "0/1/CPU0/2".
_IOSXR_NAME_PREFIX_RE = re.compile(
    r"^(?:(?:module|slot|port|card|mau)\s+)+(?=\d)",
    re.IGNORECASE,
)


def _iosxr_netconf_strip_inventory_prefix(name: str) -> str:
    """Strip XR inventory-object prefix ('module 0/...', 'Slot 0/0', ...)."""
    return _IOSXR_NAME_PREFIX_RE.sub("", name or "")


def classify_module_type_iosxr_netconf(pid: str, name: str) -> str:
    """
    Per-driver-bespoke duplicate of the SSH-driver classifier.

    Identical body to custom_napalm.iosxr.classify_module_type_iosxr —
    the duplication is the deliberate Approach-A tradeoff for batches 3+.
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


def _iosxr_netconf_rows_from_xml(xml_text: str) -> list[dict]:
    """
    Walk the flat entities/entity inventory list to row dicts.

    Each row has keys name / descr / pid / sn matching the show-inventory
    parse rows the SSH driver consumes, so the rest of the impl is
    transport-agnostic. Path: inventory/entities/entity/{name,
    attributes/inv-basic-bag/{description, model-name, serial-number}} —
    confirmed against napalm.iosxr_netconf upstream usage.
    """
    if not xml_text:
        return []
    try:
        root = ETREE.fromstring(xml_text.encode("utf-8") if isinstance(xml_text, str) else xml_text)
    except ETREE.XMLSyntaxError as e:
        logger.warning("iosxr_netconf.get_modules: XML parse failed: %s", e)
        return []
    rows: list[dict] = []
    for entity in root.findall(".//imo:inventory//imo:entity", _NS_MAP):
        name_el = entity.find("imo:name", _NS_MAP)
        bag = entity.find("imo:attributes/imo:inv-basic-bag", _NS_MAP)
        if name_el is None or bag is None:
            continue
        pid_el = bag.find("imo:model-name", _NS_MAP)
        sn_el = bag.find("imo:serial-number", _NS_MAP)
        descr_el = bag.find("imo:description", _NS_MAP)
        rows.append({
            "name": (name_el.text or "").strip(),
            "descr": (descr_el.text or "").strip() if descr_el is not None else "",
            "pid": (pid_el.text or "").strip() if pid_el is not None else "",
            "sn": (sn_el.text or "").strip() if sn_el is not None else "",
        })
    return rows


def _iosxr_netconf_build_top_bays(rows: list[dict]) -> dict[int, list[_ModuleBay]]:
    """First pass: emit one top-level bay per slot row with PID + SN."""
    bays_by_rack: dict[int, list[_ModuleBay]] = {}
    for row in rows:
        name = _iosxr_netconf_strip_inventory_prefix(row.get("name") or "")
        pid = row.get("pid") or ""
        sn = row.get("sn") or ""
        descr = row.get("descr") or ""
        if not (pid and sn):
            continue
        mtype = classify_module_type_iosxr_netconf(pid, name)
        if mtype in ("psu", "fan", "transceiver", "other"):
            continue
        head, _, _ = name.partition("/")
        try:
            rack = int(head)
        except ValueError:
            continue
        bays_by_rack.setdefault(rack, []).append(_ModuleBay(
            name=name, position=name,
            module=_ModuleEntry(model=pid, serial=sn, type=mtype, description=descr),
        ))
    return bays_by_rack


def _iosxr_netconf_collect_slot_ports(rows: list[dict], slot_prefix: str) -> tuple[list[str], list[_ModuleBay]]:
    """Per linecard slot: list of port ifnames + optic sub-bays under that slot."""
    slot_ifaces: list[str] = []
    sub_bays: list[_ModuleBay] = []
    for row in rows:
        rname = _iosxr_netconf_strip_inventory_prefix(row.get("name") or "")
        if not _IOSXR_PORT_RE.match(rname):
            continue
        if not rname.startswith(slot_prefix):
            continue
        slot_ifaces.append(rname)
        rpid = row.get("pid") or ""
        rsn = row.get("sn") or ""
        rdescr = row.get("descr") or ""
        if rpid and rsn and is_optic_pid(rpid):
            sub_bays.append(_ModuleBay(
                name=rname, position=rname,
                module=_ModuleEntry(
                    model=rpid, serial=rsn, type="transceiver", description=rdescr,
                ),
            ))
    return slot_ifaces, sub_bays


def _iosxr_netconf_attach_sub_bays(
    rows: list[dict],
    bays_by_rack: dict[int, list[_ModuleBay]],
) -> dict[int | None, dict[str, list[str]]]:
    """Second pass: attach optic sub-bays + build interfaces_by_bay per member."""
    ifaces_by_member: dict[int | None, dict[str, list[str]]] = {}
    vsf = len(bays_by_rack) >= 2
    for rack, bays in bays_by_rack.items():
        member = rack if vsf else None
        for bay in bays:
            if not _IOSXR_LC_RE.match(bay.name):
                continue
            slot = bay.name.split("/")[1]
            slot_prefix = f"{rack}/{slot}/"
            slot_ifaces, sub_bays = _iosxr_netconf_collect_slot_ports(rows, slot_prefix)
            for sb in sub_bays:
                ifaces_by_member.setdefault(member, {})[sb.name] = [sb.name]
            if sub_bays:
                bay.module.sub_bays.extend(sub_bays)
            if slot_ifaces:
                ifaces_by_member.setdefault(member, {})[bay.name] = list(slot_ifaces)
    return ifaces_by_member


def _iosxr_netconf_get_modules_impl(driver) -> dict | None:
    """
    Standalone + nV-cluster module discovery for IOS-XR via NETCONF.

    Mirrors the SSH driver's two-pass build (top-level bays, then optic
    sub-bay attachment) once the XML response has been flattened to rows.
    """
    try:
        reply = driver.device.get(filter=("subtree", _INV_FILTER))
    except NCClientError as e:
        # Narrow catch: NCClientError covers all ncclient transport / operation /
        # RPC failures but lets programming errors (AttributeError, TypeError) on
        # `driver.device` propagate so they're not silently masked as transport
        # errors in tests or development.
        logger.warning("iosxr_netconf.get_modules: NETCONF get failed: %s", e)
        return None
    xml_text = getattr(reply, "xml", None) or getattr(reply, "data_xml", None) or ""
    if not xml_text:
        return None
    rows = _iosxr_netconf_rows_from_xml(xml_text)
    if not rows:
        return None

    bays_by_rack = _iosxr_netconf_build_top_bays(rows)
    if not bays_by_rack:
        return None

    ifaces_by_member = _iosxr_netconf_attach_sub_bays(rows, bays_by_rack)
    vsf = len(bays_by_rack) >= 2

    if vsf:
        return _modules_to_payload({
            rack: _MemberModules(bays=bays, interfaces_by_bay=ifaces_by_member.get(rack, {}))
            for rack, bays in bays_by_rack.items()
        })
    only_rack = next(iter(bays_by_rack))
    return _modules_to_payload({
        None: _MemberModules(
            bays=bays_by_rack[only_rack],
            interfaces_by_bay=ifaces_by_member.get(None, {}),
        ),
    })


class IOSXRNETCONFDriver(_UpstreamIOSXRNetconfDriver):
    """Custom IOS-XR NETCONF driver shim adding get_modules()."""

    def get_modules(self) -> dict | None:
        """Return per-rack module / module-bay inventory or None."""
        return _iosxr_netconf_get_modules_impl(self)
