# Copyright 2026 NetBox Labs Inc
# Based on napalm-sros (Apache-2.0): https://github.com/napalm-automation-community/napalm-sros
"""
Custom Nokia SR-OS NETCONF NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans,
  get_modules.

Uses ncclient for NETCONF/YANG transport and lxml for structured XML parsing
against Nokia's YANG models (urn:nokia.com:sros:ns:yang:sr:*).

Modernisations over the community napalm-sros driver:
  - logging.exception() replaces print() + traceback
  - lxml.etree used directly (not ncclient.xml_ shims)
  - Inline NETCONF filters (no separate nc_filters module)
  - Multiple IPv4 secondary addresses handled via loop
  - No config-write methods (read-only subset)
  - No extra paramiko SSH channel
  - Type hints throughout
"""

import logging
import re
from datetime import datetime

import napalm.base as _napalm_base
from lxml import etree
from napalm.base import models
from napalm.base.helpers import convert
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
    orphan_optic_bay as _orphan_optic_bay,
)
from custom_napalm._modules import (
    to_payload as _modules_to_payload,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Nokia YANG namespaces
# ---------------------------------------------------------------------------

_NS_STATE = "urn:nokia.com:sros:ns:yang:sr:state"
_NS_CONF = "urn:nokia.com:sros:ns:yang:sr:conf"
_NS_NC = "urn:ietf:params:xml:ns:netconf:base:1.0"

_NSMAP: dict[str, str] = {
    "state_ns": _NS_STATE,
    "configure_ns": _NS_CONF,
}

# ---------------------------------------------------------------------------
# NETCONF filters
# ---------------------------------------------------------------------------

_FILTER_FACTS = f"""
<filter xmlns="{_NS_NC}">
    <state xmlns="{_NS_STATE}">
        <chassis>
            <hardware-data>
                <serial-number/>
            </hardware-data>
        </chassis>
        <system>
            <oper-name/>
            <up-time/>
            <platform/>
            <version>
                <version-number/>
            </version>
        </system>
        <port>
            <port-id/>
        </port>
        <router>
            <router-name/>
            <interface>
                <interface-name/>
            </interface>
        </router>
    </state>
</filter>
"""

# R19 uses <if-oper-status> instead of <oper-state> for router interfaces.
# The tag is injected at runtime via .format().
_FILTER_INTERFACES_TMPL = """\
<filter xmlns="{ns_nc}">
    <state xmlns="{ns_state}">
        <port>
            <port-id/>
            <oper-state/>
            <hardware-mac-address/>
            <ethernet>
                <oper-speed/>
            </ethernet>
        </port>
        <router>
            <router-name/>
            <interface>
                <interface-name/>
                <oper-ip-mtu/>
                {oper_state_tag}
                <last-oper-change/>
            </interface>
        </router>
        <chassis>
            <hardware-data>
                <base-mac-address/>
            </hardware-data>
        </chassis>
    </state>
    <configure xmlns="{ns_conf}">
        <port>
            <port-id/>
            <description/>
            <admin-state/>
            <ethernet>
                <mtu/>
            </ethernet>
        </port>
        <router>
            <router-name/>
            <interface>
                <interface-name/>
                <admin-state/>
                <description/>
                <mac/>
                <port/>
                <loopback/>
            </interface>
        </router>
    </configure>
</filter>"""

_FILTER_INTERFACES_IP = f"""
<filter xmlns="{_NS_NC}">
    <configure xmlns="{_NS_CONF}">
        <router>
            <router-name/>
            <interface>
                <interface-name/>
                <ipv4>
                    <primary>
                        <address/>
                        <prefix-length/>
                    </primary>
                    <secondary>
                        <address/>
                        <prefix-length/>
                    </secondary>
                </ipv4>
                <ipv6>
                    <address>
                        <ipv6-address/>
                        <prefix-length/>
                    </address>
                </ipv6>
            </interface>
        </router>
        <service>
            <vprn>
                <service-name/>
                <interface>
                    <interface-name/>
                    <ipv4>
                        <primary>
                            <address/>
                            <prefix-length/>
                        </primary>
                        <secondary>
                            <address/>
                            <prefix-length/>
                        </secondary>
                    </ipv4>
                    <ipv6>
                        <address>
                            <ipv6-address/>
                            <prefix-length/>
                        </address>
                    </ipv6>
                </interface>
            </vprn>
        </service>
    </configure>
</filter>
"""

# Subtree filter for module / module bay discovery. Returns the chassis
# fingerprint plus every card (CPM, IOM, IMM, SFM) with its nested MDA list.
_FILTER_MODULES = f"""
<filter xmlns="{_NS_NC}">
    <state xmlns="{_NS_STATE}">
        <chassis>
            <hardware-data>
                <part-number/>
                <serial-number/>
                <manufactured-string/>
            </hardware-data>
        </chassis>
        <card>
            <slot-number/>
            <equipped-type/>
            <hardware-data>
                <part-number/>
                <serial-number/>
            </hardware-data>
            <mda>
                <mda-slot/>
                <equipped-type/>
                <hardware-data>
                    <part-number/>
                    <serial-number/>
                </hardware-data>
            </mda>
        </card>
        <sfm>
            <sfm-slot/>
            <equipped-type/>
            <hardware-data>
                <part-number/>
                <serial-number/>
            </hardware-data>
        </sfm>
    </state>
</filter>
"""

# Separate filter for transceiver inventory under each port. Issued as a
# second RPC so the cheap card-only path stays small for chassis without
# optics enumerated.
_FILTER_PORTS_TRANSCEIVER = f"""
<filter xmlns="{_NS_NC}">
    <state xmlns="{_NS_STATE}">
        <port>
            <port-id/>
            <transceiver>
                <model/>
                <serial-number/>
                <part-number/>
                <vendor-manufacture-code/>
            </transceiver>
        </port>
    </state>
</filter>
"""

# Subtree filter for VRF (VPRN service) discovery. One RPC returns every
# VPRN with its route distinguisher (bgp-ipvpn/mpls) and member interfaces.
_FILTER_NETWORK_INSTANCES = f"""
<filter xmlns="{_NS_NC}">
    <configure xmlns="{_NS_CONF}">
        <service>
            <vprn>
                <service-name/>
                <bgp-ipvpn>
                    <mpls>
                        <route-distinguisher/>
                    </mpls>
                </bgp-ipvpn>
                <interface>
                    <interface-name/>
                </interface>
            </vprn>
        </service>
    </configure>
</filter>
"""

# ---------------------------------------------------------------------------
# Config sanitization — Nokia SR-OS YANG XML sensitive element content
# ---------------------------------------------------------------------------
# Pattern: (<tag>)[^<]*(</tag>)  →  \1REDACTED\2
# Covers both plain-text and encrypted values inside XML elements.
# Note: replacement is the plain word REDACTED (not XML tags) so the output
# remains well-formed XML and can be re-parsed without errors.

_AUTH_KEY_RE = re.compile(r"(<authentication-key>)[^<]*(</authentication-key>)", re.IGNORECASE)
_HMAC_MD5_RE = re.compile(r"(<hmac-md5-key>)[^<]*(</hmac-md5-key>)", re.IGNORECASE)
_DES_KEY_RE = re.compile(r"(<des-key>)[^<]*(</des-key>)", re.IGNORECASE)
_AES_KEY_RE = re.compile(r"(<aes-key>)[^<]*(</aes-key>)", re.IGNORECASE)
_PASSWORD_RE = re.compile(r"(<password>)[^<]*(</password>)", re.IGNORECASE)
_SECRET_RE = re.compile(r"(<secret>)[^<]*(</secret>)", re.IGNORECASE)
_COMMUNITY_STR_RE = re.compile(r"(<community-string>)[^<]*(</community-string>)", re.IGNORECASE)
_PRIVATE_KEY_RE = re.compile(r"(<private-key>)[^<]*(</private-key>)", re.IGNORECASE)
_PSK_RE = re.compile(r"(<pre-shared-key>)[^<]*(</pre-shared-key>)", re.IGNORECASE)


def _sanitize_config(text: str) -> str:
    """Redact Nokia SR-OS YANG XML secret values, replacing content with REDACTED."""
    text = _AUTH_KEY_RE.sub(r"\1REDACTED\2", text)
    text = _HMAC_MD5_RE.sub(r"\1REDACTED\2", text)
    text = _DES_KEY_RE.sub(r"\1REDACTED\2", text)
    text = _AES_KEY_RE.sub(r"\1REDACTED\2", text)
    text = _PASSWORD_RE.sub(r"\1REDACTED\2", text)
    text = _SECRET_RE.sub(r"\1REDACTED\2", text)
    text = _COMMUNITY_STR_RE.sub(r"\1REDACTED\2", text)
    text = _PRIVATE_KEY_RE.sub(r"\1REDACTED\2", text)
    text = _PSK_RE.sub(r"\1REDACTED\2", text)
    return text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Safe XML parser — disables external entity expansion and network access to prevent
# XXE (XML External Entity) injection attacks on untrusted NETCONF responses.
_SAFE_XML_PARSER = etree.XMLParser(resolve_entities=False, no_network=True)


def _parse_xml(data_xml: str | bytes) -> etree._Element:
    """Parse a NETCONF data_xml payload into an lxml Element."""
    if isinstance(data_xml, str):
        data_xml = data_xml.encode("utf-8")
    return etree.fromstring(data_xml, parser=_SAFE_XML_PARSER)


def _with_defaults_kwarg(capabilities: list[str]) -> dict:
    """
    Return ``{"with_defaults": "report-all"}`` only when the server advertises it.

    ncclient raises ``MissingCapabilityError`` if ``with_defaults`` is passed to a
    server that has not announced the ``:with-defaults`` capability, so we must
    gate the argument on the negotiated capability set.
    """
    if any("with-defaults" in c for c in capabilities):
        return {"with_defaults": "report-all"}
    return {}


def _find_txt(xml_tree: etree._Element, xpath: str, default: str = "") -> str:
    """Extract the text of the first XPath match; return *default* on miss."""
    try:
        results = xml_tree.xpath(xpath, namespaces=_NSMAP)
        if results:
            node = results[0]
            if hasattr(node, "text") and node.text is not None:
                return node.text.strip()
            if isinstance(node, str):
                return node.strip()
    except Exception:
        logger.debug("XPath '%s' returned nothing", xpath)
    return default


def _xpath_one(xml_tree: etree._Element, xpath: str) -> etree._Element | None:
    """Return the first XPath match as an Element, or None."""
    try:
        results = xml_tree.xpath(xpath, namespaces=_NSMAP)
        return results[0] if results else None
    except Exception:
        return None


def _port_ref_from_cfg(cfg_block: etree._Element | None) -> str:
    """
    Extract the bare port-id from a configure/router/interface block.

    SR-OS encodes sub-interface references as ``port-id:channel`` (e.g. ``1/1/1:0``).
    The channel suffix after the colon is stripped so the result matches the
    top-level port-id key used in the state tree.
    """
    if cfg_block is None:
        return ""
    port_ref = _find_txt(cfg_block, "configure_ns:port")
    return port_ref.split(":")[0] if ":" in port_ref else port_ref


def _resolve_if_mac(
    result: etree._Element,
    cfg_block: etree._Element | None,
    if_name: str,
    chassis_mac: str,
) -> str:
    """Resolve MAC for a logical router interface: cfg override → port MAC → chassis MAC."""
    if cfg_block is not None:
        cfg_mac = _find_txt(cfg_block, "configure_ns:mac")
        if cfg_mac:
            return cfg_mac
    if_port = _port_ref_from_cfg(cfg_block)
    if if_port:
        port_state = _xpath_one(result, f'state_ns:state/state_ns:port[state_ns:port-id="{if_port}"]')
        if port_state is not None:
            port_mac = _find_txt(port_state, "state_ns:hardware-mac-address")
            if port_mac:
                return port_mac
    if if_name == "system":
        return chassis_mac
    return ""


def _resolve_if_speed(result: etree._Element, cfg_block: etree._Element | None) -> float:
    """Resolve speed for a logical router interface from its associated port."""
    if_port = _port_ref_from_cfg(cfg_block)
    if not if_port:
        return -1.0
    port_state = _xpath_one(result, f'state_ns:state/state_ns:port[state_ns:port-id="{if_port}"]')
    if port_state is None:
        return -1.0
    return convert(float, _find_txt(port_state, "state_ns:ethernet/state_ns:oper-speed"), default=-1.0)


def _extract_if_addrs(interface: etree._Element) -> dict:
    """Build the IP address dict for a single configure/interface element."""
    entry: dict = {}

    # IPv4 primary
    ipv4_primary = _find_txt(interface, "configure_ns:ipv4/configure_ns:primary/configure_ns:address")
    if ipv4_primary:
        entry.setdefault("ipv4", {})[ipv4_primary] = {
            "prefix_length": convert(
                int,
                _find_txt(interface, "configure_ns:ipv4/configure_ns:primary/configure_ns:prefix-length"),
                default=0,
            )
        }

    # IPv4 secondaries (can be multiple)
    for secondary in interface.xpath("configure_ns:ipv4/configure_ns:secondary", namespaces=_NSMAP):
        sec_addr = _find_txt(secondary, "configure_ns:address")
        if sec_addr:
            entry.setdefault("ipv4", {})[sec_addr] = {
                "prefix_length": convert(int, _find_txt(secondary, "configure_ns:prefix-length"), default=0)
            }

    # IPv6 addresses (can be multiple)
    for ipv6_entry in interface.xpath("configure_ns:ipv6/configure_ns:address", namespaces=_NSMAP):
        ipv6_addr = _find_txt(ipv6_entry, "configure_ns:ipv6-address")
        if ipv6_addr:
            entry.setdefault("ipv6", {})[ipv6_addr] = {
                "prefix_length": convert(int, _find_txt(ipv6_entry, "configure_ns:prefix-length"), default=0)
            }

    return entry


def _merge_if_addrs(interfaces_ip: dict, key: str, entry: dict) -> None:
    """Merge *entry* address families into *interfaces_ip[key]*."""
    if not entry:
        return
    existing = interfaces_ip.setdefault(key, {})
    for family, addrs in entry.items():
        existing.setdefault(family, {}).update(addrs)


# strptime format fallbacks for Nokia last-oper-change timestamps.
# %f accepts 1–6 fractional-second digits (unlike Python 3.10 fromisoformat),
# so ".0" and ".123" are both handled correctly.
# %z accepts "+HHMM" / "+HH:MM" forms; "Z" is normalised to "+0000" before parsing.
_FLAP_FMTS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",  # with fractional seconds  (e.g. 2021-06-01T08:00:00.0Z)
    "%Y-%m-%dT%H:%M:%S%z",     # without fractional seconds (e.g. 2021-06-01T08:00:00Z)
)


def _parse_last_flapped(flap_str: str) -> float:
    """
    Convert a Nokia last-oper-change timestamp to a UTC epoch float.

    Accepts RFC 3339 variants with or without fractional seconds, and with
    either a ``Z`` suffix or a numeric UTC offset.
    """
    if not flap_str:
        return -1.0
    # strptime %z needs "+HHMM"; normalise the UTC "Z" designator.
    s = flap_str[:-1] + "+0000" if flap_str.endswith("Z") else flap_str
    for fmt in _FLAP_FMTS:
        try:
            return datetime.strptime(s, fmt).timestamp()
        except ValueError:
            continue
    logger.debug("Cannot parse last-oper-change: %s", flap_str)
    return -1.0


# ---------------------------------------------------------------------------
# get_modules — module / module bay discovery via NETCONF
# ---------------------------------------------------------------------------


def classify_module_type_nokia_sros(equipped_type: str) -> str:
    """
    Classify a Nokia SR-OS card / MDA by its equipped-type string.

      iom*, imm*, xcm*  -> linecard  (XCM = 7950 XRS forwarding card)
      cpm*              -> supervisor
      sfm*              -> linecard (no separate fabric type today)
      anything else     -> "other" (envelope drops on emit)
    """
    et = (equipped_type or "").strip().lower()
    if et.startswith(("iom", "imm", "xcm")):
        return "linecard"
    if et.startswith("cpm"):
        return "supervisor"
    if et.startswith("sfm"):
        return "linecard"
    return "other"


def _nokia_sros_rows_from_state_xml(state_root: etree._Element) -> list[dict]:
    """Walk state/card[/mda] and return a flat row list (cards + nested MDAs)."""
    rows: list[dict] = []
    for card in state_root.findall("state_ns:card", _NSMAP):
        slot_el = card.find("state_ns:slot-number", _NSMAP)
        et_el = card.find("state_ns:equipped-type", _NSMAP)
        hw = card.find("state_ns:hardware-data", _NSMAP)
        pn_el = hw.find("state_ns:part-number", _NSMAP) if hw is not None else None
        sn_el = hw.find("state_ns:serial-number", _NSMAP) if hw is not None else None
        slot = (slot_el.text or "").strip() if slot_el is not None else ""
        if not slot:
            continue
        rows.append({
            "kind": "card",
            "slot": slot,
            "parent_slot": None,
            "mda_slot": None,
            "equipped_type": (et_el.text or "").strip() if et_el is not None else "",
            "pid": (pn_el.text or "").strip() if pn_el is not None else "",
            "sn": (sn_el.text or "").strip() if sn_el is not None else "",
        })
        for mda in card.findall("state_ns:mda", _NSMAP):
            mslot_el = mda.find("state_ns:mda-slot", _NSMAP)
            met_el = mda.find("state_ns:equipped-type", _NSMAP)
            mhw = mda.find("state_ns:hardware-data", _NSMAP)
            mpn = mhw.find("state_ns:part-number", _NSMAP) if mhw is not None else None
            msn = mhw.find("state_ns:serial-number", _NSMAP) if mhw is not None else None
            mslot = (mslot_el.text or "").strip() if mslot_el is not None else ""
            if not mslot:
                continue
            rows.append({
                "kind": "mda",
                "slot": f"{slot}/{mslot}",
                "parent_slot": slot,
                "mda_slot": mslot,
                "equipped_type": (met_el.text or "").strip() if met_el is not None else "",
                "pid": (mpn.text or "").strip() if mpn is not None else "",
                "sn": (msn.text or "").strip() if msn is not None else "",
            })
    # SFMs live in a SEPARATE state subtree (not under <card>). Emit each as
    # a top-level bay; the existing classifier maps `sfm*` -> `linecard`.
    # Bay names are prefixed `SFM <N>` to avoid collision with same-numbered
    # card slots in a chassis that uses both namespaces.
    for sfm in state_root.findall("state_ns:sfm", _NSMAP):
        sslot_el = sfm.find("state_ns:sfm-slot", _NSMAP)
        set_el = sfm.find("state_ns:equipped-type", _NSMAP)
        shw = sfm.find("state_ns:hardware-data", _NSMAP)
        spn = shw.find("state_ns:part-number", _NSMAP) if shw is not None else None
        ssn = shw.find("state_ns:serial-number", _NSMAP) if shw is not None else None
        sslot = (sslot_el.text or "").strip() if sslot_el is not None else ""
        if not sslot:
            continue
        rows.append({
            "kind": "card",
            "slot": f"SFM {sslot}",
            "parent_slot": None,
            "mda_slot": None,
            "equipped_type": (set_el.text or "").strip() if set_el is not None else "",
            "pid": (spn.text or "").strip() if spn is not None else "",
            "sn": (ssn.text or "").strip() if ssn is not None else "",
        })
    return rows


def _nokia_sros_transceiver_rows_from_state_xml(state_root: etree._Element) -> list[dict]:
    """
    Walk state/port[*] and return per-port rows.

    Every discovered port emits a row regardless of transceiver presence —
    copper / RJ45 / empty-cage ports also need a parent-bay routing entry.
    Model and serial fields are populated only when a transceiver is
    installed AND exposes both values; otherwise the row is port_id-only.
    """
    rows: list[dict] = []
    for port in state_root.findall("state_ns:port", _NSMAP):
        port_id_el = port.find("state_ns:port-id", _NSMAP)
        if port_id_el is None:
            continue
        port_id = (port_id_el.text or "").strip()
        if not port_id:
            continue
        model = ""
        sn = ""
        tx = port.find("state_ns:transceiver", _NSMAP)
        if tx is not None:
            model_el = tx.find("state_ns:model", _NSMAP)
            sn_el = tx.find("state_ns:serial-number", _NSMAP)
            part_el = tx.find("state_ns:part-number", _NSMAP)
            model = (model_el.text or "").strip() if model_el is not None else ""
            sn = (sn_el.text or "").strip() if sn_el is not None else ""
            if not model and part_el is not None:
                model = (part_el.text or "").strip()
        rows.append({"port_id": port_id, "model": model, "sn": sn})
    return rows


def _nokia_sros_slot_sort_key(slot: str) -> tuple[int, int | str]:
    """Stable order for SR-OS chassis slots: letter slots (CPM-A/B) first, then numeric."""
    if slot.isalpha():
        return (0, slot)
    try:
        return (1, int(slot))
    except ValueError:
        return (2, slot)


def _nokia_sros_build_card_bays(rows: list[dict]) -> list[_ModuleBay]:
    """First pass: emit one top-level bay per card row, sorted for stable output."""
    bays: list[_ModuleBay] = []
    for row in rows:
        if row.get("kind") != "card":
            continue
        pid = row.get("pid") or ""
        sn = row.get("sn") or ""
        et = row.get("equipped_type") or ""
        slot = row.get("slot") or ""
        if not (pid and sn and slot):
            continue
        mtype = classify_module_type_nokia_sros(et)
        if mtype == "other":
            continue
        bays.append(_ModuleBay(
            name=slot,
            position=slot,
            module=_ModuleEntry(
                model=pid, serial=sn, type=mtype, description=et,
            ),
        ))
    bays.sort(key=lambda b: _nokia_sros_slot_sort_key(b.name))
    return bays


def _nokia_sros_attach_mda_sub_bays(
    rows: list[dict],
    bays: list[_ModuleBay],
) -> dict[str, _ModuleBay]:
    """Second pass: nest MDA sub-bays under their parent card. Returns mda-path -> bay."""
    bays_by_slot: dict[str, _ModuleBay] = {bay.name: bay for bay in bays}
    mda_bays_by_path: dict[str, _ModuleBay] = {}
    for row in rows:
        if row.get("kind") != "mda":
            continue
        parent_slot = row.get("parent_slot") or ""
        mda_slot = row.get("mda_slot") or ""
        pid = row.get("pid") or ""
        sn = row.get("sn") or ""
        et = row.get("equipped_type") or ""
        if not (parent_slot and mda_slot and pid and sn):
            continue
        parent_bay = bays_by_slot.get(parent_slot)
        if parent_bay is None or parent_bay.module is None:
            continue
        mda_bay = _ModuleBay(
            name=f"{parent_slot}/{mda_slot}",
            position=f"{parent_slot}/{mda_slot}",
            module=_ModuleEntry(
                model=pid, serial=sn, type="linecard", description=et,
            ),
        )
        parent_bay.module.sub_bays.append(mda_bay)
        mda_bays_by_path[f"{parent_slot}/{mda_slot}"] = mda_bay
    return mda_bays_by_path


def _nokia_sros_attach_transceiver_sub_bays(
    transceiver_rows: list[dict],
    mda_bays_by_path: dict[str, _ModuleBay],
    bays: list[_ModuleBay],
) -> dict[str, list[str]]:
    """Route every port to its parent bays; emit transceiver sub-bay only when populated."""
    interfaces_by_bay: dict[str, list[str]] = {}
    # Snapshot whether this chassis had ANY card bay BEFORE the promotion
    # loop runs. `bays` is the very list promotion appends device-rooted
    # optics to, so testing it live would let the first promoted optic make
    # `bays` non-empty and wrongly decline every optic that follows on a
    # genuinely fixed platform (no cards at all). Capturing the snapshot
    # once, before the loop, is what lets every fixed-platform optic
    # promote while still refusing promotion on a modular chassis whose
    # card hierarchy is real but an MDA row happens to be incomplete.
    #
    # This is the deliberate opposite of the ios-xr rack-roster guard
    # (`if bays_by_rack and rack not in bays_by_rack`), which reads its
    # roster live on purpose: ios-xr asks "is this rack already known?",
    # where minting the first rack is legitimate and the guard must see
    # its own additions. Nokia asks "did this chassis have a card hierarchy
    # at all?" — a property of the input that promotion must not be able
    # to change by running.
    had_card_bays = bool(bays)
    for row in transceiver_rows:
        port_id = row.get("port_id") or ""
        if not port_id:
            continue
        parts = port_id.split("/")
        if len(parts) < 3:
            continue
        mda_path = f"{parts[0]}/{parts[1]}"
        mda_bay = mda_bays_by_path.get(mda_path)
        card_slot = parts[0]
        model = row.get("model") or ""
        sn = row.get("sn") or ""
        if mda_bay is None or mda_bay.module is None:
            if had_card_bays:
                # Modular chassis: this MDA row either lacked a PID/serial
                # or its parent card never made it into the bay map — it is
                # real hardware that simply didn't reach mda_bays_by_path.
                # Promoting the optic device-rooted would invent a false
                # topology (the optic actually sits inside an MDA inside a
                # card), so decline rather than promote.
                if model and sn:
                    logger.debug(
                        "nokia_sros.get_modules: declining optic on port %s, "
                        "MDA %s missing from bay map",
                        port_id, mda_path,
                    )
                continue
            # Fixed platforms expose ports with no MDA module above them.
            if model and sn:
                bays.append(_orphan_optic_bay(port_id, _ModuleEntry(
                    model=model, serial=sn, type="transceiver", description="",
                )))
                interfaces_by_bay[port_id] = [port_id]
            continue
        # Routing layers are emitted for EVERY discovered port (copper,
        # empty cage, optic-without-data, …) — get_interfaces() emits the
        # physical port regardless of optic, so it needs a module to land
        # on in both linecards and full modes:
        #   - card-slot key   -> linecards mode routing
        #   - mda-path key    -> full mode at MDA depth
        interfaces_by_bay.setdefault(card_slot, []).append(port_id)
        interfaces_by_bay.setdefault(mda_path, []).append(port_id)
        # Transceiver sub-bay (and its per-port deepest-wins routing key)
        # only emit when the optic exposes both model and serial.
        if model and sn:
            mda_bay.module.sub_bays.append(_ModuleBay(
                name=port_id, position=port_id,
                module=_ModuleEntry(model=model, serial=sn, type="transceiver", description=""),
            ))
            interfaces_by_bay[port_id] = [port_id]
    return interfaces_by_bay


def _nokia_sros_get_modules_impl(driver) -> dict | None:
    """
    Module discovery for Nokia SR-OS via NETCONF.

    Two RPCs: first the card+MDA tree, then a best-effort transceiver pass.
    A fixed-port platform has no cards at all, so the "nothing found" gate
    runs after the transceiver pass: an orphan optic promoted to a
    device-rooted bay (no MDA parent) can carry the result on its own.
    The transceiver pass itself is non-fatal — a card-only envelope still
    ships if the second RPC fails.
    """
    # Narrow except scope: ncclient transport / RPC errors and lxml parse
    # errors are recoverable (return None / log + continue). Programming
    # errors (AttributeError on driver.conn=None, ImportError) propagate
    # so they surface as bugs instead of being silently masked.
    try:
        reply = driver.conn.get(filter=_FILTER_MODULES)
    except NCClientError as e:
        logger.warning("nokia_sros.get_modules: card RPC failed: %s", e)
        return None
    if getattr(reply, "data_xml", None) is None:
        logger.warning("nokia_sros.get_modules: card RPC returned empty data_xml")
        return None
    try:
        state = _parse_xml(reply.data_xml).find(".//state_ns:state", _NSMAP)
    except etree.XMLSyntaxError as e:
        logger.warning("nokia_sros.get_modules: card XML parse failed: %s", e)
        return None
    if state is None:
        return None
    rows = _nokia_sros_rows_from_state_xml(state)
    bays = _nokia_sros_build_card_bays(rows)
    mda_bays_by_path = _nokia_sros_attach_mda_sub_bays(rows, bays)

    interfaces_by_bay: dict[str, list[str]] = {}
    try:
        tx_reply = driver.conn.get(filter=_FILTER_PORTS_TRANSCEIVER)
        if getattr(tx_reply, "data_xml", None) is None:
            logger.warning("nokia_sros.get_modules: transceiver RPC returned empty data_xml")
        else:
            tx_state = _parse_xml(tx_reply.data_xml).find(".//state_ns:state", _NSMAP)
            if tx_state is not None:
                tx_rows = _nokia_sros_transceiver_rows_from_state_xml(tx_state)
                interfaces_by_bay = _nokia_sros_attach_transceiver_sub_bays(
                    tx_rows, mda_bays_by_path, bays,
                )
    except (NCClientError, etree.XMLSyntaxError) as e:
        # Non-fatal: cards-only payload still ships.
        logger.warning("nokia_sros.get_modules: transceiver RPC failed: %s", e)

    if not bays:
        return None

    return _modules_to_payload({
        None: _MemberModules(bays=bays, interfaces_by_bay=interfaces_by_bay),
    })


def _nokia_sros_filter_instances(instances: dict, name: str) -> dict:
    """Apply the NAPALM name-filter contract on every return path."""
    if name:
        return {name: instances[name]} if name in instances else {}
    return instances


def _nokia_sros_get_network_instances_impl(driver, name: str = "") -> dict:
    """
    VRF discovery for Nokia SR-OS via NETCONF: VPRN services as L3VRFs.

    SR OS models VRFs as VPRN services — each maps to a NetBox VRF, with
    member interfaces keyed "<service>/<interface>" to match how
    get_interfaces_ip() names them. The Base router is the global routing
    table and is emitted as the DEFAULT_INSTANCE with empty membership:
    the discovery pipeline only consumes VRF memberships, and interfaces
    of the Base and management router contexts (which get_interfaces_ip
    keys "<router>/<interface>" for non-Base routers) are deliberately
    not claimed by any VRF. The RD lives at vprn/bgp-ipvpn/mpls and is
    absent on VPRNs without an MPLS L3VPN backbone.
    """
    instances: dict = {
        "Base": {
            "name": "Base",
            "type": "DEFAULT_INSTANCE",
            "state": {"route_distinguisher": ""},
            "interfaces": {"interface": {}},
        },
    }
    try:
        reply = driver.conn.get(filter=_FILTER_NETWORK_INSTANCES)
    except NCClientError as e:
        logger.warning("nokia_sros.get_network_instances: VPRN RPC failed: %s", e)
        # Deliberately {} (not the seeded default instance): a transport
        # failure means the device state is unknown, and an empty dict is
        # the unambiguous "discovery failed" signal. The seeded default is
        # returned only on paths where the device DID respond — there the
        # default table is a platform invariant, not fabricated knowledge.
        return {}
    if getattr(reply, "data_xml", None) is None:
        logger.warning(
            "nokia_sros.get_network_instances: VPRN RPC returned empty data_xml"
        )
        return _nokia_sros_filter_instances(instances, name)
    try:
        root = _parse_xml(reply.data_xml)
    except etree.XMLSyntaxError as e:
        logger.warning("nokia_sros.get_network_instances: XML parse failed: %s", e)
        return _nokia_sros_filter_instances(instances, name)
    for vprn in root.findall(
        ".//configure_ns:service/configure_ns:vprn", _NSMAP,
    ):
        svc_el = vprn.find("configure_ns:service-name", _NSMAP)
        svc_name = (svc_el.text or "").strip() if svc_el is not None else ""
        # Never let a VPRN row overwrite the seeded DEFAULT_INSTANCE —
        # "Base" is the global routing table, not an L3VRF. Mirrors the
        # IOS-XR drivers' guard against rows named "default".
        if not svc_name or svc_name == "Base":
            continue
        rd_el = vprn.find(
            "configure_ns:bgp-ipvpn/configure_ns:mpls/configure_ns:route-distinguisher",
            _NSMAP,
        )
        rd = (rd_el.text or "").strip() if rd_el is not None else ""
        interfaces: dict = {}
        for if_el in vprn.findall(
            "configure_ns:interface/configure_ns:interface-name", _NSMAP,
        ):
            ifname = (if_el.text or "").strip()
            if ifname:
                # Keyed "<service>/<interface>" to match how
                # get_interfaces_ip() names VPRN interfaces — downstream
                # VRF attachment joins on exact interface names.
                interfaces[f"{svc_name}/{ifname}"] = {}
        instances[svc_name] = {
            "name": svc_name,
            "type": "L3VRF",
            "state": {"route_distinguisher": rd},
            "interfaces": {"interface": interfaces},
        }
    return _nokia_sros_filter_instances(instances, name)


class SROSDriver(_napalm_base.NetworkDriver):
    """Nokia SR-OS NAPALM driver using NETCONF/YANG (read-only subset for device-discovery)."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Initialise driver — no network connection is made here."""
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.conn = None
        if optional_args is None:
            optional_args = {}
        self.port: int = int(optional_args.get("port", 830))
        # Accept both the ncclient-canonical "hostkey_verify" and the underscore
        # form "host_key_verify" so that either convention works in optional_args.
        self.hostkey_verify: bool = bool(
            optional_args.get("hostkey_verify", optional_args.get("host_key_verify", False))
        )
        # R19 = True for SR-OS < 21.x (older YANG revision 2016-07-06)
        self.R19: bool = False

    def open(self) -> None:
        """Open a NETCONF session to the device."""
        from ncclient import manager  # deferred: not needed until connection time

        self.conn = manager.connect(
            host=self.hostname,
            port=self.port,
            username=self.username,
            password=self.password,
            hostkey_verify=self.hostkey_verify,
            timeout=self.timeout,
        )
        # Detect legacy R19 YANG revision (SR-OS < 21.x firmware).
        # Capability URIs look like: urn:...nokia-state?module=nokia-state&revision=YYYY-MM-DD
        # Use a non-greedy match anchored to the revision parameter to avoid capturing
        # any subsequent query parameters (e.g. &features=...).
        _rev_re = re.compile(r"[?&]revision=([^&]+)")
        revisions = [
            m.group(1)
            for c in self.conn.server_capabilities
            if "nokia-state" in c and (m := _rev_re.search(c))
        ]
        self.R19 = "2016-07-06" in revisions

    def close(self) -> None:
        """Close the NETCONF session."""
        if self.conn is not None:
            self.conn.close_session()
            self.conn = None

    def is_alive(self) -> dict:
        """Return NETCONF session liveness by probing ncclient's connection state."""
        if self.conn is None:
            return {"is_alive": False}

        connected = getattr(self.conn, "connected", None)
        if connected is not None:
            return {"is_alive": bool(connected)}

        session = getattr(self.conn, "_session", None)
        if session is not None:
            session_connected = getattr(session, "connected", None)
            if session_connected is not None:
                return {"is_alive": bool(session_connected)}

            transport = getattr(session, "_transport", None)
            if transport is not None:
                is_active = getattr(transport, "is_active", None)
                if callable(is_active):
                    return {"is_alive": bool(is_active())}

        return {"is_alive": False}

    # -----------------------------------------------------------------------
    # NAPALM getters
    # -----------------------------------------------------------------------

    def get_facts(self) -> dict:
        """Return general device facts via NETCONF state tree."""
        try:
            result = _parse_xml(self.conn.get(filter=_FILTER_FACTS).data_xml)
            # ``_find_txt`` returns "" when the XPath misses, and an empty hostname
            # becomes an empty Device.name on the wire. Every other driver falls back
            # to the target host or "Unknown"; do the same here.
            hostname = (
                _find_txt(result, "state_ns:state/state_ns:system/state_ns:oper-name")
                or self.hostname
            )
            uptime_ms_str = _find_txt(result, "state_ns:state/state_ns:system/state_ns:up-time")
            # Nokia YANG up-time is milliseconds (integer string)
            uptime = convert(float, uptime_ms_str, default=0.0) / 1000.0 if uptime_ms_str else 0.0
            # Build interface list using the same scoping as get_interfaces():
            # Base router → bare name, non-Base routers → "{router}/{if_name}".
            # Physical port-ids are also included.
            interface_names: set[str] = set()
            for router_el in result.xpath("state_ns:state/state_ns:router", namespaces=_NSMAP):
                router_name = _find_txt(router_el, "state_ns:router-name")
                for if_el in router_el.xpath("state_ns:interface", namespaces=_NSMAP):
                    if_name = _find_txt(if_el, "state_ns:interface-name")
                    if not if_name:
                        continue
                    if router_name and router_name != "Base":
                        interface_names.add(f"{router_name}/{if_name}")
                    else:
                        interface_names.add(if_name)
            for port_el in result.xpath(
                "state_ns:state/state_ns:port/state_ns:port-id", namespaces=_NSMAP
            ):
                if port_el.text:
                    interface_names.add(port_el.text.strip())
            interface_list = sorted(interface_names)
            return {
                "hostname": hostname,
                "vendor": "Nokia",
                "model": _find_txt(result, "state_ns:state/state_ns:system/state_ns:platform"),
                "os_version": _find_txt(
                    result,
                    "state_ns:state/state_ns:system/state_ns:version/state_ns:version-number",
                ),
                "serial_number": _find_txt(
                    result,
                    "state_ns:state/state_ns:chassis/state_ns:hardware-data/state_ns:serial-number",
                ),
                "uptime": uptime,
                "fqdn": hostname,
                "interface_list": interface_list,
            }
        except Exception:
            logger.exception("get_facts failed")
            return {}

    def get_interfaces(self) -> dict:
        """
        Return interface details keyed by name (physical ports + logical router interfaces).

        Physical ports and logical interfaces from all router VRFs (Base router and named VRFs)
        are included. VPRN service interfaces are not enumerated here because they lack
        port-state (speed/MAC) data in the YANG model; their IP addresses are available via
        get_interfaces_ip().
        """
        try:
            oper_state_tag = "<if-oper-status/>" if self.R19 else "<oper-state/>"
            nc_filter = _FILTER_INTERFACES_TMPL.format(
                ns_nc=_NS_NC,
                ns_state=_NS_STATE,
                ns_conf=_NS_CONF,
                oper_state_tag=oper_state_tag,
            )
            get_kwargs = _with_defaults_kwarg(self.conn.server_capabilities)
            result = _parse_xml(self.conn.get(filter=nc_filter, **get_kwargs).data_xml)
            interfaces: dict = {}

            # --- Physical ports ---
            for port in result.xpath("state_ns:state/state_ns:port", namespaces=_NSMAP):
                port_id = _find_txt(port, "state_ns:port-id")
                if not port_id:
                    continue
                cfg_block = _xpath_one(
                    result,
                    f'configure_ns:configure/configure_ns:port[configure_ns:port-id="{port_id}"]',
                )
                interfaces[port_id] = {
                    "is_up": _find_txt(port, "state_ns:oper-state") == "up",
                    "is_enabled": (
                        _find_txt(cfg_block, "configure_ns:admin-state") == "enable"
                        if cfg_block is not None
                        else False
                    ),
                    "description": (
                        _find_txt(cfg_block, "configure_ns:description")
                        if cfg_block is not None
                        else ""
                    ),
                    "last_flapped": -1.0,
                    "speed": convert(
                        float,
                        _find_txt(port, "state_ns:ethernet/state_ns:oper-speed"),
                        default=-1.0,
                    ),
                    "mtu": convert(
                        int,
                        _find_txt(cfg_block, "configure_ns:ethernet/configure_ns:mtu")
                        if cfg_block is not None
                        else "",
                        default=-1,
                    ),
                    "mac_address": _find_txt(port, "state_ns:hardware-mac-address"),
                }

            # --- Logical router interfaces ---
            chassis_mac = _find_txt(
                result,
                "state_ns:state/state_ns:chassis/state_ns:hardware-data/state_ns:base-mac-address",
            )
            oper_state_xpath = "state_ns:if-oper-status" if self.R19 else "state_ns:oper-state"

            for router_state in result.xpath("state_ns:state/state_ns:router", namespaces=_NSMAP):
                router_name = _find_txt(router_state, "state_ns:router-name")
                for if_state in router_state.xpath("state_ns:interface", namespaces=_NSMAP):
                    self._add_router_if(
                        interfaces, if_state, result, router_name, oper_state_xpath, chassis_mac
                    )

            return interfaces
        except Exception:
            logger.exception("get_interfaces failed")
            return {}

    def _add_router_if(
        self,
        interfaces: dict,
        if_state: "etree._Element",
        result: "etree._Element",
        router_name: str,
        oper_state_xpath: str,
        chassis_mac: str,
    ) -> None:
        """Populate *interfaces* with one logical router interface entry."""
        if_name = _find_txt(if_state, "state_ns:interface-name")
        if not if_name:
            return
        # Qualify config lookup by router-name to avoid cross-router collisions.
        cfg_block = _xpath_one(
            result,
            f"configure_ns:configure/configure_ns:router"
            f'[configure_ns:router-name="{router_name}"]'
            f'/configure_ns:interface[configure_ns:interface-name="{if_name}"]',
        )
        # Key by plain interface-name for Base router; prefix with router-name for
        # named VRF routers so same-named interfaces across contexts don't collide.
        key = if_name if router_name == "Base" else f"{router_name}/{if_name}"
        interfaces[key] = {
            "is_up": _find_txt(if_state, oper_state_xpath) == "up",
            "is_enabled": _find_txt(cfg_block, "configure_ns:admin-state") == "enable"
            if cfg_block is not None
            else False,
            "description": _find_txt(cfg_block, "configure_ns:description")
            if cfg_block is not None
            else "",
            "last_flapped": _parse_last_flapped(_find_txt(if_state, "state_ns:last-oper-change")),
            "speed": _resolve_if_speed(result, cfg_block),
            "mtu": convert(int, _find_txt(if_state, "state_ns:oper-ip-mtu"), default=-1),
            "mac_address": _resolve_if_mac(result, cfg_block, if_name, chassis_mac),
        }

    def get_interfaces_ip(self) -> dict:
        """
        Return all configured IP addresses per interface (configure tree).

        Keys use the same scoping convention as ``get_interfaces()``: Base router
        interfaces are keyed by bare interface-name; non-Base router VRF interfaces
        are prefixed as ``{router_name}/{if_name}``; VPRN service interfaces are
        prefixed as ``{service_name}/{if_name}``.
        """
        try:
            get_kwargs = _with_defaults_kwarg(self.conn.server_capabilities)
            result = _parse_xml(self.conn.get(filter=_FILTER_INTERFACES_IP, **get_kwargs).data_xml)
            interfaces_ip: dict = {}

            # Router interfaces (Base router + named VRF routers)
            for router in result.xpath("configure_ns:configure/configure_ns:router", namespaces=_NSMAP):
                router_name = _find_txt(router, "configure_ns:router-name")
                for iface in router.xpath("configure_ns:interface", namespaces=_NSMAP):
                    if_name = _find_txt(iface, "configure_ns:interface-name")
                    if not if_name:
                        continue
                    key = if_name if router_name == "Base" else f"{router_name}/{if_name}"
                    _merge_if_addrs(interfaces_ip, key, _extract_if_addrs(iface))

            # VPRN service interfaces
            for vprn in result.xpath(
                "configure_ns:configure/configure_ns:service/configure_ns:vprn", namespaces=_NSMAP
            ):
                svc_name = _find_txt(vprn, "configure_ns:service-name")
                for iface in vprn.xpath("configure_ns:interface", namespaces=_NSMAP):
                    if_name = _find_txt(iface, "configure_ns:interface-name")
                    if not if_name:
                        continue
                    _merge_if_addrs(interfaces_ip, f"{svc_name}/{if_name}", _extract_if_addrs(iface))

            return interfaces_ip
        except Exception:
            logger.exception("get_interfaces_ip failed")
            return {}

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """Return Nokia SR-OS running configuration as NETCONF XML."""
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}
        try:
            if retrieve in ("all", "running"):
                data = _parse_xml(self.conn.get_config(source="running").data_xml)
                cfg_nodes = data.xpath("configure_ns:configure", namespaces=_NSMAP)
                if cfg_nodes:
                    config["running"] = etree.tostring(
                        cfg_nodes[0], pretty_print=True
                    ).decode("utf-8")
        except Exception:
            logger.exception("get_config failed")
        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])
        return config

    def get_vlans(self) -> dict:
        """Nokia SR-OS uses a service-based architecture — no traditional VLAN table."""
        return {}

    def get_modules(self) -> dict | None:
        """Return per-chassis module / module bay inventory or None."""
        return _nokia_sros_get_modules_impl(self)

    def get_network_instances(self, name: str = "") -> dict:
        """Return network instances (VPRNs as VRFs) keyed by name, NAPALM OC shape."""
        return _nokia_sros_get_network_instances_impl(self, name)
