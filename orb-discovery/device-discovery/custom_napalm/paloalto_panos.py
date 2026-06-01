# Copyright 2026 NetBox Labs Inc
# Based on napalm-panos (Apache-2.0): https://github.com/napalm-automation-community/napalm-panos
"""
Custom PAN-OS NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.
"""

import json
import logging
import re
import xml.etree.ElementTree

import napalm.base as _napalm_base
import pan.xapi
import xmltodict
from napalm.base import models
from napalm.base.exceptions import ConnectionException
from napalm.base.helpers import mac as standardize_mac
from napalm.base.utils.string_parsers import convert_uptime_string_seconds

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
    to_payload as _modules_to_payload,
)

logger = logging.getLogger(__name__)

_SECRET_TAG_RE = re.compile(
    r"(<(phash|password|psk|secret|hash|bind-password|api-key)>)"
    r"[^<]*"
    r"(</\2>)"
)


def _sanitize_config(text: str) -> str:
    return _SECRET_TAG_RE.sub(r"\1<redacted>\3", text)


def _extract_ip_info(parsed_intf_dict: dict) -> dict:
    """Extract NAPALM-format IP address info from a single PAN-OS interface dict."""
    intf = parsed_intf_dict["name"]
    ip_info: dict = {intf: {}}

    v4_ip = parsed_intf_dict.get("ip")
    secondary_v4_ip = parsed_intf_dict.get("addr")
    v6_ip = parsed_intf_dict.get("addr6")

    if v4_ip and v4_ip != "N/A":
        address, pref = v4_ip.split("/")
        ip_info[intf].setdefault("ipv4", {})[address] = {"prefix_length": int(pref)}

    if secondary_v4_ip is not None:
        members = secondary_v4_ip["member"]
        if not isinstance(members, list):
            members = [members]
        for entry in members:
            address, pref = entry.split("/")
            ip_info[intf].setdefault("ipv4", {})[address] = {"prefix_length": int(pref)}

    if v6_ip is not None:
        members = v6_ip["member"]
        if not isinstance(members, list):
            members = [members]
        for entry in members:
            address, pref = entry.split("/")
            ip_info[intf].setdefault("ipv6", {})[address] = {"prefix_length": int(pref)}

    if ip_info == {intf: {}}:
        return {}
    return ip_info


# ---------------------------------------------------------------------------
# get_modules — module / module bay discovery via PAN-OS XML API
# ---------------------------------------------------------------------------


_MODULAR_PANOS_PREFIXES = ("PA-7050", "PA-7080", "PA-7500", "PA-5450")


def _is_modular_panos(model: str | None) -> bool:
    """
    Return True when PAN-OS model identifies an in-scope modular chassis.

    Handles trailing variants like ``PA-7050B`` or ``PA-5450-AC`` by prefix
    match on the uppercased model string. Fixed-config / VM-series /
    Panorama appliances short-circuit before any chassis-inventory RPC.
    Accepts ``None`` to tolerate missing facts entries.
    """
    upper = (model or "").strip().upper()
    return any(upper.startswith(p) for p in _MODULAR_PANOS_PREFIXES)


# SKU card-type classifier. Each entry is a hyphen-bounded token that
# appears in PaloAlto card PIDs (e.g. `MPC` matches `PA-7500-MPC-A` AND
# `PA-XXX-MPC`). The token must be preceded by `-` and followed by either
# `-` or end-of-string — naked-substring matching would over-trigger.
#
# ORDER MATTERS (first-match-wins). The generic invariant: any token that
# is a strict substring of another token MUST appear AFTER the longer
# token. None of the current entries actually exhibit the substring
# relation, but `test_panos_sku_classifier_ordering_invariant` enforces
# the rule across the whole table — so future additions like a `PC`
# token (substring of MPC / NPC / DPC / LPC) would be caught.
_PANOS_SKU_CLASSIFIER: tuple[tuple[str, str], ...] = (
    ("MPC", "supervisor"),
    ("SMC", "supervisor"),
    ("SFC", "linecard"),
    ("NPC", "linecard"),
    ("LFC", "linecard"),
    ("LPC", "linecard"),
    ("DPC", "linecard"),
    ("BC", "linecard"),
    ("NC", "linecard"),
)


def classify_module_type_panos(part_number: str) -> str:
    """Classify a PAN-OS card by hyphen-bounded token in the SKU (case-insensitive)."""
    pid = (part_number or "").upper()
    for token, mtype in _PANOS_SKU_CLASSIFIER:
        if f"-{token}-" in pid or pid.endswith(f"-{token}"):
            return mtype
    return "other"


def _panos_token_from_sku(part_number: str) -> str:
    """Extract canonical card-type token from a PaloAlto SKU (e.g. "NPC" from "PA-7000-100G-NPC-A")."""
    pid = (part_number or "").upper()
    for token, _ in _PANOS_SKU_CLASSIFIER:
        if f"-{token}-" in pid or pid.endswith(f"-{token}"):
            return token
    return ""


def _extract_model_from_info_xml(xml_text: str) -> str:
    """
    Extract <model> text from a `<show><system><info>` response.

    Returns empty string if the model element is absent or parsing fails.
    """
    if not xml_text:
        return ""
    try:
        root = xml.etree.ElementTree.fromstring(xml_text)
    except xml.etree.ElementTree.ParseError as e:
        logger.warning("paloalto_panos.get_modules: system info parse failed: %s", e)
        return ""
    model_el = root.find(".//system/model")
    return (model_el.text or "").strip() if model_el is not None else ""


def _parse_chassis_inventory_xml(xml_text: str) -> list[dict]:
    """
    Parse `<show><chassis><inventory></inventory></chassis></show>` response.

    Walks ``chassis/slots/entry/*`` and returns one row per ``<entry>``,
    with empty strings for any missing child element. Filtering of rows
    that lack a usable PID or serial happens downstream in
    ``_panos_build_bays``; this layer is intentionally permissive so the
    PA-5450 Base Card row (blank ``<slot>``) reaches the builder.
    """
    rows: list[dict] = []
    try:
        root = xml.etree.ElementTree.fromstring(xml_text)
    except xml.etree.ElementTree.ParseError as e:
        logger.warning("paloalto_panos.get_modules: chassis inventory parse failed: %s", e)
        return rows
    for entry in root.findall(".//chassis/slots/entry"):
        slot_el = entry.find("slot")
        pn_el = entry.find("part-number")
        sn_el = entry.find("serial")
        # Empty / missing <slot> is allowed at the parser layer — the
        # builder synthesizes a bay name from the SKU token for cards like
        # the PA-5450 Base Card that PAN-OS prints without a slot id.
        rows.append({
            "slot": (slot_el.text or "").strip() if slot_el is not None else "",
            "pid": (pn_el.text or "").strip() if pn_el is not None else "",
            "sn": (sn_el.text or "").strip() if sn_el is not None else "",
        })
    return rows


def _panos_build_bays(rows: list[dict]) -> list[_ModuleBay]:
    """Build one top-level bay per inventory row; description derived from SKU token."""
    bays: list[_ModuleBay] = []
    for row in rows:
        slot = row.get("slot") or ""
        pid = row.get("pid") or ""
        sn = row.get("sn") or ""
        if not (pid and sn):
            continue
        mtype = classify_module_type_panos(pid)
        if mtype == "other":
            continue
        token = _panos_token_from_sku(pid)
        # PA-5450 Base Card prints with a blank Slot column in real PAN-OS
        # output — synthesize a bay name from the SKU token so the bay
        # still emits with a stable human-readable id.
        if not slot:
            slot = token
        if not slot:
            continue
        bays.append(_ModuleBay(
            name=slot, position=slot,
            module=_ModuleEntry(
                model=pid, serial=sn, type=mtype, description=token,
            ),
        ))
    return bays


def _panos_get_modules_impl(driver) -> dict | None:
    """
    Module discovery for PaloAlto PAN-OS via XML API.

    1. Issue `<show><system><info></info></system></show>`, read model.
    2. Short-circuit on non-modular models (no second RPC).
    3. Issue `<show><chassis><inventory></inventory></chassis></show>` op RPC.
    4. Parse slots and emit canonical envelope.

    Goes direct to a lightweight model lookup instead of calling
    ``driver.get_facts()`` — that getter issues a heavy
    `<show><interface>all</interface></show>` RPC that we don't need just
    to decide whether the chassis is modular.
    """
    try:
        driver.device.op(cmd="<show><system><info></info></system></show>")
        info_xml = driver.device.xml_root()
    except pan.xapi.PanXapiError as e:
        logger.warning("paloalto_panos.get_modules: system info RPC failed: %s", e)
        return None
    model = _extract_model_from_info_xml(info_xml or "")
    if not _is_modular_panos(model):
        return None
    try:
        driver.device.op(cmd="<show><chassis><inventory></inventory></chassis></show>")
        xml_text = driver.device.xml_root()
    except pan.xapi.PanXapiError as e:
        logger.warning("paloalto_panos.get_modules: chassis inventory RPC failed: %s", e)
        return None
    rows = _parse_chassis_inventory_xml(xml_text or "")
    bays = _panos_build_bays(rows)
    if not bays:
        return None
    return _modules_to_payload({
        None: _MemberModules(bays=bays, interfaces_by_bay={}),
    })


class PANOSDriver(_napalm_base.NetworkDriver):
    """PAN-OS NAPALM driver (read-only subset for device-discovery)."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Initialize the driver."""
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.device = None

        if optional_args is None:
            optional_args = {}
        self.api_key = optional_args.get("api_key", "")

    def open(self):
        """Open connection to the device using the PAN-OS XML API."""
        try:
            if self.api_key:
                self.device = pan.xapi.PanXapi(
                    hostname=self.hostname,
                    api_key=self.api_key,
                )
            else:
                self.device = pan.xapi.PanXapi(
                    hostname=self.hostname,
                    api_username=self.username,
                    api_password=self.password,
                )
        except Exception as exc:
            raise ConnectionException(str(exc))

    def close(self):
        """Close connection."""
        self.device = None

    def is_alive(self):
        """Return liveness status."""
        return {"is_alive": self.device is not None}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_interface_list(self):
        """Return a flat list of all interface names from the device."""
        self.device.op(cmd="<show><interface>all</interface></show>")
        interfaces_xml = xmltodict.parse(self.device.xml_root())
        interfaces_json = json.dumps(interfaces_xml["response"]["result"])
        interfaces = json.loads(interfaces_json)

        if interfaces is None:
            return []

        interface_set = set()
        for entry in interfaces.values():
            for entry_contents in entry.values():
                if isinstance(entry_contents, dict):
                    entry_contents = [entry_contents]
                for intf in entry_contents:
                    interface_set.add(intf["name"])

        return list(interface_set)

    def _get_running(self):
        """Return the running (active) configuration as an XML string."""
        self.device.show()
        return str(self.device.xml_root())

    def _get_candidate(self):
        """Return the candidate configuration as an XML string."""
        self.device.op(cmd="<show><config><candidate></candidate></config></show>")
        return str(self.device.xml_root())

    # ------------------------------------------------------------------
    # NAPALM getters
    # ------------------------------------------------------------------

    def get_facts(self):
        """Return general device facts."""
        facts = {}
        try:
            self.device.op(cmd="<show><system><info></info></system></show>")
            system_info_xml = xmltodict.parse(self.device.xml_root())
            system_info_json = json.dumps(system_info_xml["response"]["result"]["system"])
            system_info = json.loads(system_info_json)
        except AttributeError:
            system_info = {}

        if system_info:
            facts["hostname"] = system_info["hostname"]
            facts["vendor"] = "Palo Alto Networks"
            facts["uptime"] = float(convert_uptime_string_seconds(system_info["uptime"]))
            facts["os_version"] = system_info["sw-version"]
            facts["serial_number"] = system_info["serial"]
            facts["model"] = system_info["model"]
            facts["fqdn"] = "N/A"
            facts["interface_list"] = sorted(self._extract_interface_list())

        return facts

    @staticmethod
    def _parse_speed(speed_raw) -> float:
        """Convert a raw speed value from PAN-OS to a float (Mbps). Returns 0.0 for unknown."""
        if speed_raw in ("[n/a]", "unknown", None):
            return 0.0
        try:
            return float(speed_raw)
        except ValueError:
            return 0.0

    def get_interfaces(self):
        """Return interface details keyed by interface name."""
        subif_defaults = {
            "is_up": True,
            "is_enabled": True,
            "speed": 0.0,
            "last_flapped": -1.0,
            "mac_address": "",
            "mtu": 0,
            "description": "",
        }
        subif_pattern = re.compile(
            r"(ethernet\d+/\d+\.\d+)|(ae\d+\.\d+)|(loopback\.)|(tunnel\.)|(vlan\.)|(sdwan\.)"
        )
        interface_dict = {}
        interface_descr = {}
        interface_list = self._extract_interface_list()

        config = xml.etree.ElementTree.fromstring(self._get_running())  # nosec
        for eth_int in config.findall(".//ethernet/entry"):
            name = eth_int.attrib["name"]
            interface_descr[name] = (eth_int.findtext(".//comment") or "").strip()
        for eth_int in config.findall(".//vlan/units/entry"):
            name = eth_int.attrib["name"]
            interface_descr[name] = (eth_int.findtext(".//comment") or "").strip()
        for eth_int in config.findall(".//tunnel/units/entry"):
            name = eth_int.attrib["name"]
            interface_descr[name] = (eth_int.findtext(".//comment") or "").strip()
        interface_descr["loopback"] = (config.findtext(".//loopback/comment") or "").strip()

        for intf in interface_list:
            cmd = f"<show><interface>{intf}</interface></show>"
            try:
                self.device.op(cmd=cmd)
                interface_info_xml = xmltodict.parse(self.device.xml_root())
                interface_info_json = json.dumps(interface_info_xml["response"]["result"]["hw"])
                interface_info = json.loads(interface_info_json)
            except KeyError as err:
                if subif_pattern.search(intf) and "hw" in str(err):
                    interface_dict[intf] = subif_defaults
                    continue
                raise

            is_enabled = True
            conf_state = interface_info.get("state_c")
            if conf_state == "down":
                is_enabled = False
            elif conf_state not in ("up", "auto"):
                logger.warning("Unknown configured state %s for interface %s", conf_state, intf)

            speed = self._parse_speed(interface_info.get("speed"))

            interface_dict[intf] = {
                "is_up": interface_info.get("state") == "up",
                "is_enabled": is_enabled,
                "speed": speed,
                "last_flapped": -1.0,
                "mtu": 0,
                "mac_address": standardize_mac(interface_info.get("mac")),
                "description": interface_descr.get(intf, ""),
            }

        return interface_dict

    def get_interfaces_ip(self):
        """Return IP addresses per interface."""
        self.device.op(cmd="<show><interface>all</interface></show>")
        interface_info_xml = xmltodict.parse(self.device.xml_root())
        result = interface_info_xml.get("response", {}).get("result", {}) or {}
        ifnet = result.get("ifnet") or {}
        entry = ifnet.get("entry")
        if not entry:
            return {}

        interface_info = entry if isinstance(entry, list) else [entry]

        ip_interfaces = {}
        for intf_dict in interface_info:
            ip_info = _extract_ip_info(intf_dict)
            if ip_info:
                ip_interfaces.update(ip_info)

        return ip_interfaces

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """Return device configuration (running and/or candidate)."""
        running = ""
        candidate = ""

        if retrieve in ("all", "running"):
            running = self._get_running()
        if retrieve in ("all", "candidate"):
            candidate = self._get_candidate()

        if sanitized:
            if running:
                running = _sanitize_config(running)
            if candidate:
                candidate = _sanitize_config(candidate)

        return {"running": running, "candidate": candidate, "startup": ""}

    def get_vlans(self):
        """
        Return VLAN information.

        PAN-OS does not expose a traditional VLAN table via the XML API in the
        same way as Cisco/Juniper platforms. Returns an empty dict so that
        device-discovery can continue without VLAN data.
        """
        return {}

    def get_modules(self) -> dict | None:
        """Return per-chassis module / module bay inventory or None."""
        return _panos_get_modules_impl(self)
