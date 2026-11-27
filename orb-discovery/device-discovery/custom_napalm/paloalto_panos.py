# Copyright 2026 NetBox Labs Inc
# Based on napalm-panos (Apache-2.0): https://github.com/napalm-automation-community/napalm-panos
"""
Custom PAN-OS NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.
"""

import ipaddress
import json
import logging
import re
import xml.etree.ElementTree
import xml.parsers.expat

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


# Management-plane values that are not real addresses.
_PANOS_MGMT_SKIP = {"", "unknown", "n/a", "0.0.0.0"}


def _netmask_to_prefix(netmask: str) -> int | None:
    """
    Convert dotted-decimal netmask to a CIDR prefix length; None if malformed.

    Uses stdlib ``ipaddress`` so wrong-length, out-of-range, AND non-contiguous
    masks (e.g. ``255.0.255.0``) are all rejected — a plain 1-bit count would
    accept the latter as a bogus ``/16``.
    """
    try:
        return ipaddress.ip_network(f"0.0.0.0/{netmask}").prefixlen
    except ValueError:
        return None


def _is_link_local_v6(addr: str) -> bool:
    """Return True if *addr* is an IPv6 link-local address (the full ``fe80::/10``)."""
    try:
        return ipaddress.ip_address(addr).is_link_local
    except ValueError:
        # Unparseable — fall back to the fe80::/10 textual prefixes (fe8/fe9/fea/feb).
        return addr.lower().startswith(("fe8", "fe9", "fea", "feb"))


def _usable_mgmt_ipv6(ipv6_raw: str) -> tuple[str, int] | None:
    """
    Parse a usable global management ``(addr, prefix)`` from the ``ipv6-address`` field.

    Returns None for skip values, link-local (``fe80::/10``), prefix-less, or
    out-of-range entries. IPv6 without an explicit ``/prefix`` is skipped (not
    assumed ``/64``), mirroring the checkpoint_gaia / dell_ftos / aruba_os convention.
    """
    raw = (ipv6_raw or "").strip()
    if raw.lower() in _PANOS_MGMT_SKIP:
        return None
    if "/" not in raw:
        logger.debug("paloalto_panos: skipping mgmt IPv6 %s: no prefix length", raw)
        return None
    addr, plen = raw.rsplit("/", 1)
    if _is_link_local_v6(addr):
        logger.debug("paloalto_panos: skipping mgmt IPv6 %s: link-local", raw)
        return None
    # Validate it's a real, unscoped IPv6 before emitting — a malformed value or a
    # zone index (e.g. `2001:db8::1%mgmt`) would otherwise crash translation when
    # `ipaddress.ip_network(addr/prefix)` is built downstream.
    try:
        if ipaddress.ip_address(addr).version != 6 or "%" in addr:
            raise ValueError
    except ValueError:
        logger.debug("paloalto_panos: skipping mgmt IPv6 %s: not a valid global IPv6", raw)
        return None
    try:
        plen_int = int(plen)
    except ValueError:
        logger.debug("paloalto_panos: skipping mgmt IPv6 %s: bad prefix", raw)
        return None
    if not (0 <= plen_int <= 128):
        logger.debug("paloalto_panos: skipping mgmt IPv6 %s: prefix out of range", raw)
        return None
    return addr, plen_int


def _mgmt_interface_from_system_info(system_info: dict) -> dict:
    """
    Build the NAPALM ``get_interfaces`` entry for the management interface.

    The management port is not listed by ``show interface all``; its MAC
    comes from ``show system info``. Emitted whenever a usable management IP
    (IPv4 or IPv6) is present — i.e. exactly the cases where
    ``get_interfaces_ip`` emits a management IP, so the MAC is carried even on
    IPv6-only management planes. A missing / malformed MAC yields an empty
    ``mac_address`` rather than dropping the entry.
    """
    if not _mgmt_ip_from_system_info(system_info):
        return {}
    mac_raw = (system_info.get("mac-address") or "").strip()
    try:
        mgmt_mac = standardize_mac(mac_raw) if mac_raw else ""
    except Exception:
        mgmt_mac = ""
    return {
        "management": {
            "is_up": True,
            "is_enabled": True,
            "speed": 0.0,
            "last_flapped": -1.0,
            "mtu": 0,
            "mac_address": mgmt_mac,
            "description": "",
        }
    }


def _usable_mgmt_ipv4(ipv4: str, netmask: str) -> int | None:
    """
    Return the CIDR prefix for a usable management IPv4, or None.

    Skips junk / ``0.0.0.0`` values, addresses that aren't valid IPv4, and
    unparseable / non-contiguous netmasks — so a malformed ``ip-address`` can't
    reach translation and crash ``ipaddress.ip_network(...)``.
    """
    ipv4 = (ipv4 or "").strip()
    netmask = (netmask or "").strip()
    if ipv4.lower() in _PANOS_MGMT_SKIP or netmask.lower() in _PANOS_MGMT_SKIP:
        return None
    try:
        if ipaddress.ip_address(ipv4).version != 4:
            return None
    except ValueError:
        logger.debug("paloalto_panos: skipping mgmt IPv4 %s: not a valid address", ipv4)
        return None
    return _netmask_to_prefix(netmask)


def _mgmt_ip_from_system_info(system_info: dict) -> dict:
    """
    Build the NAPALM ``interface_ip`` fragment for the management interface.

    PAN-OS exposes the management-plane IP in ``show system info``
    (``ip-address`` / ``netmask`` / ``ipv6-address``), not in
    ``show interface all``. Returns ``{"management": {...}}`` or ``{}`` when
    nothing usable is present. IPv6 without an explicit ``/prefix`` is skipped
    (matching the checkpoint_gaia / dell_ftos / aruba_os convention) rather
    than assuming ``/64``; link-local ``fe80::`` is ignored.
    """
    mgmt: dict = {}

    ipv4 = (system_info.get("ip-address") or "").strip()
    prefix = _usable_mgmt_ipv4(ipv4, system_info.get("netmask") or "")
    if prefix is not None:
        mgmt.setdefault("ipv4", {})[ipv4] = {"prefix_length": prefix}

    mgmt_v6 = _usable_mgmt_ipv6(system_info.get("ipv6-address") or "")
    if mgmt_v6 is not None:
        mgmt.setdefault("ipv6", {})[mgmt_v6[0]] = {"prefix_length": mgmt_v6[1]}

    if not mgmt:
        return {}
    return {"management": mgmt}


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


# "fwd" values on PAN-OS interface entries: "vr:<name>" (classic virtual
# routers), "logical-router:<name>" (Advanced Routing, PAN-OS 10.2+); L2 /
# HA / unassigned interfaces report "N/A" or other non-routing tokens.
_PANOS_FWD_PREFIXES = ("vr:", "logical-router:")


def _panos_vr_from_fwd(fwd: object) -> str:
    """Return the virtual-router name from a fwd field, or "" when non-L3."""
    if not isinstance(fwd, str):
        return ""
    for prefix in _PANOS_FWD_PREFIXES:
        if fwd.startswith(prefix):
            return fwd[len(prefix):].strip()
    return ""


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

    def _system_info_dict(self) -> dict:
        """
        Return the parsed ``show system info`` ``result.system`` dict, or {} on failure.

        Best-effort: a failed RPC (``PanXapiError`` — timeout / auth / API error), a
        malformed/unparseable XML body (``ExpatError``), or an unexpected payload all
        yield {} rather than propagating. The management-IP lookup is an enhancement
        layered on top of ``get_interfaces()`` / ``get_interfaces_ip()``, so a
        system-info failure must not fail those getters once their data-plane
        interfaces/IPs have been collected.
        """
        try:
            self.device.op(cmd="<show><system><info></info></system></show>")
            parsed = xmltodict.parse(self.device.xml_root())
            system = parsed["response"]["result"]["system"]
        except pan.xapi.PanXapiError as e:
            logger.warning("paloalto_panos: `show system info` RPC failed: %s", e)
            return {}
        except xml.parsers.expat.ExpatError as e:
            logger.warning("paloalto_panos: `show system info` XML parse failed: %s", e)
            return {}
        except (KeyError, TypeError, AttributeError):
            return {}
        return system or {}

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

        # Management interface — MAC comes from `show system info`
        # (the management port is not listed by `show interface all`).
        interface_dict.update(_mgmt_interface_from_system_info(self._system_info_dict()))

        return interface_dict

    def get_interfaces_ip(self):
        """Return IP addresses per interface (data-plane + management)."""
        self.device.op(cmd="<show><interface>all</interface></show>")
        interface_info_xml = xmltodict.parse(self.device.xml_root())
        result = interface_info_xml.get("response", {}).get("result", {}) or {}
        ifnet = result.get("ifnet") or {}
        entry = ifnet.get("entry")

        ip_interfaces = {}
        if entry:
            interface_info = entry if isinstance(entry, list) else [entry]
            for intf_dict in interface_info:
                ip_info = _extract_ip_info(intf_dict)
                if ip_info:
                    ip_interfaces.update(ip_info)

        # PAN-OS exposes the management-plane IP only via `show system info`.
        # Merge (don't clobber): the MGT port is genuinely absent from
        # `show interface all` today, but a nested merge is collision-safe if a
        # future PAN-OS ever lists a "management" key there too.
        for intf, families in _mgmt_ip_from_system_info(self._system_info_dict()).items():
            dest = ip_interfaces.setdefault(intf, {})
            for family, addrs in families.items():
                dest.setdefault(family, {}).update(addrs)

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

    def get_network_instances(self, name: str = "") -> dict:
        """
        Return network instances (PAN-OS virtual routers), NAPALM OC shape.

        Derived from the ``fwd`` field of the same ``show interface all``
        op-command the interface getters consume — L3 interfaces report
        ``vr:<name>`` (or ``logical-router:<name>`` with Advanced Routing
        on PAN-OS 10.2+), so member names join exactly. VSYS are NOT
        VRFs and are never mapped. The factory virtual router named
        ``default`` is treated as the global routing table
        (DEFAULT_INSTANCE, empty membership). PAN-OS virtual routers
        carry no route distinguisher. Limitation: enumeration is
        membership-derived, so a virtual router with no interfaces
        assigned does not appear.
        """
        instances: dict = {
            "default": {
                "name": "default",
                "type": "DEFAULT_INSTANCE",
                "state": {"route_distinguisher": ""},
                "interfaces": {"interface": {}},
            },
        }
        self.device.op(cmd="<show><interface>all</interface></show>")
        parsed = xmltodict.parse(self.device.xml_root())
        result = (parsed.get("response") or {}).get("result") or {}
        entries = (result.get("ifnet") or {}).get("entry") or []
        if isinstance(entries, dict):
            entries = [entries]
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            ifname = (entry.get("name") or "").strip()
            vr_name = _panos_vr_from_fwd(entry.get("fwd"))
            # The factory "default" VR is the seeded DEFAULT_INSTANCE.
            if not ifname or not vr_name or vr_name == "default":
                continue
            instances.setdefault(
                vr_name,
                {
                    "name": vr_name,
                    "type": "L3VRF",
                    "state": {"route_distinguisher": ""},
                    "interfaces": {"interface": {}},
                },
            )["interfaces"]["interface"][ifname] = {}
        if name:
            return {name: instances[name]} if name in instances else {}
        return instances
