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
