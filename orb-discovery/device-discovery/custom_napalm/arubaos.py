# Copyright 2026 NetBox Labs Inc
"""
Custom ArubaOS NAPALM driver (Aruba Mobility Controllers / wireless OS).

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko (aruba_os device type) and ntc-templates 9.x for structured
CLI parsing wherever templates are available; falls back to regex for uptime
which lacks a dedicated template.
"""

import ipaddress
import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import ParsingException, parse_output
from textfsm.parser import TextFSMError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config sanitization
# ---------------------------------------------------------------------------

# "mgmt-user <user> <role> <hash>" — management user password
_MGMT_USER_RE = re.compile(
    r"(mgmt-user\s+\S+\s+\S+)\s+\S+",
    re.IGNORECASE,
)

# "wpa-passphrase <key>" — WPA pre-shared key
_WPA_PSK_RE = re.compile(
    r"(wpa-passphrase)\s+\S+",
    re.IGNORECASE,
)

# "key <secret>" — RADIUS/TACACS+ shared secret (indented sub-block lines only)
# Using MULTILINE + start-of-line whitespace anchor avoids false positives on
# "public-key rsa" or "ssh authorized-key rsa ..." lines.
_KEY_RE = re.compile(
    r"(^\s+key)\s+\S+",
    re.IGNORECASE | re.MULTILINE,
)

# "snmp-server community <string> ..." — SNMP community string
_SNMP_COMMUNITY_RE = re.compile(
    r"(snmp-server\s+community)\s+\S+",
    re.IGNORECASE,
)


def _sanitize_config(text: str) -> str:
    text = _MGMT_USER_RE.sub(r"\1 <redacted>", text)
    text = _WPA_PSK_RE.sub(r"\1 <redacted>", text)
    text = _KEY_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_COMMUNITY_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Uptime helper
# ---------------------------------------------------------------------------

_UPTIME_FACTORS = {
    "second": 1,
    "minute": 60,
    "hour": 3600,
    "day": 86400,
    "week": 604800,
}


def _parse_uptime(text: str) -> float:
    """
    Extract uptime in seconds from free-form ArubaOS uptime text.

    Handles multi-unit strings such as:
      "Switch uptime is 1 days 3 hours 27 minutes 5 seconds"
      "1 days 3 hours 27 minutes 5 seconds"
    """
    total = 0
    for pattern, factor in (
        (r"(\d+)\s+week", _UPTIME_FACTORS["week"]),
        (r"(\d+)\s+day", _UPTIME_FACTORS["day"]),
        (r"(\d+)\s+hour", _UPTIME_FACTORS["hour"]),
        (r"(\d+)\s+minute", _UPTIME_FACTORS["minute"]),
        (r"(\d+)\s+second", _UPTIME_FACTORS["second"]),
    ):
        m = re.search(pattern, text)
        if m:
            total += int(m.group(1)) * factor

    return float(total) if total else -1.0


class ArubaOSDriver(_napalm_base.NetworkDriver):
    """ArubaOS NAPALM driver (Aruba Mobility Controllers)."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Initialize the driver."""
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.device = None

        if optional_args is None:
            optional_args = {}

        self.netmiko_optional_args = netmiko_args(optional_args)
        self.netmiko_optional_args.setdefault("port", 22)

    def open(self):
        """Open an SSH connection to the device via Netmiko."""
        self.device = self._netmiko_open(
            "aruba_os", netmiko_optional_args=self.netmiko_optional_args
        )

    def close(self):
        """Close the connection."""
        self._netmiko_close()

    def is_alive(self):
        """Return connection liveness."""
        if self.device is None:
            return {"is_alive": False}
        try:
            self.device.write_channel(chr(0))
            return {"is_alive": self.device.remote_conn.transport.is_active()}
        except (EOFError, OSError, AttributeError):
            return {"is_alive": False}

    # ------------------------------------------------------------------
    # NAPALM getters
    # ------------------------------------------------------------------

    def get_facts(self) -> dict:
        """Return general device facts."""
        hostname = os_version = serial_number = model = "Unknown"
        uptime = -1.0
        interface_list: list[str] = []

        # --- hostname ---
        hostname_out = self.device.send_command("show hostname")
        try:
            parsed_hn = parse_output(
                platform="aruba_os", command="show hostname", data=hostname_out
            )
        except (TextFSMError, ParsingException):
            logger.warning("Failed to parse show hostname output")
            parsed_hn = []
        if parsed_hn:
            hostname = parsed_hn[0].get("hostname", "Unknown") or "Unknown"

        # --- OS version (IMAGE_VERSION) ---
        ver_out = self.device.send_command("show version")
        try:
            parsed_ver = parse_output(
                platform="aruba_os", command="show version", data=ver_out
            )
        except (TextFSMError, ParsingException):
            logger.warning("Failed to parse show version output")
            parsed_ver = []
        if parsed_ver:
            os_version = parsed_ver[0].get("image_version", "Unknown") or "Unknown"

        # --- serial number, model ---
        inv_out = self.device.send_command("show inventory")
        try:
            parsed_inv = parse_output(
                platform="aruba_os", command="show inventory", data=inv_out
            )
        except (TextFSMError, ParsingException):
            logger.warning("Failed to parse show inventory output")
            parsed_inv = []
        if parsed_inv:
            row = parsed_inv[0]
            serial_number = row.get("system_serial", "Unknown") or "Unknown"
            model = row.get("sc_model", "Unknown") or "Unknown"

        # --- uptime (no template — parse from show version text) ---
        uptime = _parse_uptime(ver_out)

        # --- interface list from show ip interface brief ---
        ip_brief_out = self.device.send_command("show ip interface brief")
        try:
            parsed_ip = parse_output(
                platform="aruba_os", command="show ip interface brief", data=ip_brief_out
            )
        except (TextFSMError, ParsingException):
            logger.warning("Failed to parse show ip interface brief output")
            parsed_ip = []
        interface_list = [row["interface"] for row in parsed_ip if row.get("interface")]

        return {
            "hostname": hostname,
            "vendor": "HPE Aruba",
            "model": model,
            "os_version": os_version,
            "serial_number": serial_number,
            "uptime": uptime,
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """Return interface details keyed by interface name."""
        ip_brief_out = self.device.send_command("show ip interface brief")
        try:
            parsed = parse_output(
                platform="aruba_os", command="show ip interface brief", data=ip_brief_out
            )
        except (TextFSMError, ParsingException):
            logger.warning("Failed to parse show ip interface brief output")
            parsed = []
        interfaces = {}
        for row in parsed:
            intf = row.get("interface", "")
            if not intf:
                continue
            admin = row.get("admin", "").lower()
            protocol = row.get("protocol", "").lower()
            interfaces[intf] = {
                "is_up": protocol == "up",
                "is_enabled": admin == "up",
                "description": "",
                "last_flapped": -1.0,
                "mtu": -1,
                "speed": -1.0,
                "mac_address": "",
            }
        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface."""
        interfaces_ip: dict = {}
        self._collect_ipv4(interfaces_ip)
        self._collect_ipv6(interfaces_ip)
        return interfaces_ip

    def _collect_ipv4(self, interfaces_ip: dict) -> None:
        """Populate IPv4 entries into interfaces_ip in place."""
        ip_brief_out = self.device.send_command("show ip interface brief")
        try:
            parsed = parse_output(
                platform="aruba_os", command="show ip interface brief", data=ip_brief_out
            )
        except (TextFSMError, ParsingException):
            logger.warning("Failed to parse show ip interface brief output")
            return
        for row in parsed:
            intf = row.get("interface", "")
            ip_addr = row.get("ip_address", "")
            netmask = row.get("netmask", "")
            if not intf or not ip_addr or ip_addr in ("unassigned", ""):
                continue
            prefix_len = _mask_to_prefix(netmask)
            if prefix_len < 0:
                continue
            interfaces_ip.setdefault(intf, {}).setdefault("ipv4", {})[ip_addr] = {
                "prefix_length": prefix_len
            }

    def _collect_ipv6(self, interfaces_ip: dict) -> None:
        """Populate IPv6 entries into interfaces_ip in place."""
        ipv6_brief_out = self.device.send_command("show ipv6 interface brief")
        try:
            parsed = parse_output(
                platform="aruba_os", command="show ipv6 interface brief", data=ipv6_brief_out
            )
        except (TextFSMError, ParsingException):
            logger.warning("Failed to parse show ipv6 interface brief output")
            return
        for row in parsed:
            intf = row.get("interface", "")
            ipv6_addrs = row.get("ipv6_address", [])
            if not intf or not ipv6_addrs:
                continue
            for addr_with_prefix in ipv6_addrs:
                if not addr_with_prefix or "/" not in addr_with_prefix:
                    continue
                ip, prefix = addr_with_prefix.rsplit("/", 1)
                try:
                    plen = int(prefix)
                except ValueError:
                    continue
                interfaces_ip.setdefault(intf, {}).setdefault("ipv6", {})[ip] = {
                    "prefix_length": plen
                }

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """
        Return device configuration.

        ArubaOS mobility controllers maintain a single active configuration
        (committed to flash on write); there is no separate startup config.
        ``startup`` is always returned as an empty string.
        """
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}

        if retrieve.lower() in ("running", "all"):
            config["running"] = self.device.send_command("show running-config")

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Return VLAN information keyed by VLAN ID string."""
        vlan_out = self.device.send_command("show vlan")
        try:
            parsed = parse_output(platform="aruba_os", command="show vlan", data=vlan_out)
        except (TextFSMError, ParsingException):
            logger.warning("Failed to parse show vlan output")
            parsed = []

        vlans: dict = {}
        for row in parsed:
            vlan_id = row.get("vlan_id", "")
            if not vlan_id:
                continue
            vlan_name = row.get("vlan_name", "").strip() or vlan_id
            vlans[vlan_id] = {"name": vlan_name, "interfaces": []}

        return vlans


def _mask_to_prefix(netmask: str) -> int:
    """Convert dotted-decimal subnet mask or prefix length string to int prefix length."""
    if not netmask:
        return -1
    try:
        if "." in netmask:
            return ipaddress.IPv4Network(f"0.0.0.0/{netmask}", strict=False).prefixlen
        return int(netmask)
    except (ValueError, TypeError):
        return -1
