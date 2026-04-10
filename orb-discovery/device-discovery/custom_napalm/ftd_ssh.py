# Copyright 2026 NetBox Labs Inc
"""
Custom Cisco FTD SSH NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko cisco_ftd device type and ntc-templates cisco_asa platform.
FTD clish show version raises TextFSMError or ParsingException from the
cisco_asa template; get_facts catches both and falls back to regex parsing
of the FTD clish block format. Interface commands are format-compatible
with cisco_asa templates.
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.helpers import mac as normalize_mac
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import ParsingException, parse_output
from textfsm.parser import TextFSMError

_PARSE_ERRORS = (TextFSMError, ParsingException)

logger = logging.getLogger(__name__)

# --- config sanitization (Cisco FTD / ASA-lineage sensitive fields) ---
_SANITIZE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^(\s*enable\s+password)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*passwd)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*username\s+\S+\s+(?:password|secret))\s+(?:\d\s+)?\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*snmp-server\s+community)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*snmp-server\s+host\s+\S+\s+\S+(?:\s+vrf\s+\S+)?(?:\s+version\s+\S+)?)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*(?:password|secret))\s+(?:\d\s+)?\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(.*wpa-psk\s+ascii\s+\d)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(.*\bkey\s+7)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*tacacs-server\b[^\n]*?\bkey)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*crypto\s+isakmp\s+key)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*ip\s+ospf\s+message-digest-key\s+\d+\s+md5)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*ip\s+ospf\s+authentication-key)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*neighbor\s+\S+\s+password)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*vrrp\s+\d+\s+authentication\s+text)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*standby\s+\d+\s+authentication\s+md5\s+key-string)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*standby\s+\d+\s+authentication)\s+\S{1,8}$", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*key-string)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*(?:tacacs|radius)\s+server\s+\S+\s+key)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*ppp\s+(?:chap|pap)\s+password\s+\d)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*pre-shared-key)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s+key)\s+\S+", re.M), r"\1 <redacted>"),
]

# Regex for FTD clish show version block
_FTD_HOSTNAME_RE = re.compile(r"-+\[\s*(.+?)\s*\]-+")
_FTD_VERSION_RE = re.compile(r"Version\s+([\d.]+)\s+\(Build\s+(\d+)\)", re.IGNORECASE)
_FTD_MODEL_RE = re.compile(r"Model\s*:\s*(.+?)\s*(?:\(\d+\)|Version)", re.IGNORECASE)


def _sanitize_config(text: str) -> str:
    for pattern, replacement in _SANITIZE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _parse_uptime(uptime_str: str) -> int:
    """Convert ASA uptime string like '3 hours 24 mins' to total seconds."""
    seconds = 0
    for pattern, factor in (
        (r"(\d+)\s+year", 365 * 86400),
        (r"(\d+)\s+week", 7 * 86400),
        (r"(\d+)\s+day", 86400),
        (r"(\d+)\s+hour", 3600),
        (r"(\d+)\s+min", 60),
        (r"(\d+)\s+sec", 1),
    ):
        m = re.search(pattern, uptime_str, re.IGNORECASE)
        if m:
            seconds += int(m.group(1)) * factor
    return seconds


def _netmask_to_prefix(netmask: str) -> int:
    """Convert dotted-decimal netmask to CIDR prefix length."""
    return sum(bin(int(octet)).count("1") for octet in netmask.split("."))


def _parse_speed(speed_raw: str) -> float:
    """Convert speed string like '1000 Mbps' or '10 Gbps' to float Mbps."""
    m = re.match(r"(\d+)\s*(Gbps|Mbps|Kbps)", speed_raw, re.IGNORECASE)
    if not m:
        return 0.0
    num = float(m.group(1))
    unit = m.group(2).lower()
    if unit == "gbps":
        return num * 1000.0
    if unit == "kbps":
        return num / 1000.0
    return num


class FTDSSHDriver(_napalm_base.NetworkDriver):
    """Cisco FTD NAPALM driver using SSH CLI + ntc-templates (read-only subset for device-discovery)."""

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
            "cisco_ftd", netmiko_optional_args=self.netmiko_optional_args
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
        version_raw = self.device.send_command("show version")

        hostname = "Unknown"
        model = "Unknown"
        os_version = "Unknown"
        uptime = 0.0
        serial_number = "Unknown"

        use_regex = False
        try:
            parsed = parse_output(platform="cisco_asa", command="show version", data=version_raw)
            if parsed and parsed[0].get("hostname"):
                # ntc-template path: ASA-style show version output
                row = parsed[0]
                hostname = row.get("hostname", "Unknown")
                hardware = row.get("hardware", "") or ""
                model_id = row.get("model", "") or ""
                model = model_id or hardware.split(",")[0].strip() or "Unknown"
                os_version = row.get("version", "Unknown")
                uptime = float(_parse_uptime(row.get("uptime", "")))
                serial_list = row.get("serial", [])
                serial_number = serial_list[0] if serial_list else "Unknown"
            else:
                use_regex = True
        except _PARSE_ERRORS:
            use_regex = True

        if use_regex:
            # Regex fallback: FTD clish block format
            m_host = _FTD_HOSTNAME_RE.search(version_raw)
            hostname = m_host.group(1) if m_host else self.hostname

            m_model = _FTD_MODEL_RE.search(version_raw)
            model = m_model.group(1).strip() if m_model else "Unknown"

            m_ver = _FTD_VERSION_RE.search(version_raw)
            if m_ver:
                os_version = f"{m_ver.group(1)}.{m_ver.group(2)}"

            # Serial not present in FTD clish show version — get from show inventory
            inv_raw = self.device.send_command("show inventory")
            try:
                inv_parsed = parse_output(
                    platform="cisco_asa", command="show inventory", data=inv_raw
                )
                if inv_parsed:
                    chassis = next(
                        (r for r in inv_parsed if "chassis" in r.get("name", "").lower()),
                        inv_parsed[0],
                    )
                    serial_number = chassis.get("sn", "Unknown") or "Unknown"
            except _PARSE_ERRORS:
                logger.debug("Failed to parse show inventory; serial unknown")

        # Build interface list from show interface ip brief (works on both paths)
        ip_brief_raw = self.device.send_command("show interface ip brief")
        try:
            ip_brief_parsed = parse_output(
                platform="cisco_asa", command="show interface ip brief", data=ip_brief_raw
            )
            interface_list = sorted(r["interface"] for r in ip_brief_parsed if r.get("interface"))
        except _PARSE_ERRORS:
            logger.debug("Failed to parse show interface ip brief; interface_list empty")
            interface_list = []

        return {
            "hostname": hostname,
            "vendor": "Cisco",
            "model": model,
            "os_version": os_version,
            "serial_number": serial_number,
            "uptime": uptime,
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """Return interface details keyed by interface name."""
        raw = self.device.send_command("show interface")
        parsed = parse_output(platform="cisco_asa", command="show interface", data=raw)

        interfaces = {}
        for row in parsed:
            intf = row.get("interface", "")
            if not intf:
                continue

            link_status = row.get("link_status", "").lower()
            proto_status = row.get("protocol_status", "").lower()

            mac_raw = row.get("mac_address", "")
            try:
                mac_address = normalize_mac(mac_raw) if mac_raw else ""
            except Exception:
                mac_address = mac_raw

            interfaces[intf] = {
                "is_up": link_status == "up" and proto_status == "up",
                "is_enabled": "admin" not in link_status,
                "description": row.get("description", "").strip(),
                "last_flapped": -1.0,
                "mtu": int(row["mtu"]) if row.get("mtu") else 0,
                "speed": _parse_speed(row.get("speed", "")),
                "mac_address": mac_address,
            }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface."""
        raw = self.device.send_command("show interface")
        parsed = parse_output(platform="cisco_asa", command="show interface", data=raw)

        interfaces_ip: dict = {}
        for row in parsed:
            intf = row.get("interface", "")
            ip = row.get("ip_address", "")
            netmask = row.get("netmask", "")
            if not intf or not ip or not netmask:
                continue
            try:
                prefix = _netmask_to_prefix(netmask)
                interfaces_ip.setdefault(intf, {}).setdefault("ipv4", {})[ip] = {
                    "prefix_length": prefix
                }
            except (ValueError, AttributeError):
                continue

        return interfaces_ip

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """Return device configuration."""
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}

        if retrieve in ("all", "running"):
            config["running"] = self.device.send_command("show running-config")

        if retrieve in ("all", "startup"):
            config["startup"] = self.device.send_command("show startup-config")

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """FTD does not expose a traditional VLAN table via clish."""
        return {}
