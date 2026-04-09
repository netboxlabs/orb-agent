# Copyright 2026 NetBox Labs Inc
"""
Custom Cisco ASA SSH NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses ntc-templates 9.x for structured parsing.
"""

import logging
import re
import socket

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.helpers import mac as normalize_mac
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

logger = logging.getLogger(__name__)

# --- config sanitization (Cisco ASA sensitive fields) ---
# Mirrors the pattern set in custom_napalm/asa.py so both drivers redact the same fields.
_SANITIZE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^(\s*enable\s+password)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*passwd)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*username\s+\S+\s+(?:password|secret))\s+(?:\d\s+)?\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*snmp-server\s+community)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*snmp-server\s+host\s+\S+(?:\s+vrf\s+\S+)?(?:\s+version\s+\S+)?)\s+\S+", re.M | re.I), r"\1 <redacted>"),
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
    # Indented "key <secret>" lines inside aaa-server / radius-server config blocks
    (re.compile(r"^(\s+key)\s+\S+", re.M), r"\1 <redacted>"),
]


def _sanitize_config(text: str) -> str:
    for pattern, replacement in _SANITIZE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _parse_uptime(uptime_str: str) -> int:
    """Convert an ASA uptime string like '3 hours 24 mins' to total seconds."""
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
    """Convert a speed string like '1000 Mbps' to float Mbps."""
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


class ASASSHDriver(_napalm_base.NetworkDriver):
    """Cisco ASA NAPALM driver using SSH CLI + ntc-templates (read-only subset for device-discovery)."""

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
            "cisco_asa", netmiko_optional_args=self.netmiko_optional_args
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
        raw = self.device.send_command("show version")
        parsed = parse_output(platform="cisco_asa", command="show version", data=raw)
        if not parsed:
            return {}

        row = parsed[0]
        serial_list = row.get("serial", [])

        # `Model Id:` is present on some platforms; fall back to the first token
        # of the Hardware line (e.g. "ASA5516, 8192 MB RAM, ..." → "ASA5516").
        model = row.get("model", "") or ""
        if not model:
            hardware = row.get("hardware", "") or ""
            model = hardware.split(",")[0].strip()
        model = model or "Unknown"

        return {
            "hostname": row.get("hostname", "Unknown"),
            "vendor": "Cisco",
            "model": model,
            "os_version": row.get("version", "Unknown"),
            "serial_number": serial_list[0] if serial_list else "Unknown",
            "uptime": float(_parse_uptime(row.get("uptime", ""))),
            "fqdn": "Unknown",
            "interface_list": row.get("interfaces", []),
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

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Cisco ASA does not expose a traditional VLAN table via SSH CLI."""
        return {}
