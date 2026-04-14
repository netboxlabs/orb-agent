# Copyright 2026 NetBox Labs Inc
# Based on napalm-hp-procurve (Apache-2.0): https://github.com/napalm-automation-community/napalm-hp-procurve
"""
Custom HP ProCurve NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko (hp_procurve device type) and ntc-templates for structured
parsing wherever templates are available; falls back to regex for commands
without templates (uptime, model).
"""

import ipaddress
import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

logger = logging.getLogger(__name__)

# --- config sanitization ---
# HP ProCurve: "password manager [sha1] <hash>" / "password operator [sha1] <hash>"
# Redact the full line after "password manager/operator" (algorithm + hash)
_PASSWORD_RE = re.compile(r"(password\s+(?:manager|operator))\s+.*", re.IGNORECASE)
# SNMP community string: quoted ("public") or unquoted (public)
_SNMP_COMM_RE = re.compile(r'(snmp-server\s+community)\s+(?:"[^"]*"|\S+)', re.IGNORECASE)
# RADIUS shared secret
_RADIUS_KEY_RE = re.compile(r"(radius-server\s+key)\s+\S+", re.IGNORECASE)
# TACACS+ key (standalone or per-host)
_TACACS_KEY_RE = re.compile(
    r"(tacacs-server(?:\s+host\s+\S+)?\s+key)\s+\S+", re.IGNORECASE
)


def _sanitize_config(text: str) -> str:
    text = _PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_COMM_RE.sub(r"\1 <redacted>", text)
    text = _RADIUS_KEY_RE.sub(r"\1 <redacted>", text)
    text = _TACACS_KEY_RE.sub(r"\1 <redacted>", text)
    return text


# Uptime conversion constants
_MINUTE_SECONDS = 60
_HOUR_SECONDS = 3600
_DAY_SECONDS = 24 * _HOUR_SECONDS


def _parse_uptime(uptime_str: str) -> float:
    """
    Convert a ProCurve 'show uptime' string (d:h:m:s) to total seconds.

    The `show uptime` command on HP ProCurve returns output like::

        0:00:00:42

    where the format is ``d:hh:mm:ss``. Falls back to 0 on parse failure.
    """
    parts = uptime_str.strip().split(":")
    if len(parts) == 4:
        try:
            days, hours, minutes, seconds = parts
            return (
                int(days) * _DAY_SECONDS
                + int(hours) * _HOUR_SECONDS
                + int(minutes) * _MINUTE_SECONDS
                + int(seconds)
            )
        except ValueError:
            pass
    return 0.0


def _parse_speed(mode: str) -> float:
    """
    Extract link speed in Mbps from ProCurve MODE column (e.g. '1000FDx').

    Returns -1.0 when the speed cannot be determined.
    """
    if not mode or mode.lower() in ("auto", "none", ""):
        return -1.0
    m = re.match(r"(\d+)(G?)", mode, re.IGNORECASE)
    if not m:
        return -1.0
    value = float(m.group(1))
    # MODE like "10GFDx" uses "G" suffix for Gigabit
    if m.group(2).upper() == "G":
        value *= 1000
    return value


def _mask_to_prefix(mask: str) -> int:
    """Convert dotted-decimal subnet mask to prefix length integer."""
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False).prefixlen
    except ValueError:
        return -1


def _strip_config_header(text: str) -> str:
    """
    Strip ProCurve's '; ... Configuration Editor; ...' preamble.

    HP ProCurve prepends a '; ... Configuration Editor; ...' banner before
    the actual config body, followed by version comment lines starting with ';'.
    """
    # Split on the Configuration Editor banner line (if present)
    parts = re.split(r"^;.*Configuration Editor.*$", text, maxsplit=1, flags=re.MULTILINE)
    body = parts[-1]  # everything after the banner (or the whole text)

    # Strip remaining leading ';' comment lines and blank lines
    lines = body.splitlines()
    start = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.startswith(";"):
            start = i
            break

    return "\n".join(lines[start:]).strip()


class ProCurveDriver(_napalm_base.NetworkDriver):
    """HP ProCurve NAPALM driver (read-only subset for device-discovery)."""

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
            "hp_procurve", netmiko_optional_args=self.netmiko_optional_args
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
        hostname = os_version = serial_number = "Unknown"
        model = "Unknown"
        uptime = 0.0

        # --- system info via ntc-template ---
        raw_system = self.device.send_command("show system")
        parsed_system = parse_output(
            platform="hp_procurve", command="show system", data=raw_system
        )
        if parsed_system:
            row = parsed_system[0]
            hostname = row.get("name") or "Unknown"
            os_version = row.get("software_version") or "Unknown"
            serial_number = row.get("serial") or "Unknown"

        # --- model: regex on the raw show system header (before "Status and Counters") ---
        header = raw_system.split("Status and Counters")[0]
        m = re.search(
            r"((?:HP\s+)?(?:ProCurve|Aruba)\s+(?:Switch\s+)?\S+)", header, re.IGNORECASE
        )
        if m:
            model = m.group(1).strip()

        # --- uptime via show uptime (d:h:m:s) ---
        raw_uptime = self.device.send_command("show uptime")
        uptime = _parse_uptime(raw_uptime)

        # --- interface list from show interfaces brief ---
        raw_brief = self.device.send_command("show interfaces brief")
        parsed_brief = parse_output(
            platform="hp_procurve", command="show interfaces brief", data=raw_brief
        )
        interface_list = [row["port"] for row in parsed_brief if row.get("port")]

        return {
            "hostname": hostname,
            "vendor": "HP",
            "model": model,
            "os_version": os_version,
            "serial_number": serial_number,
            "uptime": uptime,
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """Return interface details keyed by interface name."""
        raw = self.device.send_command("show interfaces brief")
        if not raw:
            return {}

        parsed = parse_output(
            platform="hp_procurve", command="show interfaces brief", data=raw
        )
        interfaces = {}
        for row in parsed:
            port = row.get("port", "")
            if not port:
                continue
            interfaces[port] = {
                "is_up": row.get("status", "").lower() == "up",
                "is_enabled": row.get("enabled", "").lower() == "yes",
                "description": "",
                "last_flapped": -1.0,
                "mtu": -1,
                "speed": _parse_speed(row.get("mode", "")),
                "mac_address": "",
            }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface."""
        raw = self.device.send_command("show ip")
        if not raw:
            return {}

        parsed = parse_output(platform="hp_procurve", command="show ip", data=raw)
        interfaces_ip: dict = {}
        for row in parsed:
            vlan_name = row.get("vlan_name", "").strip()
            ip_address = row.get("ip_address", "").strip()
            subnet_mask = row.get("subnet_mask", "").strip()
            config = row.get("config", "").strip()

            if not vlan_name or not ip_address or config.lower() == "disabled":
                continue

            prefix_length = _mask_to_prefix(subnet_mask)
            if prefix_length < 0:
                continue
            interfaces_ip.setdefault(vlan_name, {}).setdefault("ipv4", {})[ip_address] = {
                "prefix_length": prefix_length
            }

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

        if retrieve.lower() in ("running", "all"):
            raw = self.device.send_command("show running-config")
            config["running"] = _strip_config_header(raw)

        if retrieve.lower() in ("startup", "all"):
            raw = self.device.send_command("show config")
            config["startup"] = _strip_config_header(raw)

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Return VLAN information keyed by VLAN ID string."""
        raw = self.device.send_command("show vlans")
        if not raw:
            return {}

        parsed = parse_output(platform="hp_procurve", command="show vlans", data=raw)
        vlans: dict = {}
        for row in parsed:
            vlan_id = row.get("vlan_id", "")
            if not vlan_id:
                continue
            vlan_name = row.get("vlan_name", "").strip() or vlan_id
            vlans[vlan_id] = {"name": vlan_name, "interfaces": []}

        return vlans
