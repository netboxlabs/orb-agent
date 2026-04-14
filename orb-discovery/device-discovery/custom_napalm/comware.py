# Copyright 2026 NetBox Labs Inc
# Based on napalm-h3c-cw7-ssh (Apache-2.0): https://github.com/napalm-automation-community/napalm-h3c-cw7-ssh
"""
Custom HP Comware NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko (hp_comware device type) and ntc-templates for structured
parsing wherever templates are available; falls back to regex for commands
without templates (display version).
"""

import ipaddress
import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.helpers import mac as normalize_mac
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

logger = logging.getLogger(__name__)

# --- config sanitization ---
# "password cipher/simple <value>" — local user passwords
_PASSWORD_RE = re.compile(r"(password\s+(?:cipher|simple))\s+\S+", re.IGNORECASE)
# "key cipher <value>"
_KEY_CIPHER_RE = re.compile(r"(\bkey\s+cipher)\s+\S+", re.IGNORECASE)
# "pre-shared-key cipher/simple <value>"
_PSK_RE = re.compile(r"(pre-shared-key\s+(?:cipher|simple))\s+\S+", re.IGNORECASE)
# "authentication-key cipher <value>"
_AUTH_KEY_RE = re.compile(r"(authentication-key\s+cipher)\s+\S+", re.IGNORECASE)
# "snmp-agent community [read|write] [cipher|simple] <value>"
# The optional cipher/simple mode keyword must be consumed before redacting
# so that lines like "community read cipher <secret>" redact the secret,
# not the keyword.
_SNMP_COMMUNITY_RE = re.compile(
    r"(snmp-agent\s+community\s+(?:read|write)(?:\s+(?:cipher|simple))?)\s+\S+",
    re.IGNORECASE,
)


def _sanitize_config(text: str) -> str:
    text = _PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _KEY_CIPHER_RE.sub(r"\1 <redacted>", text)
    text = _PSK_RE.sub(r"\1 <redacted>", text)
    text = _AUTH_KEY_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_COMMUNITY_RE.sub(r"\1 <redacted>", text)
    return text


# Uptime conversion constants
_MINUTE_SECONDS = 60
_HOUR_SECONDS = 3600
_DAY_SECONDS = 24 * _HOUR_SECONDS
_WEEK_SECONDS = 7 * _DAY_SECONDS


def _parse_uptime(uptime_str: str) -> float:
    """
    Convert a Comware 'display version' uptime string to total seconds.

    Comware reports uptime on the device description line, e.g.::

        H3C S5560X-30C-EI uptime is 10 weeks, 5 days, 7 hours, 50 minutes

    Returns 0.0 on parse failure.
    """
    seconds = 0.0
    for pattern, factor in (
        (r"(\d+)\s+week", _WEEK_SECONDS),
        (r"(\d+)\s+day", _DAY_SECONDS),
        (r"(\d+)\s+hour", _HOUR_SECONDS),
        (r"(\d+)\s+minute", _MINUTE_SECONDS),
        (r"(\d+)\s+second", 1),
    ):
        m = re.search(pattern, uptime_str)
        if m:
            seconds += int(m.group(1)) * factor
    return seconds


def _parse_speed(speed_str: str) -> float:
    """
    Normalize Comware speed string to Mbps float.

    Examples: "100Mbps" → 100.0, "1000Mbps" → 1000.0, "10GE" → 10000.0,
    "40GE" → 40000.0, "100GE" → 100000.0. Returns -1.0 for unknown.
    """
    if not speed_str:
        return -1.0
    s = speed_str.strip().upper()
    # e.g. "10GE", "40GE", "100GE", "400GE"
    m = re.match(r"(\d+(?:\.\d+)?)GE?$", s)
    if m:
        return float(m.group(1)) * 1000
    # e.g. "100Mbps", "1000Mbps", "100M", "1G"
    m = re.match(r"(\d+(?:\.\d+)?)G(?:BPS|B/S)?$", s)
    if m:
        return float(m.group(1)) * 1000
    m = re.match(r"(\d+(?:\.\d+)?)M(?:BPS|B/S)?$", s)
    if m:
        return float(m.group(1))
    # e.g. plain number (some templates return just the digit)
    m = re.match(r"^(\d+)$", s)
    if m:
        return float(m.group(1))
    return -1.0


def _parse_version_output(raw: str) -> tuple[str, str, float]:
    """
    Parse 'display version' output into (model, os_version, uptime_seconds).

    Comware 7 example::

        H3C Comware Platform Software
        Comware Software, Version 7.1.070, Release 3506P03
        ...
        H3C S5560X-30C-EI uptime is 10 weeks, 5 days, 7 hours, 50 minutes

    HP-branded devices may say::

        HP Comware Platform Software
        Comware Software Version 5.20.99 Release 1808P10
        ...
        HP A5500-24G-PoE EI Switch uptime is 0 weeks, 1 days, 2 hours, 3 minutes
    """
    model = "Unknown"
    os_version = "Unknown"
    uptime = 0.0

    # OS version: "Version X.Y.Z, Release ABC" or "Version X.Y.Z Release ABC"
    m = re.search(r"Version\s+([\d.]+[^,\n]*?)(?:,?\s*Release\s+|$)", raw, re.IGNORECASE)
    if m:
        os_version = m.group(1).strip()

    # Uptime line (single line): "<Vendor> <Model> uptime is ..."
    # e.g. "H3C S5560X-30C-EI uptime is 2 weeks, 3 days, 4 hours, 15 minutes"
    m_uptime = re.search(
        r"^(?:H3C|HP|HPE)\s+(.+?)\s+uptime\s+is\s+(.+)$",
        raw,
        re.IGNORECASE | re.MULTILINE,
    )
    if m_uptime:
        model = m_uptime.group(1).strip()
        uptime = _parse_uptime(m_uptime.group(2))

    return model, os_version, uptime


class ComwareDriver(_napalm_base.NetworkDriver):
    """HP Comware NAPALM driver (read-only subset for device-discovery)."""

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
        # Comware has no enable mode — tell NAPALM not to call enable()
        self.force_no_enable = True

    def open(self):
        """Open an SSH connection to the device via Netmiko."""
        self.device = self._netmiko_open(
            "hp_comware", netmiko_optional_args=self.netmiko_optional_args
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
        # --- hostname from sysname in running config ---
        hostname = "Unknown"
        sysname_out = self.device.send_command("display current-configuration | include sysname")
        if "sysname " in sysname_out:
            hostname = sysname_out.split("sysname ", 1)[1].strip().splitlines()[0].strip()

        # --- model / os_version / uptime from 'display version' ---
        raw_version = self.device.send_command("display version")
        model, os_version, uptime = _parse_version_output(raw_version)

        # --- serial number from 'display device manuinfo' ---
        serial_number = "Unknown"
        raw_manuinfo = self.device.send_command("display device manuinfo")
        parsed_manuinfo = parse_output(
            platform="hp_comware", command="display device manuinfo", data=raw_manuinfo
        )
        chassis_sns = [
            row["device_serial_number"]
            for row in parsed_manuinfo
            if row.get("slot_type", "").lower() == "chassis"
            and row.get("device_serial_number")
        ]
        if chassis_sns:
            serial_number = chassis_sns[0]
        else:
            slot_sns = [
                row["device_serial_number"]
                for row in parsed_manuinfo
                if row.get("device_serial_number")
            ]
            if slot_sns:
                serial_number = slot_sns[0]

        # --- interface list from 'display interface' ---
        raw_intf = self.device.send_command("display interface")
        parsed_intf = parse_output(
            platform="hp_comware", command="display interface", data=raw_intf
        )
        interface_list = [row["interface"] for row in parsed_intf if row.get("interface")]

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
        raw = self.device.send_command("display interface")
        if not raw:
            return {}

        parsed = parse_output(platform="hp_comware", command="display interface", data=raw)
        interfaces = {}
        for row in parsed:
            intf = row.get("interface", "")
            if not intf:
                continue

            line_status = row.get("line_status", "").lower()
            proto_status = row.get("protocol_status", "").lower()

            # Administratively DOWN means disabled; any other DOWN means enabled but down
            is_enabled = "administratively" not in line_status
            is_up = "up" in proto_status and "spoofing" not in proto_status

            hw_address_list = row.get("hw_address", [])
            raw_mac = hw_address_list[0] if hw_address_list else ""
            try:
                mac_address = normalize_mac(raw_mac) if raw_mac else ""
            except Exception:
                mac_address = raw_mac

            try:
                mtu = int(row.get("mtu", "") or -1)
            except ValueError:
                mtu = -1

            interfaces[intf] = {
                "is_up": is_up,
                "is_enabled": is_enabled,
                "description": row.get("description", "").strip(),
                "last_flapped": -1.0,
                "mtu": mtu,
                "speed": _parse_speed(row.get("speed", "")),
                "mac_address": mac_address,
            }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface."""
        raw = self.device.send_command("display interface")
        if not raw:
            return {}

        parsed = parse_output(platform="hp_comware", command="display interface", data=raw)
        interfaces_ip: dict = {}
        for row in parsed:
            intf = row.get("interface", "")
            if not intf:
                continue
            for cidr in row.get("ip_address", []):
                if not cidr or "/" not in cidr:
                    continue
                ip_str, prefix_str = cidr.rsplit("/", 1)
                try:
                    prefix_length = int(prefix_str)
                    addr = ipaddress.ip_address(ip_str)
                except ValueError:
                    continue
                family = "ipv4" if isinstance(addr, ipaddress.IPv4Address) else "ipv6"
                interfaces_ip.setdefault(intf, {}).setdefault(family, {})[ip_str] = {
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
            config["running"] = self.device.send_command("display current-configuration")

        if retrieve.lower() in ("startup", "all"):
            config["startup"] = self.device.send_command("display saved-configuration")

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Return VLAN information keyed by VLAN ID string."""
        raw = self.device.send_command("display vlan brief")
        if not raw:
            return {}

        parsed = parse_output(platform="hp_comware", command="display vlan brief", data=raw)
        vlans: dict = {}
        for row in parsed:
            vlan_id = row.get("vlan_id", "")
            if not vlan_id:
                continue
            vlan_name = row.get("vlan_name", "").strip() or vlan_id
            vlans[vlan_id] = {"name": vlan_name, "interfaces": []}

        return vlans
