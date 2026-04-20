# Copyright 2026 NetBox Labs Inc
"""
Custom Cisco Viptela SD-WAN NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko cisco_viptela device type and ntc-templates cisco_viptela
platform for structured parsing of 'show interface'.  System facts are
extracted from 'show system status' via regex since no ntc-template
exists for that command.
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config sanitization — Cisco Viptela SD-WAN sensitive fields
# ---------------------------------------------------------------------------

# IKE/IPSec pre-shared key: "pre-shared-key <value>"
# .* consumes the entire value segment, covering multi-token forms such as
# "pre-shared-key ascii2 MyKey" that \S+ would only partially redact.
_PSK_RE = re.compile(r"(pre-shared-key)\s+.*", re.IGNORECASE)

# User/interface password: "password <value>"
# Line-anchored to avoid false positives in descriptions; .* redacts full value.
_PASSWORD_RE = re.compile(r"^(\s*password)\s+.*", re.IGNORECASE | re.MULTILINE)

# RADIUS/TACACS auth-password: "auth-password <value>"
_AUTH_PASSWORD_RE = re.compile(r"(auth-password)\s+.*", re.IGNORECASE)

# SNMP community string: "community <value>"
# Line-anchored to avoid false positives; .* redacts full value.
_COMMUNITY_RE = re.compile(r"^(\s*community)\s+.*", re.IGNORECASE | re.MULTILINE)

# Generic secret field: "secret <value>"
# Line-anchored to avoid false positives; .* redacts full value.
_SECRET_RE = re.compile(r"^(\s*secret)\s+.*", re.IGNORECASE | re.MULTILINE)


def _sanitize_config(text: str) -> str:
    text = _PSK_RE.sub(r"\1 <redacted>", text)
    text = _PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _AUTH_PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _COMMUNITY_RE.sub(r"\1 <redacted>", text)
    text = _SECRET_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Uptime helpers
# ---------------------------------------------------------------------------

_DAY_SECONDS = 86400
_HOUR_SECONDS = 3600
_MINUTE_SECONDS = 60


def _parse_uptime_words(uptime_str: str) -> float:
    """
    Parse Viptela 'show system status' uptime string to seconds.

    Handles both full-word and abbreviated Cisco SD-WAN formats:
      "5 days 3 hours 24 minutes 18 seconds"   (full words)
      "5 days 3 hrs 24 min 18 sec"             (abbreviations)
      "0 days 2 hours 30 minutes"              (seconds absent)
      "1 day 0 hours 12 minutes 30 seconds"
    """
    seconds = 0.0
    for pattern, factor in (
        (r"(\d+)\s+days?", _DAY_SECONDS),
        (r"(\d+)\s+(?:hours?|hrs?)", _HOUR_SECONDS),
        (r"(\d+)\s+(?:minutes?|mins?)", _MINUTE_SECONDS),
        (r"(\d+)\s+(?:seconds?|secs?)", 1),
    ):
        m = re.search(pattern, uptime_str, re.IGNORECASE)
        if m:
            seconds += int(m.group(1)) * factor
    return seconds


# ---------------------------------------------------------------------------
# Fact extraction helpers
# ---------------------------------------------------------------------------

def _extract_fact(text: str, *patterns: str) -> str:
    """
    Try each regex pattern in order; return the first non-empty group(1) match.

    All patterns must have exactly one capture group for the value.
    Returns empty string if no pattern matches.
    """
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
        if m:
            value = m.group(1).strip()
            if value:
                return value
    return ""


# ---------------------------------------------------------------------------
# Speed helper
# ---------------------------------------------------------------------------

def _parse_speed(speed_str: str) -> float:
    """Convert SPEED column string (Mbps) to float; -1.0 if non-numeric."""
    try:
        return float(speed_str)
    except (ValueError, TypeError):
        return -1.0


# ---------------------------------------------------------------------------
# IP address helpers
# ---------------------------------------------------------------------------

def _split_cidr(cidr: str) -> tuple[str, int]:
    """
    Split a CIDR string ('a.b.c.d/prefix') into (address, prefix_length).

    Returns ("", -1) if the string is not a valid CIDR notation.
    """
    if not cidr or "/" not in cidr:
        return "", -1
    parts = cidr.split("/", 1)
    try:
        return parts[0], int(parts[1])
    except (ValueError, IndexError):
        return parts[0], -1


class ViptelaSSHDriver(_napalm_base.NetworkDriver):
    """Cisco Viptela SD-WAN NAPALM driver (read-only subset for device-discovery)."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Initialise driver state; no connection is opened yet."""
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
            "cisco_viptela", netmiko_optional_args=self.netmiko_optional_args
        )

    def close(self):
        """Close the SSH connection."""
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

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _parsed_interfaces(self) -> list[dict]:
        """
        Run 'show interface' and return the ntc-templates parsed rows.

        Returns an empty list on any parse failure.
        """
        raw = self.device.send_command("show interface")
        if not raw:
            return []
        try:
            return parse_output(
                platform="cisco_viptela", command="show interface", data=raw
            )
        except Exception:
            logger.debug("Failed to parse 'show interface' output", exc_info=True)
            return []

    # -----------------------------------------------------------------------
    # NAPALM getters
    # -----------------------------------------------------------------------

    def get_facts(self) -> dict:
        """
        Return general device facts.

        Hostname, model, OS version, serial number, and uptime come from
        'show system status' (regex-parsed).  Interface list comes from
        'show interface' (ntc-templates).  Falls back to safe defaults when
        a command returns no output or parsing fails.
        """
        hostname = self.hostname
        vendor = "Cisco"
        model = "Unknown"
        os_version = "Unknown"
        serial_number = "Unknown"
        uptime = 0.0

        sys_raw = self.device.send_command("show system status")
        if sys_raw:
            hostname = (
                _extract_fact(
                    sys_raw,
                    r"^Hostname\s*:\s*(.+)",
                    r"^System\s+hostname\s*:\s*(.+)",
                )
                or hostname
            )
            model = (
                _extract_fact(
                    sys_raw,
                    r"^(?:Device\s+Model|Chassis\s+type|Model\s+name)\s*:\s*(.+)",
                )
                or model
            )
            os_version = (
                _extract_fact(
                    sys_raw,
                    r"^Version\s*:\s*(.+)",
                    r"^Software\s+[Vv]ersion\s*:\s*(.+)",
                )
                or os_version
            )
            # Serial: first token on the line (may be padded with spaces).
            # Reject known placeholder tokens so they don't pollute inventory
            # with a fake serial shared across many devices.
            _SERIAL_PLACEHOLDERS = {"none", "n/a", "na", "null", "unknown", "-"}
            serial_raw = _extract_fact(
                sys_raw,
                r"^Chassis\s+serial\s+number(?:/Token)?\s*:\s*(\S+)",
                r"^Serial\s+[Nn]umber\s*:\s*(\S+)",
            )
            if serial_raw and serial_raw.lower() not in _SERIAL_PLACEHOLDERS:
                serial_number = serial_raw

            uptime_raw = _extract_fact(
                sys_raw,
                r"^Uptime\s*:\s*(.+)",
                r"^System\s+uptime\s*:\s*(.+)",
            )
            if uptime_raw:
                uptime = _parse_uptime_words(uptime_raw)

        # Interface list from 'show interface'
        parsed_intfs = self._parsed_interfaces()
        seen: set[str] = set()
        interface_list: list[str] = []
        for row in parsed_intfs:
            name = row.get("interface", "")
            if name and name not in seen:
                seen.add(name)
                interface_list.append(name)
        interface_list.sort()

        return {
            "hostname": hostname,
            "vendor": vendor,
            "model": model,
            "os_version": os_version,
            "serial_number": serial_number,
            "uptime": uptime,
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """
        Return interface details keyed by interface name.

        Physical attributes (admin/oper status, speed, MTU, MAC) are taken
        from the first 'show interface' row for each interface name.  When the
        template returns '-' for a numeric field the NAPALM sentinel (-1 / -1.0)
        is used instead.
        """
        parsed = self._parsed_interfaces()
        interfaces: dict = {}

        for row in parsed:
            name = row.get("interface", "")
            if not name or name in interfaces:
                # Skip empty names; keep only the first row per interface
                # (the template may emit one row per address family).
                continue

            admin_up = row.get("admin_status", "").strip().lower() == "up"
            oper_up = row.get("oper_status", "").strip().lower() == "up"
            mtu_str = row.get("mtu", "-")
            try:
                mtu = int(mtu_str)
            except (ValueError, TypeError):
                mtu = -1

            mac = row.get("mac_address", "")
            if mac == "-":
                mac = ""

            # Suppress speed for loopback interfaces so the translation layer
            # does not fall back to speed-based type detection (which would
            # yield '1000base-t' for Viptela loopbacks whose name is lowercase
            # and therefore does not match the built-in '^Loopback\d+' pattern).
            is_loopback = row.get("port_type", "").strip().lower() == "loopback"

            interfaces[name] = {
                "is_up": oper_up,
                "is_enabled": admin_up,
                "description": "",
                "last_flapped": -1.0,
                "mtu": mtu,
                "speed": -1.0 if is_loopback else _parse_speed(row.get("speed", "-")),
                "mac_address": mac,
            }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """
        Return IP addresses per interface.

        Viptela's 'show interface' includes a CIDR IP_ADDRESS column and an
        AF_TYPE column.  Both IPv4 and IPv6 rows are handled.  Rows with
        '-' in the IP_ADDRESS column are skipped.
        """
        parsed = self._parsed_interfaces()
        interfaces_ip: dict = {}

        for row in parsed:
            name = row.get("interface", "")
            ip_cidr = row.get("ip_address", "").strip()
            af_type = row.get("af_type", "").strip().lower()

            if not name or not ip_cidr or ip_cidr == "-":
                continue

            address, prefix_length = _split_cidr(ip_cidr)
            if not address or prefix_length < 0:
                continue

            if af_type == "ipv6":
                family = "ipv6"
            else:
                family = "ipv4"

            interfaces_ip.setdefault(name, {}).setdefault(family, {})[address] = {
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
        """
        Return device configuration.

        Viptela uses 'show running-config' for the full configuration.
        There is no separate candidate or startup config.
        """
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}

        if retrieve in ("all", "running"):
            config["running"] = self.device.send_command("show running-config")

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """
        Return VLAN information.

        Cisco Viptela SD-WAN does not expose a traditional Layer-2 VLAN table
        via the CLI; VPN segmentation is used instead.  Returns an empty dict.
        """
        return {}
