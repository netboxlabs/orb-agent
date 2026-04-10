# Copyright 2026 NetBox Labs Inc
"""
Custom Aruba AOS-CX NAPALM driver — SSH CLI via Netmiko + ntc-templates.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses the ``aruba_aoscx`` Netmiko device type and ntc-templates platform
for structured parsing of:
  show system, show interface, show vlan, show running-config, show startup-config.

IP address extraction uses the IP_ADDRESS field from the ``show interface``
template which captures the primary IPv4 address in CIDR notation.
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.helpers import mac as normalize_mac
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

logger = logging.getLogger(__name__)

_PLATFORM = "aruba_aoscx"

# ---------------------------------------------------------------------------
# Config sanitization
# AOS-CX CLI config uses password/passkey/secret keywords
# ---------------------------------------------------------------------------
_PASSWORD_RE = re.compile(
    r"((?:password|secret|passkey)\s+)\S+", re.IGNORECASE
)
_RADIUS_KEY_RE = re.compile(
    r"(radius-server\s+(?:host\s+\S+\s+)?key)\s+\S+", re.IGNORECASE
)
_TACACS_KEY_RE = re.compile(
    r"(tacacs-server\s+(?:host\s+\S+\s+)?key)\s+\S+", re.IGNORECASE
)
_SNMP_COMM_RE = re.compile(
    r"(snmp-server\s+community)\s+\S+", re.IGNORECASE
)


def _sanitize_config(text: str) -> str:
    text = _PASSWORD_RE.sub(r"\1<redacted>", text)
    text = _RADIUS_KEY_RE.sub(r"\1 <redacted>", text)
    text = _TACACS_KEY_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_COMM_RE.sub(r"\1 <redacted>", text)
    return text


# Uptime conversion constants
_WEEK_SECONDS = 7 * 24 * 3600
_DAY_SECONDS = 24 * 3600
_HOUR_SECONDS = 3600
_MINUTE_SECONDS = 60


def _parse_uptime(row: dict) -> float:
    """Convert ntc-template uptime fields (weeks/days/hours/minutes) to seconds."""
    seconds = 0.0
    for field, factor in (
        ("uptime_weeks", _WEEK_SECONDS),
        ("uptime_days", _DAY_SECONDS),
        ("uptime_hours", _HOUR_SECONDS),
        ("uptime_minutes", _MINUTE_SECONDS),
    ):
        val = row.get(field, "") or ""
        if val.isdigit():
            seconds += int(val) * factor
    return seconds


def _parse_speed_mbps(speed_str: str) -> float:
    """
    Convert an AOS-CX speed string to Mbps (float).

    The ntc-template captures speed as e.g. ``"1000 Mb/s"``, ``"10 Gb/s"``.
    Returns -1.0 when the string is empty or unparseable.
    """
    if not speed_str:
        return -1.0
    speed_str = speed_str.strip().lower()
    m = re.match(r"(\d+(?:\.\d+)?)\s*(gb|mb|kb)?", speed_str)
    if not m:
        return -1.0
    value = float(m.group(1))
    unit = m.group(2) or "mb"
    if unit == "gb":
        value *= 1000.0
    elif unit == "kb":
        value /= 1000.0
    return value


class AOSCXSSHDriver(_napalm_base.NetworkDriver):
    """Aruba AOS-CX NAPALM SSH driver using Netmiko + ntc-templates (read-only subset)."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Initialise driver — no network connection is made here."""
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
        """Open an SSH connection via Netmiko."""
        self.device = self._netmiko_open(
            "aruba_aoscx",
            netmiko_optional_args=self.netmiko_optional_args,
        )

    def close(self):
        """Close the SSH connection."""
        self._netmiko_close()

    def is_alive(self):
        """Return whether the SSH channel is still active."""
        if self.device is None:
            return {"is_alive": False}
        try:
            self.device.write_channel(chr(0))
            return {"is_alive": self.device.remote_conn.transport.is_active()}
        except (EOFError, OSError, AttributeError):
            return {"is_alive": False}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _send(self, command: str) -> str:
        return self.device.send_command(command)

    def _parse(self, command: str, data: str) -> list[dict]:
        return parse_output(platform=_PLATFORM, command=command, data=data)

    # ------------------------------------------------------------------
    # NAPALM getters
    # ------------------------------------------------------------------

    def get_facts(self) -> dict:
        """Return general device facts from ``show system``."""
        raw = self._send("show system")
        parsed = self._parse("show system", raw)
        if not parsed:
            return {}

        row = parsed[0]
        interface_list = []
        intf_raw = self._send("show interface")
        if intf_raw:
            intf_parsed = self._parse("show interface", intf_raw)
            interface_list = [
                r["interface"]
                for r in intf_parsed
                if r.get("interface")
            ]

        return {
            "hostname": row.get("hostname", "Unknown"),
            "vendor": row.get("vendor", "Aruba") or "Aruba",
            "model": (row.get("product", "") or "Unknown").strip(),
            "os_version": row.get("version", "Unknown"),
            "serial_number": row.get("serial", "Unknown"),
            "uptime": _parse_uptime(row),
            "fqdn": row.get("hostname", "Unknown"),
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """Return interface details from ``show interface``."""
        raw = self._send("show interface")
        if not raw:
            return {}

        parsed = self._parse("show interface", raw)
        result = {}
        for row in parsed:
            name = row.get("interface", "")
            if not name:
                continue

            mac_raw = row.get("mac_address", "")
            try:
                mac_address = normalize_mac(mac_raw) if mac_raw else ""
            except Exception:
                mac_address = mac_raw

            result[name] = {
                "is_up": row.get("link_status", "").lower() == "up",
                "is_enabled": row.get("link_admin", "").lower() == "up",
                "description": (row.get("interface_desc", "") or "").strip(),
                "last_flapped": -1.0,
                "mtu": int(row["mtu"]) if row.get("mtu", "").isdigit() else -1,
                "speed": _parse_speed_mbps(row.get("speed", "")),
                "mac_address": mac_address,
            }

        return result

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface from ``show interface``."""
        raw = self._send("show interface")
        if not raw:
            return {}

        parsed = self._parse("show interface", raw)
        result = {}
        for row in parsed:
            name = row.get("interface", "")
            if not name:
                continue

            intf_ips: dict = {}

            # Primary IPv4 (format: "x.x.x.x/prefix")
            ip_primary = row.get("ip_address", "")
            if ip_primary and "/" in ip_primary:
                addr, prefix = ip_primary.rsplit("/", 1)
                if prefix.isdigit():
                    intf_ips.setdefault("ipv4", {})[addr] = {
                        "prefix_length": int(prefix)
                    }

            # Secondary IPv4
            for ip_sec in row.get("secondary_ip_address", []):
                if ip_sec and "/" in ip_sec:
                    addr, prefix = ip_sec.rsplit("/", 1)
                    if prefix.isdigit():
                        intf_ips.setdefault("ipv4", {})[addr] = {
                            "prefix_length": int(prefix)
                        }

            if intf_ips:
                result[name] = intf_ips

        return result

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """Return device configuration from ``show running-config`` / ``show startup-config``."""
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}

        if retrieve in ("running", "all"):
            config["running"] = self._send("show running-config")

        if retrieve in ("startup", "all"):
            config["startup"] = self._send("show startup-config")

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Return VLAN information from ``show vlan``."""
        raw = self._send("show vlan")
        if not raw:
            return {}

        parsed = self._parse("show vlan", raw)
        result: dict = {}
        for row in parsed:
            vlan_id = row.get("vlan_id", "")
            if not vlan_id:
                continue
            entry = result.setdefault(
                vlan_id,
                {
                    "name": row.get("vlan_name", "") or vlan_id,
                    "interfaces": [],
                },
            )
            for intf in row.get("interfaces", []):
                intf = intf.strip()
                if intf and intf not in entry["interfaces"]:
                    entry["interfaces"].append(intf)

        return result
