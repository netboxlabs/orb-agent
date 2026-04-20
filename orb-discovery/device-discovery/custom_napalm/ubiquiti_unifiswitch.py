# Copyright 2026 NetBox Labs Inc
"""
Custom Ubiquiti UniFi Switch NAPALM driver.

UniFi switches run a Cisco IOS-style CLI, but the SSH session first lands at a
Linux shell; Netmiko's ubiquiti_unifiswitch driver transparently runs
'telnet localhost' to reach the network CLI before handing control over.

No ntc-templates exist for ubiquiti_unifiswitch; all parsing is done with regex.

Implements: get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.
"""

import ipaddress
import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.netmiko_helpers import netmiko_args

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config sanitization — Cisco IOS-style credentials
# ---------------------------------------------------------------------------

# "username admin password 7 HASH" / "username admin secret 5 $1$..."
_USERNAME_RE = re.compile(
    r"(username\s+\S+\s+(?:password|secret)(?:\s+\d+)?)\s+\S+",
    re.IGNORECASE,
)
# "enable password 7 HASH" / "enable secret 5 $1$..."
_ENABLE_RE = re.compile(
    r"(enable\s+(?:password|secret)(?:\s+\d+)?)\s+\S+",
    re.IGNORECASE,
)
# "snmp-server community public ro"
_SNMP_RE = re.compile(
    r"(snmp-server\s+community)\s+\S+",
    re.IGNORECASE,
)


def _sanitize_config(text: str) -> str:
    text = _USERNAME_RE.sub(r"\1 <redacted>", text)
    text = _ENABLE_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# 'show version' parsing — regex (no ntc-template available)
# ---------------------------------------------------------------------------

# "Machine Model.............. US-24-250W"
_MODEL_RE = re.compile(r"Machine\s+Model[.\s]+(\S+)", re.IGNORECASE)
# "Serial Number.............. F09FC2AB1234"
_SERIAL_RE = re.compile(r"Serial\s+Number[.\s]+(\S+)", re.IGNORECASE)
# "Software Version........... 4.0.66.10832"
_VERSION_RE = re.compile(r"Software\s+Version[.\s]+(\S+)", re.IGNORECASE)


def _parse_version(raw: str) -> dict[str, str]:
    """Extract model, serial, and software version from 'show version' output."""
    result: dict[str, str] = {}
    for key, pattern in (
        ("model", _MODEL_RE),
        ("serial_number", _SERIAL_RE),
        ("os_version", _VERSION_RE),
    ):
        m = pattern.search(raw)
        result[key] = m.group(1).strip() if m else "Unknown"
    return result


# ---------------------------------------------------------------------------
# Interface status parsing — 'show interfaces status all'
# ---------------------------------------------------------------------------

# Same column layout as EdgeSwitch:
#    0/1    Copper  Enabled     Forwarding  Up      Full-100M   Full-100M   Copper
_INTF_LINE_RE = re.compile(
    r"^\s*"
    r"(?P<intf>\S+)\s+"                       # channel/interface
    r"\S+\s+"                                  # Type (Copper, Fiber)
    r"(?P<neg>Enabled|Disabled)\s+"            # Neg/admin — anchors against headers
    r"(?P<state>\S+)\s+"                       # Port state (Forwarding, Disabled, Blocking, …)
    r"(?P<link>\S+)",                           # Link state (Up/Down)
    re.IGNORECASE,
)

# "Full-100M" → 100.0 Mbps, "Full-1000M" → 1000.0, "Full-10G" → 10000.0
_SPEED_RE = re.compile(r"(?:Full|Half)-(\d+)([MG])", re.IGNORECASE)


def _parse_speed(speed_str: str) -> float:
    """Convert 'Full-100M' style string to Mbps."""
    m = _SPEED_RE.match(speed_str)
    if not m:
        return -1.0
    val, unit = int(m.group(1)), m.group(2).upper()
    return float(val * 1000 if unit == "G" else val)


# ---------------------------------------------------------------------------
# IP interface parsing — 'show ip interface'
# ---------------------------------------------------------------------------

# "192.168.1.1        255.255.255.0      VLAN 1     Valid"
_IP_INTF_RE = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<mask>[\d.]+)\s+"
    r"(?P<intf_type>\w+)\s+(?P<intf_id>\d+)\s+"
    r"Valid",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# VLAN parsing — 'show vlan' (no ntc-template, regex only)
# ---------------------------------------------------------------------------

# "1        Default                      Default"
# "100      Management                   Static"
# Name and type are separated by 2+ spaces; match any type word.
_VLAN_LINE_RE = re.compile(
    r"^(?P<id>\d+)\s+(?P<name>.*?)\s{2,}\S+\s*$",
)


# ---------------------------------------------------------------------------
# VLAN membership parsing — 'show running-config'
# ---------------------------------------------------------------------------

def _expand_vlan_tokens(token_str: str) -> list[str]:
    """Expand a comma-separated VLAN list (with optional ranges) into VLAN ID strings."""
    vids: list[str] = []
    for token in token_str.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            start, _, end = token.partition("-")
            try:
                start_vid = int(start.strip())
                end_vid = int(end.strip())
            except ValueError:
                logger.warning("Skipping malformed VLAN range token %r", token)
                continue
            if start_vid > end_vid:
                logger.warning("Skipping reversed VLAN range token %r", token)
                continue
            vids.extend(str(v) for v in range(start_vid, end_vid + 1))
        else:
            try:
                int(token)
            except ValueError:
                logger.warning("Skipping malformed VLAN token %r", token)
                continue
            vids.append(token)
    return vids


def _parse_vlan_members(config: str) -> dict[str, list[str]]:
    """
    Extract VLAN → interface membership from UniFi running-config.

    Returns {vlan_id_str: [interface_names]}.
    """
    result: dict[str, list[str]] = {}
    current_intf: str | None = None
    for line in config.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        m_intf = re.match(r"^interface\s+(.+)$", stripped)
        if m_intf:
            current_intf = m_intf.group(1)
            continue
        if stripped == "!":
            current_intf = None
            continue
        if current_intf:
            m_vlan = re.match(r"^vlan\s+participation\s+include\s+(.+)$", stripped)
            if m_vlan:
                for vid in _expand_vlan_tokens(m_vlan.group(1)):
                    result.setdefault(vid, []).append(current_intf)
    return result


class UniFiSwitchDriver(_napalm_base.NetworkDriver):
    """Ubiquiti UniFi Switch NAPALM driver (read-only subset for device-discovery)."""

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
        """Open an SSH connection via Netmiko (handles telnet-localhost tunnel internally)."""
        self.device = self._netmiko_open(
            "ubiquiti_unifiswitch", netmiko_optional_args=self.netmiko_optional_args
        )
        self._intf_status_raw: str | None = None

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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _hostname_from_config(self, config: str) -> str:
        """Extract hostname from 'hostname <name>' line in running-config."""
        for line in config.splitlines():
            stripped = line.strip()
            if stripped.startswith("hostname "):
                return stripped.split("hostname ", 1)[1].strip()
        return self.hostname

    def _get_intf_status_raw(self) -> str:
        """Fetch 'show interfaces status all' once and cache for this connection."""
        if not hasattr(self, "_intf_status_raw") or self._intf_status_raw is None:
            self._intf_status_raw = self.device.send_command("show interfaces status all")
        return self._intf_status_raw

    # ------------------------------------------------------------------
    # NAPALM getters
    # ------------------------------------------------------------------

    def get_facts(self) -> dict:
        """
        Return general device facts.

        Facts are assembled from three commands:
        - 'show version'               → model, serial, os_version (regex)
        - 'show running-config'        → hostname (regex on 'hostname' line)
        - 'show interfaces status all' → interface_list (regex)

        Uptime is not available without a dedicated parse; it is returned as 0.0.
        """
        raw_ver = self.device.send_command("show version")
        ver_info = _parse_version(raw_ver)

        config_raw = self.device.send_command("show running-config")
        hostname = self._hostname_from_config(config_raw)

        interface_list: list[str] = []
        for line in self._get_intf_status_raw().splitlines():
            m = _INTF_LINE_RE.match(line)
            if m:
                interface_list.append(m.group("intf"))

        return {
            "hostname": hostname,
            "vendor": "Ubiquiti",
            "model": ver_info["model"],
            "os_version": ver_info["os_version"],
            "serial_number": ver_info["serial_number"],
            "uptime": 0.0,
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """
        Return interface details from 'show interfaces status all'.

        is_enabled: Port State != 'Disabled' (Disabled = admin-shutdown)
        is_up:      Link State == 'Up'
        speed:      parsed from Physical Mode column (e.g. 'Full-100M' → 100.0 Mbps)

        Note: the Neg column reflects auto-negotiation, not admin state.
        Admin-shutdown ports show Port State == 'Disabled' regardless of Neg.
        """
        interfaces: dict = {}
        for line in self._get_intf_status_raw().splitlines():
            m = _INTF_LINE_RE.match(line)
            if not m:
                continue
            intf = m.group("intf")
            state = m.group("state").lower()
            link = m.group("link").lower()

            remainder = line[m.end():]
            speed_m = _SPEED_RE.search(remainder)
            speed = _parse_speed(speed_m.group(0)) if speed_m else -1.0

            interfaces[intf] = {
                "is_up": link == "up",
                "is_enabled": state != "disabled",
                "description": "",
                "last_flapped": -1.0,
                "mtu": -1,
                "speed": speed,
                "mac_address": "",
            }
        return interfaces

    def get_interfaces_ip(self) -> dict:
        """
        Return IP addresses per interface from 'show ip interface'.

        Interface names are normalised to lowercase (e.g. 'VLAN 1' → 'vlan1').
        """
        interfaces_ip: dict = {}
        raw = self.device.send_command("show ip interface")
        for line in raw.splitlines():
            m = _IP_INTF_RE.match(line)
            if not m:
                continue
            ip_str = m.group("ip")
            mask_str = m.group("mask")
            intf_name = f"{m.group('intf_type').lower()}{m.group('intf_id')}"
            try:
                prefix = ipaddress.IPv4Network(
                    f"0.0.0.0/{mask_str}", strict=False
                ).prefixlen
            except ValueError:
                continue
            (
                interfaces_ip
                .setdefault(intf_name, {})
                .setdefault("ipv4", {})[ip_str]
            ) = {"prefix_length": prefix}
        return interfaces_ip

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """Return device configuration from 'show running-config' and 'show startup-config'."""
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
        """
        Return VLAN information keyed by VLAN ID string.

        VLAN names are parsed from 'show vlan' with regex (no ntc-template available).
        Interface membership is parsed from 'show running-config' by scanning
        'vlan participation include <ids>' lines within interface blocks.
        """
        vlans: dict = {}

        raw_vlan = self.device.send_command("show vlan")
        for line in raw_vlan.splitlines():
            m = _VLAN_LINE_RE.match(line)
            if m:
                vid = m.group("id").strip()
                name = m.group("name").strip() or vid
                vlans[vid] = {"name": name, "interfaces": []}

        config_raw = self.device.send_command("show running-config")
        for vid, intfs in _parse_vlan_members(config_raw).items():
            if vid in vlans:
                vlans[vid]["interfaces"] = intfs
            else:
                vlans[vid] = {"name": vid, "interfaces": intfs}

        return vlans
