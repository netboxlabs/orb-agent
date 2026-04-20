# Copyright 2026 NetBox Labs Inc
"""
Custom Ubiquiti EdgeSwitch NAPALM driver.

EdgeSwitch runs a Cisco IOS-style CLI. Uses Netmiko (ubiquiti_edgeswitch) for
SSH connectivity, ntc-templates for 'show version' and 'show vlan', and regex
for interface status and IP address parsing.

Implements: get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.
"""

import ipaddress
import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

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
# Interface status parsing — 'show interfaces status all'
# ---------------------------------------------------------------------------

# Output columns (example):
#    0/1    Copper  Enabled     Forwarding  Up      Full-100M   Full-100M   Copper
# Ch = channel (0/1, 1/0/1, lag1, etc.)
# Leading whitespace is optional: some firmware variants start rows at column 1.
# Anchoring on Enabled|Disabled for the Neg column prevents false matches on
# header ("Neg") and separator ("---") lines when no indent is present.
_ES_INTF_LINE_RE = re.compile(
    r"^\s*"
    r"(?P<intf>\S+)\s+"                       # channel/interface
    r"\S+\s+"                                  # Type (Copper, Fiber)
    r"(?P<neg>Enabled|Disabled)\s+"            # Neg/admin — anchors against headers
    r"(?P<state>\S+)\s+"                       # Port state (Forwarding, Disabled, …)
    r"(?P<link>\S+)",                          # Link state (Up/Down)
    re.IGNORECASE,
)

# "Full-100M" → 100.0 Mbps, "Full-1000M" → 1000.0, "Full-10G" → 10000.0
_SPEED_RE = re.compile(r"(?:Full|Half)-(\d+)([MG])", re.IGNORECASE)


def _parse_speed(speed_str: str) -> float:
    """Convert EdgeSwitch physical mode string (e.g. 'Full-100M') to Mbps."""
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
    Extract VLAN → interface membership from EdgeSwitch running-config.

    Parses interface blocks looking for:
        vlan participation include <id>,<id>,...

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


class EdgeSwitchDriver(_napalm_base.NetworkDriver):
    """Ubiquiti EdgeSwitch NAPALM driver (read-only subset for device-discovery)."""

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
        """Open an SSH connection via Netmiko."""
        self.device = self._netmiko_open(
            "ubiquiti_edgeswitch", netmiko_optional_args=self.netmiko_optional_args
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
        - 'show version'              → model, serial, os_version (ntc-template)
        - 'show running-config'       → hostname (regex on 'hostname' line)
        - 'show interfaces status all' → interface_list (regex)

        Uptime is not available from the EdgeSwitch CLI without a dedicated
        'show system' parse; it is returned as 0.0.
        """
        model = serial = os_version = "Unknown"
        raw_ver = self.device.send_command("show version")
        try:
            parsed = parse_output(
                platform="ubiquiti_edgeswitch", command="show version", data=raw_ver
            )
            if parsed:
                row = parsed[0]
                model = row.get("switch_model", "Unknown").strip()
                serial = row.get("serial", "Unknown").strip()
                os_version = row.get("version", "Unknown").strip()
        except Exception:
            logger.debug("Failed to parse 'show version'", exc_info=True)

        config_raw = self.device.send_command("show running-config")
        hostname = self._hostname_from_config(config_raw)

        interface_list: list[str] = []
        for line in self._get_intf_status_raw().splitlines():
            m = _ES_INTF_LINE_RE.match(line)
            if m:
                interface_list.append(m.group("intf"))

        return {
            "hostname": hostname,
            "vendor": "Ubiquiti",
            "model": model,
            "os_version": os_version,
            "serial_number": serial,
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
            m = _ES_INTF_LINE_RE.match(line)
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

        VLAN names are fetched via 'show vlan' (ntc-template).
        Interface membership is parsed from 'show running-config' by scanning
        'vlan participation include <ids>' lines within interface blocks.
        """
        vlans: dict = {}

        raw_vlan = self.device.send_command("show vlan")
        try:
            parsed = parse_output(
                platform="ubiquiti_edgeswitch", command="show vlan", data=raw_vlan
            )
            for row in parsed:
                vid = row.get("vlan_id", "").strip()
                if vid:
                    vlans[vid] = {
                        "name": row.get("vlan_name", vid).strip(),
                        "interfaces": [],
                    }
        except Exception:
            logger.debug("Failed to parse 'show vlan'", exc_info=True)

        config_raw = self.device.send_command("show running-config")
        for vid, intfs in _parse_vlan_members(config_raw).items():
            if vid in vlans:
                vlans[vid]["interfaces"] = intfs
            else:
                vlans[vid] = {"name": vid, "interfaces": intfs}

        return vlans
