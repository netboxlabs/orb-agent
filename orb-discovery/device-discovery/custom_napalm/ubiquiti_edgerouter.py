# Copyright 2026 NetBox Labs Inc
"""
Custom Ubiquiti EdgeRouter (EdgeOS) NAPALM driver.

EdgeOS is based on VyOS/Vyatta and uses set-command style configuration.
Uses Netmiko (ubiquiti_edgerouter) for SSH connectivity, ntc-templates for
structured parsing of 'show version' and 'show interfaces'.

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
# Config sanitization — EdgeOS/VyOS set-command style
# ---------------------------------------------------------------------------

# Matches: set ... <sensitive-keyword> 'value'  or  set ... <sensitive-keyword> value
# Keywords: password, encrypted-password, plaintext-password, pre-shared-secret, auth-key
_SET_PASS_RE = re.compile(
    r"(set\s+\S[^\n]*?\s+"
    r"(?:encrypted-password|plaintext-password|password|pre-shared-secret|auth-key))"
    r"\s+(?:'[^']*'|\S+)",
    re.IGNORECASE,
)
# "set service snmp community <name> ..."
_SNMP_COMMUNITY_RE = re.compile(
    r"(set\s+service\s+snmp\s+community)\s+\S+",
    re.IGNORECASE,
)


def _sanitize_config(text: str) -> str:
    text = _SET_PASS_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_COMMUNITY_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Uptime parsing — "5 days, 5 hours, 39 minutes, 19 seconds"
# ---------------------------------------------------------------------------

_UPTIME_RE = re.compile(
    r"(?:(\d+)\s+years?(?:,\s*)?)?"
    r"(?:(\d+)\s+weeks?(?:,\s*)?)?"
    r"(?:(\d+)\s+days?(?:,\s*)?)?"
    r"(?:(\d+)\s+hours?(?:,\s*)?)?"
    r"(?:(\d+)\s+minutes?(?:,\s*)?)?"
    r"(?:(\d+)\s+seconds?)?",
    re.IGNORECASE,
)

_YEAR_S = 365.25 * 24 * 3600
_WEEK_S = 7 * 24 * 3600
_DAY_S = 24 * 3600
_HOUR_S = 3600
_MIN_S = 60


def _parse_uptime(uptime_str: str) -> float:
    """Convert an EdgeOS uptime string to total seconds."""
    for m in _UPTIME_RE.finditer(uptime_str):
        if not any(v is not None for v in m.groups()):
            continue
        years, weeks, days, hours, minutes, seconds = (int(v or 0) for v in m.groups())
        return float(
            years * _YEAR_S
            + weeks * _WEEK_S
            + days * _DAY_S
            + hours * _HOUR_S
            + minutes * _MIN_S
            + seconds
        )
    return 0.0


class EdgeRouterDriver(_napalm_base.NetworkDriver):
    """Ubiquiti EdgeRouter (EdgeOS) NAPALM driver (read-only subset for device-discovery)."""

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
            "ubiquiti_edgerouter", netmiko_optional_args=self.netmiko_optional_args
        )
        self._interfaces_cache: list[dict] | None = None

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

    def _parse_interfaces_raw(self) -> list[dict]:
        """Parse 'show interfaces' and cache the result for the lifetime of this connection."""
        if not hasattr(self, "_interfaces_cache") or self._interfaces_cache is None:
            raw = self.device.send_command("show interfaces")
            try:
                self._interfaces_cache = parse_output(
                    platform="ubiquiti_edgerouter", command="show interfaces", data=raw
                )
            except Exception:
                logger.debug("Failed to parse 'show interfaces'", exc_info=True)
                self._interfaces_cache = []
        return self._interfaces_cache

    # ------------------------------------------------------------------
    # NAPALM getters
    # ------------------------------------------------------------------

    def get_facts(self) -> dict:
        """
        Return general device facts.

        Facts are assembled from three commands:
        - 'show version'           → os_version, model, serial, uptime (ntc-template)
        - 'show system host-name'  → hostname (plain text)
        - 'show interfaces'        → interface_list (ntc-template)
        """
        model = serial = os_version = "Unknown"
        uptime_str = ""
        raw_ver = self.device.send_command("show version")
        try:
            parsed = parse_output(
                platform="ubiquiti_edgerouter", command="show version", data=raw_ver
            )
            if parsed:
                row = parsed[0]
                model = row.get("hardware_model", "Unknown").strip()
                os_version = row.get("version", "Unknown").strip()
                serial = row.get("serial_number", "Unknown").strip()
                uptime_str = row.get("uptime", "")
        except Exception:
            logger.debug("Failed to parse 'show version'", exc_info=True)

        hostname_raw = self.device.send_command("show system host-name")
        hostname = hostname_raw.strip() or self.hostname

        interface_list: list[str] = []
        for intf_row in self._parse_interfaces_raw():
            intf = intf_row.get("interface", "").strip()
            if intf:
                interface_list.append(intf)

        return {
            "hostname": hostname,
            "vendor": "Ubiquiti",
            "model": model,
            "os_version": os_version,
            "serial_number": serial,
            "uptime": _parse_uptime(uptime_str),
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """
        Return interface details keyed by interface name.

        Parses 'show interfaces' with the ubiquiti_edgerouter ntc-template.
        State codes: u=up, D=down, A=admin-down.
        """
        interfaces: dict = {}
        for row in self._parse_interfaces_raw():
            intf = row.get("interface", "").strip()
            if not intf:
                continue
            state = row.get("state", "").upper()
            link = row.get("link_status", "").upper()
            interfaces[intf] = {
                "is_up": link == "U",
                "is_enabled": state != "A",
                "description": row.get("description", "").strip(),
                "last_flapped": -1.0,
                "mtu": -1,
                "speed": -1.0,
                "mac_address": "",
            }
        return interfaces

    def get_interfaces_ip(self) -> dict:
        """
        Return IP addresses per interface.

        Parses IP_ADDRESS list from 'show interfaces' ntc-template.
        Handles both IPv4 (e.g. '192.168.1.1/24') and IPv6 (e.g. '::1/128').
        """
        interfaces_ip: dict = {}
        for row in self._parse_interfaces_raw():
            intf = row.get("interface", "").strip()
            if not intf:
                continue
            for ip_cidr in row.get("ip_address", []):
                if not ip_cidr or ip_cidr == "-":
                    continue
                try:
                    net = ipaddress.ip_interface(ip_cidr)
                except ValueError:
                    continue
                ip_str = str(net.ip)
                prefix = net.network.prefixlen
                family = "ipv4" if net.version == 4 else "ipv6"
                (
                    interfaces_ip
                    .setdefault(intf, {})
                    .setdefault(family, {})[ip_str]
                ) = {"prefix_length": prefix}
        return interfaces_ip

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """
        Return EdgeOS configuration.

        Uses 'show configuration commands' which outputs VyOS-style
        set-command format (e.g. 'set system host-name ubnt').
        EdgeOS has no startup or candidate config; those keys are empty strings.
        """
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}
        if retrieve in ("all", "running"):
            config["running"] = self.device.send_command("show configuration commands")
        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])
        return config

    def get_vlans(self) -> dict:
        """EdgeRouter is a router and does not support 802.1Q VLANs on switch ports."""
        return {}
