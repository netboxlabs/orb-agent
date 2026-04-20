# Copyright 2026 NetBox Labs Inc
"""
Custom Ericsson IPOS NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko (ericsson_ipos device type) and ntc-templates for structured
parsing where templates are available; falls back to regex for commands
without templates.

Config sanitization covers:
  - ``password <value>``      — local user passwords
  - ``key <value>``           — RADIUS/TACACS+ pre-shared keys
  - ``community <value>``     — SNMP community strings
  - ``encrypted-key <value>`` — protocol authentication keys
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config sanitisation
# ---------------------------------------------------------------------------

# "password <hash>" — local user or line password
_PASSWORD_RE = re.compile(r"(\bpassword)\s+\S+", re.IGNORECASE)

# "key <secret>" — RADIUS/TACACS+ pre-shared key.
# Anchored to the first non-whitespace token on the line to avoid false
# positives on "authentication-key N md5 ..." or "crypto key generate rsa".
_KEY_RE = re.compile(r"^(\s*key)\s+\S+", re.IGNORECASE | re.MULTILINE)

# "snmp-server community <string>" — SNMP community string.
# Anchored to the full SNMP server command form to avoid redacting BGP
# community values (e.g. "set community 64512:100" in route-policies).
_COMMUNITY_RE = re.compile(r"(snmp-server\s+community)\s+\S+", re.IGNORECASE)

# "encrypted-key <value>" — protocol authentication keys
_ENCRYPTED_KEY_RE = re.compile(r"(\bencrypted-key)\s+\S+", re.IGNORECASE)


def _sanitize_config(text: str) -> str:
    """Redact credential fields from an IPOS configuration block."""
    text = _PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _KEY_RE.sub(r"\1 <redacted>", text)
    text = _COMMUNITY_RE.sub(r"\1 <redacted>", text)
    text = _ENCRYPTED_KEY_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Uptime parsing
# ---------------------------------------------------------------------------

_HOUR_SECONDS = 3600
_DAY_SECONDS = 24 * _HOUR_SECONDS
_WEEK_SECONDS = 7 * _DAY_SECONDS
_YEAR_SECONDS = 365 * _DAY_SECONDS


def _parse_uptime(uptime_str: str) -> float:
    """
    Convert an IPOS uptime string to total seconds.

    Expected format: ``"10 hours 48 minutes 41 seconds"``
    Individual components are optional (e.g., ``"2 days 3 hours"`` is valid).
    Returns 0.0 when the string is empty or unparseable.
    """
    seconds = 0.0
    for pattern, factor in (
        (r"(\d+)\s+year", _YEAR_SECONDS),
        (r"(\d+)\s+week", _WEEK_SECONDS),
        (r"(\d+)\s+day", _DAY_SECONDS),
        (r"(\d+)\s+hour", _HOUR_SECONDS),
        (r"(\d+)\s+minute", 60),
        (r"(\d+)\s+second", 1),
    ):
        m = re.search(pattern, uptime_str, re.IGNORECASE)
        if m:
            seconds += int(m.group(1)) * factor
    return seconds


# Fallback: extract the full uptime string directly from show version output.
# Matches "Router Up Time - <value>" regardless of how many time components
# are present, covering the case where the ntc-template requires exactly three
# pairs and returns empty for freshly rebooted devices (e.g. "3 minutes 5 seconds").
_UPTIME_LINE_RE = re.compile(r"Up\s+Time\s+-\s+(.+)", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Interface / IP parsing helpers (module-level for efficiency)
# ---------------------------------------------------------------------------

# IPOS show port table: port-id, admin-state, physical-state [, ...]
# Example row: "  1/1     up      up      No"
_PORT_ROW_RE = re.compile(
    r"^\s+(?P<port>\d+/\d+(?:/\d+)?)\s+"
    r"(?P<admin>\S+)\s+"
    r"(?P<oper>\S+)",
    re.MULTILINE,
)

# show ip local interface: "<intf>  <ip>/<prefix>  ..."
_IP_ROW_RE = re.compile(
    r"^\s*(?P<intf>\S+)\s+(?P<ip>\d+\.\d+\.\d+\.\d+)/(?P<prefix>\d+)",
    re.MULTILINE,
)

# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


class IPOSDriver(_napalm_base.NetworkDriver):
    """Ericsson IPOS NAPALM driver (read-only subset for device-discovery)."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Initialise the driver."""
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
            "ericsson_ipos", netmiko_optional_args=self.netmiko_optional_args
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
        ver_output = self.device.send_command("show version")
        try:
            parsed = parse_output(
                platform="ericsson_ipos", command="show version", data=ver_output
            )
        except Exception:
            logger.warning("ipos: ntc-template failed for 'show version'", exc_info=True)
            parsed = []

        os_version = "Unknown"
        uptime = 0.0
        if parsed:
            row = parsed[0]
            os_version = row.get("version", "Unknown")
            # The ntc-template only captures uptime strings with exactly three
            # time components.  Fall back to a direct regex on the raw output
            # for freshly rebooted devices (e.g. "3 minutes 5 seconds").
            uptime_str = row.get("uptime", "")
            if not uptime_str:
                m = _UPTIME_LINE_RE.search(ver_output)
                if m:
                    uptime_str = m.group(1).strip()
            uptime = _parse_uptime(uptime_str)

        # Regex fallback for os_version when the template is unavailable.
        # Matches the version token in "Ericsson IPOS Version IPOS-v<ver>-Release".
        if os_version == "Unknown":
            m = re.search(r"IPOS-v([\d.]+)", ver_output)
            if m:
                os_version = m.group(1)

        # Regex fallback for uptime when the template returned nothing.
        if uptime == 0.0 and not parsed:
            m = _UPTIME_LINE_RE.search(ver_output)
            if m:
                uptime = _parse_uptime(m.group(1).strip())

        # The CLI prompt is the router hostname on IPOS.
        # Netmiko stores the prompt without the trailing '#' in base_prompt.
        hostname = getattr(self.device, "base_prompt", None) or self.hostname

        interface_list = self._get_interface_list()

        return {
            "hostname": hostname,
            "vendor": "Ericsson",
            "model": "Unknown",
            "os_version": os_version,
            "serial_number": "Unknown",
            "uptime": uptime,
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def _get_interface_list(self) -> list[str]:
        """Return a list of port names from ``show port``."""
        output = self.device.send_command("show port")
        if not output:
            return []
        return [m.group("port") for m in _PORT_ROW_RE.finditer(output)]

    def get_interfaces(self) -> dict:
        """
        Return interface details keyed by port name.

        Parses ``show port`` output.  Each row provides admin and physical
        (operational) state.  Speed, MTU and MAC are not available in the
        brief port table and are returned as sentinel values.
        """
        output = self.device.send_command("show port")
        if not output:
            return {}

        interfaces: dict = {}
        for m in _PORT_ROW_RE.finditer(output):
            port = m.group("port")
            admin_up = m.group("admin").lower() in ("up", "enabled", "ena")
            oper_up = m.group("oper").lower() in ("up", "running")
            interfaces[port] = {
                "is_up": oper_up,
                "is_enabled": admin_up,
                "description": "",
                "last_flapped": -1.0,
                "mtu": -1,
                "speed": -1.0,
                "mac_address": "",
            }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """
        Return IP addresses per interface.

        Parses ``show ip local interface`` output.
        Each line with an IPv4 CIDR address is mapped to its interface.
        """
        output = self.device.send_command("show ip local interface")
        if not output:
            return {}

        interfaces_ip: dict = {}
        for m in _IP_ROW_RE.finditer(output):
            intf = m.group("intf")
            ip = m.group("ip")
            prefix = int(m.group("prefix"))
            interfaces_ip.setdefault(intf, {}).setdefault("ipv4", {})[ip] = {
                "prefix_length": prefix
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
            config["running"] = self.device.send_command("show configuration")

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Ericsson IPOS does not use traditional IEEE 802.1Q VLAN tables."""
        return {}
