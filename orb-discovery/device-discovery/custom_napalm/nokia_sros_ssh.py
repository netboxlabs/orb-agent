# Copyright 2026 NetBox Labs Inc
"""
Custom Nokia/Alcatel SR-OS SSH NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko (nokia_sros) for SSH transport and ntc-templates (alcatel_sros)
for structured parsing of show port and show router interface.
show version / show system information are parsed with regex (no templates exist).
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config sanitization — Nokia SR-OS sensitive fields
# ---------------------------------------------------------------------------

# Quoted values after keywords such as:
#   authentication-key "MyAuthKey123"
#   hmac-md5-key "MyHmacKey456"
#   password "MyS3cr3tP4ssword"
#   community "public" hash2 "c2VjcmV0" ...
_AUTH_KEY_RE = re.compile(r'(authentication-key)\s+"[^"]*"', re.IGNORECASE)
_HMAC_MD5_RE = re.compile(r'(hmac-md5-key)\s+"[^"]*"', re.IGNORECASE)
_DES_KEY_RE = re.compile(r'(des-key)\s+"[^"]*"', re.IGNORECASE)
_AES_KEY_RE = re.compile(r'(aes-key)\s+"[^"]*"', re.IGNORECASE)
_PASSWORD_RE = re.compile(r'(password)\s+"[^"]*"', re.IGNORECASE)
# SNMP community lines: community "<name>" [hash|hash2] "<hash-value>" ...
# Redact both the community name and its hash value.
_COMMUNITY_RE = re.compile(r'(community)\s+"[^"]*"', re.IGNORECASE)
_HASH2_RE = re.compile(r'(hash2?)\s+"[^"]*"', re.IGNORECASE)


def _sanitize_config(text: str) -> str:
    # SR-OS config stores secrets inside double quotes; preserve the enclosing
    # quotes so the redacted output remains syntactically valid SR-OS config.
    text = _AUTH_KEY_RE.sub(r'\1 "<redacted>"', text)
    text = _HMAC_MD5_RE.sub(r'\1 "<redacted>"', text)
    text = _DES_KEY_RE.sub(r'\1 "<redacted>"', text)
    text = _AES_KEY_RE.sub(r'\1 "<redacted>"', text)
    text = _PASSWORD_RE.sub(r'\1 "<redacted>"', text)
    text = _COMMUNITY_RE.sub(r'\1 "<redacted>"', text)
    text = _HASH2_RE.sub(r'\1 "<redacted>"', text)
    return text


# ---------------------------------------------------------------------------
# Uptime parsing
# ---------------------------------------------------------------------------

_UPTIME_RE = re.compile(r"(\d+)\s+days?,\s+(\d+):(\d+):(\d+)", re.IGNORECASE)


def _parse_uptime(uptime_str: str) -> float:
    """Convert SR-OS uptime 'N days, H:MM:SS.ms' to total seconds."""
    m = _UPTIME_RE.search(uptime_str)
    if not m:
        return 0.0
    days, hours, minutes, secs = (
        int(m.group(1)),
        int(m.group(2)),
        int(m.group(3)),
        int(m.group(4)),
    )
    return float(days * 86400 + hours * 3600 + minutes * 60 + secs)


class SROSSSHDriver(_napalm_base.NetworkDriver):
    """Nokia/Alcatel SR-OS NAPALM driver using SSH CLI + ntc-templates (read-only subset for device-discovery)."""

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
        # SR-OS users log in with privileged access; no enable command needed.
        self.force_no_enable = True

    def open(self):
        """Open an SSH connection to the device via Netmiko."""
        self.device = self._netmiko_open(
            "nokia_sros", netmiko_optional_args=self.netmiko_optional_args
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
        except (EOFError, OSError, AttributeError):  # socket.error is OSError in Python 3.3+
            return {"is_alive": False}

    # -----------------------------------------------------------------------
    # NAPALM getters
    # -----------------------------------------------------------------------

    def get_facts(self) -> dict:
        """Return general device facts."""
        os_version = "Unknown"
        model = "Unknown"
        hostname = "Unknown"
        serial_number = "Unknown"
        uptime = 0.0

        # --- version / model ---
        ver_out = self.device.send_command("show version")
        m = re.search(r"System Version\s*:\s*(\S+)", ver_out)
        if m:
            os_version = m.group(1)
        m = re.search(r"System Type\s*:\s*(.+)", ver_out)
        if m:
            model = m.group(1).strip()

        # --- hostname / uptime / serial ---
        sysinfo_out = self.device.send_command("show system information")
        m = re.search(r"System Name\s*:\s*(\S+)", sysinfo_out)
        if m:
            hostname = m.group(1).strip()
        m = re.search(r"System Up Time\s*:\s*(.+)", sysinfo_out)
        if m:
            uptime = _parse_uptime(m.group(1))
        m = re.search(r"Chassis Serial #\s*:\s*(\S+)", sysinfo_out)
        if m:
            serial_number = m.group(1).strip()

        # --- interface list from show port ---
        port_out = self.device.send_command("show port")
        parsed_ports = parse_output(platform="alcatel_sros", command="show port", data=port_out)
        interface_list = [
            row["port_id"]
            for row in parsed_ports
            if row.get("port_id") and row.get("admin_state")
        ]

        return {
            "hostname": hostname,
            "vendor": "Nokia",
            "model": model,
            "os_version": os_version,
            "serial_number": serial_number,
            "uptime": uptime,
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """Return interface details keyed by interface name."""
        port_out = self.device.send_command("show port")
        parsed = parse_output(platform="alcatel_sros", command="show port", data=port_out)

        interfaces = {}
        for row in parsed:
            port_id = row.get("port_id", "")
            admin_state = row.get("admin_state", "")
            # Skip rows without a proper admin state (connector summary lines)
            if not port_id or not admin_state:
                continue

            port_state = row.get("port_state", "")
            cfg_mtu = row.get("cfg_mtu", "")
            try:
                mtu = int(cfg_mtu) if cfg_mtu else -1
            except ValueError:
                mtu = -1

            interfaces[port_id] = {
                "is_enabled": admin_state.lower() == "up",
                "is_up": port_state.lower() == "up",
                "description": "",
                "last_flapped": -1.0,
                "mtu": mtu,
                "speed": 0.0,
                "mac_address": "",
            }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface."""
        intf_out = self.device.send_command("show router interface")
        parsed = parse_output(
            platform="alcatel_sros", command="show router interface", data=intf_out
        )

        interfaces_ip: dict = {}
        for row in parsed:
            intf = row.get("interface", "")
            if not intf:
                continue

            ip_addresses = row.get("ip_address", [])
            if isinstance(ip_addresses, str):
                ip_addresses = [ip_addresses]

            for cidr in ip_addresses:
                if not cidr or "/" not in cidr:
                    continue
                try:
                    addr, prefix_str = cidr.split("/", 1)
                    prefix_length = int(prefix_str)
                except (ValueError, AttributeError):
                    continue

                family = "ipv6" if ":" in addr else "ipv4"
                interfaces_ip.setdefault(intf, {}).setdefault(family, {})[addr] = {
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

        if retrieve in ("all", "running"):
            config["running"] = self.device.send_command("admin display-config")

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Nokia SR-OS uses a service-based architecture — no traditional VLAN table."""
        return {}
