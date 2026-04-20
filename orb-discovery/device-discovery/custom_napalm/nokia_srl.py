# Copyright 2026 NetBox Labs Inc
# Based on napalm-srlinux (Apache-2.0): https://github.com/napalm-automation-community/napalm-srlinux
"""
Custom Nokia SR Linux NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko (nokia_srl) for SSH transport and regex for CLI parsing.
No ntc-templates exist for nokia_srl; all parsing is done with compiled
regular expressions against SR Linux show command output.

SR Linux commands used:
  show version              — hostname, software version, chassis type
  show system information   — uptime, serial number
  show interface all        — interface status, speed, IP addresses
  admin display-config      — running configuration (YANG flat format)
"""

import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.netmiko_helpers import netmiko_args

# ---------------------------------------------------------------------------
# Config sanitization — Nokia SR Linux sensitive fields
# ---------------------------------------------------------------------------

# SR Linux stores passwords and SNMP community strings as hashed values:
#   password $6$<hash>
#   community $aes1$<salt>$<hash>
# Both are identified by the leading "$" in the value.
_PASSWORD_RE = re.compile(r"(\bpassword)\s+\$\S+", re.IGNORECASE)
_COMMUNITY_RE = re.compile(r"(\bcommunity)\s+\$\S+", re.IGNORECASE)


def _sanitize_config(text: str) -> str:
    text = _PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _COMMUNITY_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Uptime parsing — "N days H hours M minutes S seconds"
# ---------------------------------------------------------------------------

def _parse_uptime(uptime_str: str) -> float:
    """Convert SR Linux uptime string to total seconds."""
    seconds = 0.0
    for pattern, factor in (
        (r"(\d+)\s+day", 86400),
        (r"(\d+)\s+hour", 3600),
        (r"(\d+)\s+minute", 60),
        (r"(\d+)\s+second", 1),
    ):
        m = re.search(pattern, uptime_str)
        if m:
            seconds += int(m.group(1)) * factor
    return seconds


# ---------------------------------------------------------------------------
# Speed parsing — "25G", "1G", "100M", "400G", "10G", …  → float Mbps
# ---------------------------------------------------------------------------

_SPEED_RE = re.compile(r"(\d+(?:\.\d+)?)\s*([GMTgmt])", re.IGNORECASE)
_SPEED_MULT = {"g": 1_000.0, "m": 1.0, "t": 1_000_000.0}


def _parse_speed(speed_str: str) -> float:
    """Return interface speed in Mbps, or -1.0 if unparseable."""
    m = _SPEED_RE.match(speed_str.strip())
    if not m:
        return -1.0
    value, unit = float(m.group(1)), m.group(2).lower()
    return value * _SPEED_MULT.get(unit, 1.0)


# ---------------------------------------------------------------------------
# Interface output parser — shared by get_interfaces and get_interfaces_ip
# ---------------------------------------------------------------------------

# Physical interface line: "ethernet-1/1 is up, speed 25G, type None"
#                          "ethernet-1/2 is down, reason port-admin-disabled"
# Use character classes to stop capture before the next comma.
_PHYS_INTF_RE = re.compile(
    r"^(\S+) is (up|down)(?:,\s*reason\s+([\w-]+))?(?:,\s*speed\s+([\w.]+))?",
    re.IGNORECASE,
)

# Subinterface line: "  ethernet-1/1.0 is up"
_SUB_INTF_RE = re.compile(r"^\s{2}(\S+\.\d+) is (up|down)", re.IGNORECASE)

# IP address lines under a subinterface
_IPV4_ADDR_RE = re.compile(
    r"IPv4 addr\s+:\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)", re.IGNORECASE
)
_IPV6_ADDR_RE = re.compile(r"IPv6 addr\s+:\s+([^\s\/]+)\/(\d+)", re.IGNORECASE)

# Separator lines between interfaces (dashes or equals)
_SEPARATOR_RE = re.compile(r"^[-=]{10,}")

# SR Linux CLI context/prompt line at end of output: "--{ running }--[  ]--"
_SRL_PROMPT_RE = re.compile(r"^--\{[^}]*\}--.*$", re.MULTILINE)

# MTU line: "    MTU      : 1500"
_MTU_RE = re.compile(r"MTU\s*:\s*(\d+)", re.IGNORECASE)

# Description line: "    Description  : some text"
_DESC_RE = re.compile(r"Description\s*:\s*(.*)", re.IGNORECASE)


def _strip_prompt(text: str) -> str:
    """Remove SR Linux CLI context/prompt lines (``--{ running }--[  ]--``) from output."""
    return _SRL_PROMPT_RE.sub("", text).rstrip()


def _make_intf_entry(m) -> dict:
    """Build a fresh interface entry dict from a physical-interface regex match."""
    reason = m.group(3)
    return {
        "name": m.group(1),
        "is_up": m.group(2).lower() == "up",
        "is_enabled": reason != "port-admin-disabled" if reason else True,
        "speed": _parse_speed(m.group(4)) if m.group(4) else -1.0,
        "mtu": -1,
        "description": "",
        "ipv4": [],
        "ipv6": [],
    }


def _collect_ip_addresses(line: str, current: dict) -> None:
    """Append any IPv4/IPv6 address found in *line* to *current*'s lists."""
    m_ipv4 = _IPV4_ADDR_RE.search(line)
    if m_ipv4:
        current["ipv4"].append((m_ipv4.group(1), int(m_ipv4.group(2))))
        return
    m_ipv6 = _IPV6_ADDR_RE.search(line)
    if m_ipv6:
        addr, prefix = m_ipv6.group(1), int(m_ipv6.group(2))
        if not addr.lower().startswith("fe80"):  # skip link-local
            current["ipv6"].append((addr, prefix))


def _parse_interface_output(output: str) -> list[dict]:
    """
    Parse ``show interface all`` output into a list of interface dicts.

    Each dict has: name, is_up, is_enabled, speed, mtu, description,
    ipv4 (list of (addr, prefix_len)), ipv6 (same).
    """
    interfaces: list[dict] = []
    current: dict | None = None
    current_sub: str | None = None

    for line in output.splitlines():
        if _SEPARATOR_RE.match(line):
            current_sub = None
            continue
        if line.strip().startswith("Summary") or line.startswith("--{"):
            current = None
            current_sub = None
            continue

        m_phys = _PHYS_INTF_RE.match(line)
        if m_phys and not line.startswith(" "):
            current = _make_intf_entry(m_phys)
            current_sub = None
            interfaces.append(current)
            continue

        if current is None:
            continue

        m_sub = _SUB_INTF_RE.match(line)
        if m_sub:
            current_sub = m_sub.group(1)
            continue

        m_mtu = _MTU_RE.search(line)
        if m_mtu:
            current["mtu"] = int(m_mtu.group(1))
            continue

        m_desc = _DESC_RE.search(line)
        if m_desc:
            current["description"] = m_desc.group(1).strip()
            continue

        if current_sub:
            _collect_ip_addresses(line, current)

    return interfaces


class SRLDriver(_napalm_base.NetworkDriver):
    """
    Nokia SR Linux NAPALM driver (read-only subset for device-discovery).

    Uses Netmiko (nokia_srl) over SSH and regex-based CLI parsing.
    """

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
            "nokia_srl", netmiko_optional_args=self.netmiko_optional_args
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
        except (OSError, EOFError, AttributeError):
            return {"is_alive": False}

    # -----------------------------------------------------------------------
    # NAPALM getters
    # -----------------------------------------------------------------------

    def get_facts(self) -> dict:
        """Return general device facts."""
        hostname = "Unknown"
        os_version = "Unknown"
        model = "Unknown"
        serial_number = "Unknown"
        uptime = 0.0

        # --- show version: hostname, software version, chassis type ---
        ver_out = self.device.send_command("show version")
        if ver_out:
            m = re.search(r"Hostname\s*:\s*(\S+)", ver_out)
            if m:
                hostname = m.group(1).strip()
            m = re.search(r"Software Version\s*:\s*(\S+)", ver_out)
            if m:
                os_version = m.group(1).strip()
            m = re.search(r"Chassis Type\s*:\s*(.+)", ver_out)
            if m:
                model = m.group(1).strip()

        # --- show system information: uptime, serial number ---
        sys_out = self.device.send_command("show system information")
        if sys_out:
            m = re.search(
                r"Uptime\s*:\s*(.+)", sys_out, re.IGNORECASE
            )
            if m:
                uptime = _parse_uptime(m.group(1))
            m = re.search(r"Chassis serial number\s*:\s*(\S+)", sys_out, re.IGNORECASE)
            if m:
                serial_number = m.group(1).strip()

        # Fallback: parse serial from show version if still unknown
        if serial_number == "Unknown" and ver_out:
            m = re.search(r"Serial Number\s*:\s*(.+)", ver_out, re.IGNORECASE)
            if m:
                serial_number = m.group(1).strip()

        # --- show interface all: interface list ---
        intf_out = self.device.send_command("show interface all")
        parsed = _parse_interface_output(intf_out) if intf_out else []
        interface_list = [entry["name"] for entry in parsed]

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
        intf_out = self.device.send_command("show interface all")
        if not intf_out:
            return {}

        parsed = _parse_interface_output(intf_out)
        interfaces = {}
        for entry in parsed:
            interfaces[entry["name"]] = {
                "is_up": entry["is_up"],
                "is_enabled": entry["is_enabled"],
                "description": entry["description"],
                "last_flapped": -1.0,
                "mtu": entry["mtu"],
                "speed": entry["speed"],
                "mac_address": "",
            }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface."""
        intf_out = self.device.send_command("show interface all")
        if not intf_out:
            return {}

        parsed = _parse_interface_output(intf_out)
        interfaces_ip: dict = {}
        for entry in parsed:
            name = entry["name"]
            for addr, prefix_len in entry["ipv4"]:
                interfaces_ip.setdefault(name, {}).setdefault("ipv4", {})[addr] = {
                    "prefix_length": prefix_len
                }
            for addr, prefix_len in entry["ipv6"]:
                interfaces_ip.setdefault(name, {}).setdefault("ipv6", {})[addr] = {
                    "prefix_length": prefix_len
                }

        return interfaces_ip

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """Return device configuration (YANG flat format)."""
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}

        if retrieve in ("all", "running"):
            config["running"] = _strip_prompt(self.device.send_command("admin display-config"))

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """SR Linux uses network instances, not traditional VLANs."""
        return {}
