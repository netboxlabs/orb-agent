# Copyright 2026 NetBox Labs Inc
"""
Custom Avaya ERS NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses ntc-templates 9.x for structured parsing wherever templates are available
(sys-info, interface name, vlan); falls back to regex for commands without
templates (interface status, IPv4/IPv6 addresses).
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.helpers import mac as normalize_mac
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config sanitization
# ---------------------------------------------------------------------------
# ERS stores passwords as:
#   username <name> password <hash>       (local user)
#   password <hash>                        (enable password)
#   community <name>                       (SNMP community – treat as secret)
# ---------------------------------------------------------------------------
_USERNAME_PASSWORD_RE = re.compile(
    r"(username\s+\S+\s+password)\s+\S+", re.IGNORECASE
)
_PASSWORD_RE = re.compile(
    r"^(\s*password)\s+\S+",
    re.IGNORECASE | re.MULTILINE,
)
_COMMUNITY_RE = re.compile(
    r"(community)\s+\S+",
    re.IGNORECASE,
)


def _sanitize_config(text: str) -> str:
    text = _USERNAME_PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _COMMUNITY_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Uptime helpers
# ---------------------------------------------------------------------------
_UPTIME_UNITS = (
    (r"(\d+)\s+day", 86400),
    (r"(\d+)\s+hour", 3600),
    (r"(\d+)\s+minute", 60),
    (r"(\d+)\s+second", 1),
)
# Matches the HH:MM:SS component from "35 days, 07:24:53"
_UPTIME_HMS_RE = re.compile(r"(\d+):(\d{2}):(\d{2})")


def _parse_uptime(uptime_str: str) -> float:
    """
    Convert an ERS uptime string to total seconds.

    Handles two formats emitted by different ERS firmware versions:

    - ``"0 day(s), 1 hour(s), 26 minute(s), 13 second(s)"`` (older firmware)
    - ``"35 days, 07:24:53"``  (newer firmware / ntc-template capture)
    """
    seconds = 0.0
    # Try HH:MM:SS component first (newer format)
    hms = _UPTIME_HMS_RE.search(uptime_str)
    if hms:
        seconds += int(hms.group(1)) * 3600 + int(hms.group(2)) * 60 + int(hms.group(3))
    # Days component is always a plain digit prefix (both formats)
    for pattern, factor in _UPTIME_UNITS:
        m = re.search(pattern, uptime_str, re.IGNORECASE)
        if m:
            # Avoid double-counting hours/minutes/seconds already handled by HMS
            if factor < 3600 and hms:
                continue
            if factor == 3600 and hms:
                continue
            seconds += int(m.group(1)) * factor
    return seconds


# ---------------------------------------------------------------------------
# Interface helpers  (regex – no suitable ntc-template for ERS interface status)
# ---------------------------------------------------------------------------
_INTF_BLOCK_RE = re.compile(
    r"^(Port\s+\S+.*?)(?=^Port\s+\S+|\Z)",
    re.MULTILINE | re.DOTALL,
)
# "Port 1/1" or "Port 1" header line
_INTF_HEADER_RE = re.compile(r"^Port\s+(\S+)", re.MULTILINE)
_LINK_RE = re.compile(r"Link\s*:\s*(\S+)", re.IGNORECASE)
_ADMIN_RE = re.compile(r"Admin\s*:\s*(\S+)", re.IGNORECASE)
_SPEED_RE = re.compile(r"Speed\s*:\s*(\d+)", re.IGNORECASE)
_MTU_RE = re.compile(r"MTU\s*:\s*(\d+)", re.IGNORECASE)
_MAC_RE = re.compile(
    r"MAC\s+Address\s*:\s*([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}"
    r"[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})",
    re.IGNORECASE,
)
# ---------------------------------------------------------------------------
# IP address helpers (regex – no ntc-template for ERS IP interfaces)
# ---------------------------------------------------------------------------
# ERS show ip interface section header: "Interface : Vlan 1"
_IP_HEADER_RE = re.compile(
    r"^Interface\s*:\s+(.+?)\s*$",
    re.MULTILINE | re.IGNORECASE,
)
# ERS: "IP Address      : 10.0.0.1" and "Mask            : 255.255.255.0"
_IPV4_ADDR_RE = re.compile(r"IP\s+Address\s*:\s*(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)
_IPV4_MASK_RE = re.compile(r"Mask\s*:\s*(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)
# ERS: "IPv6 Address  : 2001:db8::1/64"
_IPV6_RE = re.compile(
    r"IPv6\s+Address\s*:\s*([0-9a-fA-F:]+(?:/\d+)?)",
    re.IGNORECASE,
)
# section separator matching the "Interface : " header
_IP_SECTION_RE = re.compile(
    r"^Interface\s*:",
    re.MULTILINE | re.IGNORECASE,
)


def _mask_to_prefix(mask: str) -> int:
    """Convert dotted-quad netmask to prefix length."""
    return sum(bin(int(octet)).count("1") for octet in mask.split("."))


class AvayaERSDriver(_napalm_base.NetworkDriver):
    """Avaya ERS NAPALM driver (read-only subset for device-discovery)."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Initialise driver parameters."""
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
            "avaya_ers", netmiko_optional_args=self.netmiko_optional_args
        )

    def close(self):
        """Close the connection."""
        self._netmiko_close()

    def is_alive(self) -> dict:
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
        facts = {
            "hostname": "Unknown",
            "vendor": "Avaya",
            "model": "Avaya ERS",
            "os_version": "Unknown",
            "serial_number": "Unknown",
            "uptime": -1.0,
            "fqdn": "Unknown",
            "interface_list": [],
        }

        sys_output = self.device.send_command("show sys-info")
        parsed = parse_output(platform="avaya_ers", command="show sys-info", data=sys_output)

        if not parsed:
            logger.warning("Failed to parse 'show sys-info'; returning default facts")
        else:
            row = parsed[0]
            facts["uptime"] = _parse_uptime(row.get("sys_up_time", ""))
            facts["hostname"] = row.get("sys_name", "Unknown") or "Unknown"
            facts["serial_number"] = row.get("serial_number", "Unknown") or "Unknown"
            facts["os_version"] = row.get("operational_software", "Unknown") or "Unknown"
            # ERS sys-info does not expose a human-readable model string; keep
            # the "Avaya ERS" fallback set above.

        # Interface list comes from show interface name
        intf_output = self.device.send_command("show interface name")
        intf_parsed = parse_output(
            platform="avaya_ers", command="show interface name", data=intf_output
        )
        facts["interface_list"] = [
            row["port"]
            for row in intf_parsed
            if row.get("port") and not row["port"].startswith("-")
        ]

        return facts

    def get_interfaces(self) -> dict:
        """
        Return interface details keyed by interface name.

        Uses ``show interfaces`` (status per port) and augments with
        interface names from ``show interface name``.
        """
        # --- interface names / descriptions ---
        name_output = self.device.send_command("show interface name")
        name_parsed = parse_output(
            platform="avaya_ers", command="show interface name", data=name_output
        )
        descriptions: dict[str, str] = {}
        for row in name_parsed:
            port = row.get("port", "")
            if port and not port.startswith("-"):
                descriptions[port] = row.get("name", "").strip()

        # --- interface status ---
        intf_output = self.device.send_command("show interfaces")
        interfaces: dict = {}

        for block_match in _INTF_BLOCK_RE.finditer(intf_output):
            block = block_match.group(0)
            header = _INTF_HEADER_RE.search(block)
            if not header:
                continue
            port = header.group(1)

            link_m = _LINK_RE.search(block)
            admin_m = _ADMIN_RE.search(block)
            speed_m = _SPEED_RE.search(block)
            mtu_m = _MTU_RE.search(block)
            mac_m = _MAC_RE.search(block)

            link_status = link_m.group(1).lower() if link_m else "down"
            admin_status = admin_m.group(1).lower() if admin_m else "up"
            speed_raw = speed_m.group(1) if speed_m else "0"
            mtu_raw = mtu_m.group(1) if mtu_m else "0"
            mac_raw = mac_m.group(1) if mac_m else ""

            try:
                mac_address = normalize_mac(mac_raw) if mac_raw else ""
            except Exception:
                mac_address = mac_raw

            interfaces[port] = {
                "is_up": link_status == "up",
                "is_enabled": admin_status != "disabled",
                "description": descriptions.get(port, ""),
                "last_flapped": -1.0,
                "mtu": int(mtu_raw) if mtu_raw.isdigit() else -1,
                "speed": float(speed_raw) if speed_raw.isdigit() else -1.0,
                "mac_address": mac_address,
            }

        # --- fall back: ports listed in interface name but not in show interfaces ---
        for port, desc in descriptions.items():
            if port not in interfaces:
                interfaces[port] = {
                    "is_up": False,
                    "is_enabled": True,
                    "description": desc,
                    "last_flapped": -1.0,
                    "mtu": -1,
                    "speed": -1.0,
                    "mac_address": "",
                }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """
        Return IP addresses per interface.

        Parses ``show ip interface`` for IPv4 and ``show ipv6 interface``
        for IPv6.  Falls back gracefully if IPv6 is not configured.
        """
        interfaces_ip: dict = {}

        # --- IPv4 ---
        ipv4_output = self.device.send_command("show ip interface")
        _collect_ipv4(ipv4_output, interfaces_ip)

        # --- IPv6 ---
        ipv6_output = self.device.send_command("show ipv6 interface")
        _collect_ipv6(ipv6_output, interfaces_ip)

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

        retrieve = retrieve.lower()
        running_config = ""
        if retrieve in ("running", "startup", "all"):
            running_config = self.device.send_command("show running-config")

        if retrieve in ("running", "all"):
            config["running"] = running_config

        if retrieve in ("startup", "all"):
            # ERS does not distinguish startup from running config; mirror the
            # running config rather than silently returning an empty startup.
            config["startup"] = running_config

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Return VLAN information keyed by VLAN ID string."""
        output = self.device.send_command("show vlan")
        parsed = parse_output(platform="avaya_ers", command="show vlan", data=output)

        vlans: dict = {}
        for row in parsed:
            vlan_id = row.get("vlan_id", "")
            if not vlan_id:
                continue
            entry = vlans.setdefault(
                vlan_id,
                {
                    "name": row.get("vlan_name", "") or vlan_id,
                    "interfaces": [],
                },
            )
            for member in row.get("vlan_port_members", []):
                for port in _expand_port_range(member):
                    if port and port not in entry["interfaces"]:
                        entry["interfaces"].append(port)

        return vlans


# ---------------------------------------------------------------------------
# Module-level helpers (kept out of class to stay close to their usage)
# ---------------------------------------------------------------------------


def _expand_port_range(token: str) -> list[str]:
    """
    Expand a VLAN port-member token into individual port name strings.

    The ntc-template returns each ``Port Members`` continuation line as one
    token that may itself be a comma-separated list of entries.  Each entry is
    one of:

    - ``"NONE"``       → empty list
    - ``"1/1"``        → ``["1/1"]``
    - ``"1"``          → ``["1"]``
    - ``"2-4"``        → ``["2", "3", "4"]``
    - ``"1/2-8"``      → ``["1/2", "1/3", …, "1/8"]``  (same-unit range)
    - ``"1/1,1/49,…"`` → expanded recursively for each comma-separated part

    Entries that cannot be parsed are passed through as-is.
    """
    ports: list[str] = []
    # Split comma-separated compound tokens first
    for part in token.split(","):
        part = part.strip()
        if not part or part.upper() == "NONE":
            continue
        if "-" in part:
            # May be "2-4" or "1/2-8"
            if "/" in part:
                # unit/port-start - port-end  e.g. "1/2-8"
                unit, rest = part.split("/", 1)
                if "-" in rest:
                    p_start, _, p_end = rest.partition("-")
                    try:
                        ports.extend(
                            f"{unit}/{p}"
                            for p in range(int(p_start), int(p_end) + 1)
                        )
                        continue
                    except ValueError:
                        pass
            else:
                # simple "2-4"
                start, _, end = part.partition("-")
                try:
                    ports.extend(str(i) for i in range(int(start), int(end) + 1))
                    continue
                except ValueError:
                    pass
        ports.append(part)
    return ports


def _collect_ipv4(output: str, interfaces_ip: dict) -> None:
    """
    Parse ``show ip interface`` output and populate *interfaces_ip*.

    ERS section format::

        Interface : Vlan 1
            IP Address      : 10.0.0.1
            Mask            : 255.255.255.0
    """
    if not output:
        return
    # Split on "Interface :" section headers
    sections = _IP_SECTION_RE.split(output)
    # sections[0] is the preamble; rest are the bodies after each "Interface :"
    for body in sections[1:]:
        header_m = _IP_HEADER_RE.search("Interface :" + body)
        if not header_m:
            continue
        intf_name = header_m.group(1).strip()
        addr_m = _IPV4_ADDR_RE.search(body)
        mask_m = _IPV4_MASK_RE.search(body)
        if addr_m and mask_m:
            ip = addr_m.group(1)
            prefix = _mask_to_prefix(mask_m.group(1))
            interfaces_ip.setdefault(intf_name, {}).setdefault("ipv4", {})[ip] = {
                "prefix_length": prefix
            }


def _collect_ipv6(output: str, interfaces_ip: dict) -> None:
    """
    Parse ``show ipv6 interface`` output and populate *interfaces_ip*.

    ERS section format::

        Interface : Vlan 1
            IPv6 Address  : 2001:db8::1/64
    """
    if not output:
        return
    sections = _IP_SECTION_RE.split(output)
    for body in sections[1:]:
        header_m = _IP_HEADER_RE.search("Interface :" + body)
        if not header_m:
            continue
        intf_name = header_m.group(1).strip()
        for m in _IPV6_RE.finditer(body):
            addr_str = m.group(1)
            if "/" in addr_str:
                addr, prefix_str = addr_str.rsplit("/", 1)
                prefix = int(prefix_str)
            else:
                addr, prefix = addr_str, 128
            interfaces_ip.setdefault(intf_name, {}).setdefault("ipv6", {})[addr] = {
                "prefix_length": prefix
            }
