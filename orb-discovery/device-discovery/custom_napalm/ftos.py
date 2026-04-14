# Copyright 2026 NetBox Labs Inc
# Based on napalm-ftos (Apache-2.0): https://github.com/napalm-automation-community/napalm-ftos
"""
Custom Dell Force10 FTOS NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko (dell_force10 device type) for SSH connectivity and ntc-templates
for structured parsing wherever templates exist; falls back to regex for commands
that have no template (show interfaces, show system stack-unit 0, IPv6 interfaces).
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
# Config sanitization — Dell FTOS sensitive fields
# ---------------------------------------------------------------------------

# "username <name> password [<N>] <hash>" and "enable password [<N>] <hash>"
# The encryption-type digit (\d+) is optional: FTOS allows cleartext form
# "password MyPassword" (type 0) as well as the typed form "password 7 <hash>".
_PASSWORD_RE = re.compile(
    r"((?:username\s+\S+\s+)?(?:enable\s+)?password(?:\s+\d+)?)\s+\S+",
    re.IGNORECASE,
)

# "enable secret [<N>] <hash>" — encryption-type digit is optional, same as password.
_SECRET_RE = re.compile(r"(enable\s+secret)(?:\s+\d+)?\s+\S+", re.IGNORECASE)

# "snmp-server community <string> ..." — redact the community string token only.
# Anchored after the keyword so downstream access-list names are not affected.
_SNMP_COMMUNITY_RE = re.compile(
    r"(snmp-server\s+community)\s+\S+", re.IGNORECASE
)


def _sanitize_config(text: str) -> str:
    text = _PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _SECRET_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_COMMUNITY_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Uptime parsing
# ---------------------------------------------------------------------------

_WEEK_SECONDS = 7 * 24 * 3600
_DAY_SECONDS = 24 * 3600
_HOUR_SECONDS = 3600
_MINUTE_SECONDS = 60


def _parse_uptime(uptime_str: str) -> float:
    """
    Convert a Dell FTOS uptime string to total seconds.

    Handles formats emitted by 'show version' (via ntc-template) and
    'show system stack-unit 0', e.g.:
      "33 wk, 4 day, 12 hr, 4 min"
      "33 week(s), 4 day(s), 12 hour(s), 4 minute(s)"
      "1:23:45"   (hh:mm:ss — short uptime before first day rolls over)
    """
    uptime_str = uptime_str.strip()

    # hh:mm:ss short form
    m = re.fullmatch(r"(\d+):(\d+):(\d+)", uptime_str)
    if m:
        return int(m.group(1)) * _HOUR_SECONDS + int(m.group(2)) * _MINUTE_SECONDS + int(m.group(3))

    seconds = 0.0
    for pattern, factor in (
        (r"(\d+)\s+y(?:ear)?", 365 * _DAY_SECONDS),
        (r"(\d+)\s+w(?:ee)?k", _WEEK_SECONDS),
        (r"(\d+)\s+day", _DAY_SECONDS),
        (r"(\d+)\s+h(?:ou)?r", _HOUR_SECONDS),
        (r"(\d+)\s+min(?:ute)?", _MINUTE_SECONDS),
        (r"(\d+)\s+sec(?:ond)?", 1),
    ):
        hit = re.search(pattern, uptime_str, re.IGNORECASE)
        if hit:
            seconds += int(hit.group(1)) * factor

    return seconds


# ---------------------------------------------------------------------------
# Interface parsing helpers
# ---------------------------------------------------------------------------

# Matches the first line of a 'show interfaces' block:
#   "TenGigabitEthernet 0/1 is up, line protocol is up"
#   "GigabitEthernet 1/1 is administratively down, line protocol is down"
# [^,\n]+ stops at the first comma or newline so the match stays on one line.
_INTF_HDR_RE = re.compile(
    r"^(?P<name>\S+\s+\S+)\s+is\s+(?P<admin>[^,\n]+),\s*line\s+protocol\s+is\s+(?P<oper>\S+)",
    re.MULTILINE,
)


def _parse_interfaces(raw: str) -> dict:
    """
    Parse 'show interfaces' output into a dict keyed by interface name.

    Returns the NAPALM interface dict (is_up, is_enabled, description,
    last_flapped, mtu, speed, mac_address) for every interface block found.
    """
    interfaces: dict = {}
    if not raw:
        return interfaces

    # Split output into blocks on interface header lines.
    # re.split with a capturing group keeps the delimiter.
    parts = re.split(r"(?=^\S+\s+\S+\s+is\s+)", raw, flags=re.MULTILINE)

    for block in parts:
        m_hdr = _INTF_HDR_RE.match(block)
        if not m_hdr:
            continue

        name = m_hdr.group("name")
        admin_raw = m_hdr.group("admin").lower()
        oper_raw = m_hdr.group("oper").lower()

        is_enabled = "administratively" not in admin_raw
        is_up = oper_raw == "up"

        # Description
        m_desc = re.search(r"^\s*Description:\s*(.+)$", block, re.MULTILINE)
        description = m_desc.group(1).strip() if m_desc else ""

        # MAC address
        mac_address = ""
        m_mac = re.search(
            r"Hardware\s+is\s+\S+.*?address\s+is\s+([0-9a-fA-F]{2}(?:[:\-\.][0-9a-fA-F]{2}){5})",
            block,
            re.IGNORECASE,
        )
        if m_mac:
            try:
                mac_address = normalize_mac(m_mac.group(1))
            except Exception:
                mac_address = m_mac.group(1)

        # MTU — "MTU 12000 bytes"
        mtu = -1
        m_mtu = re.search(r"\bMTU\s+(\d+)\s+bytes", block, re.IGNORECASE)
        if m_mtu:
            try:
                mtu = int(m_mtu.group(1))
            except ValueError:
                pass

        # Speed — "LineSpeed 10000 Mbit" or "LineSpeed 1000 Mbit"
        speed = -1.0
        m_speed = re.search(r"LineSpeed\s+(\d+)\s+Mbit", block, re.IGNORECASE)
        if m_speed:
            try:
                speed = float(m_speed.group(1))
            except ValueError:
                pass

        interfaces[name] = {
            "is_up": is_up,
            "is_enabled": is_enabled,
            "description": description,
            "last_flapped": -1.0,
            "mtu": mtu,
            "speed": speed,
            "mac_address": mac_address,
        }

    return interfaces


class FTOSDriver(_napalm_base.NetworkDriver):
    """Dell Force10 FTOS NAPALM driver (read-only subset for device-discovery)."""

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
            "dell_force10", netmiko_optional_args=self.netmiko_optional_args
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

    # ------------------------------------------------------------------
    # NAPALM getters
    # ------------------------------------------------------------------

    def _facts_from_version(self) -> tuple[str, float, str]:
        """Return (os_version, uptime, model) from 'show version' (ntc-template)."""
        os_version = "Unknown"
        uptime = 0.0
        model = "Unknown"
        raw = self.device.send_command("show version")
        try:
            parsed = parse_output(platform="dell_force10", command="show version", data=raw)
            if parsed:
                row = parsed[0]
                os_version = row.get("os_version", "Unknown") or "Unknown"
                uptime_str = row.get("uptime", "")
                if uptime_str:
                    uptime = _parse_uptime(uptime_str)
                device_type = row.get("device_type", "")
                if device_type:
                    model = device_type
        except Exception:
            logger.debug("Failed to parse 'show version' output", exc_info=True)
        return os_version, uptime, model

    def _facts_from_stack_unit(self) -> tuple[str, str, str]:
        """Return (serial_number, model, vendor) from 'show system stack-unit 0' (regex)."""
        serial_number = "Unknown"
        model = "Unknown"
        vendor = "Dell"
        raw = self.device.send_command("show system stack-unit 0")
        for line in raw.splitlines():
            stripped = line.strip()
            if stripped.startswith("Serial Number"):
                val = stripped.split(":", 1)[-1].strip()
                if val:
                    serial_number = val
            elif stripped.startswith("Product Name"):
                val = stripped.split(":", 1)[-1].strip()
                if val:
                    model = val
            elif stripped.startswith("Mfg By"):
                val = stripped.split(":", 1)[-1].strip()
                if val:
                    vendor = val
        return serial_number, model, vendor

    def get_facts(self) -> dict:
        """
        Return general device facts.

        Facts are assembled from four commands:
        - 'show version'          → os_version, uptime (ntc-template)
        - 'show system stack-unit 0' → serial_number, model, vendor (regex)
        - 'show running-config'   → hostname (regex on first 'hostname' line)
        - 'show interfaces'       → interface_list (regex scan for interface names)
        """
        os_version, uptime, model = self._facts_from_version()
        serial_number, stack_model, vendor = self._facts_from_stack_unit()
        # stack-unit Product Name takes precedence over show version System Type
        if stack_model != "Unknown":
            model = stack_model

        hostname = self.hostname
        cfg_raw = self.device.send_command("show running-config")
        for line in cfg_raw.splitlines():
            if line.strip().startswith("hostname "):
                hostname = line.strip().split("hostname ", 1)[1].strip()
                break

        intf_raw = self.device.send_command("show interfaces")
        seen: set[str] = set()
        interface_list: list[str] = []
        for m in _INTF_HDR_RE.finditer(intf_raw):
            name = m.group("name")
            if name not in seen:
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

        Parses 'show interfaces' blocks with regex.  No ntc-template exists
        for this command on dell_force10.
        """
        raw = self.device.send_command("show interfaces")
        return _parse_interfaces(raw)

    def _resolve_bare_ipv4(self, bare: dict, interfaces_ip: dict) -> None:
        """Resolve prefix lengths for bare IPv4 addresses using 'show running-config'."""
        cfg_raw = self.device.send_command("show running-config")
        prefix_map: dict[str, int] = {}
        for m in re.finditer(r"\bip\s+address\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", cfg_raw):
            prefix_map[m.group(1)] = int(m.group(2))
        for intf, addr in bare.items():
            if addr in prefix_map:
                interfaces_ip.setdefault(intf, {}).setdefault("ipv4", {})[addr] = {
                    "prefix_length": prefix_map[addr]
                }

    def _ipv4_from_brief(self, interfaces_ip: dict) -> None:
        """
        Populate *interfaces_ip* with IPv4 addresses from 'show ip interface brief'.

        Rows that include a CIDR prefix (the common case) are stored directly.
        Rows with a bare IP (no prefix) are resolved against 'show running-config'.
        """
        raw = self.device.send_command("show ip interface brief")
        try:
            parsed = parse_output(
                platform="dell_force10", command="show ip interface brief", data=raw
            )
        except Exception:
            logger.debug("Failed to parse 'show ip interface brief' output", exc_info=True)
            return
        bare: dict[str, str] = {}
        for row in parsed:
            intf = row.get("interface", "").strip()
            ip_addr = row.get("ip_address", "").strip()
            if not intf or not ip_addr or ip_addr.lower() in ("unassigned", ""):
                continue
            if "/" in ip_addr:
                addr, prefix_str = ip_addr.split("/", 1)
                try:
                    prefix = int(prefix_str)
                except ValueError:
                    continue
                interfaces_ip.setdefault(intf, {}).setdefault("ipv4", {})[addr] = {
                    "prefix_length": prefix
                }
            else:
                bare[intf] = ip_addr
        if bare:
            self._resolve_bare_ipv4(bare, interfaces_ip)

    def _ipv6_from_brief(self, interfaces_ip: dict) -> None:
        """Populate *interfaces_ip* with IPv6 addresses from 'show ipv6 interface brief'."""
        raw = self.device.send_command("show ipv6 interface brief")
        current_intf: str | None = None
        for line in raw.splitlines():
            m_hdr = re.match(r"^(\S+\s+\S+)\s+is\s+", line)
            if m_hdr:
                current_intf = m_hdr.group(1)
                continue
            if current_intf is None:
                continue
            m_addr = re.match(r"^\s+([0-9a-fA-F:]+(?:%\S+)?)/(\d+)", line)
            if not m_addr:
                continue
            addr = m_addr.group(1)
            try:
                prefix = int(m_addr.group(2))
            except ValueError:
                continue
            interfaces_ip.setdefault(current_intf, {}).setdefault("ipv6", {})[addr] = {
                "prefix_length": prefix
            }

    def get_interfaces_ip(self) -> dict:
        """
        Return IP addresses per interface.

        IPv4 comes from 'show ip interface brief' (ntc-template);
        IPv6 from 'show ipv6 interface brief' (regex).
        """
        interfaces_ip: dict = {}
        self._ipv4_from_brief(interfaces_ip)
        self._ipv6_from_brief(interfaces_ip)
        return interfaces_ip

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """Return device configuration (running and/or startup)."""
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

        Parses 'show vlan' with the dell_force10 ntc-template.  The template
        emits one row per port (multiple rows share the same VLAN_ID), so rows
        are grouped and all non-empty port column values are aggregated into the
        'interfaces' list.
        """
        raw = self.device.send_command("show vlan")
        try:
            parsed = parse_output(platform="dell_force10", command="show vlan", data=raw)
        except Exception:
            logger.debug("Failed to parse 'show vlan' output", exc_info=True)
            return {}

        # Port columns produced by the template — each row has at most one filled.
        _PORT_KEYS = (
            "ports_u_gi", "ports_t_gi",
            "ports_u_te", "ports_t_te",
            "ports_u_fo", "ports_t_fo",
            "ports_u_ma", "ports_t_ma",
        )

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
            # Collect whichever port column is non-empty in this row.
            for key in _PORT_KEYS:
                port = row.get(key, "").strip()
                if port and port not in entry["interfaces"]:
                    entry["interfaces"].append(port)

        return vlans
