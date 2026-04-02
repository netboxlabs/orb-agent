# Copyright 2026 NetBox Labs Inc
# Based on napalm-huawei-vrp (Apache-2.0): https://github.com/napalm-automation-community/napalm-huawei-vrp
"""
Custom Huawei VRP NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses ntc-templates 9.x for structured parsing wherever templates are available;
falls back to regex for commands without templates (serial number, IPv6).
"""

import logging
import re
import socket

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.helpers import mac as normalize_mac
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

logger = logging.getLogger(__name__)

# Uptime conversion constants
_HOUR_SECONDS = 3600
_DAY_SECONDS = 24 * _HOUR_SECONDS
_WEEK_SECONDS = 7 * _DAY_SECONDS
_YEAR_SECONDS = 365 * _DAY_SECONDS


def _parse_uptime(uptime_str: str) -> int:
    """Convert a Huawei VRP uptime string to total seconds."""
    seconds = 0

    for pattern, factor in (
        (r"(\d+)\s+year", _YEAR_SECONDS),
        (r"(\d+)\s+week", _WEEK_SECONDS),
        (r"(\d+)\s+day", _DAY_SECONDS),
        (r"(\d+)\s+hour", _HOUR_SECONDS),
        (r"(\d+)\s+minute", 60),
        (r"(\d+)\s+second", 1),
    ):
        m = re.search(pattern, uptime_str)
        if m:
            seconds += int(m.group(1)) * factor

    return seconds


def _separate_section(separator: str, content: str) -> list[str]:
    """Split CLI output into per-interface sections using a regex separator."""
    if not content:
        return []

    parts = re.split(separator, content, flags=re.M)
    if len(parts) == 1:
        return []

    parts.pop(0)  # discard empty preamble

    if len(parts) % 2 != 0:
        return []

    it = iter(parts)
    return [line + next(it, "") for line in it]


class VRPDriver(_napalm_base.NetworkDriver):
    """Huawei VRP NAPALM driver (read-only subset for device-discovery)."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Initialize the driver."""
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.device = None

        if optional_args is None:
            optional_args = {}

        transport = optional_args.get("transport", "ssh")
        if transport not in ("ssh", "telnet"):
            raise ValueError(f"Unsupported transport '{transport}': must be 'ssh' or 'telnet'")
        self.transport = transport
        self.netmiko_optional_args = netmiko_args(optional_args)
        default_port = {"ssh": 22, "telnet": 23}
        self.netmiko_optional_args.setdefault("port", default_port[self.transport])

    def open(self):
        """Open an SSH (or Telnet) connection to the device via Netmiko."""
        device_type = "huawei_telnet" if self.transport == "telnet" else "huawei"
        self.device = self._netmiko_open(
            device_type, netmiko_optional_args=self.netmiko_optional_args
        )

    def close(self):
        """Close the connection."""
        self._netmiko_close()

    def is_alive(self):
        """Return connection liveness."""
        if self.device is None:
            return {"is_alive": False}
        try:
            null = chr(0)
            self.device.write_channel(null)
            return {"is_alive": self.device.remote_conn.transport.is_active()}
        except (EOFError, OSError, AttributeError):
            return {"is_alive": False}

    # ------------------------------------------------------------------
    # NAPALM getters
    # ------------------------------------------------------------------

    def get_facts(self) -> dict:
        """Return general device facts."""
        vendor = "Huawei"
        hostname = os_version = model = "Unknown"
        uptime = -1
        serial_number: list[str] = []

        # --- version / model / uptime ---
        ver_output = self.device.send_command("display version")
        parsed_ver = parse_output(platform="huawei_vrp", command="display version", data=ver_output)
        if parsed_ver:
            row = parsed_ver[0]
            os_version = row.get("vrp_version", "Unknown")
            model = row.get("model", "Unknown").strip() or "Unknown"
            uptime = _parse_uptime(row.get("uptime", ""))

        # --- hostname (no template: just grep sysname) ---
        sysname_out = self.device.send_command("display current-configuration | inc sysname")
        if "sysname " in sysname_out:
            hostname = sysname_out.split("sysname ", 1)[1].strip().splitlines()[0].strip()

        # --- serial number ---
        # 'display esn' returns one line per slot for stacked devices
        esn_out = self.device.send_command("display esn")
        serial_number = re.findall(r"ESN\s+of\s+slot\s+\S+\s+(\S+)", esn_out, flags=re.M)
        if not serial_number:
            # Fallback for single devices: "ESN of device: <SN>"
            m = re.search(r"ESN\s+of\s+device\s*:\s*(\S+)", esn_out, flags=re.M)
            if m:
                serial_number = [m.group(1)]

        # --- interface list ---
        brief_out = self.device.send_command("display interface brief")
        parsed_brief = parse_output(
            platform="huawei_vrp", command="display interface brief", data=brief_out
        )
        interface_list = [row["interface"] for row in parsed_brief if row.get("interface")]

        return {
            "uptime": int(uptime),
            "vendor": vendor,
            "os_version": os_version,
            "serial_number": serial_number[0] if serial_number else "Unknown",
            "model": model,
            "hostname": hostname,
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """Return interface details keyed by interface name."""
        output = self.device.send_command("display interface")
        if not output:
            return {}

        parsed = parse_output(platform="huawei_vrp", command="display interface", data=output)
        interfaces = {}
        for row in parsed:
            intf = row.get("interface", "")
            if not intf:
                continue

            link_status = row.get("link_status", "").lower()
            proto_status = row.get("protocol_status", "").lower()

            speed_raw = row.get("speed", "")
            try:
                speed = float(speed_raw) if speed_raw else -1.0
            except ValueError:
                speed = -1.0

            mac_raw = row.get("mac_address", "")
            try:
                mac_address = normalize_mac(mac_raw) if mac_raw else ""
            except Exception:
                mac_address = mac_raw

            interfaces[intf] = {
                "is_up": "up" in proto_status,
                "is_enabled": "up" in link_status,
                "description": row.get("interface_description", "").strip(),
                "last_flapped": -1.0,
                "mtu": int(row["mtu"]) if row.get("mtu") else -1,
                "speed": speed,
                "mac_address": mac_address,
            }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface."""
        interfaces_ip: dict = {}

        # --- IPv4: display ip interface (regex, captures secondary IPs) ---
        ipv4_out = self.device.send_command("display ip interface")
        separator = r"(^(?!Line protocol).*current state.*$)"
        re_intf_name = r"^(?!Line protocol)(?P<intf_name>\S+).+current state"
        re_intf_ip = r"Internet Address is\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)"

        for section in _separate_section(separator, ipv4_out):
            m_intf = re.search(re_intf_name, section, flags=re.M)
            if not m_intf:
                continue
            intf_name = m_intf.group("intf_name")
            for ip, prefix in re.findall(re_intf_ip, section, flags=re.M):
                interfaces_ip.setdefault(intf_name, {}).setdefault("ipv4", {})[ip] = {
                    "prefix_length": int(prefix)
                }

        # --- IPv6: display ipv6 interface (regex, no template available) ---
        ipv6_out = self.device.send_command("display ipv6 interface")
        separator_v6 = r"(^(?!IPv6 protocol).*current state.*$)"
        re_intf_name_v6 = r"^(?!IPv6 protocol)(?P<intf_name>\S+).+current state"
        re_intf_ip_v6 = r"(?P<ip>\S+), subnet is.+\/(?P<prefix>\d+)"

        for section in _separate_section(separator_v6, ipv6_out):
            m_intf = re.search(re_intf_name_v6, section, flags=re.M)
            if not m_intf:
                continue
            intf_name = m_intf.group("intf_name")
            for m in re.finditer(re_intf_ip_v6, section, flags=re.M):
                interfaces_ip.setdefault(intf_name, {}).setdefault("ipv6", {})[m.group("ip")] = {
                    "prefix_length": int(m.group("prefix"))
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
            config["running"] = self.device.send_command("display current-configuration")
        if retrieve.lower() in ("startup", "all"):
            config["startup"] = self.device.send_command("display saved-configuration")

        return config

    def get_vlans(self) -> dict:
        """Return VLAN information keyed by VLAN ID string."""
        output = self.device.send_command("display vlan brief")
        parsed = parse_output(platform="huawei_vrp", command="display vlan brief", data=output)

        # The template uses Filldown + List, so rows may repeat VLAN_ID.
        # Aggregate interfaces per VLAN_ID.
        vlans: dict = {}
        for row in parsed:
            vlan_id = row.get("vlan_id", "")
            if not vlan_id:
                continue
            entry = vlans.setdefault(
                vlan_id,
                {"name": row.get("vlan_name", "") or vlan_id, "interfaces": []},
            )
            for intf in row.get("interface", []):
                if intf and intf not in entry["interfaces"]:
                    entry["interfaces"].append(intf)

        return vlans
