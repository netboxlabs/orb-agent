# Copyright 2026 NetBox Labs Inc
"""
Custom Cisco WLC (AireOS) NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko cisco_wlc_ssh device type and ntc-templates cisco_wlc_ssh
platform for structured parsing wherever templates are available.
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

logger = logging.getLogger(__name__)

# --- config sanitization (Cisco WLC AireOS sensitive fields) ---
# RADIUS auth/acct secret: "config radius auth add 1 1.2.3.4 1812 ascii <secret>"
_RADIUS_SECRET_RE = re.compile(
    r"(config\s+radius\s+(?:auth|acct)\s+add\s+\d+\s+\S+\s+\d+\s+\S+)\s+\S+",
    re.M | re.I,
)
# TACACS secret: "config tacacs add 1 1.2.3.4 49 <secret>"
_TACACS_SECRET_RE = re.compile(
    r"(config\s+tacacs\s+add\s+\d+\s+\S+\s+\d+)\s+\S+",
    re.M | re.I,
)
# WPA PSK key: "config wlan security wpa akm psk set-key ascii 1 <key>"
_PSK_KEY_RE = re.compile(
    r"(config\s+wlan\s+security\s+wpa\s+akm\s+psk\s+set-key\s+ascii\s+\d+)\s+\S+",
    re.M | re.I,
)
# Management user password: "config mgmtuser add <user> <password> ..."
_MGMT_USER_RE = re.compile(
    r"(config\s+mgmtuser\s+add\s+\S+)\s+\S+",
    re.M | re.I,
)
# Local management users: "config local-mgmt-users add <user> <password>"
_LOCAL_USER_RE = re.compile(
    r"(config\s+local-mgmt-users\s+add\s+\S+)\s+\S+",
    re.M | re.I,
)
# SNMPv3 auth/priv passwords: "config snmp v3user add <user> <access> <auth-proto> <priv-proto> <auth-pass> <priv-pass>"
# Preserves first 4 params (user + access + auth-proto + priv-proto), redacts the last two (passwords).
_SNMP_V3_RE = re.compile(
    r"(config\s+snmp\s+v3user\s+add\s+\S+(?:\s+\S+){3})\s+\S+\s+\S+",
    re.M | re.I,
)
# SNMPv1/v2c community string: "config snmp community create <community>" or "delete <community>"
_SNMP_COMMUNITY_RE = re.compile(
    r"(config\s+snmp\s+community\s+(?:create|delete))\s+\S+",
    re.M | re.I,
)


def _sanitize_config(text: str) -> str:
    text = _RADIUS_SECRET_RE.sub(r"\1 <redacted>", text)
    text = _TACACS_SECRET_RE.sub(r"\1 <redacted>", text)
    text = _PSK_KEY_RE.sub(r"\1 <redacted>", text)
    text = _MGMT_USER_RE.sub(r"\1 <redacted>", text)
    text = _LOCAL_USER_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_V3_RE.sub(r"\1 <redacted> <redacted>", text)
    text = _SNMP_COMMUNITY_RE.sub(r"\1 <redacted>", text)
    return text


# Uptime conversion constants
_MINUTE_SECONDS = 60
_HOUR_SECONDS = 3600
_DAY_SECONDS = 24 * _HOUR_SECONDS


def _parse_uptime(uptime_str: str) -> float:
    """Convert WLC uptime string (e.g. '0 days 2 hrs 30 mins 20 secs') to seconds."""
    seconds = 0.0
    for pattern, factor in (
        (r"(\d+)\s+days?", _DAY_SECONDS),
        (r"(\d+)\s+hrs?", _HOUR_SECONDS),
        (r"(\d+)\s+mins?", _MINUTE_SECONDS),
        (r"(\d+)\s+secs?", 1),
    ):
        m = re.search(pattern, uptime_str, re.IGNORECASE)
        if m:
            seconds += int(m.group(1)) * factor
    return seconds


def _netmask_to_prefix(netmask: str) -> int:
    """Convert dotted-decimal netmask to CIDR prefix length."""
    try:
        parts = netmask.split(".")
        if len(parts) != 4:
            return -1
        return sum(bin(int(octet)).count("1") for octet in parts)
    except (ValueError, AttributeError):
        return -1


def _parse_speed(physical_mode: str) -> float:
    """
    Extract link speed in Mbps from WLC port PHYSICAL_MODE column.

    Examples: "1000 Full" → 1000.0, "100 Half" → 100.0, "Auto" → -1.0
    """
    if not physical_mode or physical_mode.lower() in ("auto", ""):
        return -1.0
    m = re.match(r"(\d+)", physical_mode)
    if not m:
        return -1.0
    return float(m.group(1))


class WLCDriver(_napalm_base.NetworkDriver):
    """Cisco WLC (AireOS) NAPALM driver (read-only subset for device-discovery)."""

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
            "cisco_wlc_ssh", netmiko_optional_args=self.netmiko_optional_args
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
        hostname = os_version = serial_number = model = "Unknown"
        uptime = 0.0

        # --- hostname / version / uptime from show sysinfo ---
        sysinfo_raw = self.device.send_command("show sysinfo")
        try:
            parsed_sysinfo = parse_output(
                platform="cisco_wlc_ssh", command="show sysinfo", data=sysinfo_raw
            )
            if parsed_sysinfo:
                row = parsed_sysinfo[0]
                hostname = (row.get("system_name") or "").strip() or self.hostname
                os_version = (row.get("product_version") or "").strip() or "Unknown"
                uptime = _parse_uptime(row.get("system_up_time") or "")
        except Exception:
            logger.debug("Failed to parse show sysinfo; hostname/version/uptime unknown")

        # --- model / serial from show inventory ---
        inv_raw = self.device.send_command("show inventory")
        try:
            parsed_inv = parse_output(
                platform="cisco_wlc_ssh", command="show inventory", data=inv_raw
            )
            # Pick first row with a non-empty PID (chassis entry)
            chassis = next(
                (r for r in parsed_inv if r.get("pid")),
                parsed_inv[0] if parsed_inv else None,
            )
            if chassis:
                model = chassis.get("pid") or "Unknown"
                serial_number = chassis.get("sn") or "Unknown"
        except Exception:
            logger.debug("Failed to parse show inventory; model/serial unknown")

        # --- interface list from show interface summary ---
        iface_raw = self.device.send_command("show interface summary")
        try:
            parsed_iface = parse_output(
                platform="cisco_wlc_ssh", command="show interface summary", data=iface_raw
            )
            interface_list = sorted(r["name"] for r in parsed_iface if r.get("name"))
        except Exception:
            logger.debug("Failed to parse show interface summary; interface_list empty")
            interface_list = []

        return {
            "hostname": hostname,
            "vendor": "Cisco",
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

        WLC logical interfaces (management, ap-manager, dynamic) are returned
        with link status derived from the physical port they are bound to.
        Physical port status comes from 'show port summary'.
        """
        # Build physical port status map: port_number (str) → (is_up, is_enabled, speed)
        port_status: dict[str, dict] = {}
        port_raw = self.device.send_command("show port summary")
        try:
            parsed_ports = parse_output(
                platform="cisco_wlc_ssh", command="show port summary", data=port_raw
            )
            for row in parsed_ports:
                port = row.get("port", "")
                if not port:
                    continue
                link_status = row.get("link_status", "").lower()
                admin_mode = row.get("admin_mode", "").lower()
                port_status[port] = {
                    "is_up": link_status == "up",
                    "is_enabled": admin_mode == "enable",
                    "speed": _parse_speed(row.get("physical_mode", "")),
                }
        except Exception:
            logger.debug("Failed to parse show port summary")

        # Build logical interface table from show interface summary
        iface_raw = self.device.send_command("show interface summary")
        interfaces: dict = {}
        try:
            parsed_iface = parse_output(
                platform="cisco_wlc_ssh", command="show interface summary", data=iface_raw
            )
            for row in parsed_iface:
                name = row.get("name", "")
                if not name:
                    continue
                port = row.get("port", "").strip()
                # Distinguish virtual/unbound interfaces (non-numeric port: "", "N/A",
                # "LAG", etc.) from bound interfaces not found in port_status (parse miss).
                # Virtual/aggregate interfaces are always considered up; parse misses
                # default to False to avoid false-positive healthy reports.
                is_virtual = not port or not port.isdigit()
                phys = port_status.get(port, {})
                interfaces[name] = {
                    "is_up": phys.get("is_up", is_virtual),
                    "is_enabled": phys.get("is_enabled", is_virtual),
                    "description": "",
                    "last_flapped": -1.0,
                    "mtu": -1,
                    "speed": phys.get("speed", -1.0),
                    "mac_address": "",
                }
        except Exception:
            logger.debug("Failed to parse show interface summary for get_interfaces")

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface."""
        iface_raw = self.device.send_command("show interface summary")
        interfaces_ip: dict = {}

        try:
            parsed_iface = parse_output(
                platform="cisco_wlc_ssh", command="show interface summary", data=iface_raw
            )
        except Exception:
            logger.debug("Failed to parse show interface summary for get_interfaces_ip")
            return {}

        for row in parsed_iface:
            name = row.get("name", "")
            ip = row.get("ip_address", "").strip()
            if not name or not ip or ip in ("0.0.0.0", ""):
                continue

            # Get detailed info to obtain the subnet mask
            detail_raw = self.device.send_command(f"show interface detailed {name}")
            try:
                parsed_detail = parse_output(
                    platform="cisco_wlc_ssh",
                    command=f"show interface detailed {name}",
                    data=detail_raw,
                )
                if parsed_detail:
                    detail = parsed_detail[0]
                    netmask = detail.get("netmask", "").strip()
                    prefix_length = _netmask_to_prefix(netmask) if netmask else -1
                else:
                    prefix_length = -1
            except Exception:
                logger.debug("Failed to parse show interface detailed %s", name)
                prefix_length = -1

            if prefix_length < 0:
                continue

            interfaces_ip.setdefault(name, {}).setdefault("ipv4", {})[ip] = {
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
        """
        Return device configuration.

        WLC AireOS uses 'show run-config' for the full running configuration.
        There is no separate startup config; 'save config' commits changes in-place.
        """
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}

        if retrieve in ("all", "running"):
            config["running"] = self.device.send_command("show run-config")

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """
        Return VLAN-to-interface mapping derived from WLC logical interfaces.

        WLC AireOS does not have a traditional L2 VLAN table. Each logical
        interface is bound to a VLAN ID, so we report those bindings here.
        """
        iface_raw = self.device.send_command("show interface summary")
        vlans: dict = {}

        try:
            parsed_iface = parse_output(
                platform="cisco_wlc_ssh", command="show interface summary", data=iface_raw
            )
        except Exception:
            logger.debug("Failed to parse show interface summary for get_vlans")
            return {}

        for row in parsed_iface:
            vlan_id = row.get("vlan_id", "").strip()
            name = row.get("name", "").strip()
            if not vlan_id or vlan_id in ("N/A", "0") or not name:
                continue
            entry = vlans.setdefault(vlan_id, {"name": name, "interfaces": []})
            if name not in entry["interfaces"]:
                entry["interfaces"].append(name)

        return vlans
