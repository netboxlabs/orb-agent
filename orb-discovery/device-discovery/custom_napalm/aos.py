# Copyright 2026 NetBox Labs Inc
# Based on napalm-aos (Apache-2.0): https://github.com/napalm-automation-community/napalm-aos
"""
Custom Alcatel-Lucent AOS NAPALM driver for OmniSwitch devices.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko (alcatel_aos device type) and ntc-templates 9.x for structured
CLI parsing wherever templates are available; falls back to regex for commands
without templates (IP interface table, IPv6 interface table).
"""

import logging
import re
import socket
import struct

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.helpers import mac as normalize_mac
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config sanitization
# ---------------------------------------------------------------------------

# "snmp community-map hash-key <key> ..." — SNMP community hash key
_SNMP_HASH_KEY_RE = re.compile(
    r"(snmp\s+community-map\s+hash-key)\s+\S+",
    re.IGNORECASE,
)

# "user <name> password <hash>" — local user password
_USER_PASSWORD_RE = re.compile(
    r"(user\s+\S+\s+password)\s+\S+",
    re.IGNORECASE,
)

# "aaa radius-server <name> key <secret>" — RADIUS shared secret
_RADIUS_KEY_RE = re.compile(
    r"(aaa\s+radius-server\s+\S+\s+key)\s+\S+",
    re.IGNORECASE,
)


def _sanitize_config(text: str) -> str:
    """Redact credential fields from an AOS configuration snapshot."""
    text = _SNMP_HASH_KEY_RE.sub(r"\1 <redacted>", text)
    text = _USER_PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _RADIUS_KEY_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Uptime parsing
# ---------------------------------------------------------------------------

_HOUR_SECONDS = 3600
_DAY_SECONDS = 24 * _HOUR_SECONDS


def _parse_uptime(uptime_str: str) -> int:
    """
    Convert an AOS uptime string to total integer seconds.

    Examples:
      "0 days 1 hours 57 minutes and 25 seconds" -> 7045
      "1 days 0 hours 0 minutes and 0 seconds"   -> 86400

    """
    seconds = 0
    for pattern, factor in (
        (r"(\d+)\s+day", _DAY_SECONDS),
        (r"(\d+)\s+hour", _HOUR_SECONDS),
        (r"(\d+)\s+minute", 60),
        (r"(\d+)\s+second", 1),
    ):
        m = re.search(pattern, uptime_str, re.IGNORECASE)
        if m:
            seconds += int(m.group(1)) * factor
    return seconds


# ---------------------------------------------------------------------------
# Netmask to prefix-length helper
# ---------------------------------------------------------------------------

def _mask_to_prefix(mask: str) -> int:
    """Convert a dotted-decimal subnet mask to a prefix length integer."""
    try:
        packed = struct.unpack("!I", socket.inet_aton(mask))[0]
        return bin(packed).count("1")
    except (OSError, struct.error):
        return -1


# ---------------------------------------------------------------------------
# IP interface table parsers (extracted to keep get_interfaces_ip simple)
# ---------------------------------------------------------------------------

def _ntc_parse(platform: str, command: str, data: str) -> list:
    """Call ``parse_output`` and return an empty list on any parse error."""
    try:
        return parse_output(platform=platform, command=command, data=data)
    except Exception:
        logger.debug("aos: ntc-template parse failed for command %r", command, exc_info=True)
        return []


_TABLE_SEPARATOR_RE = re.compile(r"^-+\+")
_IPV4_ROW_RE = re.compile(
    r"^(\S.*?)\s{2,}(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+\S"
)
_IPV6_ROW_RE = re.compile(r"^(\S.*?)\s{2,}(\S+/\d+)\s+\S")


def _parse_ipv4_interfaces(output: str, result: dict) -> None:
    """Parse ``show ip interface`` output and populate *result* with IPv4 entries."""
    in_table = False
    for line in output.splitlines():
        stripped = line.strip()
        if _TABLE_SEPARATOR_RE.match(stripped):
            in_table = True
            continue
        if not in_table or not stripped:
            continue
        m = _IPV4_ROW_RE.match(line)
        if not m:
            continue
        intf_name, ip_addr, subnet_mask = m.group(1).strip().lower(), m.group(2), m.group(3)
        if ip_addr == "0.0.0.0":
            continue
        result.setdefault(intf_name, {}).setdefault("ipv4", {})[ip_addr] = {
            "prefix_length": _mask_to_prefix(subnet_mask)
        }


def _parse_ipv6_interfaces(output: str, result: dict) -> None:
    """Parse ``show ipv6 interface`` output and populate *result* with IPv6 entries."""
    in_table = False
    for line in output.splitlines():
        stripped = line.strip()
        if _TABLE_SEPARATOR_RE.match(stripped):
            in_table = True
            continue
        if not in_table or not stripped:
            continue
        m = _IPV6_ROW_RE.match(line)
        if not m:
            continue
        intf_name = m.group(1).strip().lower()
        cidr = m.group(2)
        ipv6_addr, _, prefix_str = cidr.rpartition("/")
        if not ipv6_addr:
            continue
        try:
            prefix_length = int(prefix_str)
        except ValueError:
            prefix_length = -1
        result.setdefault(intf_name, {}).setdefault("ipv6", {})[ipv6_addr] = {
            "prefix_length": prefix_length
        }


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


class AOSDriver(_napalm_base.NetworkDriver):
    """Alcatel-Lucent AOS NAPALM driver (read-only subset for device-discovery)."""

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
            "alcatel_aos", netmiko_optional_args=self.netmiko_optional_args
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
        hostname = "Unknown"
        vendor = "Alcatel-Lucent"
        model = "Unknown"
        os_version = "Unknown"
        serial_number = "Unknown"
        uptime = 0

        # --- hostname / uptime / os_version / vendor from show system ---
        sys_out = self.device.send_command("show system")
        parsed_sys = _ntc_parse("alcatel_aos", "show system", sys_out)
        if parsed_sys:
            row = parsed_sys[0]
            hostname = row.get("name", "Unknown") or "Unknown"
            uptime = _parse_uptime(row.get("uptime", ""))

        # --- model / serial_number from show chassis ---
        chass_out = self.device.send_command("show chassis")
        parsed_chass = _ntc_parse("alcatel_aos", "show chassis", chass_out)
        if parsed_chass:
            # First chassis entry is the master CMM
            chass = parsed_chass[0]
            model = chass.get("model_name", "Unknown").strip() or "Unknown"
            serial_number = chass.get("serial_number", "Unknown").strip() or "Unknown"

        # Split description on model name to extract vendor / os_version.
        # description format: "Alcatel-Lucent Enterprise OS6860E-24 8.5.152.R01 ..."
        if parsed_sys and model != "Unknown":
            desc = parsed_sys[0].get("description", "")
            if model in desc:
                before, _, after = desc.partition(model)
                vendor = before.strip().rstrip(",") or "Alcatel-Lucent"
                os_version = after.strip().lstrip(",").strip() or "Unknown"
            elif desc:
                os_version = desc.strip()
        elif parsed_sys:
            desc = parsed_sys[0].get("description", "")
            if desc:
                os_version = desc.strip()

        # --- interface list from show interfaces alias ---
        alias_out = self.device.send_command("show interfaces alias")
        parsed_alias = _ntc_parse("alcatel_aos", "show interfaces alias", alias_out)
        interface_list = [row["port"] for row in parsed_alias if row.get("port")]

        return {
            "hostname": hostname,
            "vendor": vendor,
            "model": model,
            "os_version": os_version,
            "serial_number": serial_number,
            "uptime": float(uptime),
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """Return interface details keyed by interface name."""
        interfaces: dict = {}

        # --- show interfaces alias: admin/link status + description ---
        alias_out = self.device.send_command("show interfaces alias")
        parsed_alias = _ntc_parse("alcatel_aos", "show interfaces alias", alias_out)
        for row in parsed_alias:
            port = row.get("port", "")
            if not port:
                continue
            admin_status = row.get("admin_status", "").lower()
            link_status = row.get("link_status", "").lower()
            interfaces[port] = {
                "is_up": link_status == "up",
                "is_enabled": admin_status == "en",
                "description": row.get("alias", "").strip(),
                "last_flapped": -1.0,
                "speed": -1.0,
                "mtu": -1,
                "mac_address": "",
            }

        # --- show interfaces: MAC address, speed, MTU (per-port ethernet detail) ---
        eth_out = self.device.send_command("show interfaces")
        parsed_eth = _ntc_parse("alcatel_aos", "show interfaces", eth_out)
        for row in parsed_eth:
            port = row.get("port", "")
            if not port:
                continue

            mac_raw = row.get("mac_address", "")
            try:
                mac = normalize_mac(mac_raw) if mac_raw else ""
            except Exception:
                mac = mac_raw

            bw_raw = row.get("bandwidth", "")
            try:
                speed = float(bw_raw) if bw_raw and bw_raw != "-" else -1.0
            except ValueError:
                speed = -1.0

            mtu_raw = row.get("long_frame_size", "")
            try:
                mtu = int(mtu_raw) if mtu_raw else -1
            except ValueError:
                mtu = -1

            if port in interfaces:
                interfaces[port]["mac_address"] = mac
                interfaces[port]["speed"] = speed
                interfaces[port]["mtu"] = mtu
            else:
                # Port appeared in ethernet output but not in alias output.
                # Use admin_status when the template provides it (tabular format);
                # fall back to True when it is absent (verbose per-port format).
                status_raw = row.get("status", "").lower()
                admin_raw = row.get("admin_status", "").lower()
                is_enabled = (admin_raw != "disabled") if admin_raw else True
                interfaces[port] = {
                    "is_up": status_raw == "up",
                    "is_enabled": is_enabled,
                    "description": "",
                    "last_flapped": -1.0,
                    "speed": speed,
                    "mtu": mtu,
                    "mac_address": mac,
                }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface."""
        interfaces_ip: dict = {}
        ipv4_out = self.device.send_command("show ip interface")
        _parse_ipv4_interfaces(ipv4_out, interfaces_ip)
        ipv6_out = self.device.send_command("show ipv6 interface")
        _parse_ipv6_interfaces(ipv6_out, interfaces_ip)
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

        AOS exposes the running configuration via ``show configuration snapshot``.
        Startup config (flash/working/boot.cfg) is not retrieved here to avoid
        relying on shell access. Candidate config is not supported by AOS.
        """
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}

        if retrieve.lower() in ("running", "all"):
            config["running"] = self.device.send_command("show configuration snapshot")

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Return VLAN information keyed by VLAN ID string."""
        vlans: dict = {}

        # --- show vlan: VLAN_ID and name ---
        vlan_out = self.device.send_command("show vlan")
        parsed_vlan = _ntc_parse("alcatel_aos", "show vlan", vlan_out)
        for row in parsed_vlan:
            vlan_id = row.get("vlan_id", "")
            if not vlan_id:
                continue
            vlan_name = row.get("vlan_name", "").strip() or vlan_id
            vlans[vlan_id] = {"name": vlan_name, "interfaces": []}

        # --- show vlan port: VLAN to port mapping ---
        vlan_port_out = self.device.send_command("show vlan port")
        parsed_vlan_port = _ntc_parse("alcatel_aos", "show vlan port", vlan_port_out)
        for row in parsed_vlan_port:
            vlan_id = row.get("vlan_id", "")
            port = row.get("port", "")
            if not vlan_id or not port:
                continue
            vlan = vlans.setdefault(vlan_id, {"name": vlan_id, "interfaces": []})
            if port not in vlan["interfaces"]:
                vlan["interfaces"].append(port)

        return vlans
