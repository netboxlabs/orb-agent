# Copyright 2026 NetBox Labs Inc
"""
Custom Extreme EXOS NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko (extreme_exos device type) + ntc-templates for structured parsing.
Falls back to regex for commands without templates (show version).
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

logger = logging.getLogger(__name__)

# --- config sanitization -------------------------------------------------- #
# "create account admin encrypted-secret "$1$xxx""
_ENCRYPTED_SECRET_RE = re.compile(
    r"(encrypted-secret)\s+\"[^\"]*\"",
    re.IGNORECASE,
)
# "[keyword] encrypted "hash"" — covers shared-secret encrypted, etc.
_ENCRYPTED_RE = re.compile(
    r"(\S+\s+encrypted)\s+\"[^\"]*\"",
    re.IGNORECASE,
)
# "configure snmp add community readonly/readwrite "string""
_SNMP_COMMUNITY_RE = re.compile(
    r"(configure\s+snmp\s+add\s+community\s+(?:readonly|readwrite))\s+\"[^\"]*\"",
    re.IGNORECASE,
)


def _sanitize_config(text: str) -> str:
    text = _ENCRYPTED_SECRET_RE.sub(r'\1 "<redacted>"', text)
    text = _ENCRYPTED_RE.sub(r'\1 "<redacted>"', text)
    text = _SNMP_COMMUNITY_RE.sub(r'\1 "<redacted>"', text)
    return text


# --- VLAN parsing helpers -------------------------------------------------- #
# Split raw "show ports information detail" output into per-port sections.
# Matches both standalone ports (e.g. "1") and slot-qualified stack ports (e.g. "1:1").
_PORT_SECTION_RE = re.compile(r"(?=^Port:\s*[\d:]+)", re.M)
# Capture the full port identifier from the opening line of a section.
_PORT_NUM_RE = re.compile(r"^Port:\s*([\d:]+)", re.M)
# Capture the Internal Tag (untagged/native VLAN ID) from a VLAN cfg entry.
# Matches: "Name: Default, Internal Tag = 1, MAC-limit = ..."
_INTERNAL_TAG_RE = re.compile(r"Internal\s+Tag\s*=\s*(\d+)")

# --- regex fallbacks for "show ports information detail" ------------------- #
# Used when ntc-template raises TextFSMError on stacked/chassis port IDs.
_PORT_ADMIN_RE = re.compile(r"Admin\s+State\s*:\s*(\S+)", re.IGNORECASE)
_PORT_LINK_RE = re.compile(r"Link\s+State\s*:\s*(\S+)", re.IGNORECASE)
_PORT_DESC_RE = re.compile(r"Description\s+String\s*:\s*\"?(.*?)\"?\s*$", re.IGNORECASE | re.M)
# Match "802.1Q Tag = <vid>" lines — the definitive indicator of tagged VLAN membership.
# "Port-specific VLAN ID" is an optional PVID-override sub-line that is absent on many
# trunk ports, so relying on it would miss VLANs for ports that carry multiple tagged VLANs.
_PORT_8021Q_RE = re.compile(r"802\.1Q\s+Tag\s*=\s*(\d+)", re.IGNORECASE)


def _parse_interfaces_regex(output: str) -> dict:
    """Regex fallback for get_interfaces when ntc-template cannot parse the output."""
    interfaces: dict = {}
    for section in _PORT_SECTION_RE.split(output):
        port_m = _PORT_NUM_RE.search(section)
        if not port_m:
            continue
        port = port_m.group(1)
        admin_m = _PORT_ADMIN_RE.search(section)
        link_m = _PORT_LINK_RE.search(section)
        desc_m = _PORT_DESC_RE.search(section)
        interfaces[port] = {
            "is_up": link_m.group(1).lower() == "active" if link_m else False,
            "is_enabled": admin_m.group(1).lower().startswith("enabled") if admin_m else False,
            "description": desc_m.group(1).strip() if desc_m else "",
            "last_flapped": -1.0,
            "mtu": -1,
            "speed": -1.0,
            "mac_address": "",
        }
    return interfaces


def _parse_interface_list_regex(output: str) -> list:
    """
    Regex fallback for interface list from 'show ports information'.

    Each data row starts with the port identifier (numeric or slot:port such as
    '1:1') followed by whitespace.  Header and separator lines start with letters
    or '=' so they are not matched.
    """
    return [m.group(1) for m in re.finditer(r"^([\d:]+)\s", output, re.M)]


def _add_tagged_vlan_ports_regex(vlans: dict, ports_output: str) -> None:
    """Regex fallback for tagged VLAN port membership when ntc-template cannot parse."""
    for section in _PORT_SECTION_RE.split(ports_output):
        port_m = _PORT_NUM_RE.search(section)
        if not port_m:
            continue
        port = port_m.group(1)
        for vid_m in _PORT_8021Q_RE.finditer(section):
            vid = vid_m.group(1)
            if vid in vlans and port not in vlans[vid]["interfaces"]:
                vlans[vid]["interfaces"].append(port)

# --- uptime helpers -------------------------------------------------------- #
_HOUR_SECONDS = 3_600
_DAY_SECONDS = 24 * _HOUR_SECONDS
_WEEK_SECONDS = 7 * _DAY_SECONDS
_YEAR_SECONDS = 365 * _DAY_SECONDS


def _parse_uptime(uptime_str: str) -> float:
    """Convert an EXOS uptime string like '3 days 4 hours 22 minutes' to seconds."""
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


class ExosDriver(_napalm_base.NetworkDriver):
    """Extreme EXOS NAPALM driver (read-only subset for device-discovery)."""

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
            "extreme_exos", netmiko_optional_args=self.netmiko_optional_args
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

    # ---------------------------------------------------------------------- #
    # NAPALM getters
    # ---------------------------------------------------------------------- #

    def get_facts(self) -> dict:
        """Return general device facts."""
        hostname = "Unknown"
        model = "Unknown"
        os_version = "Unknown"
        serial_number = "Unknown"
        uptime: float = -1.0

        ver_output = self.device.send_command("show version")
        if ver_output:
            m = re.search(r"^SysName\s*:\s*(\S+)", ver_output, re.M)
            if m:
                hostname = m.group(1)

            m = re.search(r"^System Type\s*:\s*(\S+)", ver_output, re.M)
            if m:
                model = m.group(1)

            # Match "Image : Version <x>" and the common variant
            # "Image : ExtremeXOS version <x>" (product token before "version").
            m = re.search(r"^Image\s*:.*?\bversion\s+(\S+)", ver_output, re.M | re.IGNORECASE)
            if m:
                os_version = m.group(1)

            # Prefer the dedicated SysSerial field, which holds the unique device serial.
            # The \d{6}-\d{2}-\d+ pattern in the Switch line is the hardware part number
            # (shared across all units of the same model) and should not be used as a
            # serial; it is kept as a last resort for output that lacks SysSerial.
            m = re.search(r"^SysSerial\s*:\s*(\S+)", ver_output, re.M)
            if not m:
                m = re.search(r"\((\d{6}-\d{2}-\d+)\)", ver_output)
            if not m:
                m = re.search(r"\b(\d{6}-\d{2}-\d+)\b", ver_output)
            if m:
                serial_number = m.group(1)

            # Uptime: "Up 3 days 4 hours 22 minutes ago"
            m = re.search(r"\bUp\s+(.*?)\s+ago\b", ver_output)
            if m:
                uptime = _parse_uptime(m.group(1))

        # Fetch interface list separately; this command succeeds even when
        # `show version` returns nothing (e.g. on devices where the template
        # is unavailable), so we always populate interface_list.
        # Guard against TextFSMError: on stacked devices ports are "slot:port"
        # (e.g. "1:1"), which the ntc-template's \d+ rule cannot match and
        # raises TextFSMError.  Fall back to regex rather than returning [].
        ports_output = self.device.send_command("show ports information")
        try:
            parsed_ports = parse_output(
                platform="extreme_exos", command="show ports information", data=ports_output
            )
            interface_list = [row["interface"] for row in parsed_ports if row.get("interface")]
        except Exception:
            logger.warning(
                "exos: ntc-template failed for 'show ports information'; "
                "falling back to regex (stacked port IDs?)"
            )
            interface_list = _parse_interface_list_regex(ports_output)

        return {
            "hostname": hostname,
            "vendor": "Extreme",
            "model": model,
            "os_version": os_version,
            "serial_number": serial_number,
            "uptime": uptime,
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """Return interface details keyed by port number."""
        output = self.device.send_command("show ports information detail")
        if not output:
            return {}

        try:
            parsed = parse_output(
                platform="extreme_exos", command="show ports information detail", data=output
            )
        except Exception:
            logger.warning(
                "exos: ntc-template failed for 'show ports information detail'; "
                "falling back to regex (stacked port IDs?)"
            )
            return _parse_interfaces_regex(output)
        interfaces = {}
        for row in parsed:
            port = row.get("interface", "")
            if not port:
                continue
            admin_state = row.get("admin_state", "")
            link_state = row.get("link_state", "").lower()
            interfaces[port] = {
                "is_up": link_state == "active",
                "is_enabled": admin_state.lower().startswith("enabled"),
                "description": row.get("description", ""),
                "last_flapped": -1.0,
                "mtu": -1,
                "speed": -1.0,
                "mac_address": "",
            }
        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per VLAN interface."""
        output = self.device.send_command("show ipconfig")
        if not output:
            return {}

        parsed = parse_output(
            platform="extreme_exos", command="show ipconfig", data=output
        )
        # The ntc-template emits one aggregated row with list-valued fields
        # (INTERFACE, IP, SUBNET are all List values in a single record).
        # If a future template version emits one row per interface, those fields
        # will be plain strings; zip() over strings iterates character-by-character,
        # so we normalise scalars to single-element lists before zipping.
        interfaces_ip: dict = {}
        for row in parsed:
            interfaces = row.get("interface", [])
            ips = row.get("ip", [])
            subnets = row.get("subnet", [])
            if not isinstance(interfaces, (list, tuple)):
                interfaces = [interfaces]
            if not isinstance(ips, (list, tuple)):
                ips = [ips]
            if not isinstance(subnets, (list, tuple)):
                subnets = [subnets]
            for intf, ip, subnet in zip(interfaces, ips, subnets):
                try:
                    prefix_len = int(subnet.lstrip("/"))
                except (ValueError, AttributeError):
                    # Skip entries whose subnet token cannot be parsed; storing
                    # prefix_length=-1 would cause ip_network() to raise ValueError
                    # in the downstream translate layer.
                    logger.warning("exos: skipping IP %s on %s — unparseable subnet %r", ip, intf, subnet)
                    continue
                interfaces_ip.setdefault(intf, {}).setdefault("ipv4", {})[ip] = {
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
        """Return device configuration."""
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}

        # EXOS has no distinct startup configuration; "show configuration" outputs
        # the effective saved config. Populate both running and startup from the same
        # command to avoid emitting empty startup data when startup capture is enabled.
        if retrieve in ("all", "running", "startup"):
            config_text = self.device.send_command("show configuration")
            if retrieve in ("all", "running"):
                config["running"] = config_text
            if retrieve in ("all", "startup"):
                config["startup"] = config_text

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Return VLAN information keyed by VLAN ID string, with port membership."""
        vlan_output = self.device.send_command("show vlan description")
        parsed_vlans = parse_output(
            platform="extreme_exos", command="show vlan description", data=vlan_output
        )

        vlans: dict = {}
        for row in parsed_vlans:
            vlan_id = row.get("vlan_id", "")
            if not vlan_id:
                continue
            vlans[vlan_id] = {
                "name": row.get("vlan_name", vlan_id),
                "interfaces": [],
            }

        if vlans:
            ports_output = self.device.send_command("show ports information detail")
            self._add_tagged_vlan_ports(vlans, ports_output)
            self._add_untagged_vlan_ports(vlans, ports_output)

        return vlans

    def _add_tagged_vlan_ports(self, vlans: dict, ports_output: str) -> None:
        """
        Add tagged 802.1Q port memberships to *vlans*.

        Pass 1a — ntc-template: reads the ``vlan_id`` field populated from
        ``Port-specific VLAN ID`` lines (optional sub-line; absent on trunk ports
        without a PVID override → empty list even when the template succeeds).

        Pass 1b — regex (always runs): scans ``802.1Q Tag = <vid>`` lines which
        are present for every tagged VLAN membership, covering the trunk-port gap.
        Duplicates are prevented by the ``if port not in`` check.
        """
        try:
            parsed_ports = parse_output(
                platform="extreme_exos",
                command="show ports information detail",
                data=ports_output,
            )
            for row in parsed_ports:
                port = row.get("interface", "")
                if not port:
                    continue
                for vid in row.get("vlan_id", []):
                    if vid in vlans and port not in vlans[vid]["interfaces"]:
                        vlans[vid]["interfaces"].append(port)
        except Exception:
            logger.warning(
                "exos: ntc-template failed for 'show ports information detail' (tagged VLANs); "
                "regex pass will cover membership (stacked port IDs?)"
            )
        # Always supplement with 802.1Q Tag regex: the ntc-template only captures
        # Port-specific VLAN ID (an optional sub-line), so tagged VLANs on trunk
        # ports without that sub-line are missed by the template pass alone.
        _add_tagged_vlan_ports_regex(vlans, ports_output)

    def _add_untagged_vlan_ports(self, vlans: dict, ports_output: str) -> None:
        """Pass 2 — regex: add untagged/native VLAN memberships via Internal Tag lines."""
        for section in _PORT_SECTION_RE.split(ports_output):
            port_m = _PORT_NUM_RE.search(section)
            if not port_m:
                continue
            port = port_m.group(1)
            for tag_m in _INTERNAL_TAG_RE.finditer(section):
                vid = tag_m.group(1)
                if vid in vlans and port not in vlans[vid]["interfaces"]:
                    vlans[vid]["interfaces"].append(port)
