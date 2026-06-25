# Copyright 2026 NetBox Labs Inc
"""
Custom Check Point Gaia NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses ntc-templates 9.x for structured parsing wherever templates are available;
falls back to regex for commands without templates (e.g. hostname).
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
# Config sanitization — Check Point Gaia credential patterns
# ---------------------------------------------------------------------------
_SANITIZE_PATTERNS: list[tuple[re.Pattern, str]] = [
    # set user <name> password-hash <hash>
    (re.compile(r"^(set\s+user\s+\S+\s+password-hash)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    # set snmp community <string> read-only|read-write  (community string is before read-only)
    (re.compile(r"^(set\s+snmp\s+community)\s+\S+(\s+(?:read-only|read-write))", re.M | re.I), r"\1 <redacted>\2"),
    # set aaa tacacs-servers server <ip> key <secret> ...
    (re.compile(r"^(set\s+aaa\s+tacacs-servers\b.*?\bkey)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    # set vpn ... pre-shared-secret <s>
    (re.compile(r"^(.*pre-shared-secret)\s+\S+", re.M | re.I), r"\1 <redacted>"),
]


# Matches Gaia config syntax: set interface <name> ipv6-address <addr> mask-length <len>
_IPV6_CFG_RE = re.compile(
    r"^set\s+interface\s+(\S+)\s+ipv6-address\s+([0-9a-f:]+)\s+mask-length\s+(\d+)",
    re.M | re.I,
)


def _sanitize_config(text: str) -> str:
    for pattern, replacement in _SANITIZE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _parse_speed(speed_raw: str) -> float:
    """
    Convert Gaia speed string to float Mbps.

    Examples: '1000M' -> 1000.0, '10G' -> 10000.0, 'N/A' -> 0.0
    """
    if not speed_raw or speed_raw.startswith("N/A"):
        return 0.0
    m = re.match(r"(\d+(?:\.\d+)?)\s*([MmGgKk])", speed_raw)
    if not m:
        return 0.0
    num = float(m.group(1))
    unit = m.group(2).upper()
    if unit == "G":
        return num * 1000.0
    if unit == "K":
        return num / 1000.0
    return num  # M


class GaiaDriver(_napalm_base.NetworkDriver):
    """Check Point Gaia NAPALM driver (read-only subset for device-discovery)."""

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
            "checkpoint_gaia", netmiko_optional_args=self.netmiko_optional_args
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

    def get_facts(self) -> dict:
        """Return general device facts."""
        # --- version ---
        ver_raw = self.device.send_command("show version all")
        parsed_ver = parse_output(platform="checkpoint_gaia", command="show version all", data=ver_raw)
        os_version = parsed_ver[0].get("version", "Unknown") if parsed_ver else "Unknown"

        # --- model + serial ---
        asset_raw = self.device.send_command("show asset all")
        parsed_asset = parse_output(platform="checkpoint_gaia", command="show asset all", data=asset_raw)
        model = "Unknown"
        serial_number = "Unknown"
        for row in parsed_asset:
            if row.get("model") and model == "Unknown":
                model = row["model"]
            if row.get("serial") and serial_number == "Unknown":
                serial_number = row["serial"]

        # --- hostname ---
        hostname_raw = self.device.send_command("show hostname")
        m = re.match(r"^(\S+)", hostname_raw.strip())
        hostname = m.group(1) if m else self.hostname

        # --- fqdn ---
        domain_raw = self.device.send_command("show domainname")
        parsed_domain = parse_output(platform="checkpoint_gaia", command="show domainname", data=domain_raw)
        domainname = parsed_domain[0].get("domainname", "") if parsed_domain else ""
        fqdn = f"{hostname}.{domainname}" if domainname else hostname

        # --- interface list ---
        intf_raw = self.device.send_command("show interfaces all")
        parsed_intf = parse_output(platform="checkpoint_gaia", command="show interfaces all", data=intf_raw)
        interface_list = [row["interface"] for row in parsed_intf if row.get("interface")]

        return {
            "hostname": hostname,
            "vendor": "Check Point",
            "model": model,
            "os_version": os_version,
            "serial_number": serial_number,
            "uptime": -1.0,
            "fqdn": fqdn,
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """Return interface details keyed by interface name."""
        raw = self.device.send_command("show interfaces all")
        parsed = parse_output(platform="checkpoint_gaia", command="show interfaces all", data=raw)

        interfaces = {}
        for row in parsed:
            intf = row.get("interface", "")
            if not intf:
                continue

            mac_raw = row.get("mac_address", "")
            try:
                mac_address = (
                    normalize_mac(mac_raw)
                    if mac_raw and mac_raw.lower() not in ("not configured", "")
                    else ""
                )
            except Exception:
                mac_address = mac_raw

            interfaces[intf] = {
                "is_up": "link up" in row.get("link_state", "").lower(),
                "is_enabled": row.get("state", "").lower() == "on",
                "description": "",
                "last_flapped": -1.0,
                "mtu": int(row["mtu"]) if row.get("mtu") else 0,
                "speed": _parse_speed(row.get("speed", "")),
                "mac_address": mac_address,
            }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface."""
        raw = self.device.send_command("show interfaces all")
        parsed = parse_output(platform="checkpoint_gaia", command="show interfaces all", data=raw)

        # Build IPv6 prefix map from running config:
        # "set interface <name> ipv6-address <addr> mask-length <len>"
        ipv6_prefix_map: dict[str, dict[str, int]] = {}
        config_raw = self.device.send_command("show configuration")
        for m in _IPV6_CFG_RE.finditer(config_raw):
            intf_name, addr, prefix = m.group(1), m.group(2), int(m.group(3))
            ipv6_prefix_map.setdefault(intf_name, {})[addr.lower()] = prefix

        interfaces_ip: dict = {}
        _NOT_CONFIGURED = {"not configured", ""}

        for row in parsed:
            intf = row.get("interface", "")
            if not intf:
                continue

            # IPv4 — field contains CIDR e.g. "2.2.2.2/29"
            ipv4_cidr = row.get("ipv4_address", "")
            if ipv4_cidr and ipv4_cidr.lower() not in _NOT_CONFIGURED and "/" in ipv4_cidr:
                try:
                    ip, prefix_str = ipv4_cidr.split("/")
                    interfaces_ip.setdefault(intf, {}).setdefault("ipv4", {})[ip] = {
                        "prefix_length": int(prefix_str)
                    }
                except (ValueError, AttributeError):
                    pass

            # IPv6 — prefix sourced from running config; skip if unavailable
            ipv6_addr = row.get("ipv6_address", "")
            if ipv6_addr and ipv6_addr.lower() not in _NOT_CONFIGURED:
                prefix_len = ipv6_prefix_map.get(intf, {}).get(ipv6_addr.lower())
                if prefix_len is not None:
                    interfaces_ip.setdefault(intf, {}).setdefault("ipv6", {})[ipv6_addr] = {
                        "prefix_length": prefix_len
                    }
                else:
                    logger.debug(
                        "Skipping IPv6 address %s on %s: prefix length not found in config",
                        ipv6_addr,
                        intf,
                    )

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

        if retrieve.lower() in ("all", "running"):
            config["running"] = self.device.send_command("show configuration")

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Check Point Gaia does not expose a traditional VLAN table via CLI."""
        return {}
