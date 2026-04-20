# Copyright 2026 NetBox Labs Inc
"""
Custom Brocade/Extreme NetIron NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko for SSH connectivity and ntc-templates 9.x for structured
parsing wherever templates are available; falls back to regex for commands
without templates (show version, IP prefix extraction).
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

# "enable <level> <hash>" — numeric level (0, 1, 2, ...)
# "enable super-user-password <hash>" — non-numeric ICX/NetIron form
_ENABLE_RE = re.compile(
    r"(\benable\s+(?:\d+|super-user-password))\s+\S+", re.IGNORECASE
)

# Covers all common NetIron username credential forms:
#   "username <name> password <type> <hash>"
#   "username <name> privilege <level> password <type> <hash>"
#   "username <name> <type> <hash>"               (no 'password' keyword)
_USERNAME_PASSWORD_RE = re.compile(
    r"(\busername\s+\S+(?:\s+privilege\s+\d+)?(?:\s+password)?\s+\d+)\s+\S+",
    re.IGNORECASE,
)

# "username ... <hash> history <hash>" — redacts the history hash separately so
# the 'history' keyword is preserved in the sanitized output.
_USERNAME_HISTORY_RE = re.compile(
    r"(\busername\s+\S+.*?\bhistory)\s+\S+",
    re.IGNORECASE,
)

# "snmp-server community <string> ..."
_SNMP_COMMUNITY_RE = re.compile(
    r"(\bsnmp-server\s+community)\s+(?:\S+)", re.IGNORECASE
)

# "ip vrrp-extended auth-type simple-text-auth <password>"
_VRRP_AUTH_RE = re.compile(
    r"(\bauth-type\s+simple-text-auth)\s+\S+", re.IGNORECASE
)


def _sanitize_config(text: str) -> str:
    text = _ENABLE_RE.sub(r"\1 <redacted>", text)
    text = _USERNAME_PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _USERNAME_HISTORY_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_COMMUNITY_RE.sub(r"\1 <redacted>", text)
    text = _VRRP_AUTH_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Uptime helpers
# ---------------------------------------------------------------------------

_DAY_SECONDS = 86400
_HOUR_SECONDS = 3600


def _parse_uptime(uptime_str: str) -> int:
    """
    Convert a NetIron uptime string to total seconds.

    Handles two common formats:
      "5 days 4 hours 3 minutes 12 seconds"
      "4 hours 12 minutes 5 seconds"
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
# Speed helpers
# ---------------------------------------------------------------------------

_SPEED_MAP = {
    "1mbit": 1,
    "10mbit": 10,
    "100mbit": 100,
    "1gbit": 1000,
    "2.5gbit": 2500,
    "5gbit": 5000,
    "10gbit": 10000,
    "25gbit": 25000,
    "40gbit": 40000,
    "100gbit": 100000,
}


def _parse_speed(speed_str: str) -> float:
    """Convert a NetIron speed string (e.g. '1Gbit') to Mbps as a float."""
    key = speed_str.strip().lower()
    return float(_SPEED_MAP.get(key, 0))


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


class NetIronDriver(_napalm_base.NetworkDriver):
    """Brocade/Extreme NetIron NAPALM driver (read-only subset for device-discovery)."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Initialize the driver."""
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.device = None
        # Prevent NAPALM's _netmiko_open from attempting enable mode;
        # NetIron discovery is read-only and does not require privileged exec.
        self.force_no_enable = True

        if optional_args is None:
            optional_args = {}
        self.netmiko_optional_args = netmiko_args(optional_args)
        self.netmiko_optional_args.setdefault("port", 22)

    def open(self):
        """Open an SSH connection to the device via Netmiko."""
        self.device = self._netmiko_open(
            "brocade_netiron", netmiko_optional_args=self.netmiko_optional_args
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

    # ------------------------------------------------------------------
    # NAPALM getters
    # ------------------------------------------------------------------

    def get_facts(self) -> dict:
        """
        Return general device facts.

        Parses ``show version`` with regex (no ntc-template exists for this
        command on brocade_netiron) and ``show interfaces`` via ntc-templates
        for the interface list, giving canonical names consistent with
        ``get_interfaces()``.
        """
        # Default hostname to the connection target; overridden if show version
        # contains a "hostname <name>" line (not all NetIron variants include it).
        hostname = self.hostname
        os_version = model = serial_number = "Unknown"
        uptime: float = 0.0

        ver_out = self.device.send_command("show version")
        if ver_out:
            # Hostname: "hostname <name>" appears in some NetIron variants
            m = re.search(r"^hostname\s+(\S+)", ver_out, re.MULTILINE | re.IGNORECASE)
            if m:
                hostname = m.group(1)

            # System/model name — e.g. "System: NetIron MLX-8" or
            # UNIT line like "UNIT 1: SL 1: ICX7450-24:"
            m = re.search(r"System:\s+(.+)", ver_out)
            if m:
                model = m.group(1).strip()
            else:
                m = re.search(r"UNIT\s+\d+:\s+SL\s+\d+:\s+(\S[^:]+):", ver_out)
                if m:
                    model = m.group(1).strip()

            # SW version — "SW: Version X.Y.Z" or "SW Version: X.Y.Z"
            m = re.search(r"SW(?:\s+Version|\s*:\s*Version)\s*:?\s*(\S+)", ver_out, re.IGNORECASE)
            if m:
                os_version = m.group(1)

            # Serial number — "Serial  #: <SN>" or "Serial Number: <SN>"
            m = re.search(r"Serial\s+(?:#|Number)\s*:\s*(\S+)", ver_out, re.IGNORECASE)
            if m:
                serial_number = m.group(1)

            # Uptime — "Uptime: X days Y hours Z minutes W seconds"
            m = re.search(r"Uptime:\s+(.+)", ver_out, re.IGNORECASE)
            if m:
                uptime = float(_parse_uptime(m.group(1)))

        # Interface list from show interfaces — canonical names, consistent with get_interfaces().
        intf_out = self.device.send_command("show interfaces")
        parsed_intfs = parse_output(
            platform="brocade_netiron", command="show interfaces", data=intf_out
        )
        interface_list = [row["interface"] for row in parsed_intfs if row.get("interface")]

        return {
            "hostname": hostname,
            "vendor": "Brocade",
            "model": model,
            "os_version": os_version,
            "serial_number": serial_number,
            "uptime": uptime,
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """Return interface details keyed by interface name."""
        raw = self.device.send_command("show interfaces")
        parsed = parse_output(
            platform="brocade_netiron", command="show interfaces", data=raw
        )

        interfaces = {}
        for row in parsed:
            intf = row.get("interface", "")
            if not intf:
                continue

            intstate = row.get("intstate", "").lower()
            protostate = row.get("protostate", "").lower()

            mac_raw = row.get("mac", "") or row.get("bia", "")
            try:
                mac_address = normalize_mac(mac_raw) if mac_raw else ""
            except Exception:
                mac_address = mac_raw

            speed_raw = row.get("actualspeed", "")
            speed = _parse_speed(speed_raw) if speed_raw else 0.0

            mtu_raw = row.get("l2mtubytes", "") or row.get("l3mtubytes", "")
            try:
                mtu = int(mtu_raw) if mtu_raw else 0
            except ValueError:
                mtu = 0

            description = row.get("portname", "").strip()

            interfaces[intf] = {
                "is_up": protostate == "up",
                "is_enabled": intstate != "disabled",
                "description": description,
                "last_flapped": -1.0,
                "mtu": mtu,
                "speed": speed,
                "mac_address": mac_address,
            }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """
        Return IP addresses per interface.

        The ntc-template for ``show interfaces`` captures the ``IPADDRESS``
        field in CIDR notation (e.g. ``172.24.18.1/24``) from lines like
        ``Internet address is <ip>/<prefix>``.  Entries with address
        ``0.0.0.0/0`` are skipped (unconfigured routing interfaces).
        """
        raw = self.device.send_command("show interfaces")
        parsed = parse_output(
            platform="brocade_netiron", command="show interfaces", data=raw
        )

        # Only IPv4 is collected here: the brocade_netiron ntc-template captures
        # a single IPADDRESS field (IPv4 CIDR) per interface.  IPv6 addresses
        # are not exposed by this template and are therefore not returned.
        interfaces_ip: dict = {}
        for row in parsed:
            intf = row.get("interface", "")
            ip_cidr = row.get("ipaddress", "")
            if not intf or not ip_cidr or ip_cidr == "0.0.0.0/0":
                continue
            try:
                ip, prefix_str = ip_cidr.split("/")
                prefix = int(prefix_str)
            except (ValueError, AttributeError):
                continue
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

        if retrieve in ("all", "running"):
            config["running"] = self.device.send_command("show running-config")
        # NetIron startup config ("show startup-config") is not collected:
        # the command is not available on all platforms and the running config
        # is the authoritative source for device-discovery purposes.

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """
        Return VLAN information keyed by VLAN ID string.

        Uses ``show running-config vlan`` parsed via ntc-templates.  The
        template records one row per VLAN block.  Tagged and untagged port
        lists arrive as a space-separated string such as
        ``e 1/1 e 1/2 to 1/5``; non-port tokens (``e``, ``ethe``, ``eth``,
        ``to``) are stripped so only slot/port identifiers remain.
        """
        raw = self.device.send_command("show running-config vlan")
        parsed = parse_output(
            platform="brocade_netiron", command="show running-config vlan", data=raw
        )

        # Tokens that appear in Brocade port lists but are not port identifiers.
        # NOTE: compact range notation ("e 1/1 to 1/5") is NOT expanded here;
        # only the individual endpoint tokens are kept.  Range expansion is a
        # future improvement if needed.
        _NON_PORT = frozenset({"e", "ethe", "eth", "to"})

        vlans: dict = {}
        for row in parsed:
            vlan_id = row.get("vlan_id", "")
            if not vlan_id:
                continue

            # Collect tagged and untagged port identifiers
            interfaces: list[str] = []
            for field in ("taggedports", "untaggedports"):
                raw_ports = row.get(field, "").strip()
                if not raw_ports:
                    continue
                for token in raw_ports.split():
                    token = token.strip()
                    if token and token not in _NON_PORT:
                        interfaces.append(token)

            entry = vlans.setdefault(
                vlan_id,
                {
                    "name": row.get("vlan_name", "").strip() or vlan_id,
                    "interfaces": [],
                },
            )
            seen: set[str] = set(entry["interfaces"])
            for intf in interfaces:
                if intf not in seen:
                    seen.add(intf)
                    entry["interfaces"].append(intf)

        return vlans
