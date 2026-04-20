# Copyright 2026 NetBox Labs Inc
"""
Custom Extreme SLX-OS NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko (extreme_slx device type) + ntc-templates for structured parsing
wherever templates are available (show ip interface brief); falls back to regex
for commands without templates (show version, show interface brief, show vlan brief).
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import ParsingException, parse_output
from textfsm import TextFSMError

# socket.error is an alias for OSError in Python 3; no socket import needed.

logger = logging.getLogger(__name__)

# --- config sanitization -------------------------------------------------- #
# "username admin password encrypted <hash>" or "password encrypted <hash>"
_PASSWORD_ENCRYPTED_RE = re.compile(
    r"((?:password|passwd)\s+encrypted)\s+\S+",
    re.IGNORECASE,
)
# "username admin password 7 <hash>" or "username admin password <hash>" (bare form)
# The encryption-type digit (e.g. 0, 7) is optional — SLX-OS also emits it without a type prefix.
# Negative lookahead (?!encrypted\b) prevents matching the "password encrypted <hash>" form,
# which is already handled by _PASSWORD_ENCRYPTED_RE above.
_PASSWORD_TYPE_RE = re.compile(
    r"(username\s+\S+(?:\s+privilege\s+\d+)?\s+password(?:\s+\d+)?)\s+(?!encrypted\b)\S+",
    re.IGNORECASE,
)
# "enable password <value>" / "enable password 7 <hash>" (optional encryption-type token)
_ENABLE_PASSWORD_RE = re.compile(
    r"(enable\s+password)(?:\s+\d+)?\s+\S+",
    re.IGNORECASE,
)
# "enable secret sha256 <hash>" / "enable secret 8 <hash>"
_ENABLE_SECRET_RE = re.compile(
    r"(enable\s+secret\s+\S+)\s+\S+",
    re.IGNORECASE,
)
# "snmp-server community <string> ro" / "snmp-server community <string> rw"
_SNMP_COMMUNITY_RE = re.compile(
    r"(snmp-server\s+community)\s+\S+(\s+(?:ro|rw))",
    re.IGNORECASE,
)
# "radius-server host <ip> ... key <key>" / "... key 7 <hash>" (per-host)
_RADIUS_HOST_KEY_RE = re.compile(
    r"(\bradius-server\s+host\s+\S+.*?\bkey)(?:\s+\d+)?\s+\S+",
    re.IGNORECASE,
)
# "radius-server key <key>" / "radius-server key 7 <hash>" (global)
_RADIUS_GLOBAL_KEY_RE = re.compile(
    r"(\bradius-server\s+key)(?:\s+\d+)?\s+\S+",
    re.IGNORECASE,
)
# "tacacs-server host <ip> ... key <key>" / "... key 7 <hash>" (per-host)
_TACACS_HOST_KEY_RE = re.compile(
    r"(\btacacs-server\s+host\s+\S+.*?\bkey)(?:\s+\d+)?\s+\S+",
    re.IGNORECASE,
)
# "tacacs-server key <key>" / "tacacs-server key 7 <hash>" (global)
_TACACS_GLOBAL_KEY_RE = re.compile(
    r"(\btacacs-server\s+key)(?:\s+\d+)?\s+\S+",
    re.IGNORECASE,
)
# Standalone indented "key <secret>" / "key 7 <hash>" lines emitted when SLX-OS
# writes AAA host blocks in hierarchical form.
# Matches only indented lines so that top-level "key" keywords (already covered
# by the per-host regexes above) are not double-substituted.
_AAA_KEY_STANDALONE_RE = re.compile(
    r"^(\s+key)(?:\s+\d+)?\s+\S+",
    re.IGNORECASE | re.M,
)


def _sanitize_config(text: str) -> str:
    text = _PASSWORD_ENCRYPTED_RE.sub(r"\1 <redacted>", text)
    text = _PASSWORD_TYPE_RE.sub(r"\1 <redacted>", text)
    text = _ENABLE_PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _ENABLE_SECRET_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_COMMUNITY_RE.sub(r"\1 <redacted>\2", text)
    text = _RADIUS_HOST_KEY_RE.sub(r"\1 <redacted>", text)
    text = _RADIUS_GLOBAL_KEY_RE.sub(r"\1 <redacted>", text)
    text = _TACACS_HOST_KEY_RE.sub(r"\1 <redacted>", text)
    text = _TACACS_GLOBAL_KEY_RE.sub(r"\1 <redacted>", text)
    text = _AAA_KEY_STANDALONE_RE.sub(r"\1 <redacted>", text)
    return text


# --- uptime helpers -------------------------------------------------------- #
_HOUR_SECONDS = 3_600
_DAY_SECONDS = 24 * _HOUR_SECONDS
_WEEK_SECONDS = 7 * _DAY_SECONDS
_YEAR_SECONDS = 365 * _DAY_SECONDS


def _parse_uptime(uptime_str: str) -> float:
    """
    Convert an SLX-OS uptime string to seconds.

    Handles both the long form  ("X days, X hours, X minutes, X seconds")
    and the compact abbreviation form ("0days 4hrs 52mins 22secs") emitted
    by some SLX-OS firmware versions.  The digit and unit may be separated
    by optional whitespace in either form.
    """
    seconds = 0.0
    for pattern, factor in (
        (r"(\d+)\s*(?:years?|yr)", _YEAR_SECONDS),
        (r"(\d+)\s*(?:weeks?|wk)", _WEEK_SECONDS),
        (r"(\d+)\s*days?", _DAY_SECONDS),
        (r"(\d+)\s*(?:hours?|hrs?)", _HOUR_SECONDS),
        (r"(\d+)\s*(?:minutes?|mins?)", 60),
        (r"(\d+)\s*(?:seconds?|secs?)", 1),
    ):
        m = re.search(pattern, uptime_str, re.IGNORECASE)
        if m:
            seconds += int(m.group(1)) * factor
    return seconds


def _speed_mbps(token: str) -> float:
    """
    Convert a speed token from 'show interface brief' to Mbps.

    Examples: "10G" → 10000.0, "1G" → 1000.0, "100M" → 100.0, "-" → -1.0.
    """
    token = token.upper()
    if token.endswith("G"):
        try:
            return float(token[:-1]) * 1000
        except ValueError:
            pass
    elif token.endswith("M"):
        try:
            return float(token[:-1])
        except ValueError:
            pass
    return -1.0


# --- interface brief parsing ----------------------------------------------- #
# Matches SLX-OS "show interface brief" rows:
#   "Ethernet 0/1    up        10G"
#   "Management 1    up        1G"
#   "Port-channel 1  up        -"
#   "Loopback 1      up        -"
#   "Ve 10           up        -"
#   "Ethernet 0/4    Disabled  -"   (admin-down)
# Group 1: interface name, Group 2: link/admin state, Group 3: speed token
_INTF_BRIEF_RE = re.compile(
    r"^((?:Ethernet|Management|Port-channel|Loopback|Ve)\s+\S+)\s+(\S+)\s+(\S+)",
    re.M | re.IGNORECASE,
)

# --- vlan brief parsing ---------------------------------------------------- #
# Matches leading VLAN row.  The name capture uses a greedy (.+) so that VLAN
# names that themselves contain the word "active" or "inactive" (e.g.
# "User active zone") are captured in full: the greedy match backtracks to the
# LAST occurrence of the state keyword, which is the actual State column.
# Example: "10    Voice User      ACTIVE   Eth 0/1(u) Eth 0/2(u)"
_VLAN_ROW_RE = re.compile(
    r"^(\d+)\s+(.+)\s+(?:active|inactive)\s*(.*)?$",
    re.M | re.IGNORECASE,
)
# Port tokens like "Eth 0/1" or "Po 1" (with optional trailing "(u)"/"(t)" suffix)
_VLAN_PORT_RE = re.compile(r"((?:Eth|Po)\s+\S+)")

# --- show ip interface brief Management handling -------------------------- #
# The extreme_slxos ntc-template does not include a Management interface state
# and raises TextFSMError on Management rows.  We pre-filter them before passing
# to parse_output, then collect their IPs with a dedicated regex so that
# management addresses are not silently dropped.
#
# Example row: "Management 0    10.255.255.1/24    mgmt-vrf    up    up"
_MGMT_LINE_RE = re.compile(r"^\s*Management\s+\S+", re.IGNORECASE)
_MGMT_IP_RE = re.compile(
    r"^\s*(Management\s+\S+)\s+(\d[\d.]+(?:/\d+)?)\s",
    re.IGNORECASE,
)
# Regex fallback covering all known interface types, used when ntc-template
# parse_output() fails entirely so no interface address is silently dropped.
_INTF_IP_FALLBACK_RE = re.compile(
    r"^\s*((?:Ethernet|Management|Port-channel|Loopback|Ve)\s+\S+)\s+(\d[\d.]+(?:/\d+)?)\s",
    re.IGNORECASE,
)


def _record_ip(interfaces_ip: dict, intf: str, ip_addr: str) -> None:
    """
    Insert one IP address entry into the interfaces_ip accumulator.

    Silently skips unassigned or malformed entries.
    """
    if not intf or not ip_addr or ip_addr == "unassigned":
        return
    if "/" in ip_addr:
        ip, prefix_str = ip_addr.split("/", 1)
        try:
            prefix_len = int(prefix_str)
        except ValueError:
            logger.warning("slxos: unparseable prefix %r on %s; skipping", ip_addr, intf)
            return
    else:
        ip, prefix_len = ip_addr, 32
    interfaces_ip.setdefault(intf, {}).setdefault("ipv4", {})[ip] = {
        "prefix_length": prefix_len
    }


def _expand_vlan_port(token: str) -> str:
    """
    Expand abbreviated VLAN port tokens to canonical interface names.

    Maps "show vlan brief" abbreviations to the same names produced by
    get_interfaces() so that VLAN membership can be correlated with interface data.
    Trailing state suffixes like "(u)" (untagged) and "(t)" (tagged) are stripped.

    Examples: "Eth 0/1(u)" → "Ethernet 0/1", "Po 1(t)" → "Port-channel 1".
    """
    token = re.sub(r"\([^)]*\)$", "", token.strip())
    parts = token.split(None, 1)
    if not parts:
        return token
    prefix, rest = parts[0].upper(), parts[1].strip() if len(parts) > 1 else ""
    if prefix == "ETH":
        return f"Ethernet {rest}"
    if prefix == "PO":
        return f"Port-channel {rest}"
    return token


class SLXOSDriver(_napalm_base.NetworkDriver):
    """Extreme SLX-OS NAPALM driver (read-only subset for device-discovery)."""

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
            "extreme_slx", netmiko_optional_args=self.netmiko_optional_args
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
            # Hostname: "System Name: slx9640"
            m = re.search(r"System\s+Name\s*:\s*(\S+)", ver_output, re.IGNORECASE)
            if m:
                hostname = m.group(1)

            # Model: "Chassis information for: SLX_9640" or "Chassis Type: SLX 9640"
            m = re.search(
                r"Chassis(?:\s+information\s+for|\s+Type)\s*:\s+(.+)",
                ver_output,
                re.IGNORECASE,
            )
            if m:
                # Normalise "SLX_9640" → "SLX 9640"
                model = m.group(1).strip().replace("_", " ")

            # OS version: "SLX-OS Software Version: SLX-OS 20.2.3"
            # or: "SLX-OS Operating System Version: 20.2.3"
            # (?:\w+\s+)+ matches one or more label words ("Software", "Operating System", …)
            # (?:\S+\s+)? skips an optional non-version prefix token (e.g. "SLX-OS")
            m = re.search(
                r"SLX-OS\s+(?:\w+\s+)+Version\s*:\s*(?:\S+\s+)?(\d+\.\d+[^_\s]*)",
                ver_output,
                re.IGNORECASE,
            )
            if not m:
                # Fallback: "SW-Version: SLX-OS_v20.2.3_SLX_9640" → extract version token
                m = re.search(r"SW-Version\s*:\s*\S+?v?(\d+\.\d+[^_\s]*)", ver_output, re.IGNORECASE)
            if m:
                os_version = m.group(1)

            # Serial number: "SN: FTX2244H01B3"
            m = re.search(r"\bSN\s*:\s+(\S+)", ver_output, re.IGNORECASE)
            if m:
                serial_number = m.group(1)

            # Uptime: "System uptime: 0 days, 2 hours, 17 minutes, 30 seconds"
            m = re.search(r"System\s+uptime\s*:\s*(.+)", ver_output, re.IGNORECASE)
            if m:
                uptime = _parse_uptime(m.group(1))

        # Interface list from "show interface brief" — all interfaces, not just IP ones.
        brief_output = self.device.send_command("show interface brief")
        interface_list = [m.group(1).strip() for m in _INTF_BRIEF_RE.finditer(brief_output)]

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
        """Return interface details keyed by interface name."""
        output = self.device.send_command("show interface brief")
        if not output:
            return {}

        interfaces = {}
        for m in _INTF_BRIEF_RE.finditer(output):
            name = m.group(1).strip()
            state = m.group(2).lower()
            is_up = state == "up"
            # "Disabled" state means admin-down; "up"/"down" are admin-enabled.
            is_enabled = state != "disabled"
            interfaces[name] = {
                "is_up": is_up,
                "is_enabled": is_enabled,
                "description": "",
                "last_flapped": -1.0,
                "mtu": -1,
                "speed": _speed_mbps(m.group(3)),
                "mac_address": "",
            }
        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface, keyed by interface name."""
        output = self.device.send_command("show ip interface brief")
        if not output:
            return {}

        lines = output.splitlines()

        # The extreme_slxos ntc-template raises TextFSMError on Management rows,
        # which would drop all other interface IP data.  Strip them before parsing,
        # then collect their IPs with _MGMT_IP_RE so addresses are not silently lost.
        filtered = "\n".join(line for line in lines if not _MGMT_LINE_RE.match(line))

        try:
            parsed = parse_output(
                platform="extreme_slxos",
                command="show ip interface brief",
                data=filtered,
            )
        except (TextFSMError, ParsingException):
            logger.warning(
                "slxos: ntc-template failed for 'show ip interface brief'; "
                "falling back to regex for all interface types",
                exc_info=True,
            )
            parsed = None  # signals full regex fallback below

        interfaces_ip: dict = {}

        if parsed is None:
            # TextFSM failed: fall back to regex so no interface type is dropped.
            for line in lines:
                m = _INTF_IP_FALLBACK_RE.match(line)
                if m:
                    _record_ip(interfaces_ip, m.group(1).strip(), m.group(2).strip())
        else:
            for row in parsed:
                _record_ip(interfaces_ip, row.get("interface", "").strip(), row.get("ip_address", "").strip())

            # Collect Management interface IPs parsed separately (ntc-template
            # strips them to avoid TextFSMError on those rows).
            for line in lines:
                m = _MGMT_IP_RE.match(line)
                if m:
                    _record_ip(interfaces_ip, m.group(1).strip(), m.group(2).strip())

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
        """Return VLAN information keyed by VLAN ID string."""
        output = self.device.send_command("show vlan brief")
        if not output:
            return {}

        vlans: dict = {}
        current_id: str | None = None
        for line in output.splitlines():
            m = _VLAN_ROW_RE.match(line)
            if m:
                current_id = m.group(1)
                name = m.group(2).strip()
                port_str = m.group(3) or ""
                ports = [_expand_vlan_port(tok) for tok in _VLAN_PORT_RE.findall(port_str)]
                vlans[current_id] = {"name": name, "interfaces": ports}
            elif current_id and _VLAN_PORT_RE.search(line):
                # Continuation line: port list wrapped onto the next line(s).
                vlans[current_id]["interfaces"].extend(
                    _expand_vlan_port(tok) for tok in _VLAN_PORT_RE.findall(line)
                )
        return vlans
