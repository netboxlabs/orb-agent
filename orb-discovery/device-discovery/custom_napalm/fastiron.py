# Copyright 2026 NetBox Labs Inc
"""
Custom FastIron (IronWare) NAPALM driver.

Covers hardware sold under both the Brocade and Ruckus ICX brand names.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko (brocade_fastiron device type) for SSH connectivity and ntc-templates
for structured parsing wherever templates exist; falls back to regex for commands
that have no template or where the available template is insufficient
(IP interface, hostname extraction, VLAN parsing).
"""

import ipaddress
import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.helpers import mac as normalize_mac
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config sanitization — Brocade FastIron sensitive fields
# ---------------------------------------------------------------------------

# "enable super-user-password [<N>] <hash>", "enable password [<N>] <hash>",
# "enable port-config-password [<N>] <hash>", "enable read-only-password [<N>] <hash>"
_ENABLE_PWD_RE = re.compile(
    r"(enable\s+(?:super-user-|port-config-|read-only-)?password)(?:\s+\d+)?\s+\S+",
    re.IGNORECASE,
)

# "username <name> [privilege <N>] password [<N>] <hash>"
_USERNAME_PWD_RE = re.compile(
    r"(username\s+\S+(?:\s+privilege\s+\d+)?\s+password)(?:\s+\d+)?\s+\S+",
    re.IGNORECASE,
)

# "snmp-server community [0|1] <string> ..."
# The optional leading digit is an encryption-level marker (0=clear, 1=encrypted);
# redact it together with the community string so neither leaks.
_SNMP_COMMUNITY_RE = re.compile(
    r"(snmp-server\s+community)\s+(?:\d+\s+)?\S+",
    re.IGNORECASE,
)


def _sanitize_config(text: str) -> str:
    text = _ENABLE_PWD_RE.sub(r"\1 <redacted>", text)
    text = _USERNAME_PWD_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_COMMUNITY_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Uptime parsing
# ---------------------------------------------------------------------------

_DAY_SECONDS = 24 * 3600
_HOUR_SECONDS = 3600
_MINUTE_SECONDS = 60


def _parse_uptime(days: str, hours: str, minutes: str, seconds: str = "0") -> float:
    """Convert FastIron uptime components (lists from ntc-template) to seconds."""
    try:
        d = int(days) if days else 0
    except (ValueError, TypeError):
        d = 0
    try:
        h = int(hours) if hours else 0
    except (ValueError, TypeError):
        h = 0
    try:
        m = int(minutes) if minutes else 0
    except (ValueError, TypeError):
        m = 0
    try:
        s = int(seconds) if seconds else 0
    except (ValueError, TypeError):
        s = 0
    return float(d * _DAY_SECONDS + h * _HOUR_SECONDS + m * _MINUTE_SECONDS + s)


# ---------------------------------------------------------------------------
# Speed conversion
# ---------------------------------------------------------------------------

_SPEED_MAP: dict[str, float] = {
    "10M": 10.0,
    "100M": 100.0,
    "1G": 1000.0,
    "2.5G": 2500.0,
    "5G": 5000.0,
    "10G": 10000.0,
    "25G": 25000.0,
    "40G": 40000.0,
    "100G": 100000.0,
    "400G": 400000.0,
}


def _parse_speed(speed_str: str) -> float:
    """Convert a FastIron speed string (e.g. '1G', '10G', 'Auto') to Mbps."""
    if not speed_str:
        return -1.0
    return _SPEED_MAP.get(speed_str.upper(), -1.0)


# ---------------------------------------------------------------------------
# Port list helpers
# ---------------------------------------------------------------------------

# Tokens that introduce a physical port ID (the next token is the bare port).
_ETHE_TOKENS = frozenset({"ethe", "ethernet"})

# Tokens that form a named interface together with the following numeric ID.
# e.g. "lag 10" → "lag10", "ve 555" → "ve555"
_PREFIX_TOKENS = frozenset({"lag", "ve"})

# Matches physical port IDs including breakout (colon) notation: 1/1/1, 1/2/4:1
_PORT_ID_RE = re.compile(r"^\d+(?:[/:]\d+)*$")


def _expand_port_range(start: str, end: str) -> list[str]:
    """
    Expand a FastIron port range into individual port IDs.

    Only expands same-prefix ranges where just the last component varies
    (e.g. "1/1/1 to 1/1/4" → ["1/1/1", "1/1/2", "1/1/3", "1/1/4"]).
    Cross-module or cross-unit ranges fall back to returning only the
    two endpoints.
    """
    s_parts = start.split("/")
    e_parts = end.split("/")
    if len(s_parts) != len(e_parts) or s_parts[:-1] != e_parts[:-1]:
        return [start, end]
    try:
        s_num, e_num = int(s_parts[-1]), int(e_parts[-1])
    except ValueError:
        return [start, end]
    prefix = "/".join(s_parts[:-1]) + "/"
    return [f"{prefix}{p}" for p in range(s_num, e_num + 1)]


def _split_port_list(port_str: str) -> list[str]:
    """
    Split a FastIron port list string into individual port IDs.

    Handles:
    - Space-separated port IDs:  "1/1/1 1/1/2"
    - Type-prefixed ports:       "ethe 1/1/1 ethe 1/1/2"
    - Range notation:            "ethe 1/1/1 to 1/1/4"

    Ranges with the same unit/module prefix are fully expanded.
    Cross-module or cross-unit ranges yield only the two endpoints.
    """
    tokens = port_str.split()
    ports: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i].lower()
        if tok in _ETHE_TOKENS:
            i += 1
            continue
        if tok in _PREFIX_TOKENS:
            # Combine with next token: "lag 10" → "lag10", "ve 555" → "ve555"
            if i + 1 < len(tokens):
                ports.append(f"{tok}{tokens[i + 1]}")
                i += 2
            else:
                i += 1
            continue
        if tok == "to":
            # Range: previous port is the start; next token is the end.
            if ports and i + 1 < len(tokens):
                start = ports.pop()
                end_tok = tokens[i + 1]
                # Prefixed range: "lag 15 to 16" → start="lag15", end_tok="16"
                # Re-apply the prefix to every member of the expanded range.
                m_prefix = re.match(r"^([a-zA-Z]+)(\d+)$", start)
                if m_prefix and re.match(r"^\d+$", end_tok):
                    pfx = m_prefix.group(1)
                    s_num, e_num = int(m_prefix.group(2)), int(end_tok)
                    ports.extend(f"{pfx}{n}" for n in range(s_num, e_num + 1))
                    i += 2
                    continue
                if _PORT_ID_RE.match(end_tok):
                    ports.extend(_expand_port_range(start, end_tok))
                    i += 2
                    continue
                ports.append(start)  # restore if no valid range
            i += 1
            continue
        if _PORT_ID_RE.match(tokens[i]):
            ports.append(tokens[i])
        i += 1
    return ports


# ---------------------------------------------------------------------------
# VLAN config regex
# ---------------------------------------------------------------------------

# VLAN header: name and "by port"/"by protocol" qualifier are both optional.
# Covers: "vlan 10", "vlan 10 by port", "vlan 10 name MGMT by port"
_VLAN_HDR_RE = re.compile(
    r"^vlan\s+(?P<id>\d+)(?:\s+name\s+(?P<name>.+?))?(?:\s+by\s+\w+)?$"
)
_TAGGED_RE = re.compile(r"^\s+tagged\s+(?P<ports>.+)", re.IGNORECASE)
_UNTAGGED_RE = re.compile(r"^\s+untagged\s+(?P<ports>.+)", re.IGNORECASE)
# "router-interface ve <id>" — 08.x syntax attaching a VE as the L3 interface of a VLAN.
_ROUTER_INTF_RE = re.compile(r"^\s+router-interface\s+ve\s+(?P<ve>\d+)", re.IGNORECASE)


def _add_member_ports(line: str, interfaces: list) -> None:
    for pattern in (_TAGGED_RE, _UNTAGGED_RE):
        m = pattern.match(line)
        if m:
            for port in _split_port_list(m.group("ports")):
                if port not in interfaces:
                    interfaces.append(port)
            break


# ---------------------------------------------------------------------------
# IP interface regex
# ---------------------------------------------------------------------------

# Matches "Interface <name>" — stops before the " is <state>" status suffix
# that some IronWare versions append (e.g. "Interface Ethernet 1/1/1 is up").
_INTF_HDR_RE = re.compile(
    r"^Interface\s+(?P<name>.+?)(?:\s+is\s+|\s*$)",
    re.IGNORECASE,
)

# IPv4 CIDR:  "  ip address: 192.168.1.1/24"
_IP_ADDR_CIDR_RE = re.compile(
    r"^\s+ip\s+address[:\s]+(?P<ip>\d+\.\d+\.\d+\.\d+)/(?P<prefix>\d+)",
    re.MULTILINE,
)

# IPv4 mask:  "  ip address: 192.168.1.1 255.255.255.0"
# Handles both "ip address: 1.2.3.4 255.255.255.0" and
# "ip address: 1.2.3.4 subnet mask: 255.255.255.0" (documented IronWare format).
_IP_ADDR_MASK_RE = re.compile(
    r"^\s+ip\s+address[:\s]+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?:subnet\s+mask[:\s]+)?(?P<mask>[\d.]+)",
    re.MULTILINE,
)

# IPv6 format A (config-style): "  ipv6 address 2001:db8::1/64"
_IPV6_ADDR_RE = re.compile(
    r"^\s+ipv6\s+address\s+(?P<ip>[0-9a-fA-F:]+)/(?P<prefix>\d+)",
    re.MULTILINE,
)

# IPv6 format B (detail block): "  2001:db8::1/64 [Preferred]"
# Appears under "Global unicast address(es):" in standard IronWare output.
_IPV6_GLOBAL_RE = re.compile(
    r"^\s+(?P<ip>[0-9a-fA-F:]+)/(?P<prefix>\d+)\s+\[(?:Preferred|Deprecated)\]",
    re.MULTILINE | re.IGNORECASE,
)

# IPv6 format C (subnet line): "  2001:db8::1 [Preferred], subnet is 2001:db8::/64"
# Some IronWare versions omit the /prefix from the address and put it in a trailing
# "subnet is <network>/<prefix>" clause on the same line.
_IPV6_SUBNET_RE = re.compile(
    r"^\s+(?P<ip>[0-9a-fA-F:]+)\s+\[(?:Preferred|Deprecated)\]"
    r".*?subnet\s+is\s+[0-9a-fA-F:]+/(?P<prefix>\d+)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Interface name normalisation
# ---------------------------------------------------------------------------

# Physical ethernet prefixes — strip and keep the bare port ID (e.g. "1/1/1").
_INTF_ETH_PREFIX_RE = re.compile(
    r"^(?:GigabitEthernet|TenGigabitEthernet|FortyGigabitEthernet|"
    r"HundredGigabitEthernet|FastEthernet|Ethernet)\s*",
    re.IGNORECASE,
)


def _normalize_intf_name(name: str) -> str:
    """
    Normalise an interface name to match 'show interfaces brief' keys.

    FastIron 'show ip interface' headers may use long type prefixes
    ('Ethernet 1/1/1', 'GigabitEthernet1/1/1') while 'show interfaces brief'
    uses the bare port ID ('1/1/1').  For virtual interfaces the type and ID
    are joined without a space ('Ve 1' → 've1', 'management 1' → 'management1').
    """
    stripped = _INTF_ETH_PREFIX_RE.sub("", name).strip()
    if " " in stripped:
        parts = stripped.split()
        stripped = parts[0].lower() + "".join(parts[1:])
    return stripped


class FastIronDriver(_napalm_base.NetworkDriver):
    """FastIron IronWare NAPALM driver (read-only subset for device-discovery)."""

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
            "brocade_fastiron", netmiko_optional_args=self.netmiko_optional_args
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

    def _facts_from_version(self) -> tuple[str, str, str, float]:
        """Return (os_version, model, serial_number, uptime) from 'show version'."""
        os_version = model = serial_number = "Unknown"
        uptime = 0.0
        raw = self.device.send_command("show version")
        try:
            parsed = parse_output(platform="brocade_fastiron", command="show version", data=raw)
            if parsed:
                row = parsed[0]
                sw_versions = [v for v in row.get("sw_version", []) if v]
                if sw_versions:
                    os_version = sw_versions[0]
                models_list = [m for m in row.get("model", []) if m]
                if models_list:
                    model = models_list[0]
                serials = [s for s in row.get("serial", []) if s]
                if serials:
                    serial_number = serials[0]
                days_list = row.get("uptime_days", [])
                hours_list = row.get("uptime_hours", [])
                minutes_list = row.get("uptime_minutes", [])
                seconds_list = row.get("uptime_seconds", [])
                uptime = _parse_uptime(
                    days_list[0] if days_list else "0",
                    hours_list[0] if hours_list else "0",
                    minutes_list[0] if minutes_list else "0",
                    seconds_list[0] if seconds_list else "0",
                )
        except Exception:
            logger.debug("Failed to parse 'show version' output", exc_info=True)
        return os_version, model, serial_number, uptime

    def _hostname_from_config(self) -> str:
        """Return the hostname from 'show running-config', fallback to self.hostname."""
        cfg_raw = self.device.send_command("show running-config")
        for line in cfg_raw.splitlines():
            stripped = line.strip()
            if stripped.startswith("hostname "):
                return stripped.split("hostname ", 1)[1].strip()
        return self.hostname

    def _interface_list_from_brief(self) -> list[str]:
        """Return interface names from 'show interfaces brief' (ntc-template)."""
        interface_list: list[str] = []
        try:
            raw = self.device.send_command("show interfaces brief")
            parsed = parse_output(
                platform="brocade_fastiron", command="show interfaces brief", data=raw
            )
            for row in parsed:
                intf = row.get("interface", "").strip()
                if intf:
                    interface_list.append(intf)
        except Exception:
            logger.debug("Failed to parse 'show interfaces brief' output", exc_info=True)
        return interface_list

    def get_facts(self) -> dict:
        """
        Return general device facts.

        Facts are assembled from three commands:
        - 'show version'          → os_version, model, serial, uptime (ntc-template)
        - 'show running-config'   → hostname (regex on 'hostname' line)
        - 'show interfaces brief' → interface_list (ntc-template)
        """
        os_version, model, serial_number, uptime = self._facts_from_version()
        return {
            "hostname": self._hostname_from_config(),
            "vendor": "Brocade",
            "model": model,
            "os_version": os_version,
            "serial_number": serial_number,
            "uptime": uptime,
            "fqdn": "Unknown",
            "interface_list": self._interface_list_from_brief(),
        }

    def get_interfaces(self) -> dict:
        """
        Return interface details keyed by interface name.

        Parses 'show interfaces brief' with the brocade_fastiron ntc-template.
        """
        interfaces: dict = {}
        raw = self.device.send_command("show interfaces brief")
        try:
            parsed = parse_output(
                platform="brocade_fastiron",
                command="show interfaces brief",
                data=raw,
            )
        except Exception:
            logger.debug("Failed to parse 'show interfaces brief' output", exc_info=True)
            return {}

        for row in parsed:
            intf = row.get("interface", "").strip()
            if not intf:
                continue

            linkstate = row.get("linkstate", "").lower()

            is_up = linkstate == "up"
            is_enabled = linkstate not in ("disable", "err-dis")

            mac_raw = row.get("mac", "")
            try:
                mac_address = normalize_mac(mac_raw) if mac_raw else ""
            except Exception:
                mac_address = mac_raw

            interfaces[intf] = {
                "is_up": is_up,
                "is_enabled": is_enabled,
                "description": row.get("name", "").strip(),
                "last_flapped": -1.0,
                "mtu": -1,
                "speed": _parse_speed(row.get("speed", "")),
                "mac_address": mac_address,
            }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """
        Return IP addresses per interface.

        Parses IPv4 from 'show ip interface' and IPv6 from
        'show ipv6 interface' using regex.
        """
        interfaces_ip: dict = {}

        raw = self.device.send_command("show ip interface")
        if raw:
            self._parse_ip_interface(raw, interfaces_ip)

        raw_v6 = self.device.send_command("show ipv6 interface")
        if raw_v6:
            self._parse_ipv6_interface(raw_v6, interfaces_ip)

        return interfaces_ip

    def _parse_ip_interface(self, raw: str, interfaces_ip: dict) -> None:
        """
        Populate interfaces_ip with IPv4 addresses from 'show ip interface'.

        Handles both CIDR ("ip address 1.2.3.4/24") and mask
        ("ip address 1.2.3.4 255.255.255.0") notations.
        Interface names are normalised to match 'show interfaces brief' keys.
        """
        current_intf: str | None = None
        for line in raw.splitlines():
            m_hdr = _INTF_HDR_RE.match(line)
            if m_hdr:
                current_intf = _normalize_intf_name(m_hdr.group("name"))
                continue
            if current_intf is None:
                continue
            m_cidr = _IP_ADDR_CIDR_RE.match(line)
            if m_cidr:
                try:
                    prefix = int(m_cidr.group("prefix"))
                except ValueError:
                    continue
                (
                    interfaces_ip
                    .setdefault(current_intf, {})
                    .setdefault("ipv4", {})[m_cidr.group("ip")]
                ) = {"prefix_length": prefix}
                continue
            m_mask = _IP_ADDR_MASK_RE.match(line)
            if m_mask:
                try:
                    prefix = ipaddress.IPv4Network(
                        f"0.0.0.0/{m_mask.group('mask')}", strict=False
                    ).prefixlen
                except ValueError:
                    continue
                (
                    interfaces_ip
                    .setdefault(current_intf, {})
                    .setdefault("ipv4", {})[m_mask.group("ip")]
                ) = {"prefix_length": prefix}

    def _parse_ipv6_interface(self, raw: str, interfaces_ip: dict) -> None:
        """
        Populate interfaces_ip with IPv6 addresses from 'show ipv6 interface'.

        Supports three IronWare output formats:
        - Format A (config-style):  "  ipv6 address 2001:db8::1/64"
        - Format B (detail block):  "  2001:db8::1/64 [Preferred]"
          (appears under "Global unicast address(es):" in standard IronWare output)
        - Format C (subnet clause): "  2001:db8::1 [Preferred], subnet is 2001:db8::/64"
          (some IronWare versions omit the /prefix from the address itself)
        """
        current_intf: str | None = None
        for line in raw.splitlines():
            m_hdr = _INTF_HDR_RE.match(line)
            if m_hdr:
                current_intf = _normalize_intf_name(m_hdr.group("name"))
                continue
            if current_intf is None:
                continue
            m_addr = (
                _IPV6_ADDR_RE.match(line)
                or _IPV6_GLOBAL_RE.match(line)
                or _IPV6_SUBNET_RE.match(line)
            )
            if m_addr:
                try:
                    prefix = int(m_addr.group("prefix"))
                except ValueError:
                    continue
                (
                    interfaces_ip
                    .setdefault(current_intf, {})
                    .setdefault("ipv6", {})[m_addr.group("ip")]
                ) = {"prefix_length": prefix}

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

        Parses 'show running-config vlan' with regex to handle all FastIron port
        types: physical (ethe), LAG (lag), routed VE (ve), and VE L3 bindings
        declared via 'router-interface ve <id>' (08.x syntax).  The ntc-template
        for this command only captures physical ports, so regex is used here.
        """
        raw = self.device.send_command("show running-config vlan")
        vlans: dict = {}
        current_id: str | None = None

        for line in raw.splitlines():
            m_hdr = _VLAN_HDR_RE.match(line)
            if m_hdr:
                current_id = m_hdr.group("id")
                name = (m_hdr.group("name") or current_id).strip()
                if len(name) >= 2 and name[0] == '"' and name[-1] == '"':
                    name = name[1:-1]
                vlans.setdefault(current_id, {"name": name, "interfaces": []})
                continue

            if current_id is None:
                continue

            _add_member_ports(line, vlans[current_id]["interfaces"])

            m_ri = _ROUTER_INTF_RE.match(line)
            if m_ri:
                ve = f"ve{m_ri.group('ve')}"
                entry = vlans[current_id]
                if ve not in entry["interfaces"]:
                    entry["interfaces"].append(ve)

        return vlans
