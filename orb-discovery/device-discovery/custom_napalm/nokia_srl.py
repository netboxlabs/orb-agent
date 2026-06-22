# Copyright 2026 NetBox Labs Inc
# Based on napalm-srlinux (Apache-2.0): https://github.com/napalm-automation-community/napalm-srlinux
"""
Custom Nokia SR Linux NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko (nokia_srl) for SSH transport and regex for CLI parsing.
No ntc-templates exist for nokia_srl; all parsing is done with compiled
regular expressions against SR Linux show command output.

SR Linux commands used:
  show version              — hostname, software version, chassis type
  show system information   — uptime, serial number
  show interface all        — interface status, speed, IP addresses
  info from state interface * ethernet hw-mac-address
                            — per-interface hardware MAC (single shot,
                              wildcard expands across every physical
                              interface; YANG path is
                              /interface[name=*]/ethernet/hw-mac-address)
  admin display-config      — running configuration (YANG flat format)
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.helpers import mac as normalize_mac
from napalm.base.netmiko_helpers import netmiko_args

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config sanitization — Nokia SR Linux sensitive fields
# ---------------------------------------------------------------------------

# SR Linux stores passwords and SNMP community strings as hashed values:
#   password $6$<hash>
#   community $aes1$<salt>$<hash>
# Both are identified by the leading "$" in the value.
_PASSWORD_RE = re.compile(r"(\bpassword)\s+\$\S+", re.IGNORECASE)
_COMMUNITY_RE = re.compile(r"(\bcommunity)\s+\$\S+", re.IGNORECASE)


def _sanitize_config(text: str) -> str:
    text = _PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _COMMUNITY_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Uptime parsing — "N days H hours M minutes S seconds"
# ---------------------------------------------------------------------------

def _parse_uptime(uptime_str: str) -> float:
    """Convert SR Linux uptime string to total seconds."""
    seconds = 0.0
    for pattern, factor in (
        (r"(\d+)\s+day", 86400),
        (r"(\d+)\s+hour", 3600),
        (r"(\d+)\s+minute", 60),
        (r"(\d+)\s+second", 1),
    ):
        m = re.search(pattern, uptime_str)
        if m:
            seconds += int(m.group(1)) * factor
    return seconds


# ---------------------------------------------------------------------------
# Speed parsing — "25G", "1G", "100M", "400G", "10G", …  → float Mbps
# ---------------------------------------------------------------------------

_SPEED_RE = re.compile(r"(\d+(?:\.\d+)?)\s*([GMTgmt])", re.IGNORECASE)
_SPEED_MULT = {"g": 1_000.0, "m": 1.0, "t": 1_000_000.0}


def _parse_speed(speed_str: str) -> float:
    """Return interface speed in Mbps, or -1.0 if unparseable."""
    m = _SPEED_RE.match(speed_str.strip())
    if not m:
        return -1.0
    value, unit = float(m.group(1)), m.group(2).lower()
    return value * _SPEED_MULT.get(unit, 1.0)


# ---------------------------------------------------------------------------
# Hardware MAC parser — ``info from state interface * ethernet hw-mac-address``
# ---------------------------------------------------------------------------

# SR Linux emits one block per interface, e.g.::
#
#     interface ethernet-1/1 {
#         ethernet {
#             hw-mac-address 1A:CD:EE:FF:00:01
#         }
#     }
#
# Capture the (name, mac) pair across the braces — interfaces without an
# ethernet/hw-mac-address leaf (e.g. loopbacks, system) won't match and are
# silently skipped.
#
# The MAC capture group accepts colon-, dot-, or dash-separated forms and a
# wider length range (12-17 chars) so `napalm.base.helpers.mac()` — not the
# regex — does the format validation. This catches non-padded variants like
# `aa:bb:cc:dd:ee:1` that napalm normalises to `AA:BB:CC:DD:EE:01`.
#
# NOTE: the ``[^}]*?`` spans are NOT brace-aware — they stop at the first
# closing brace. The targeted query `info from state interface *
# ethernet hw-mac-address` keeps the ethernet sub-block flat (just the
# requested leaf), so this is safe today. If future SR Linux versions emit
# extra nested blocks inside ``ethernet { ... }`` before hw-mac-address
# (e.g. flow-control { }), the regex would silently miss those interfaces
# and the MAC field would fall back to empty string. Mitigation if that
# happens: request JSON output via ``| as json`` and switch to a structured
# parser.
_HW_MAC_BLOCK_RE = re.compile(
    r"interface\s+(\S+)\s*\{[^}]*?ethernet\s*\{[^}]*?hw-mac-address\s+([0-9A-Fa-f:.\-]{12,17})",
    re.DOTALL,
)


def _parse_hw_mac_addresses(text: str) -> dict[str, str]:
    """Return ``{interface_name: normalized_mac}`` parsed from the YANG state output."""
    result: dict[str, str] = {}
    if not text:
        return result
    for m in _HW_MAC_BLOCK_RE.finditer(text):
        name, raw = m.group(1), m.group(2)
        try:
            result[name] = normalize_mac(raw)
        except Exception:
            # napalm normalize_mac rejected the value — log and skip rather
            # than emit a malformed MAC string that downstream NetBox matching
            # would silently treat as a distinct interface.
            logger.warning(
                "nokia_srl: normalize_mac rejected %r for interface %s — emitting empty MAC",
                raw, name,
            )
    return result


# ---------------------------------------------------------------------------
# Interface output parser — shared by get_interfaces and get_interfaces_ip
# ---------------------------------------------------------------------------

# Physical interface line: "ethernet-1/1 is up, speed 25G, type None"
#                          "ethernet-1/2 is down, reason port-admin-disabled"
# Use character classes to stop capture before the next comma.
_PHYS_INTF_RE = re.compile(
    r"^(\S+) is (up|down)(?:,\s*reason\s+([\w-]+))?(?:,\s*speed\s+([\w.]+))?",
    re.IGNORECASE,
)

# Subinterface line: "  ethernet-1/1.0 is up"
#                    "  ethernet-1/1.0 is down, reason subinterface-admin-disabled"
_SUB_INTF_RE = re.compile(
    r"^\s{2}(\S+\.\d+) is (up|down)(?:,\s*reason\s+([\w-]+))?",
    re.IGNORECASE,
)

# IP address lines under a subinterface
_IPV4_ADDR_RE = re.compile(
    r"IPv4 addr\s+:\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)", re.IGNORECASE
)
_IPV6_ADDR_RE = re.compile(r"IPv6 addr\s+:\s+([^\s\/]+)\/(\d+)", re.IGNORECASE)

# Separator lines between interfaces (dashes or equals)
_SEPARATOR_RE = re.compile(r"^[-=]{10,}")

# SR Linux CLI context/prompt line at end of output: "--{ running }--[  ]--"
_SRL_PROMPT_RE = re.compile(r"^--\{[^}]*\}--.*$", re.MULTILINE)

# MTU line: "    MTU      : 1500"
_MTU_RE = re.compile(r"MTU\s*:\s*(\d+)", re.IGNORECASE)

# Description line: "    Description  : some text"
_DESC_RE = re.compile(r"Description\s*:\s*(.*)", re.IGNORECASE)


def _strip_prompt(text: str) -> str:
    """Remove SR Linux CLI context/prompt lines (``--{ running }--[  ]--``) from output."""
    return _SRL_PROMPT_RE.sub("", text).rstrip()


# SR Linux network-instance types → NAPALM OC network-instance types.
# Unknown types pass through raw so the consumer can decide.
_SRL_NI_TYPE_MAP = {
    "ip-vrf": "L3VRF",
    "default": "DEFAULT_INSTANCE",
    "mac-vrf": "L2VSI",
}

# Block headers in `info from state network-instance ...` output. Names may
# be quoted when they contain spaces; the value group strips the quotes.
_SRL_NI_HEADER_RE = re.compile(r'^\s*network-instance\s+"?([^"{\s][^"{]*?)"?\s*\{\s*$')
# Optional module prefix (srl_nokia-network-instance:ip-vrf) tolerated and
# stripped — only the short identity name is captured.
_SRL_NI_TYPE_RE = re.compile(r'^\s*type\s+"?(?:[\w.-]+:)?([\w-]+)"?\s*$')
_SRL_NI_IFACE_RE = re.compile(r'^\s*interface\s+"?([^"{\s][^"{]*?)"?\s*\{\s*$')
_SRL_NI_RD_RE = re.compile(r'^\s*rd\s+"?(\S+?)"?\s*$')


def _parse_ni_blocks(text: str, line_re: re.Pattern) -> dict[str, list[str]]:
    """
    Collect per-network-instance matches from `info from state` block output.

    The output nests everything under ``network-instance <name> {`` block
    headers; this walks line-by-line, tracks the current instance, and
    records each ``line_re`` group(1) hit against it.
    """
    out: dict[str, list[str]] = {}
    current: str | None = None
    for line in (text or "").splitlines():
        m = _SRL_NI_HEADER_RE.match(line)
        if m:
            current = m.group(1).strip()
            out.setdefault(current, [])
            continue
        if current is None:
            continue
        m = line_re.match(line)
        if m:
            out[current].append(m.group(1).strip())
    return out


def _make_intf_entry(m) -> dict:
    reason = m.group(3)
    return {
        "name": m.group(1),
        "is_up": m.group(2).lower() == "up",
        "is_enabled": reason != "port-admin-disabled" if reason else True,
        "speed": _parse_speed(m.group(4)) if m.group(4) else -1.0,
        "mtu": -1,
        "description": "",
        "subs": [],
    }


def _make_sub_entry(name: str, is_up: bool, is_enabled: bool = True) -> dict:
    return {
        "name": name,
        "is_up": is_up,
        "is_enabled": is_enabled,
        "mtu": -1,
        "description": "",
        "ipv4": [],
        "ipv6": [],
    }


def _sub_is_enabled_from_reason(reason: str | None) -> bool:
    # Any reason whose name contains "disabled" indicates admin action; pure
    # operational-down reasons (lower-layer-down, no-light, …) never use the
    # word, so this heuristic covers port-admin-disabled,
    # subinterface-admin-disabled, interface-disabled, etc. without
    # enumerating every SR Linux release's spelling.
    if reason and "disabled" in reason.lower():
        return False
    return True


def _collect_ip_addresses(line: str, sub: dict) -> None:
    """
    Append any IPv4/IPv6 address found in *line* to *sub*'s lists.

    SR Linux configures L3 addressing under sub-interfaces, so IPs are
    always attached to the current sub-interface (never the parent).
    IPv6 link-local (``fe80::``) is included for parity with the
    community ``srl`` driver and the device data model.
    """
    m_ipv4 = _IPV4_ADDR_RE.search(line)
    if m_ipv4:
        sub["ipv4"].append((m_ipv4.group(1), int(m_ipv4.group(2))))
        return
    m_ipv6 = _IPV6_ADDR_RE.search(line)
    if m_ipv6:
        sub["ipv6"].append((m_ipv6.group(1), int(m_ipv6.group(2))))


def _parse_interface_output(output: str) -> list[dict]:
    """
    Parse ``show interface all`` output into a list of physical-interface dicts.

    Each dict has: name, is_up, is_enabled, speed, mtu, description, and a
    ``subs`` list. Each sub has: name, is_up, mtu, description, ipv4, ipv6.

    Indented ``MTU`` / ``Description`` lines populate the currently open
    sub-interface when one is open; otherwise they populate the parent.
    IP-address lines are only collected when a sub is open — SR Linux does
    not configure IPs on the physical parent.
    """
    interfaces: list[dict] = []
    current: dict | None = None
    current_sub: dict | None = None

    for line in output.splitlines():
        if _SEPARATOR_RE.match(line):
            current_sub = None
            continue
        if line.strip().startswith("Summary") or line.startswith("--{"):
            current = None
            current_sub = None
            continue

        m_phys = _PHYS_INTF_RE.match(line)
        if m_phys and not line.startswith(" "):
            current = _make_intf_entry(m_phys)
            current_sub = None
            interfaces.append(current)
            continue

        if current is None:
            continue

        m_sub = _SUB_INTF_RE.match(line)
        if m_sub:
            current_sub = _make_sub_entry(
                m_sub.group(1),
                m_sub.group(2).lower() == "up",
                is_enabled=_sub_is_enabled_from_reason(m_sub.group(3)),
            )
            current["subs"].append(current_sub)
            continue

        target = current_sub if current_sub is not None else current

        m_mtu = _MTU_RE.search(line)
        if m_mtu:
            target["mtu"] = int(m_mtu.group(1))
            continue

        m_desc = _DESC_RE.search(line)
        if m_desc:
            target["description"] = m_desc.group(1).strip()
            continue

        if current_sub is not None:
            _collect_ip_addresses(line, current_sub)

    return interfaces


class SRLDriver(_napalm_base.NetworkDriver):
    """
    Nokia SR Linux NAPALM driver (read-only subset for device-discovery).

    Uses Netmiko (nokia_srl) over SSH and regex-based CLI parsing.
    """

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
            "nokia_srl", netmiko_optional_args=self.netmiko_optional_args
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

    # -----------------------------------------------------------------------
    # NAPALM getters
    # -----------------------------------------------------------------------

    def get_facts(self) -> dict:
        """Return general device facts."""
        hostname = "Unknown"
        os_version = "Unknown"
        model = "Unknown"
        serial_number = "Unknown"
        uptime = 0.0

        # --- show version: hostname, software version, chassis type ---
        ver_out = self.device.send_command("show version")
        if ver_out:
            m = re.search(r"Hostname\s*:\s*(\S+)", ver_out)
            if m:
                hostname = m.group(1).strip()
            m = re.search(r"Software Version\s*:\s*(\S+)", ver_out)
            if m:
                os_version = m.group(1).strip()
            m = re.search(r"Chassis Type\s*:\s*(.+)", ver_out)
            if m:
                model = m.group(1).strip()

        # --- show system information: uptime, serial number ---
        sys_out = self.device.send_command("show system information")
        if sys_out:
            m = re.search(
                r"Uptime\s*:\s*(.+)", sys_out, re.IGNORECASE
            )
            if m:
                uptime = _parse_uptime(m.group(1))
            m = re.search(r"Chassis serial number\s*:\s*(\S+)", sys_out, re.IGNORECASE)
            if m:
                serial_number = m.group(1).strip()

        # Fallback: parse serial from show version if still unknown
        if serial_number == "Unknown" and ver_out:
            m = re.search(r"Serial Number\s*:\s*(.+)", ver_out, re.IGNORECASE)
            if m:
                serial_number = m.group(1).strip()

        # --- show interface all: interface list ---
        intf_out = self.device.send_command("show interface all")
        parsed = _parse_interface_output(intf_out) if intf_out else []
        interface_list = [
            name
            for entry in parsed
            for name in (entry["name"], *(sub["name"] for sub in entry["subs"]))
        ]

        return {
            "hostname": hostname,
            "vendor": "Nokia",
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

        Emits one entry per physical interface plus one entry per
        sub-interface (e.g. ``mgmt0`` and ``mgmt0.0``). The translator
        maps sub-interface names to NetBox ``virtual`` interfaces with
        parent linkage automatically.

        Physical interface MACs are sourced from
        ``info from state interface * ethernet hw-mac-address`` (one
        wildcard call covers every port). Sub-interfaces inherit no
        L2 identity in SR Linux and remain MAC-less.
        """
        intf_out = self.device.send_command("show interface all")
        if not intf_out:
            return {}

        mac_by_intf = _parse_hw_mac_addresses(
            self.device.send_command(
                "info from state interface * ethernet hw-mac-address"
            )
        )

        parsed = _parse_interface_output(intf_out)
        interfaces: dict = {}
        for entry in parsed:
            interfaces[entry["name"]] = {
                "is_up": entry["is_up"],
                "is_enabled": entry["is_enabled"],
                "description": entry["description"],
                "last_flapped": -1.0,
                "mtu": entry["mtu"],
                "speed": entry["speed"],
                "mac_address": mac_by_intf.get(entry["name"], ""),
            }
            for sub in entry["subs"]:
                interfaces[sub["name"]] = {
                    "is_up": sub["is_up"],
                    "is_enabled": sub["is_enabled"],
                    "description": sub["description"],
                    "last_flapped": -1.0,
                    "mtu": sub["mtu"],
                    "speed": -1.0,
                    "mac_address": "",
                }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """
        Return IP addresses keyed by *sub-interface* name.

        SR Linux configures L3 addressing under sub-interfaces, so the
        physical parent never carries IPs. Sub-interfaces without IPs are
        omitted from the result.
        """
        intf_out = self.device.send_command("show interface all")
        if not intf_out:
            return {}

        parsed = _parse_interface_output(intf_out)
        interfaces_ip: dict = {}
        for entry in parsed:
            for sub in entry["subs"]:
                if not sub["ipv4"] and not sub["ipv6"]:
                    continue
                sub_ip: dict = {}
                if sub["ipv4"]:
                    sub_ip["ipv4"] = {
                        addr: {"prefix_length": prefix} for addr, prefix in sub["ipv4"]
                    }
                if sub["ipv6"]:
                    sub_ip["ipv6"] = {
                        addr: {"prefix_length": prefix} for addr, prefix in sub["ipv6"]
                    }
                interfaces_ip[sub["name"]] = sub_ip

        return interfaces_ip

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """Return device configuration (YANG flat format)."""
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}

        if retrieve in ("all", "running"):
            config["running"] = _strip_prompt(self.device.send_command("admin display-config"))

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """SR Linux uses network instances, not traditional VLANs."""
        return {}

    def get_network_instances(self, name: str = "") -> dict:
        """
        Return network instances keyed by name, NAPALM OC shape.

        Network instances are SR Linux's native routing model. Three
        targeted ``info from state`` calls keep the payloads small:
        instance types, interface membership, and the BGP-VPN route
        distinguisher (only present on instances participating in an
        EVPN / IP-VPN backbone). Type mapping: ``ip-vrf`` → L3VRF,
        ``default`` → DEFAULT_INSTANCE, ``mac-vrf`` → L2VSI; unknown
        types pass through raw.
        """
        type_out = self.device.send_command(
            "info from state network-instance * type"
        )
        if not type_out or not type_out.strip():
            return {}
        types = _parse_ni_blocks(type_out, _SRL_NI_TYPE_RE)
        iface_out = self.device.send_command(
            "info from state network-instance * interface * name"
        )
        ifaces = _parse_ni_blocks(iface_out, _SRL_NI_IFACE_RE)
        rd_out = self.device.send_command(
            "info from state network-instance * protocols bgp-vpn "
            "bgp-instance * route-distinguisher rd"
        )
        rds = _parse_ni_blocks(rd_out, _SRL_NI_RD_RE)

        instances: dict = {}
        for ni_name, type_hits in types.items():
            raw_type = type_hits[0] if type_hits else ""
            ni_type = _SRL_NI_TYPE_MAP.get(raw_type, raw_type)
            rd_hits = rds.get(ni_name) or []
            # Default-instance membership is left empty like the other
            # batch drivers: the discovery pipeline only consumes VRF
            # memberships, and every interface not claimed by a VRF is
            # in the default table by definition.
            if ni_type == "DEFAULT_INSTANCE":
                members: dict = {}
            else:
                members = {ifname: {} for ifname in ifaces.get(ni_name) or []}
            instances[ni_name] = {
                "name": ni_name,
                "type": ni_type,
                "state": {"route_distinguisher": rd_hits[0] if rd_hits else ""},
                "interfaces": {"interface": members},
            }
        if name:
            return {name: instances[name]} if name in instances else {}
        return instances
