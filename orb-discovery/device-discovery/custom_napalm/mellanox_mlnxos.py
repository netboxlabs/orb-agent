# Copyright 2026 NetBox Labs Inc
"""
Custom Mellanox MLNX-OS NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko for SSH transport; ntc-templates 9.x has no templates for
``mellanox_mlnxos`` so output is parsed with regular expressions tuned to
documented MLNX-OS CLI output.
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.helpers import mac as normalize_mac
from napalm.base.netmiko_helpers import netmiko_args

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sanitization patterns
#
# MLNX-OS encrypts secrets in running-config with explicit "password 7 <hash>"
# / "secret 7 <hash>" markers, plus SNMP communities and AAA shared keys.
# ---------------------------------------------------------------------------
_USERNAME_PASSWORD_RE = re.compile(
    r"(username\s+\S+\s+password\s+\d+)\s+\S+", re.IGNORECASE
)
_ENABLE_SECRET_RE = re.compile(r"(enable\s+(?:secret|password)\s+\d+)\s+\S+", re.IGNORECASE)
_SNMP_COMMUNITY_RE = re.compile(
    r"(snmp-server\s+community)\s+\S+(\s+(?:ro|rw))?", re.IGNORECASE
)
_RADIUS_KEY_RE = re.compile(r"(radius-server\s+(?:host\s+\S+\s+)?key)\s+\S+", re.IGNORECASE)
_TACACS_KEY_RE = re.compile(r"(tacacs-server\s+(?:host\s+\S+\s+)?key)\s+\S+", re.IGNORECASE)
_KEY_STRING_RE = re.compile(r"(key-string)\s+\S+", re.IGNORECASE)


def _sanitize_config(text: str) -> str:
    """Redact common MLNX-OS credential fields from a config dump."""
    text = _USERNAME_PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _ENABLE_SECRET_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_COMMUNITY_RE.sub(r"\1 <redacted>\2", text)
    text = _RADIUS_KEY_RE.sub(r"\1 <redacted>", text)
    text = _TACACS_KEY_RE.sub(r"\1 <redacted>", text)
    text = _KEY_STRING_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_UPTIME_TOKENS = (
    (r"(\d+)\s*y", 365 * 24 * 3600),
    (r"(\d+)\s*w", 7 * 24 * 3600),
    (r"(\d+)\s*d", 24 * 3600),
    (r"(\d+)\s*h", 3600),
    (r"(\d+)\s*m(?!s)", 60),
    (r"(\d+(?:\.\d+)?)\s*s", 1),
)


def _parse_uptime(uptime_str: str) -> float:
    """Convert an MLNX-OS uptime string (e.g. ``5d 22h 5m 15.139s``) to seconds."""
    seconds = 0.0
    for pattern, factor in _UPTIME_TOKENS:
        m = re.search(pattern, uptime_str)
        if m:
            seconds += float(m.group(1)) * factor
    return seconds


_SPEED_PREFIX_MULT = {"": 1.0, "k": 1e-3, "m": 1.0, "g": 1e3, "t": 1e6}
_SPEED_TOKEN_RE = re.compile(
    r"(\d+(?:\.\d+)?)\s*([kmgt])?(?:b(?:p?s|/s)?)?(?:x\d+)?",
    re.IGNORECASE,
)


def _parse_speed_mbps(speed_str: str) -> float:
    """Convert speed strings (``40 Gbps``, ``200G``, ``100Gx4``, ``1000Mb/s``) to Mbps."""
    if not speed_str:
        return 0.0
    s = speed_str.strip().lower()
    if s in ("n/a", "unknown", "-", ""):
        return 0.0
    m = _SPEED_TOKEN_RE.match(s)
    if not m:
        return 0.0
    value = float(m.group(1))
    prefix = (m.group(2) or "").lower()
    return value * _SPEED_PREFIX_MULT.get(prefix, 1.0)


def _split_sections(text: str, header_re: re.Pattern) -> list[tuple[str, str]]:
    """Split ``text`` into ``(header_match, body)`` pairs using ``header_re`` as the boundary."""
    matches = list(header_re.finditer(text))
    sections: list[tuple[str, str]] = []
    for idx, match in enumerate(matches):
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        sections.append((match.group(0), text[match.end():end]))
    return sections


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
class MLNXOSDriver(_napalm_base.NetworkDriver):
    """Mellanox MLNX-OS NAPALM driver (read-only subset for device-discovery)."""

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
            "mellanox_mlnxos", netmiko_optional_args=self.netmiko_optional_args
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
        ver_fields = _parse_version_fields(self.device.send_command("show version"))
        hostname = _parse_hostname(self.device.send_command("show hosts"))

        intf_out = self.device.send_command("show interfaces ethernet status")
        interface_list = _parse_interface_status_names(intf_out)
        mgmt_out = self.device.send_command("show interfaces mgmt0")
        if "mgmt0" in mgmt_out and "mgmt0" not in interface_list:
            interface_list.append("mgmt0")

        return {
            "uptime": ver_fields["uptime"],
            "vendor": "Mellanox",
            "os_version": ver_fields["os_version"],
            "serial_number": ver_fields["serial_number"],
            "model": ver_fields["model"],
            "hostname": hostname,
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """Return interface details keyed by interface name."""
        interfaces: dict = {}

        eth_out = self.device.send_command("show interfaces ethernet")
        for name, body in _split_sections(eth_out, _ETH_SECTION_RE):
            interfaces[name.strip().rstrip(":")] = _parse_interface_body(body)

        mgmt_out = self.device.send_command("show interfaces mgmt0")
        if mgmt_out.strip():
            interfaces["mgmt0"] = _parse_interface_body(mgmt_out)

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface."""
        interfaces_ip: dict = {}

        ipv4_out = self.device.send_command("show ip interface")
        _populate_ip(interfaces_ip, ipv4_out, family="ipv4")

        ipv6_out = self.device.send_command("show ipv6 interface")
        _populate_ip(interfaces_ip, ipv6_out, family="ipv6")

        return interfaces_ip

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """Return device configuration; MLNX-OS has no separate startup file (saved == running)."""
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}

        retrieve_norm = retrieve.lower()
        if retrieve_norm in ("running", "startup", "all"):
            running_config = self.device.send_command("show running-config")
            if retrieve_norm in ("running", "all"):
                config["running"] = running_config
            if retrieve_norm in ("startup", "all"):
                config["startup"] = running_config

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Return VLAN information keyed by VLAN ID string."""
        out = self.device.send_command("show vlan")
        return _parse_vlan_table(out)


# ---------------------------------------------------------------------------
# Module-level parsers
# ---------------------------------------------------------------------------
_ETH_SECTION_RE = re.compile(r"^Eth\d+/\d+(?:/\d+)?:?\s*$", re.M)
_INTF_STATUS_LINE_RE = re.compile(r"^(Eth\d+/\d+(?:/\d+)?)\s+", re.M)
_HOSTNAME_RE = re.compile(r"^\s*Hostname\s*:\s*(\S+)", re.M | re.I)
_VERSION_FIELD_MAP = {
    "product release": "os_version",
    "product model": "model",
    "system serial num": "serial_number",
    "uptime": "uptime",
}


def _parse_version_fields(text: str) -> dict:
    """Extract os_version, model, serial_number, uptime from ``show version`` output."""
    fields = {
        "os_version": "Unknown",
        "model": "Unknown",
        "serial_number": "Unknown",
        "uptime": -1.0,
    }
    if not text:
        return fields
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        attr = _VERSION_FIELD_MAP.get(key.strip().lower())
        value = value.strip()
        if attr is None or not value:
            continue
        fields[attr] = _parse_uptime(value) if attr == "uptime" else value
    return fields


def _parse_hostname(text: str) -> str:
    """Return the hostname reported by ``show hosts`` or ``Unknown``."""
    m = _HOSTNAME_RE.search(text)
    return m.group(1) if m else "Unknown"


def _parse_interface_status_names(text: str) -> list[str]:
    """Extract the interface column from ``show interfaces ethernet status``."""
    return [m.group(1) for m in _INTF_STATUS_LINE_RE.finditer(text)]


def _parse_interface_body(body: str) -> dict:
    """Parse the key/value block under ``show interfaces`` (Ethernet and mgmt0 key sets)."""
    fields = {}
    for line in body.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        fields[key.strip().lower()] = value.strip()

    admin_raw = (fields.get("admin state") or fields.get("admin up") or "").lower()
    oper_raw = (
        fields.get("operational state") or fields.get("link up") or fields.get("link state") or ""
    ).lower()
    is_enabled = "enabled" in admin_raw or admin_raw.startswith(("up", "yes"))
    is_up = "up" in oper_raw or oper_raw.startswith("yes")

    mtu_raw = fields.get("mtu", "")
    mtu_match = re.match(r"(\d+)", mtu_raw)
    mtu = int(mtu_match.group(1)) if mtu_match else -1

    speed = _parse_speed_mbps(fields.get("actual speed") or fields.get("speed", ""))

    mac_raw = fields.get("mac address") or fields.get("hw address", "")
    try:
        mac_address = normalize_mac(mac_raw) if mac_raw else ""
    except Exception:
        mac_address = mac_raw

    return {
        "is_up": is_up,
        "is_enabled": is_enabled,
        "description": fields.get("description", ""),
        "last_flapped": -1.0,
        "mtu": mtu,
        "speed": speed,
        "mac_address": mac_address,
    }


_IP_SECTION_HEADER_RE = re.compile(
    r"""
    ^
    (?:
        Interface\s+(?P<iname>\S+)(?:\s+status)?:?\s*$
      | (?:Vlan|VLAN)\s+(?P<vlan>\d+):?\s*$
      | (?P<short>(?:Eth|Po|Vlan|vlan|mgmt|Loopback|lo|Tunnel|tunnel)\S*):\s*$
    )
    """,
    re.M | re.X,
)
_IPV4_INLINE_RE = re.compile(
    r"(?:Internet|IP)\s+address\s*:\s*(\d+\.\d+\.\d+\.\d+)\s*/\s*(\d+)", re.I
)
_IPV4_NOPFX_RE = re.compile(
    r"(?:Internet|IP)\s+address\s*:\s*(\d+\.\d+\.\d+\.\d+)\s*(?!/|\d)$", re.I | re.M
)
_IPV4_NETMASK_RE = re.compile(r"Netmask\s*:\s*(\d+\.\d+\.\d+\.\d+)", re.I)
_IPV6_ADDR_RE = re.compile(
    r"(?P<addr>[0-9A-Fa-f:]*::?[0-9A-Fa-f:]*)\s*/\s*(?P<prefix>\d+)"
)


def _netmask_to_prefix(netmask: str) -> int:
    """Convert a dotted-decimal netmask to its CIDR prefix length."""
    return sum(bin(int(o)).count("1") for o in netmask.split("."))


def _iter_ip_sections(text: str):
    """Yield ``(interface_name, body)`` tuples for every IP-interface section in ``text``."""
    matches = list(_IP_SECTION_HEADER_RE.finditer(text))
    for idx, match in enumerate(matches):
        name = (
            match.group("iname")
            or (f"vlan{match.group('vlan')}" if match.group("vlan") else None)
            or match.group("short")
        )
        if not name:
            continue
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        yield name, text[match.end():end]


def _populate_ip(result: dict, text: str, family: str) -> None:
    """Parse ``show ip interface`` / ``show ipv6 interface`` blocks into ``result``."""
    if not text.strip():
        return

    for name, body in _iter_ip_sections(text):
        if family == "ipv4":
            entries = _parse_ipv4_addresses(body)
        else:
            entries = _parse_ipv6_addresses(body)
        for ip, prefix in entries:
            result.setdefault(name, {}).setdefault(family, {})[ip] = {
                "prefix_length": prefix
            }


def _parse_ipv4_addresses(body: str) -> list[tuple[str, int]]:
    """Return ``[(ip, prefix), ...]`` for both inline ``addr/prefix`` and split netmask layouts."""
    entries: list[tuple[str, int]] = []
    seen: set[str] = set()

    for ip, prefix in _IPV4_INLINE_RE.findall(body):
        entries.append((ip, int(prefix)))
        seen.add(ip)

    for m in _IPV4_NOPFX_RE.finditer(body):
        ip = m.group(1)
        if ip in seen:
            continue
        netmask_match = _IPV4_NETMASK_RE.search(body, pos=m.end())
        if not netmask_match:
            continue
        entries.append((ip, _netmask_to_prefix(netmask_match.group(1))))
        seen.add(ip)

    return entries


def _parse_ipv6_addresses(body: str) -> list[tuple[str, int]]:
    """Return ``[(ip, prefix), ...]`` from an IPv6 interface section body."""
    entries: list[tuple[str, int]] = []
    for m in _IPV6_ADDR_RE.finditer(body):
        ip = m.group("addr")
        if ":" not in ip:
            continue
        entries.append((ip, int(m.group("prefix"))))
    return entries


_DASHES_LINE_RE = re.compile(r"^\s*-+(?:\s+-+)+\s*$")


def _column_spans(separator_line: str) -> list[tuple[int, int]]:
    """Return ``[(start, end), ...]`` character offsets for each dash group on a separator line."""
    return [(m.start(), m.end()) for m in re.finditer(r"-+", separator_line)]


def _parse_vlan_table(text: str) -> dict:
    """Parse ``show vlan`` into ``{vlan_id: {name, interfaces}}`` using header column widths."""
    if not text.strip():
        return {}

    lines = text.splitlines()
    sep_idx = next(
        (idx for idx, line in enumerate(lines) if _DASHES_LINE_RE.match(line)),
        None,
    )
    if sep_idx is None:
        return {}

    spans = _column_spans(lines[sep_idx])
    if len(spans) < 3:
        return {}

    vlans: dict = {}
    current_id: str | None = None
    id_start = spans[0][0]
    name_start = spans[1][0]
    ports_start = spans[2][0]

    for line in lines[sep_idx + 1:]:
        if not line.strip():
            current_id = None
            continue

        id_field = line[id_start:name_start].strip() if len(line) > id_start else ""
        if id_field.isdigit():
            current_id = id_field
            name = line[name_start:ports_start].strip() if len(line) > name_start else ""
            ports_field = line[ports_start:] if len(line) > ports_start else ""
            vlans[current_id] = {
                "name": name,
                "interfaces": [p.strip() for p in ports_field.split(",") if p.strip()],
            }
        elif id_field == "" and current_id is not None and len(line) > ports_start:
            ports_field = line[ports_start:]
            vlans[current_id]["interfaces"].extend(
                p.strip() for p in ports_field.split(",") if p.strip()
            )
        else:
            current_id = None

    return vlans
