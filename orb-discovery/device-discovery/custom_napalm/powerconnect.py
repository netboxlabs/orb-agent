# Copyright 2026 NetBox Labs Inc
"""
Custom Dell PowerConnect NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko (dell_powerconnect device type) for SSH connectivity and
ntc-templates for structured parsing of 'show interfaces status' and
'show interfaces description'; falls back to regex for commands without
templates (show version, show ip interface, show vlan).
"""

import ipaddress
import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config sanitization — Dell PowerConnect sensitive fields
# ---------------------------------------------------------------------------

# "username <name> [privilege <n>] password [<enc-type>] <value>"
# "enable password [<enc-type>] <value>"
_PASSWORD_RE = re.compile(
    r"((?:username\s+\S+(?:\s+privilege\s+\d+)?\s+password|enable\s+password)(?:\s+\d+)?)\s+\S+",
    re.IGNORECASE,
)

# "snmp-server community <string> ..."
_SNMP_COMMUNITY_RE = re.compile(
    r"(snmp-server\s+community)\s+\S+",
    re.IGNORECASE,
)

# "radius-server host <ip> key [<enc-type>] <key>"
_RADIUS_KEY_RE = re.compile(
    r"(radius-server\s+host\s+\S+\s+key)(?:\s+\d+)?\s+\S+",
    re.IGNORECASE,
)

# "enable secret [<enc-type>] <hash>"
_SECRET_RE = re.compile(r"(enable\s+secret)(?:\s+\d+)?\s+\S+", re.IGNORECASE)

# "tacacs-server host <ip> key [<enc-type>] <key>"
_TACACS_KEY_RE = re.compile(
    r"(tacacs-server\s+host\s+\S+\s+key)(?:\s+\d+)?\s+\S+",
    re.IGNORECASE,
)


def _sanitize_config(text: str) -> str:
    text = _PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _SECRET_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_COMMUNITY_RE.sub(r"\1 <redacted>", text)
    text = _RADIUS_KEY_RE.sub(r"\1 <redacted>", text)
    text = _TACACS_KEY_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Uptime parsing
# ---------------------------------------------------------------------------

_MINUTE_SECONDS = 60
_HOUR_SECONDS = 3600
_DAY_SECONDS = 24 * _HOUR_SECONDS


# ---------------------------------------------------------------------------
# Interface IP parsing helpers
# ---------------------------------------------------------------------------

def _mask_to_prefix(mask: str) -> int:
    """Convert dotted-decimal subnet mask to prefix length integer."""
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False).prefixlen
    except (ValueError, AttributeError):
        return -1


_NTC_PLATFORM = "dell_powerconnect"


# ---------------------------------------------------------------------------
# Shared helpers for interface parsing
# ---------------------------------------------------------------------------

def _parse_port_descriptions_fallback(raw: str) -> dict[str, str]:
    r"""
    Regex fallback for Port section descriptions when the NTC template fails.

    Handles descriptions that contain spaces (the template's ``DESCRIPTION
    (\S*)`` capture rejects them and triggers ``^. -> Error``).
    """
    desc: dict[str, str] = {}
    in_data = False
    for line in raw.splitlines():
        if re.match(r"^-+", line.strip()):
            in_data = True
            continue
        if not in_data:
            continue
        if re.match(r"^(?:Ch|Po)\s+Description", line, re.IGNORECASE):
            break
        m = re.match(r"^(\S+)\s*(.*?)\s*$", line)
        if m:
            desc[m.group(1)] = m.group(2)
    return desc


def _parse_ch_descriptions(raw: str) -> dict[str, str]:
    """
    Parse port-channel descriptions from the Ch section of 'show interfaces description'.

    The NTC template ends with ``^Ch ... -> End`` so ch descriptions are never
    included in its output; this function fills that gap.
    """
    desc: dict[str, str] = {}
    in_ch = False
    for line in raw.splitlines():
        if re.match(r"^(?:Ch|Po)\s+Description", line, re.IGNORECASE):
            in_ch = True
            continue
        if not in_ch:
            continue
        if re.match(r"^-+", line.strip()) or not line.strip():
            continue
        m = re.match(r"^((?:ch|po)\d+)\s*(.*?)\s*$", line, re.IGNORECASE)
        if m:
            desc[m.group(1)] = m.group(2)
    return desc


def _parse_ch_rows(raw: str) -> list[dict]:
    """
    Parse port-channel rows from 'show interfaces status' output.

    The NTC template stops at the Ch/Po section header (``^Ch ... -> EOF``), so
    LAG interfaces must be extracted separately with a regex.  Both ``ch`` and
    ``po``/``Po`` naming styles are supported.
    """
    rows = []
    for m in re.finditer(
        r"^((?:ch|po)\d+)\s+\S+\s+\S+\s+(\S+)\s+\S+\s+\S+\s+(Not\s+Present|Up|Down)\s*$",
        raw,
        re.MULTILINE | re.IGNORECASE,
    ):
        rows.append(
            {"port": m.group(1), "speed": m.group(2), "linkstate": m.group(3).strip()}
        )
    return rows


def _parse_physical_rows(raw: str) -> list[dict]:
    r"""
    Regex fallback for the physical-port table in 'show interfaces status'.

    Used when the NTC template raises, e.g. on firmware that emits
    ``Not Present`` for physical stack slots (the template only accepts
    ``Up``\|``Down`` for the physical table).  Only lines after the first
    dashes-separator are processed; the Ch/Po section must already have
    been truncated from *raw* before calling this function.
    """
    rows = []
    in_data = False
    for line in raw.splitlines():
        if re.match(r"^-+", line.strip()):
            in_data = True
            continue
        if not in_data:
            continue
        m = re.match(
            r"^((?:\d+/)?[a-zA-Z]+\d+(?:[:/]\d+)*)\s+\S+\s+\S+\s+(\S+)\s+\S+\s+\S+\s+(Up|Down|Not\s+Present)",
            line,
            re.IGNORECASE,
        )
        if m:
            rows.append(
                {
                    "port": m.group(1),
                    "speed": "" if m.group(2) == "--" else m.group(2),
                    "linkstate": m.group(3).strip(),
                }
            )
    return rows


def _find_vlan_columns(raw: str) -> tuple[int | None, int | None, int | None]:
    """
    Return (col_name, col_ports, col_type) column offsets from the VLAN header line.

    Returns ``(None, None, None)`` when no header is found.
    """
    for line in raw.splitlines():
        hm = re.match(r"\s*(VLAN)\s+(Name)\s+(Ports?)\s+(Type)", line, re.IGNORECASE)
        if hm:
            return hm.start(2), hm.start(3), hm.start(4)
    return None, None, None


def _make_interface_entry(link_state: str, speed_raw: str, description: str) -> dict:
    """Build a NAPALM interface dict from parsed field values."""
    try:
        speed = float(speed_raw) if speed_raw not in ("", "--") else -1.0
    except ValueError:
        speed = -1.0
    return {
        "is_up": link_state == "up",
        "is_enabled": True,
        "description": description,
        "last_flapped": -1.0,
        "mtu": -1,
        "speed": speed,
        "mac_address": "",
    }


class PowerConnectDriver(_napalm_base.NetworkDriver):
    """Dell PowerConnect NAPALM driver (read-only subset for device-discovery)."""

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
            "dell_powerconnect", netmiko_optional_args=self.netmiko_optional_args
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

    def _parse_version_facts(self, raw: str) -> dict:
        """
        Extract hostname, os_version, model, serial_number, and uptime from 'show version'.

        Parses 'show version' output using regex.

        Example 'show version' output::

            System Description:        Dell Networking N2048, 1.0, Linux 3.6.5-1
            System Up Time (days,hour:min:sec):  0,02:14:33
            System Contact:
            System Name:               switch01
            System Location:
            System Object ID:          1.3.6.1.4.1.674.10895.3048
            System Information
              Hardware Version:        A00
              Number of Ports:         48
            ...
            Active-image: file=/flash/N2048v1-SI-10.5.2.4.stk  checksum=...
            ...
            Unit ID  HW Version  SW Version     Serial Number
            --------  ----------  -------------  ------------
             1         A00         10.5.2.4       CN07Q7ABCE0123
        """
        facts: dict = {
            "hostname": "Unknown",
            "os_version": "Unknown",
            "model": "Unknown",
            "serial_number": "Unknown",
            "uptime": 0.0,
        }

        if not raw:
            return facts

        # Hostname: "System Name: <name>"
        m = re.search(r"System\s+Name\s*:\s*(\S+)", raw, re.IGNORECASE)
        if m:
            facts["hostname"] = m.group(1).strip()

        # Model from "System Description: Dell [EMC] [Networking] <Model>, ..."
        # Handles: "Dell Networking N2048", "Dell EMC N2048", "Dell EMC Networking N3048"
        m = re.search(
            r"System\s+Description\s*:\s*Dell\s+(?:EMC\s+)?(?:Networking\s+)?(\S+)",
            raw,
            re.IGNORECASE,
        )
        if m:
            facts["model"] = m.group(1).strip().rstrip(",")

        # OS version — prefer SW Version column from the unit table.
        # Allow optional leading whitespace: some firmware emits "1  A00  10.5.2.4  ..."
        # without indentation.
        m = re.search(r"^\s*\d+\s+\S+\s+(\S+)\s+(\S+)", raw, re.MULTILINE)
        if m:
            facts["os_version"] = m.group(1).strip()
            facts["serial_number"] = m.group(2).strip()

        # Uptime: "System Up Time (days,hour:min:sec):  0,02:14:33"
        m = re.search(
            r"System\s+Up\s+Time.*?:\s+(\d+),(\d+):(\d+):(\d+)",
            raw,
            re.IGNORECASE,
        )
        if m:
            days, hours, minutes, secs = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
            facts["uptime"] = float(
                days * _DAY_SECONDS + hours * _HOUR_SECONDS + minutes * _MINUTE_SECONDS + secs
            )

        return facts

    def get_facts(self) -> dict:
        """
        Return general device facts.

        Facts are assembled from two commands:
        - 'show version'           → hostname, os_version, model, serial_number, uptime (regex)
        - 'show interfaces status' → interface_list (ntc-template)
        """
        raw_version = self.device.send_command("show version")
        facts = self._parse_version_facts(raw_version)

        # Interface list: physical ports via ntc-template + ch/po ports via regex
        raw_status = self.device.send_command("show interfaces status")
        # Truncate at the Ch/Po section header so the NTC template only sees
        # the physical-port table (mirrors the same guard in get_interfaces).
        raw_for_ntc = re.split(
            r"^(?:Ch|Po)\s+", raw_status, maxsplit=1, flags=re.MULTILINE
        )[0]
        interface_list: list[str] = []
        try:
            parsed = parse_output(
                platform=_NTC_PLATFORM, command="show interfaces status", data=raw_for_ntc
            )
        except Exception:
            logger.debug("powerconnect: failed to parse 'show interfaces status'", exc_info=True)
            parsed = _parse_physical_rows(raw_for_ntc)
        interface_list = [
            row["port"]
            for row in parsed
            if row.get("port") and row.get("linkstate", "").strip().lower() != "not present"
        ]
        # NTC template stops before the Ch section; add ch interfaces separately.
        # Use dict.fromkeys to deduplicate while preserving order.
        ch_list = [
            row["port"]
            for row in _parse_ch_rows(raw_status)
            if row["linkstate"].lower() != "not present"
        ]
        interface_list = list(dict.fromkeys(interface_list + ch_list))

        return {
            "hostname": facts["hostname"],
            "vendor": "Dell",
            "model": facts["model"],
            "os_version": facts["os_version"],
            "serial_number": facts["serial_number"],
            "uptime": facts["uptime"],
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def _description_map(self) -> dict[str, str]:
        r"""
        Return a port→description mapping from 'show interfaces description'.

        Tries the ntc-template first.  Falls back to a regex line parser when
        the template raises (e.g. descriptions that contain spaces, which the
        ``DESCRIPTION (\S*)`` capture group cannot handle).
        """
        desc_map: dict[str, str] = {}
        raw = self.device.send_command("show interfaces description")
        if not raw:
            return desc_map
        try:
            parsed = parse_output(
                platform=_NTC_PLATFORM, command="show interfaces description", data=raw
            )
            for row in parsed:
                intf = row.get("interface", "").strip()
                if intf:
                    desc_map[intf] = row.get("description", "").strip()
        except Exception:
            logger.debug(
                "powerconnect: 'show interfaces description' template failed, "
                "falling back to regex parser",
                exc_info=True,
            )
            desc_map = _parse_port_descriptions_fallback(raw)

        # The NTC template ends with ^Ch...-> End; supplement with ch descriptions.
        desc_map.update(_parse_ch_descriptions(raw))
        return desc_map

    def get_interfaces(self) -> dict:
        """
        Return interface details keyed by port name.

        Parses 'show interfaces status' (ntc-template) for port/speed/state and
        'show interfaces description' (ntc-template) for description.

        ``is_enabled`` is always ``True`` because ``show interfaces status``
        exposes only operational link state, not administrative state.
        Port-channels without members ("Not Present") are skipped entirely.
        """
        raw_status = self.device.send_command("show interfaces status")
        if not raw_status:
            return {}

        # Truncate at the Ch/Po section header so the NTC template only sees
        # the physical-port table.  _parse_ch_rows handles the rest on the
        # full output.
        raw_for_ntc = re.split(
            r"^(?:Ch|Po)\s+", raw_status, maxsplit=1, flags=re.MULTILINE
        )[0]

        try:
            parsed_status = parse_output(
                platform=_NTC_PLATFORM, command="show interfaces status", data=raw_for_ntc
            )
        except Exception:
            logger.debug("powerconnect: failed to parse 'show interfaces status'", exc_info=True)
            parsed_status = _parse_physical_rows(raw_for_ntc)

        desc_map = self._description_map()
        interfaces: dict = {}
        for row in parsed_status:
            port = row.get("port", "").strip()
            if not port:
                continue
            link_state = row.get("linkstate", "").strip().lower()
            if link_state == "not present":
                continue
            interfaces[port] = _make_interface_entry(
                link_state, row.get("speed", "").strip(), desc_map.get(port, "")
            )

        # NTC template stops before the Ch section; add ch interfaces separately.
        for row in _parse_ch_rows(raw_status):
            link_state = row["linkstate"].lower()
            if link_state == "not present":
                continue
            interfaces[row["port"]] = _make_interface_entry(
                link_state, row["speed"], desc_map.get(row["port"], "")
            )

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """
        Return IP addresses per interface.

        Parses 'show ip interface' output with regex.  Example output::

            IP address and subnet mask:
            Vlan 1              192.168.1.1/255.255.255.0
            Vlan 10             10.0.10.1/255.255.255.0

        or CIDR form::

            Vlan 1              192.168.1.1/24
        """
        raw = self.device.send_command("show ip interface")
        if not raw:
            return {}

        interfaces_ip: dict = {}
        # Match both slash-notation and space-separated (tabular) output forms:
        #   Vlan 1   192.168.1.1/255.255.255.0   (slash form)
        #   Vlan 1   192.168.1.1   255.255.255.0  (tabular form)
        for m in re.finditer(
            r"^(\S+(?:\s+\d+)?)\s+(\d+\.\d+\.\d+\.\d+)(?:/(\S+)|\s+(\d+\.\d+\.\d+\.\d+))",
            raw,
            re.MULTILINE,
        ):
            intf = m.group(1).strip()
            ip_addr = m.group(2).strip()
            mask_or_prefix = (m.group(3) or m.group(4) or "").strip()

            # Determine prefix length
            if "." in mask_or_prefix:
                prefix_length = _mask_to_prefix(mask_or_prefix)
            else:
                try:
                    prefix_length = int(mask_or_prefix)
                except ValueError:
                    continue

            if prefix_length < 0:
                continue

            interfaces_ip.setdefault(intf, {}).setdefault("ipv4", {})[ip_addr] = {
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

        Parses 'show vlan' output using column offsets derived from the header
        line.  Example output::

            VLAN  Name                 Ports                Type
            ----  -------------------  -------------------  ---------------
            1     default              g1-4,g6,ch1-4        Default
            10    MGMT                 g5,g8                Static
            20    Voice                g9-12                Static
        """
        raw = self.device.send_command("show vlan")
        if not raw:
            return {}

        # Discover column start positions from the header line.
        col_name, col_ports, col_type = _find_vlan_columns(raw)

        vlans: dict = {}
        current_vlan_id: str | None = None
        for line in raw.splitlines():
            # Allow leading whitespace — classic PowerConnect left-pads VLAN IDs.
            if not re.match(r"^\s*\d+\s", line):
                # Continuation line: port list wraps onto the next line.
                # Detected when content exists only under the Ports column and
                # the VLAN-ID area (before col_name) is all whitespace.
                if (
                    current_vlan_id is not None
                    and col_name is not None
                    and col_ports is not None
                    and col_type is not None
                    and line.strip()
                    and not re.match(r"^[-\s]+$", line)
                    and line[:col_name].strip() == ""
                ):
                    extra = line[col_ports:col_type].strip()
                    if extra:
                        vlans[current_vlan_id]["interfaces"].extend(_expand_ports(extra))
                continue

            if col_name is not None and col_ports is not None and col_type is not None:
                vlan_id = line[:col_name].strip()
                vlan_name = line[col_name:col_ports].strip()
                ports_raw = line[col_ports:col_type].strip()
            else:
                # Fallback when header is absent: single-token name, type-anchored.
                fm = re.match(r"^\s*(\d+)\s+(\S+)\s*(.*?)\s+\S+\s*$", line)
                if not fm:
                    continue
                vlan_id, vlan_name, ports_raw = fm.group(1), fm.group(2), fm.group(3).strip()

            if not vlan_id:
                continue

            # Expand port ranges like "g1-4,g6,ch1-4" into individual port names
            vlans[vlan_id] = {
                "name": vlan_name or vlan_id,
                "interfaces": _expand_ports(ports_raw),
            }
            current_vlan_id = vlan_id

        return vlans


# ---------------------------------------------------------------------------
# Port range expansion helper
# ---------------------------------------------------------------------------

def _expand_ports(ports_raw: str) -> list[str]:
    """
    Expand a Dell PowerConnect port-list string into individual port names.

    Examples::
        "g1-4,g6,ch1-4"      →  ["g1", "g2", "g3", "g4", "g6", "ch1", "ch2", "ch3", "ch4"]
        "1/g1-1/g4,1/g6"     →  ["1/g1", "1/g2", "1/g3", "1/g4", "1/g6"]
        "Gi1/0/1-48,Te1/0/1" →  ["Gi1/0/1", ..., "Gi1/0/48", "Te1/0/1"]
        ""                    →  []
    """
    if not ports_raw or ports_raw in ("--", ""):
        return []

    result: list[str] = []
    for token in ports_raw.split(","):
        token = token.strip()
        if not token:
            continue
        # Parenthesized range: <prefix>(<start>-<end>)  e.g. "g(1-24)" or "ch(1-8)"
        # Used in older PowerConnect VLAN membership output.
        m = re.fullmatch(r"([a-zA-Z]+)\((\d+)-(\d+)\)", token)
        if m:
            prefix, start, end = m.group(1), int(m.group(2)), int(m.group(3))
            result.extend(f"{prefix}{i}" for i in range(start, end + 1))
            continue
        # Three-level range: <prefix><a>/<b>/<start>-<end>  e.g. "Gi1/0/1-48"
        # Used on Dell N-series (PowerConnect successor) for GE/10GE ports.
        m = re.fullmatch(r"([a-zA-Z]+\d+/\d+/)(\d+)-(\d+)", token)
        if m:
            prefix, start, end = m.group(1), int(m.group(2)), int(m.group(3))
            result.extend(f"{prefix}{i}" for i in range(start, end + 1))
            continue
        # Stacked-unit range: <unit>/<prefix><start>-<unit>/<prefix><end>
        # e.g. "1/g1-1/g48" on stacked PowerConnect units.
        m = re.fullmatch(r"(\d+)/([a-zA-Z]+)(\d+)-(\d+)/([a-zA-Z]+)(\d+)", token)
        if m:
            unit1, pfx1, start = m.group(1), m.group(2), int(m.group(3))
            unit2, pfx2, end = m.group(4), m.group(5), int(m.group(6))
            if unit1 == unit2 and pfx1 == pfx2:
                result.extend(f"{unit1}/{pfx1}{i}" for i in range(start, end + 1))
            else:
                result.append(token)
            continue
        # Simple range: <prefix><start>-<end>  e.g. "g1-4" or "ch1-4"
        m = re.fullmatch(r"([a-zA-Z]+)(\d+)-(\d+)", token)
        if m:
            prefix, start, end = m.group(1), int(m.group(2)), int(m.group(3))
            result.extend(f"{prefix}{i}" for i in range(start, end + 1))
            continue
        result.append(token)
    return result
