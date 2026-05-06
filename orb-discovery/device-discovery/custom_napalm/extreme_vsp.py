# Copyright 2026 NetBox Labs Inc
"""
Custom NAPALM driver for Avaya/Extreme Virtual Services Platform (VSP) running VOSS.

Implements the five methods used by device-discovery using Netmiko (extreme_vsp)
and regex parsing.  The only ntc-template available for VSP is
``avaya_vsp / show software``, used to extract the primary OS version string.
All other commands are parsed with inline regexes.

Avaya VSP was rebranded as Extreme VSP when Extreme Networks acquired Avaya's
networking portfolio in 2017.  Both brands share identical hardware and the
same VOSS (Virtualized OS Software) CLI, so the Netmiko device type is
``extreme_vsp`` (the current unified driver).
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.helpers import mac as normalize_mac
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

from custom_napalm._vlan import (
    SwitchportInfo,
    classify_switchport,
    coerce_vid,
    parse_vlan_range_string,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config sanitization
# ---------------------------------------------------------------------------
# "password <hash>" on user-account lines and enable-password lines
_PASSWORD_RE = re.compile(
    r"^(\s*(?:enable\s+)?password\s+(?:level\s+\d+\s+)?)\S+",
    re.IGNORECASE | re.MULTILINE,
)
# "username <name> level <n> password <hash>"
_USERNAME_PASSWORD_RE = re.compile(
    r"(username\s+\S+(?:\s+level\s+\d+)?\s+password)\s+\S+",
    re.IGNORECASE,
)
# SNMP community string: 'snmp-server community "<name>" ro|rw'
# or unquoted: 'snmp-server community <name> ro|rw'
_SNMP_COMMUNITY_RE = re.compile(
    r'(snmp-server\s+community)\s+("[^"]*"|\S+)',
    re.IGNORECASE,
)


def _sanitize_snmp_community(match: re.Match) -> str:
    community = match.group(2)
    if community.startswith('"') and community.endswith('"'):
        return f'{match.group(1)} "<redacted>"'
    return f"{match.group(1)} <redacted>"


def _sanitize_config(text: str) -> str:
    text = _USERNAME_PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _PASSWORD_RE.sub(r"\1<redacted>", text)
    text = _SNMP_COMMUNITY_RE.sub(_sanitize_snmp_community, text)
    return text


# ---------------------------------------------------------------------------
# Uptime helper
# ---------------------------------------------------------------------------
_UPTIME_UNITS = (
    (r"(\d+)\s+day", 86_400),
    (r"(\d+)\s+hour", 3_600),
    (r"(\d+)\s+minute", 60),
    (r"(\d+)\s+second", 1),
)


def _parse_uptime(uptime_str: str) -> float:
    """
    Convert a VOSS uptime string to total seconds.

    Handles ``"0 day(s), 3 hour(s), 45 minute(s), 12 second(s)"`` format.
    """
    seconds = 0.0
    for pattern, factor in _UPTIME_UNITS:
        m = re.search(pattern, uptime_str, re.IGNORECASE)
        if m:
            seconds += int(m.group(1)) * factor
    return seconds


# ---------------------------------------------------------------------------
# Speed helper
# ---------------------------------------------------------------------------
_SPEED_RE = re.compile(
    r"(\d+(?:\.\d+)?)\s*(Gbps|Mbps|Kbps)?",
    re.IGNORECASE,
)


def _parse_speed_mbps(speed_str: str) -> float:
    """
    Convert a VOSS speed string to Mbps (float).

    Examples: ``"1 Gbps"`` → ``1000.0``, ``"100 Mbps"`` → ``100.0``.
    """
    m = _SPEED_RE.search(speed_str.strip())
    if not m:
        return -1.0
    value = float(m.group(1))
    unit = (m.group(2) or "Mbps").lower()
    if unit == "gbps":
        return value * 1_000
    if unit == "kbps":
        return value / 1_000
    return value


# ---------------------------------------------------------------------------
# Netmask helper
# ---------------------------------------------------------------------------
def _mask_to_prefix(mask: str) -> int:
    """Convert a dotted-quad netmask to prefix length."""
    try:
        return sum(bin(int(octet)).count("1") for octet in mask.split("."))
    except (ValueError, AttributeError):
        return -1


# ---------------------------------------------------------------------------
# Interface parsing  (show interfaces GigabitEthernet all)
# ---------------------------------------------------------------------------
# Split at each port block header (e.g. "Port: 1/1" line)
_INTF_BLOCK_SEP_RE = re.compile(r"(?=^Port:\s+\S+)", re.MULTILINE)
_INTF_PORT_RE = re.compile(r"^Port:\s+(\S+)", re.MULTILINE)
_INTF_ADMIN_RE = re.compile(r"Admin\s+Status\s*:\s*(\w+)", re.IGNORECASE)
_INTF_OPER_RE = re.compile(r"Oper\s+Status\s*:\s*(\w+)", re.IGNORECASE)
_INTF_SPEED_RE = re.compile(r"Speed\s*:\s*(.+?)$", re.IGNORECASE | re.MULTILINE)
_INTF_MTU_RE = re.compile(r"MTU\s*:\s*(\d+)", re.IGNORECASE)
_INTF_MAC_RE = re.compile(
    r"MAC\s+Address\s*:\s*([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}"
    r"[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})",
    re.IGNORECASE,
)
_INTF_DESC_RE = re.compile(r"Description\s*:\s*(.*?)$", re.IGNORECASE | re.MULTILINE)


def _parse_interfaces(output: str) -> dict:
    """Parse ``show interfaces GigabitEthernet all`` (or 10GigabitEthernet all)."""
    interfaces: dict = {}
    for block in _INTF_BLOCK_SEP_RE.split(output):
        port_m = _INTF_PORT_RE.search(block)
        if not port_m:
            continue
        port = port_m.group(1)

        admin_m = _INTF_ADMIN_RE.search(block)
        oper_m = _INTF_OPER_RE.search(block)
        speed_m = _INTF_SPEED_RE.search(block)
        mtu_m = _INTF_MTU_RE.search(block)
        mac_m = _INTF_MAC_RE.search(block)
        desc_m = _INTF_DESC_RE.search(block)

        admin_val = (admin_m.group(1) if admin_m else "Disable").lower()
        oper_val = (oper_m.group(1) if oper_m else "Down").lower()
        speed_str = speed_m.group(1).strip() if speed_m else ""
        mtu_raw = mtu_m.group(1) if mtu_m else ""
        mac_raw = mac_m.group(1) if mac_m else ""
        desc = desc_m.group(1).strip() if desc_m else ""

        try:
            mac_address = normalize_mac(mac_raw) if mac_raw else ""
        except Exception:
            mac_address = mac_raw

        interfaces[port] = {
            "is_up": "up" in oper_val,
            "is_enabled": admin_val.startswith("en"),
            "description": desc,
            "last_flapped": -1.0,
            "mtu": int(mtu_raw) if mtu_raw.isdigit() else -1,
            "speed": _parse_speed_mbps(speed_str) if speed_str else -1.0,
            "mac_address": mac_address,
        }
    return interfaces


# ---------------------------------------------------------------------------
# IP interface parsing  (show ip interface)
# ---------------------------------------------------------------------------
# Matches table rows: <intf-name> <ip> <mask> <type> <admin> <oper>
_IP_ROW_RE = re.compile(
    r"^(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+",
    re.MULTILINE,
)


def _parse_interfaces_ip(output: str) -> dict:
    """Parse ``show ip interface`` tabular output."""
    interfaces_ip: dict = {}
    for m in _IP_ROW_RE.finditer(output):
        intf = m.group(1)
        ip = m.group(2)
        prefix = _mask_to_prefix(m.group(3))
        if prefix < 0:
            continue
        interfaces_ip.setdefault(intf, {}).setdefault("ipv4", {})[ip] = {
            "prefix_length": prefix
        }
    return interfaces_ip


# ---------------------------------------------------------------------------
# VLAN parsing  (show vlan)
# ---------------------------------------------------------------------------
# Matches rows: <vlan_id> <name> <status> <type> [mstp_instance]
# Non-greedy (.+?) captures multi-word VLAN names. Limitation: a name that
# itself contains the word "Active" or "Suspend" will be truncated at that
# word. VOSS restricts VLAN names to alphanumerics and hyphens in practice,
# so this edge case is unlikely to appear in production configs.
_VLAN_ROW_RE = re.compile(
    r"^(\d+)\s+(.+?)\s+(?:Active|Suspend)\s+\S+",
    re.MULTILINE,
)


def _parse_vlans(output: str) -> dict:
    """Parse ``show vlan`` tabular output."""
    vlans: dict = {}
    for m in _VLAN_ROW_RE.finditer(output):
        vlan_id = m.group(1)
        name = m.group(2)
        vlans[vlan_id] = {"name": name, "interfaces": []}
    return vlans


# ---------------------------------------------------------------------------
# Per-port VLAN parsing  (show interfaces <speed> vlan)
# ---------------------------------------------------------------------------
# Match data rows from ``show interfaces gigabitethernet vlan`` (and the
# 10/40/100 Gbps variants). Row shape::
#
#     PORT     VLAN_IDS                              UNTAGGED_VID
#     1/1      1                                     1
#     1/5      1,100,200                             100
#     1/9      100-105,200                           0
#
# - PORT is a slot/port token (``1/1``, ``2/24`` …); ``\S+`` matches.
# - VLAN_IDS is a comma/range list of VIDs; whitespace between commas is
#   tolerated, but the field as a whole has no internal blocks of >1 space.
# - UNTAGGED_VID is a single integer (``0`` means "all-tagged trunk, no native").
#
# Header lines (``VLAN_IDS``/``UNTAGGED_VID``) and dash separators are rejected
# because they don't end with a bare integer in the third column.
_VSP_PORT_VLAN_RE = re.compile(
    r"^\s*(\S+)\s+([\d,\-\s]+?)\s+(\d+)\s*$",
    re.MULTILINE,
)


def _parse_vsp_port_vlans(text: str) -> list[dict]:
    """
    Parse ``show interfaces ... vlan`` rows.

    Returns a list of ``{"port": str, "vlan_ids": list[int] | "all",
    "untagged_vid": int}``. ``vlan_ids`` is the literal string ``"all"``
    when the source row encoded the full 1-4094 range (wildcard); the
    classifier promotes that to ``trunk-all``. Header rows and rows whose
    port token is a header keyword are filtered out.
    """
    rows: list[dict] = []
    for m in _VSP_PORT_VLAN_RE.finditer(text):
        port = m.group(1)
        # Reject header lines: the regex's ``\S+`` would otherwise match
        # tokens like "PORT" or "VLAN" if the header somehow ended in digits.
        if not re.match(r"^\d+/\d+", port):
            continue
        vlan_field = m.group(2)
        try:
            untagged_vid = int(m.group(3))
        except ValueError:
            continue
        vlan_ids, is_wildcard = parse_vlan_range_string(vlan_field.replace(" ", ""))
        rows.append({
            "port": port,
            "vlan_ids": "all" if is_wildcard else vlan_ids,
            "untagged_vid": untagged_vid,
        })
    return rows


def _vsp_row_to_switchport_info(row: dict) -> SwitchportInfo:
    """
    Map one VSP per-port row to a :class:`SwitchportInfo`.

    Classification rules (UNTAGGED_VID = 0 means "all-tagged trunk"):

    - empty VLAN list                                     → routed (omit)
    - vlan_ids == "all" (full 1-4094 range)               → trunk-all (native = untagged_vid or None)
    - one VLAN listed AND UNTAGGED_VID matches it         → access on that VID
    - multiple VLANs listed AND untagged_vid in the list  → trunk + native
    - multiple VLANs listed AND untagged_vid == 0         → trunk, no native
    - any other shape (e.g. one VLAN, untagged_vid=0)     → trunk, no native
    """
    vlan_ids_raw = row.get("vlan_ids")
    untagged_raw = row.get("untagged_vid")
    untagged = coerce_vid(untagged_raw)  # None when 0 or out-of-range

    if vlan_ids_raw == "all":
        return SwitchportInfo(
            enabled=True,
            admin_mode="trunk",
            oper_mode="trunk",
            access_vlan=None,
            native_vlan=untagged,
            allowed_vlans="all",
        )

    vlan_ids = list(vlan_ids_raw or [])
    if not vlan_ids:
        return SwitchportInfo(
            enabled=False,
            admin_mode=None,
            oper_mode=None,
            access_vlan=None,
            native_vlan=None,
            allowed_vlans=None,
        )

    if len(vlan_ids) == 1 and untagged is not None and untagged == vlan_ids[0]:
        return SwitchportInfo(
            enabled=True,
            admin_mode="access",
            oper_mode="access",
            access_vlan=vlan_ids[0],
            native_vlan=None,
            allowed_vlans=None,
        )

    return SwitchportInfo(
        enabled=True,
        admin_mode="trunk",
        oper_mode="trunk",
        access_vlan=None,
        native_vlan=untagged,
        allowed_vlans=list(vlan_ids),
    )


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


class VSPDriver(_napalm_base.NetworkDriver):
    """Avaya/Extreme VSP NAPALM driver (read-only subset for device-discovery)."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Initialise driver parameters."""
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
            "extreme_vsp", netmiko_optional_args=self.netmiko_optional_args
        )

    def close(self):
        """Close the connection."""
        self._netmiko_close()

    def is_alive(self) -> dict:
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

    def _facts_from_sys_info(self, facts: dict) -> None:
        """Populate hostname, serial_number, and uptime from ``show sys-info``."""
        output = self.device.send_command("show sys-info")
        if not output:
            return
        m = re.search(r"System\s+Name\s*:\s*(\S+)", output, re.IGNORECASE)
        if m:
            facts["hostname"] = m.group(1)
        m = re.search(r"Chassis\s+Serial\s+Number\s*:\s*(\S+)", output, re.IGNORECASE)
        if m:
            facts["serial_number"] = m.group(1)
        m = re.search(r"System\s+Up\s+Time\s*:\s*(.+?)$", output, re.IGNORECASE | re.MULTILINE)
        if m:
            facts["uptime"] = _parse_uptime(m.group(1))

    def _facts_from_software(self, facts: dict) -> None:
        """Populate os_version and model from ``show software`` via ntc-template."""
        output = self.device.send_command("show software")
        if not output:
            return
        parsed_sw = parse_output(platform="avaya_vsp", command="show software", data=output)
        if not parsed_sw:
            return
        row = parsed_sw[0]
        facts["os_version"] = row.get("primary_release") or row.get("backup_release") or "Unknown"
        # VOSS release names encode the hardware platform family in the prefix
        # (e.g. "VOSS8K.6.0.1.2.GA" → platform "8K").  This is a best-effort
        # extraction; the prefix is not a precise hardware model identifier.
        m = re.match(r"VOSS(\S+?)\.", facts["os_version"], re.IGNORECASE)
        if m:
            facts["model"] = f"VSP {m.group(1).upper()}"

    def get_facts(self) -> dict:
        """Return general device facts."""
        facts: dict = {
            "hostname": "Unknown",
            "vendor": "Extreme",
            "model": "VSP",
            "os_version": "Unknown",
            "serial_number": "Unknown",
            "uptime": -1.0,
            "fqdn": "Unknown",
            "interface_list": [],
        }
        self._facts_from_sys_info(facts)
        self._facts_from_software(facts)

        seen: set[str] = set()
        for cmd in (
            "show interfaces GigabitEthernet all",
            "show interfaces 10GigabitEthernet all",
        ):
            output = self.device.send_command(cmd)
            for port_m in _INTF_PORT_RE.finditer(output or ""):
                port = port_m.group(1)
                if port not in seen:
                    seen.add(port)
                    facts["interface_list"].append(port)

        return facts

    def get_interfaces(self) -> dict:
        """
        Return interface details keyed by port number.

        Queries both GigabitEthernet and 10GigabitEthernet.
        """
        interfaces: dict = {}
        for cmd in (
            "show interfaces GigabitEthernet all",
            "show interfaces 10GigabitEthernet all",
        ):
            output = self.device.send_command(cmd)
            if output:
                interfaces.update(_parse_interfaces(output))
        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IPv4 addresses per interface from ``show ip interface``."""
        output = self.device.send_command("show ip interface")
        if not output:
            return {}
        return _parse_interfaces_ip(output)

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """
        Return device configuration.

        VOSS does not expose a distinct startup configuration; both
        ``running`` and ``startup`` are populated from ``show running-config``.
        """
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}

        retrieve = retrieve.lower()
        if retrieve in ("running", "startup", "all"):
            config_text = self.device.send_command("show running-config")
            if retrieve in ("running", "all"):
                config["running"] = config_text
            if retrieve in ("startup", "all"):
                config["startup"] = config_text

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Return VLAN information keyed by VLAN ID string."""
        output = self.device.send_command("show vlan")
        if not output:
            return {}
        return _parse_vlans(output)

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """
        Return per-interface VLAN config from ``show interfaces ... vlan``.

        VOSS splits per-port VLAN config across speed-specific commands
        (gigabitethernet, tengigabitethernet, etc.); this driver issues
        the same two that ``get_interfaces()`` and ``get_facts()`` use,
        so VLAN entries always line up with discovered Interface entities.
        ``apply_interface_vlans()`` skips VLAN data for interfaces that
        weren't emitted, so the 40/100G variants would be silently
        dropped — collecting them here would just waste a CLI roundtrip.
        Extending coverage requires extending interface discovery first.

        Commands for speeds the device doesn't have return empty/error
        and are skipped silently.
        """
        rows: list[dict] = []
        for cmd in (
            "show interfaces gigabitethernet vlan",
            "show interfaces tengigabitethernet vlan",
        ):
            try:
                raw = self.device.send_command(cmd)
            except Exception:
                logger.debug("VSP %s failed", cmd, exc_info=True)
                continue
            rows.extend(_parse_vsp_port_vlans(raw or ""))

        result: dict[str, dict] = {}
        for row in rows:
            port = row.get("port")
            if not port:
                continue
            info = _vsp_row_to_switchport_info(row)
            result[port] = classify_switchport(info)
        return result
