# Copyright 2026 NetBox Labs Inc
"""
Custom ERS NAPALM driver for Avaya/Extreme ERS switches.

Avaya ERS (Ethernet Routing Switch) was acquired by Extreme Networks in 2017;
both brands use identical hardware and CLI.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses ntc-templates with platform ``avaya_ers`` (templates only exist under the
Avaya name) and Netmiko device_type ``extreme_ers`` (the current unified
driver that supports both Avaya- and Extreme-branded hardware).
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
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config sanitization
# ---------------------------------------------------------------------------
# ERS stores passwords as:
#   username <name> password <hash>       (local user)
#   password <hash>                        (enable password)
#   community <name>                       (SNMP community – treat as secret)
# ---------------------------------------------------------------------------
_USERNAME_PASSWORD_RE = re.compile(
    r"(username\s+\S+\s+password)\s+\S+", re.IGNORECASE
)
_PASSWORD_RE = re.compile(
    r"^(\s*password)\s+\S+",
    re.IGNORECASE | re.MULTILINE,
)
_COMMUNITY_RE = re.compile(
    r"(community)\s+\S+",
    re.IGNORECASE,
)


def _sanitize_config(text: str) -> str:
    text = _USERNAME_PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _COMMUNITY_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Uptime helpers
# ---------------------------------------------------------------------------
_UPTIME_UNITS = (
    (r"(\d+)\s+day", 86400),
    (r"(\d+)\s+hour", 3600),
    (r"(\d+)\s+minute", 60),
    (r"(\d+)\s+second", 1),
)
# Matches the HH:MM:SS component from "35 days, 07:24:53"
_UPTIME_HMS_RE = re.compile(r"(\d+):(\d{2}):(\d{2})")


def _parse_uptime(uptime_str: str) -> float:
    """
    Convert an ERS uptime string to total seconds.

    Handles two formats emitted by different ERS firmware versions:

    - ``"0 day(s), 1 hour(s), 26 minute(s), 13 second(s)"`` (older firmware)
    - ``"35 days, 07:24:53"``  (newer firmware / ntc-template capture)
    """
    seconds = 0.0
    # Try HH:MM:SS component first (newer format)
    hms = _UPTIME_HMS_RE.search(uptime_str)
    if hms:
        seconds += int(hms.group(1)) * 3600 + int(hms.group(2)) * 60 + int(hms.group(3))
    # Days component is always a plain digit prefix (both formats)
    for pattern, factor in _UPTIME_UNITS:
        m = re.search(pattern, uptime_str, re.IGNORECASE)
        if m:
            # Avoid double-counting hours/minutes/seconds already handled by HMS
            if factor < 3600 and hms:
                continue
            if factor == 3600 and hms:
                continue
            seconds += int(m.group(1)) * factor
    return seconds


# ---------------------------------------------------------------------------
# Interface helpers  (regex – no suitable ntc-template for ERS interface status)
# ---------------------------------------------------------------------------
_INTF_BLOCK_RE = re.compile(
    r"^(Port\s+\S+.*?)(?=^Port\s+\S+|\Z)",
    re.MULTILINE | re.DOTALL,
)
# "Port 1/1" or "Port 1" header line
_INTF_HEADER_RE = re.compile(r"^Port\s+(\S+)", re.MULTILINE)
_LINK_RE = re.compile(r"Link\s*:\s*(\S+)", re.IGNORECASE)
_ADMIN_RE = re.compile(r"Admin\s*:\s*(\S+)", re.IGNORECASE)
_SPEED_RE = re.compile(r"Speed\s*:\s*(\d+)", re.IGNORECASE)
_MTU_RE = re.compile(r"MTU\s*:\s*(\d+)", re.IGNORECASE)
_MAC_RE = re.compile(
    r"MAC\s+Address\s*:\s*([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}"
    r"[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})",
    re.IGNORECASE,
)
# ---------------------------------------------------------------------------
# IP address helpers (regex – no ntc-template for ERS IP interfaces)
# ---------------------------------------------------------------------------
# ERS show ip interface section header: "Interface : Vlan 1"
_IP_HEADER_RE = re.compile(
    r"^Interface\s*:\s+(.+?)\s*$",
    re.MULTILINE | re.IGNORECASE,
)
# ERS: "IP Address      : 10.0.0.1" and "Mask            : 255.255.255.0"
_IPV4_ADDR_RE = re.compile(r"IP\s+Address\s*:\s*(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)
_IPV4_MASK_RE = re.compile(r"Mask\s*:\s*(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)
# ERS: "IPv6 Address  : 2001:db8::1/64"
_IPV6_RE = re.compile(
    r"IPv6\s+Address\s*:\s*([0-9a-fA-F:]+(?:/\d+)?)",
    re.IGNORECASE,
)
# section separator matching the "Interface : " header
_IP_SECTION_RE = re.compile(
    r"^Interface\s*:",
    re.MULTILINE | re.IGNORECASE,
)


def _mask_to_prefix(mask: str) -> int:
    """Convert dotted-quad netmask to prefix length."""
    return sum(bin(int(octet)).count("1") for octet in mask.split("."))


# ---------------------------------------------------------------------------
# Per-port VLAN helpers (get_interfaces_vlans)
# ---------------------------------------------------------------------------
# ``show vlan interface info`` row format (variable column widths):
#
#                 Filter Filter
#                 Untagged   Unregistered                                 PVID
#   Port   Frames     Frames     STG  PVID  Tagging       Name           Pri
#   ----   ----       ----       ---  ----  -------       ----           ---
#   1/1    No         Yes        1    10    UntagAll      USER-1         0
#
# We anchor on the leading port token, the PVID integer, and the Tagging keyword
# rather than fixed columns — the ``Name`` column may be blank or contain spaces.
# ---------------------------------------------------------------------------
_ERS_PORT_TOKEN = r"(?:\d+(?:/\d+)?|Trk\d+|MLT\d+|Lag\d+)"
# ERS firmware variants emit different column orders:
#   v1: Port  FilterUF FilterUR  STG  PVID  Tagging       Name  Pri
#   v2: Port  FilterUF FilterUR  PVID PRI   Tagging       Name
# Both layouts have exactly two numeric columns between the Filter pair
# and the Tagging keyword. Capture both as ``i1``/``i2`` and let the
# parser pick the right one based on whether the header carries an
# ``STG`` column. (Codex P1 #391: anchoring on a fixed offset from
# Tagging produced the wrong PVID on v2 outputs.)
_ERS_TAGGING_KEYWORDS = (
    r"UntagAll|UntagPvidOnly|TagAll|TagPvidOnly|Hybrid|Disable|None"
)
_ERS_VLAN_INTF_INFO_RE = re.compile(
    r"^\s*(?P<port>" + _ERS_PORT_TOKEN + r")\s+"
    r"\S+\s+\S+"                                # FilterUF FilterUR (Yes/No)
    r"\s+(?P<i1>\d+)"                           # first int (STG in v1, PVID in v2)
    r"\s+(?P<i2>\d+)"                           # second int (PVID in v1, PRI in v2)
    r"\s+(?P<tagging>" + _ERS_TAGGING_KEYWORDS + r")",
    re.IGNORECASE | re.MULTILINE,
)
_ERS_HEADER_HAS_STG_RE = re.compile(
    r"^\s*Port\b.*\bSTG\b.*\bPVID\b.*\bTagging\b", re.IGNORECASE | re.MULTILINE,
)


def _parse_ers_show_vlan_interface_info(text: str) -> dict[str, dict]:
    """
    Parse ``show vlan interface info`` into per-port ``{pvid, tagging}`` dict.

    Detects whether the header carries an ``STG`` column. v1 layout
    (``STG PVID Tagging``) puts PVID in the second numeric column; v2
    layout (``PVID PRI Tagging``) puts PVID in the first.
    """
    if not text:
        return {}
    has_stg = bool(_ERS_HEADER_HAS_STG_RE.search(text))
    out: dict[str, dict] = {}
    for m in _ERS_VLAN_INTF_INFO_RE.finditer(text):
        port = m.group("port")
        try:
            pvid = int(m.group("i2") if has_stg else m.group("i1"))
        except ValueError:
            continue
        out[port] = {"pvid": pvid, "tagging": m.group("tagging")}
    return out


def _ers_aggregate_to_switchport(
    port_info: dict, member_vids: list[int]
) -> SwitchportInfo:
    """
    Map per-port info + VLAN-membership list to ``SwitchportInfo``.

    Tagging interpretation (ERS):
      - ``UntagAll``      → access on PVID (port carries only PVID, untagged)
      - ``UntagPvidOnly`` → trunk with native=PVID, tagged=members minus PVID
      - ``Hybrid``        → same NetBox-aligned semantics as ``UntagPvidOnly``
                            (PVID untagged native, others tagged egress)
      - ``TagAll``        → trunk, no native; tagged=full membership list
                            (every egress frame is tagged, PVID included —
                            so PVID stays in the tagged list when reported)
      - ``TagPvidOnly``   → same NetBox shape as ``TagAll`` (trunk-no-native,
                            members tagged). ERS allows multiple untagged-egress
                            VLANs in this mode which 802.1Q forbids and NetBox
                            can't represent; trunk-no-native is the safest
                            mapping (Codex P1 #391 round-6).
      - ``UntagPvidOnly``/``TagAll``/``TagPvidOnly``/``Hybrid`` with empty
                            membership data → routed (defensive; avoids
                            clobbering NetBox tagged_vlans via PATCH)
      - anything else (``Disable``, etc.) → routed
    """
    tagging = (port_info.get("tagging") or "").lower()
    pvid = coerce_vid(port_info.get("pvid"))
    members = [v for v in member_vids if coerce_vid(v) is not None]

    if tagging == "untagall":
        # Access on PVID requires a valid PVID. ``coerce_vid`` returns None
        # for missing or out-of-range (1..4094) values — emitting
        # ``access_vlan=None`` would clobber the existing NetBox
        # untagged_vlan via PATCH, so fall back to routed defensively.
        # (Copilot P1 #391 round-11; matches the dell_powerconnect /
        # batch-4 tightening pattern.)
        if pvid is None:
            return SwitchportInfo(
                enabled=False,
                admin_mode=None,
                oper_mode=None,
                access_vlan=None,
                native_vlan=None,
                allowed_vlans=None,
            )
        return SwitchportInfo(
            enabled=True,
            admin_mode="access",
            oper_mode="access",
            access_vlan=pvid,
            native_vlan=None,
            allowed_vlans=None,
        )
    if tagging in ("untagpvidonly", "hybrid"):
        # Trunk-with-native. ERS Hybrid is the same NetBox-aligned semantics
        # as UntagPvidOnly: PVID is the untagged native, all other member
        # VLANs are tagged egress. Both require membership data — without
        # it, fall back to routed rather than emit a no-tagged-VLAN trunk
        # that would clobber the existing NetBox tagged_vlans via PATCH.
        if not members:
            return SwitchportInfo(
                enabled=False,
                admin_mode=None,
                oper_mode=None,
                access_vlan=None,
                native_vlan=None,
                allowed_vlans=None,
            )
        tagged = [v for v in members if v != pvid]
        return SwitchportInfo(
            enabled=True,
            admin_mode="trunk",
            oper_mode="trunk",
            access_vlan=None,
            native_vlan=pvid,
            allowed_vlans=tagged if tagged else None,
        )
    if tagging in ("tagall", "tagpvidonly"):
        # tagall: every egress frame is tagged, PVID included.
        # tagpvidonly: PVID frames are tagged on egress, other VLANs egress
        #   untagged. ERS allows multiple untagged-egress VLANs in this
        #   mode, which IEEE 802.1Q forbids and NetBox can't represent —
        #   the safest NetBox-aligned mapping is the same as TagAll
        #   (trunk, no untagged native, every member VLAN in the tagged
        #   list). Operators using TagPvidOnly for QinQ-style edge cases
        #   should expect a trunk-no-native NetBox shape, not access.
        # Both modes need membership data; without it → routed.
        if not members:
            return SwitchportInfo(
                enabled=False,
                admin_mode=None,
                oper_mode=None,
                access_vlan=None,
                native_vlan=None,
                allowed_vlans=None,
            )
        return SwitchportInfo(
            enabled=True,
            admin_mode="trunk",
            oper_mode="trunk",
            access_vlan=None,
            native_vlan=None,
            allowed_vlans=members,
        )

    # Disable / unknown → routed
    return SwitchportInfo(
        enabled=False,
        admin_mode=None,
        oper_mode=None,
        access_vlan=None,
        native_vlan=None,
        allowed_vlans=None,
    )


def _ers_row_port_tokens(row: dict) -> list[str]:
    """
    Return the raw port-list tokens from a parsed ``show vlan`` row.

    The ntc-template's ``vlan_port_members`` (List) field holds the
    actual port-member tokens, captured from the ``Port Members:``
    continuation line. The ``vlan_pid`` field is the **Protocol ID**
    column (a hex value like ``0x0000``) — explicitly NOT a port
    identifier despite the misleading name. (Copilot review #391
    round-10: the previous implementation treated ``vlan_pid`` as a
    port token, polluting the per-port aggregate with bogus entries.)
    """
    return [str(member) for member in (row.get("vlan_port_members", []) or [])]


def _expand_ers_wildcard(token: str, known_ports: set[str] | None) -> list[str] | None:
    """
    Resolve ``ALL`` / ``<unit>/ALL`` wildcards. Returns None on no match.

    Without ``known_ports`` wildcards always return ``[]`` (back-compat).
    """
    upper = token.strip().upper()
    if upper == "ALL":
        return sorted(known_ports) if known_ports else []
    if upper.endswith("/ALL"):
        if not known_ports:
            return []
        prefix = f"{upper[: -len('/ALL')]}/"
        return sorted(p for p in known_ports if p.startswith(prefix))
    return None


def _expand_ers_dashed_range(part: str) -> list[str]:
    """Expand a ``lo-hi`` range chunk; returns ``[part]`` on parse failure."""
    lo, _, hi = part.partition("-")
    if "/" in part:
        u_lo, _, p_lo = lo.partition("/")
        if "/" in hi:
            u_hi, _, p_hi = hi.partition("/")
            if u_lo != u_hi:
                return [part]
            hi_port_str = p_hi
        else:
            hi_port_str = hi
        try:
            return [f"{u_lo}/{p}" for p in range(int(p_lo), int(hi_port_str) + 1)]
        except ValueError:
            return [part]
    try:
        return [str(i) for i in range(int(lo), int(hi) + 1)]
    except ValueError:
        return [part]


def _expand_ers_port_chunk(part: str, known_ports: set[str] | None = None) -> list[str]:
    """
    Expand a single comma-separated chunk of an ERS port-list.

    ``known_ports`` is the set of canonical port keys discovered from
    ``show vlan interface info``. When provided, the chassis-wide ``ALL``
    keyword expands to every known port and the unit-wide ``<unit>/ALL``
    form expands to every known port whose token starts with ``<unit>/``.
    Without it (e.g. unit tests calling the helper directly) wildcards
    return an empty list, preserving back-compat (Codex P1 #391 round-7).
    """
    if not part or part.upper() == "NONE":
        return []
    wildcard = _expand_ers_wildcard(part, known_ports)
    if wildcard is not None:
        return wildcard
    if "-" not in part:
        return [part]
    return _expand_ers_dashed_range(part)


def _expand_ers_port_list(
    token: str, known_ports: set[str] | None = None,
) -> list[str]:
    """
    Expand the ``PortMembers`` / ``PID`` value of ``show vlan`` into port tokens.

    Accepts comma-separated lists, ``unit/start-unit/end`` ranges (``1/1-1/4``),
    same-unit ``unit/start-end`` ranges (``1/2-8``), bare-digit ranges, the
    literal ``ALL``/``NONE`` keywords, and the unit-wide ``<unit>/ALL`` form.

    ``ALL`` and ``<unit>/ALL`` resolve against ``known_ports`` (the set of
    ports discovered by ``show vlan interface info``) when provided —
    that's the source of truth for what the device actually has, so we
    never invent fake ports. Without ``known_ports`` (back-compat for
    direct-call unit tests) wildcards return an empty list.
    """
    if not token:
        return []
    upper = token.strip().upper()
    if upper == "NONE":
        return []
    if upper == "ALL":
        return sorted(known_ports) if known_ports else []
    if upper.endswith("/ALL") and "," not in token:
        return _expand_ers_port_chunk(token.strip(), known_ports)
    ports: list[str] = []
    for part in token.split(","):
        ports.extend(_expand_ers_port_chunk(part.strip(), known_ports))
    return ports


class ERSDriver(_napalm_base.NetworkDriver):
    """Avaya/Extreme ERS NAPALM driver (read-only subset for device-discovery)."""

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
            "extreme_ers", netmiko_optional_args=self.netmiko_optional_args
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

    def get_facts(self) -> dict:
        """Return general device facts."""
        facts = {
            "hostname": "Unknown",
            "vendor": "Avaya",
            "model": "Avaya ERS",
            "os_version": "Unknown",
            "serial_number": "Unknown",
            "uptime": -1.0,
            "fqdn": "Unknown",
            "interface_list": [],
        }

        sys_output = self.device.send_command("show sys-info")
        parsed = parse_output(platform="avaya_ers", command="show sys-info", data=sys_output)

        if not parsed:
            logger.warning("Failed to parse 'show sys-info'; returning default facts")
        else:
            row = parsed[0]
            uptime_str = row.get("sys_up_time", "")
            if uptime_str:
                facts["uptime"] = _parse_uptime(uptime_str)
            facts["hostname"] = row.get("sys_name", "Unknown") or "Unknown"
            facts["serial_number"] = row.get("serial_number", "Unknown") or "Unknown"
            facts["os_version"] = row.get("operational_software", "Unknown") or "Unknown"
            # ERS sys-info does not expose a human-readable model string; keep
            # the "Avaya ERS" fallback set above.

        # Interface list comes from show interface name
        intf_output = self.device.send_command("show interface name")
        intf_parsed = parse_output(
            platform="avaya_ers", command="show interface name", data=intf_output
        )
        facts["interface_list"] = [
            row["port"]
            for row in intf_parsed
            if row.get("port") and not row["port"].startswith("-")
        ]

        return facts

    def get_interfaces(self) -> dict:
        """
        Return interface details keyed by interface name.

        Uses ``show interfaces`` (status per port) and augments with
        interface names from ``show interface name``.
        """
        # --- interface names / descriptions ---
        name_output = self.device.send_command("show interface name")
        name_parsed = parse_output(
            platform="avaya_ers", command="show interface name", data=name_output
        )
        descriptions: dict[str, str] = {}
        for row in name_parsed:
            port = row.get("port", "")
            if port and not port.startswith("-"):
                descriptions[port] = row.get("name", "").strip()

        # --- interface status ---
        intf_output = self.device.send_command("show interfaces")
        interfaces: dict = {}

        for block_match in _INTF_BLOCK_RE.finditer(intf_output):
            block = block_match.group(0)
            header = _INTF_HEADER_RE.search(block)
            if not header:
                continue
            port = header.group(1)

            link_m = _LINK_RE.search(block)
            admin_m = _ADMIN_RE.search(block)
            speed_m = _SPEED_RE.search(block)
            mtu_m = _MTU_RE.search(block)
            mac_m = _MAC_RE.search(block)

            link_status = link_m.group(1).lower() if link_m else "down"
            admin_status = admin_m.group(1).lower() if admin_m else "up"
            speed_raw = speed_m.group(1) if speed_m else "0"
            mtu_raw = mtu_m.group(1) if mtu_m else "0"
            mac_raw = mac_m.group(1) if mac_m else ""

            try:
                mac_address = normalize_mac(mac_raw) if mac_raw else ""
            except Exception:
                mac_address = mac_raw

            interfaces[port] = {
                "is_up": link_status == "up",
                "is_enabled": admin_status != "disabled",
                "description": descriptions.get(port, ""),
                "last_flapped": -1.0,
                "mtu": int(mtu_raw) if mtu_raw.isdigit() else -1,
                "speed": float(speed_raw) if speed_raw.isdigit() else -1.0,
                "mac_address": mac_address,
            }

        # --- fall back: ports listed in interface name but not in show interfaces ---
        for port, desc in descriptions.items():
            if port not in interfaces:
                interfaces[port] = {
                    "is_up": False,
                    "is_enabled": True,
                    "description": desc,
                    "last_flapped": -1.0,
                    "mtu": -1,
                    "speed": -1.0,
                    "mac_address": "",
                }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """
        Return IP addresses per interface.

        Parses ``show ip interface`` for IPv4 and ``show ipv6 interface``
        for IPv6.  Falls back gracefully if IPv6 is not configured.
        """
        interfaces_ip: dict = {}

        # --- IPv4 ---
        ipv4_output = self.device.send_command("show ip interface")
        _collect_ipv4(ipv4_output, interfaces_ip)

        # --- IPv6 ---
        ipv6_output = self.device.send_command("show ipv6 interface")
        _collect_ipv6(ipv6_output, interfaces_ip)

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
        running_config = ""
        if retrieve in ("running", "startup", "all"):
            running_config = self.device.send_command("show running-config")

        if retrieve in ("running", "all"):
            config["running"] = running_config

        if retrieve in ("startup", "all"):
            # ERS does not distinguish startup from running config; mirror the
            # running config rather than silently returning an empty startup.
            config["startup"] = running_config

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Return VLAN information keyed by VLAN ID string."""
        output = self.device.send_command("show vlan")
        parsed = parse_output(platform="avaya_ers", command="show vlan", data=output)

        vlans: dict = {}
        for row in parsed:
            vlan_id = row.get("vlan_id", "")
            if not vlan_id:
                continue
            entry = vlans.setdefault(
                vlan_id,
                {
                    "name": row.get("vlan_name", "") or vlan_id,
                    "interfaces": [],
                },
            )
            for member in row.get("vlan_port_members", []):
                for port in _expand_port_range(member):
                    if port and port not in entry["interfaces"]:
                        entry["interfaces"].append(port)

        return vlans

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """
        Return per-interface VLAN config keyed by ERS port token.

        Combines two CLI commands:

        - ``show vlan interface info`` — per-port PVID and tagging mode
          (``UntagAll``, ``UntagPvidOnly``, ``TagAll``, ``Disable``).
        - ``show vlan`` — per-VLAN port membership (used to build per-port
          tagged-VLAN lists by inverting the per-VLAN view).
        """
        try:
            info_raw = self.device.send_command("show vlan interface info")
        except Exception:
            logger.debug("ERS show vlan interface info failed", exc_info=True)
            return {}
        per_port_info = _parse_ers_show_vlan_interface_info(info_raw or "")
        if not per_port_info:
            return {}

        per_port_members = self._collect_ers_per_port_membership(set(per_port_info))

        result: dict[str, dict] = {}
        for port, info in per_port_info.items():
            members = per_port_members.get(port, [])
            sw = _ers_aggregate_to_switchport(info, members)
            result[port] = classify_switchport(sw)
        return result

    def _collect_ers_per_port_membership(
        self, known_ports: set[str],
    ) -> dict[str, list[int]]:
        """
        Invert ``show vlan`` to produce ``{port: [vid, ...]}`` membership.

        ``known_ports`` is the set of ports discovered from
        ``show vlan interface info`` and acts as the catalog used to
        expand chassis-wide (``ALL``) and unit-wide (``<unit>/ALL``)
        wildcards into concrete port keys (Codex P1 #391 round-7).
        """
        try:
            vlan_raw = self.device.send_command("show vlan")
            parsed = parse_output(
                platform="avaya_ers", command="show vlan", data=vlan_raw
            )
        except Exception:
            logger.debug("ERS show vlan failed", exc_info=True)
            parsed = []

        per_port_members: dict[str, list[int]] = {}
        for row in parsed or []:
            vid = coerce_vid(row.get("vlan_id", ""))
            if vid is None:
                continue
            for token in _ers_row_port_tokens(row):
                for port in _expand_ers_port_list(token, known_ports):
                    members = per_port_members.setdefault(port, [])
                    if vid not in members:
                        members.append(vid)
        return per_port_members


# ---------------------------------------------------------------------------
# Module-level helpers (kept out of class to stay close to their usage)
# ---------------------------------------------------------------------------


def _expand_port_range(token: str) -> list[str]:
    """
    Expand a VLAN port-member token into individual port name strings.

    The ntc-template returns each ``Port Members`` continuation line as one
    token that may itself be a comma-separated list of entries.  Each entry is
    one of:

    - ``"NONE"``       → empty list
    - ``"1/1"``        → ``["1/1"]``
    - ``"1"``          → ``["1"]``
    - ``"2-4"``        → ``["2", "3", "4"]``
    - ``"1/2-8"``      → ``["1/2", "1/3", …, "1/8"]``  (same-unit range)
    - ``"1/1,1/49,…"`` → expanded recursively for each comma-separated part

    Entries that cannot be parsed are passed through as-is.
    """
    ports: list[str] = []
    # Split comma-separated compound tokens first
    for part in token.split(","):
        part = part.strip()
        if not part or part.upper() == "NONE":
            continue
        if "-" in part:
            # May be "2-4" or "1/2-8"
            if "/" in part:
                # unit/port-start - port-end  e.g. "1/2-8"
                unit, rest = part.split("/", 1)
                if "-" in rest:
                    p_start, _, p_end = rest.partition("-")
                    try:
                        ports.extend(
                            f"{unit}/{p}"
                            for p in range(int(p_start), int(p_end) + 1)
                        )
                        continue
                    except ValueError:
                        pass
            else:
                # simple "2-4"
                start, _, end = part.partition("-")
                try:
                    ports.extend(str(i) for i in range(int(start), int(end) + 1))
                    continue
                except ValueError:
                    pass
        ports.append(part)
    return ports


def _collect_ipv4(output: str, interfaces_ip: dict) -> None:
    """
    Parse ``show ip interface`` output and populate *interfaces_ip*.

    ERS section format::

        Interface : Vlan 1
            IP Address      : 10.0.0.1
            Mask            : 255.255.255.0
    """
    if not output:
        return
    # Split on "Interface :" section headers
    sections = _IP_SECTION_RE.split(output)
    # sections[0] is the preamble; rest are the bodies after each "Interface :"
    for body in sections[1:]:
        header_m = _IP_HEADER_RE.search("Interface :" + body)
        if not header_m:
            continue
        intf_name = header_m.group(1).strip()
        addr_m = _IPV4_ADDR_RE.search(body)
        mask_m = _IPV4_MASK_RE.search(body)
        if addr_m and mask_m:
            ip = addr_m.group(1)
            prefix = _mask_to_prefix(mask_m.group(1))
            interfaces_ip.setdefault(intf_name, {}).setdefault("ipv4", {})[ip] = {
                "prefix_length": prefix
            }


def _collect_ipv6(output: str, interfaces_ip: dict) -> None:
    """
    Parse ``show ipv6 interface`` output and populate *interfaces_ip*.

    ERS section format::

        Interface : Vlan 1
            IPv6 Address  : 2001:db8::1/64
    """
    if not output:
        return
    sections = _IP_SECTION_RE.split(output)
    for body in sections[1:]:
        header_m = _IP_HEADER_RE.search("Interface :" + body)
        if not header_m:
            continue
        intf_name = header_m.group(1).strip()
        for m in _IPV6_RE.finditer(body):
            addr_str = m.group(1)
            if "/" in addr_str:
                addr, prefix_str = addr_str.rsplit("/", 1)
                prefix = int(prefix_str)
            else:
                addr, prefix = addr_str, 128
            interfaces_ip.setdefault(intf_name, {}).setdefault("ipv6", {})[addr] = {
                "prefix_length": prefix
            }
