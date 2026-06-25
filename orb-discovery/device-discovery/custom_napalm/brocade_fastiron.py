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

from custom_napalm._chassis import ChassisMember, normalize_role, to_payload
from custom_napalm._vlan import (
    SwitchportInfo,
    classify_switchport,
    coerce_vid,
)

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

    Handles both stacked ports (``1/1/1 to 1/1/4``) and the single-component
    form used by older CES/CER hardware (``11 to 14`` → ``["11", "12",
    "13", "14"]``). Cross-module or cross-unit ranges fall back to
    returning only the two endpoints.
    """
    s_parts = start.split("/")
    e_parts = end.split("/")
    if len(s_parts) != len(e_parts) or s_parts[:-1] != e_parts[:-1]:
        return [start, end]
    try:
        s_num, e_num = int(s_parts[-1]), int(e_parts[-1])
    except ValueError:
        return [start, end]
    head = s_parts[:-1]
    prefix = "/".join(head) + "/" if head else ""
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


# ---------------------------------------------------------------------------
# get_interfaces_vlans helpers
# ---------------------------------------------------------------------------


def _expand_fastiron_ports(text: str) -> list[str]:
    """
    Expand a FastIron port-list string from `show running-config vlan` into bare port IDs.

    Examples::

        "ethe 1/1/1 to 1/1/4"          → ["1/1/1", "1/1/2", "1/1/3", "1/1/4"]
        "ethe 1/1/1 ethe 1/1/3"        → ["1/1/1", "1/1/3"]
        "lag 15 to 17"                 → ["lag15", "lag16", "lag17"]
        "ethe 1/1/1 ethe 1/2/4:1"      → ["1/1/1", "1/2/4:1"]

    Returns the canonical port form used by ``get_vlans()`` and
    ``get_interfaces()`` (bare port IDs for physical ports, ``lag<N>`` for
    LAGs, ``ve<N>`` for VEs).
    """
    if not text:
        return []
    return _split_port_list(text)


def _invert_fastiron_vlan_config(raw: str) -> dict[str, dict]:
    """
    Invert ``show running-config vlan`` into ``{port: {untagged, tagged}}``.

    Walks the line stream tracking the active VLAN ID and, within each block,
    folds ``untagged ...`` and ``tagged ...`` member lines into per-port
    aggregates. Uses the regex helpers shared with ``get_vlans()`` so LAGs
    (``lag <N>``) and VEs are captured alongside physical ``ethe`` ports.
    """
    per_port: dict[str, dict] = {}
    current_vid: int | None = None
    for line in raw.splitlines():
        m_hdr = _VLAN_HDR_RE.match(line)
        if m_hdr:
            current_vid = coerce_vid(m_hdr.group("id"))
            continue
        if current_vid is None:
            continue
        m_un = _UNTAGGED_RE.match(line)
        if m_un:
            for port in _split_port_list(m_un.group("ports")):
                entry = per_port.setdefault(port, {"untagged": None, "tagged": []})
                entry["untagged"] = current_vid
            continue
        m_tg = _TAGGED_RE.match(line)
        if m_tg:
            for port in _split_port_list(m_tg.group("ports")):
                entry = per_port.setdefault(port, {"untagged": None, "tagged": []})
                if current_vid not in entry["tagged"]:
                    entry["tagged"].append(current_vid)
    return per_port


def _fastiron_aggregate_to_switchport(per_port: dict) -> SwitchportInfo:
    """
    Map a per-port aggregate ``{untagged: int|None, tagged: list[int]}`` to a SwitchportInfo.

    FastIron has no explicit access/trunk admin field at the port level — mode
    is derived from the membership shape:

      - exactly one untagged, no tagged   → access on the untagged VID
      - one untagged + ≥1 tagged          → trunk with the untagged as native
        (this is the dual-mode trunk pattern)
      - no untagged + ≥1 tagged           → trunk with no native
      - no membership at all              → routed (caller normally omits)
    """
    untagged_vid = coerce_vid(per_port.get("untagged"))
    tagged_vids = [v for v in (per_port.get("tagged") or []) if coerce_vid(v) is not None]

    if untagged_vid is None and not tagged_vids:
        return SwitchportInfo(
            enabled=False,
            admin_mode=None,
            oper_mode=None,
            access_vlan=None,
            native_vlan=None,
            allowed_vlans=None,
        )
    if untagged_vid is not None and not tagged_vids:
        return SwitchportInfo(
            enabled=True,
            admin_mode="access",
            oper_mode="access",
            access_vlan=untagged_vid,
            native_vlan=None,
            allowed_vlans=None,
        )
    return SwitchportInfo(
        enabled=True,
        admin_mode="trunk",
        oper_mode="trunk",
        access_vlan=None,
        native_vlan=untagged_vid,
        allowed_vlans=list(tagged_vids),
    )


# ---------------------------------------------------------------------------
# Stack discovery — Brocade / Ruckus ICX stacking
# ---------------------------------------------------------------------------
#
# `show stack` on an ICX 7xxx stack produces a fixed-width row table preceded
# by a banner and a column header::
#
#     T=11:54:25 GMT-04:00, eta 22h 5m remaining
#     alone: standalone, D: dynamic config, S: static config,
#       A: active, B: backup, M: member, X: not joined
#     ID    Type            Role     Mac Address     Pri State   Comment
#     1   S ICX7250-24P    active    cc4e.246b.b800 128  local   Ready
#     2   S ICX7250-24P    standby   cc4e.246b.c700 128  remote  Ready
#
# The ID column is the stack-member id. `D`/`S` is the configured-member type
# (dynamic vs. static). `Type` is the device model. `Role` is the live role
# (`active`, `standby`, `member`). `Mac Address` is the unit's stacking MAC in
# Cisco-dotted form. `Pri` is the stack-election priority. `State` is the
# connection location (`local`, `remote`, `reserve`). `Comment` is free text
# (`Ready` / `Down` / `Reserved` / …) and is intentionally not consumed.
#
# Standalone ICX (no stack) emits `No stack`-style banners; the regex won't
# match anything and the impl returns None at DEBUG.

_FASTIRON_STACK_ROW_RE = re.compile(
    r"""
    ^\s*
    (?P<id>\d+)\s+                          # ID
    (?P<cfg>[A-Za-z])\s+                    # Cfg (canonical D/S; widened to any
                                            # single letter to tolerate variant
                                            # IronWare markers we haven't seen
                                            # in the wild but which the legend
                                            # describes (M / R / etc.))
    (?P<model>\S+)\s+                       # Type (model token)
    (?P<role>[A-Za-z]+)\s+                  # Role (active/standby/member/alone)
    (?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})   # MAC (Cisco-dotted)
    \s+(?P<priority>\d+)                    # Pri
    \s+(?P<state>\S+)                       # State (local/remote/reserve)
    """,
    re.VERBOSE,
)


def _parse_fastiron_stack(text: str) -> list[dict]:
    """
    Parse `show stack` row table into a list of member dicts.

    Returns ``[{"id": int, "role": str, "priority": int, "mac": str,
    "state": str, "model": str}, ...]``. Header / legend / topology-art
    lines fail the regex and are skipped silently.
    """
    rows: list[dict] = []
    for line in (text or "").splitlines():
        m = _FASTIRON_STACK_ROW_RE.match(line)
        if not m:
            continue
        rows.append({
            "id": int(m.group("id")),
            "role": m.group("role"),
            "priority": int(m.group("priority")),
            "mac": m.group("mac"),
            "state": m.group("state"),
            "model": m.group("model"),
        })
    return rows


_FASTIRON_UNIT_HEADER_RE = re.compile(
    r"^UNIT\s+(?P<id>\d+):\s+SL\s+\d+:\s+(?P<model>\S+)\b",
    re.IGNORECASE,
)
# Most FastIron releases print ``Serial  #: <SN>``; some legacy outputs drop
# the ``#``. The regex accepts both forms — ``Serial #:`` with any amount of
# whitespace between ``Serial`` and ``#`` *or* a bare ``Serial:`` colon.
_FASTIRON_UNIT_SERIAL_RE = re.compile(
    r"^\s*Serial\s*#?\s*:\s*(?P<serial>\S+)",
    re.IGNORECASE,
)


def _parse_fastiron_version_units(text: str) -> tuple[
    dict[int, str], dict[int, str]
]:
    """
    Parse ``show version`` Hardware-section UNIT blocks into per-unit data.

    Returns ``(serial_by_unit, model_by_unit)`` keyed by stack-member id.
    We parse driver-locally instead of via the ntc-template because the
    template's Hardware-state Model+POE rule treats the literal ``POE``
    token as case-sensitive, which silently breaks parsing on ICX7250
    ``PoE`` / ``PoE+`` units — a very common stack hardware mix. First
    `UNIT N: SL n: <MODEL>` line wins for ``model``; first
    `Serial #: <SN>` line after a unit header wins for ``serial``.
    Subsequent rows for the same unit (license, additional modules) are
    ignored.
    """
    serial_by_id: dict[int, str] = {}
    model_by_id: dict[int, str] = {}
    current_id: int | None = None
    for line in (text or "").splitlines():
        m_header = _FASTIRON_UNIT_HEADER_RE.match(line)
        if m_header:
            try:
                current_id = int(m_header.group("id"))
            except (TypeError, ValueError):
                current_id = None
                continue
            model = (m_header.group("model") or "").strip()
            if model and current_id not in model_by_id:
                model_by_id[current_id] = model
            continue
        if current_id is None:
            continue
        m_serial = _FASTIRON_UNIT_SERIAL_RE.match(line)
        if m_serial:
            sn = (m_serial.group("serial") or "").strip()
            if sn and current_id not in serial_by_id:
                serial_by_id[current_id] = sn
    return serial_by_id, model_by_id


def _fastiron_get_chassis_members_impl(driver) -> dict | None:
    """
    Implementation of ``FastIronDriver.get_chassis_members`` (factored for testability).

    Parses ``show stack`` for member id / role / priority / MAC, joins to
    ``show version`` for per-unit serial + model (keyed by stack-member id —
    both commands use the same id space). Standalone ICX falls through to
    None (no rows in ``show stack``); a multi-member payload is validated
    by translate's ``validate_chassis_payload`` (requires ≥2 members).
    """
    try:
        stack_out = driver.device.send_command("show stack")
    except Exception:
        logger.warning(
            "brocade_fastiron.get_chassis_members: show stack failed", exc_info=True
        )
        return None

    rows = _parse_fastiron_stack(stack_out or "")
    if not rows:
        # Standalone ICX emits `No stack` banners; older FastIron releases
        # may not support `show stack` at all. Both are the no-stack path
        # — log at DEBUG and let translate use the single-Device path.
        logger.debug(
            "brocade_fastiron.get_chassis_members: no stack rows in `show stack` output"
        )
        return None

    try:
        ver_out = driver.device.send_command("show version")
    except Exception:
        # Non-fatal: members without a serial join are dropped by
        # ``to_payload()``. The show-stack table is still useful in logs.
        logger.warning(
            "brocade_fastiron.get_chassis_members: show version failed",
            exc_info=True,
        )
        ver_out = ""

    serial_by_id, model_by_id = _parse_fastiron_version_units(ver_out or "")

    members: list[ChassisMember] = []
    for row in rows:
        sid = row["id"]
        # MAC is regex-validated to Cisco-dotted form before reaching here,
        # but ``napalm.base.helpers.mac()`` delegates to ``netaddr.EUI`` whose
        # error class (``AddrFormatError``) extends ``Exception`` directly,
        # not ``ValueError``. Catch broadly so a future regex relaxation
        # never crashes discovery.
        try:
            mac_canon = normalize_mac(row["mac"])
        except Exception:
            mac_canon = None
        members.append(
            ChassisMember(
                id=sid,
                serial=serial_by_id.get(sid, ""),
                # `show version`'s MODEL list is authoritative (it captures
                # the exact PID); `show stack`'s Type column is a backup
                # used only when version data isn't joined.
                model=model_by_id.get(sid) or row.get("model"),
                role=normalize_role(row["role"]),
                priority=row["priority"],
                mac=mac_canon,
                state=row["state"],
            )
        )
    return to_payload(members, domain=None)


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

    def get_chassis_members(self) -> dict | None:
        """
        Return stack-member info for Brocade / Ruckus ICX stacks.

        Standalone ICX (no stack) returns None; multi-member stacks emit the
        payload consumed by ``device_discovery.translate``'s VirtualChassis
        emission path.
        """
        return _fastiron_get_chassis_members_impl(self)

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """
        Return per-interface VLAN configuration from ``show running-config vlan``.

        FastIron uses per-VLAN config blocks (``vlan <id> ... untagged ethe ...
        tagged ethe ...``); we invert that into per-port membership and then
        derive the access/trunk mode from the membership shape:

        - Port appears only as ``untagged`` in VLAN X         → access on X.
        - Port appears as ``untagged`` in X **and** ``tagged`` → trunk with
          native=X, tagged=[Y, Z] (dual-mode pattern).
        - Port appears only as ``tagged`` in some VLANs       → trunk with
          native=None, tagged=[...].
        - Port not seen anywhere → omitted (no first-class wildcard).

        Parsing uses regex (the same path as ``get_vlans()``) rather than the
        ``brocade_fastiron`` ntc-template, because that template only emits
        ``ethe`` ports — LAG members declared as ``tagged lag <N>`` /
        ``untagged lag <N>`` would be silently dropped by the template.
        """
        try:
            raw = self.device.send_command("show running-config vlan")
        except Exception:
            logger.debug("FastIron show running-config vlan failed", exc_info=True)
            return {}

        per_port = _invert_fastiron_vlan_config(raw)
        result: dict[str, dict] = {}
        for port, data in per_port.items():
            info = _fastiron_aggregate_to_switchport(data)
            result[port] = classify_switchport(info)
        return result
