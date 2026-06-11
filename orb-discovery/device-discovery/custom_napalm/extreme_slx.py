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
from napalm.base.helpers import mac as normalize_mac
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import ParsingException, parse_output
from textfsm import TextFSMError

from custom_napalm._vlan import (
    SwitchportInfo,
    classify_switchport,
    coerce_vid,
)

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

# --- show interface (no-arg) MAC parser ------------------------------------ #
# SLX-OS ``show interface`` (no port-arg — the command get_interfaces issues)
# emits one multi-line block per port:
#
#   Ethernet 0/1 is up, line protocol is up (connected)
#   Hardware is Ethernet, address is 6cb1.580f.b900 (bia 6cb1.580f.b900)
#   Description: ...
#   ...
#
# We pair each ``<Type> <id>`` header line with the next ``address is <mac>``
# line in the same block. The MAC capture is permissive — napalm.mac() does
# the actual validation/normalisation so dotted (``xxxx.xxxx.xxxx``), dashed,
# and colon-separated forms all resolve. ``bia <mac>`` (burned-in address)
# appears in parentheses after the configured address; we always take the
# FIRST ``address is`` value, which is the operational MAC NetBox expects.
_INTF_HEADER_RE = re.compile(
    r"^((?:Ethernet|Management|Port-channel|Loopback|Ve)\s+\S+)\s+is\s+\S+",
    re.M | re.IGNORECASE,
)
_INTF_HW_ADDR_RE = re.compile(
    # End-of-token boundary (\b) prevents the capture group from greedily
    # absorbing an adjacent string that happens to start with hex chars.
    # SLX-OS emits a trailing ``(bia <mac>)`` after the configured address
    # so we need to stop at the boundary, not the end of line.
    r"^\s*Hardware\s+is\s+\S+,\s+address\s+is\s+([0-9a-fA-F:.\-]{12,17})\b",
    re.M | re.IGNORECASE,
)


def _parse_intf_hw_addresses(text: str) -> dict[str, str]:
    """
    Parse ``show interface`` (no port-arg) multi-block output → ``{name: mac}``.

    Iterates over interface-header positions and, for each one, looks for
    the next ``Hardware is ..., address is <mac>`` line before the next
    header. Blocks without a Hardware/address line are silently skipped
    (loopbacks, VEs, port-channels often lack a per-port burned-in MAC).
    """
    result: dict[str, str] = {}
    if not text:
        return result
    headers = list(_INTF_HEADER_RE.finditer(text))
    for i, hdr in enumerate(headers):
        name = re.sub(r"\s+", " ", hdr.group(1).strip())
        # Restrict MAC search to this block: from after the header to the start
        # of the next header (or end of text for the last block).
        block_end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        block = text[hdr.end():block_end]
        mac_m = _INTF_HW_ADDR_RE.search(block)
        if not mac_m:
            continue
        raw = mac_m.group(1)
        try:
            result[name] = normalize_mac(raw)
        except Exception:
            # napalm normalize_mac rejected the value — log and skip rather
            # than emit a malformed MAC string that downstream NetBox matching
            # would silently treat as a distinct interface.
            logger.warning(
                "extreme_slx: normalize_mac rejected %r for interface %s — emitting empty MAC",
                raw, name,
            )
    return result

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
# Same pre-stripped Management rows, but capturing the Vrf column so VRF
# discovery doesn't lose mgmt-vrf membership (or the VRF itself when it
# appears only on Management interfaces).
_MGMT_VRF_RE = re.compile(
    r"^\s*(Management\s+\S+)\s+\S+\s+(\S+)\s",
    re.IGNORECASE,
)
# Regex fallback for VRF discovery when the ntc-template fails entirely —
# the interface + Vrf columns of the same interface-type set
# _INTF_IP_FALLBACK_RE covers, so a single unparseable row can't empty the
# whole VRF discovery result. Other row types (e.g. Tunnel) are skipped by
# design: interface discovery doesn't emit them either, so their VRF
# membership could never join an Interface/IP entity.
_INTF_VRF_FALLBACK_RE = re.compile(
    r"^\s*((?:Ethernet|Management|Port-channel|Loopback|Ve)\s+\S+)\s+\S+\s+(\S+)\s",
    re.IGNORECASE,
)


def _slx_vrf_memberships(output: str) -> list[tuple[str, str]]:
    """
    Extract (interface, vrf) pairs from ``show ip interface brief`` output.

    Management rows are pre-stripped before template parsing (the
    ntc-template error-exits on them) and recovered with _MGMT_VRF_RE;
    when the template fails on any other row, the whole output falls back
    to _INTF_VRF_FALLBACK_RE — the same contract get_interfaces_ip()
    follows for addresses.
    """
    memberships: list[tuple[str, str]] = []
    filtered = "\n".join(
        line for line in output.splitlines() if not _MGMT_LINE_RE.match(line)
    )
    try:
        rows = parse_output(
            platform="extreme_slxos",
            command="show ip interface brief",
            data=filtered,
        )
    except (TextFSMError, ParsingException):
        logger.warning(
            "slxos: ntc-template failed for 'show ip interface brief'; "
            "falling back to regex for VRF discovery",
            exc_info=True,
        )
        for line in output.splitlines():
            m = _INTF_VRF_FALLBACK_RE.match(line)
            if m:
                memberships.append((m.group(1).strip(), m.group(2).strip()))
        return memberships
    memberships.extend(
        ((row.get("interface") or "").strip(), (row.get("vrf") or "").strip())
        for row in rows
    )
    # Recover the pre-stripped Management rows' Vrf column (the fallback
    # branch above already covers them).
    for line in output.splitlines():
        m = _MGMT_VRF_RE.match(line)
        if m:
            memberships.append((m.group(1).strip(), m.group(2).strip()))
    return memberships
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


# --- vlan brief tagged/untagged token parsing ----------------------------- #
# Match a port token together with its trailing "(u)"/"(t)" state flag, e.g.
# "Eth 0/1(u)" or "Po 1(t)". Captures (token_with_no_flag_after_expand_call,
# flag_letter).  We deliberately keep a SEPARATE regex from _VLAN_PORT_RE so
# the existing get_vlans() path (which does not need the flag) is untouched.
_VLAN_PORT_FLAG_RE = re.compile(
    r"((?:Eth|Po)\s+\S+?)\(([ut])\)",
    re.IGNORECASE,
)


def _parse_slx_vlan_brief(text: str) -> list[dict]:
    """
    Parse `show vlan brief` into ``[{vlan_id: int, ports: [(name, flag), ...]}, ...]``.

    Each ``ports`` entry is ``(canonical_port_name, "u"|"t")`` so the inverter
    can decide tagging without re-running the port regex. Continuation lines
    (port lists wrapping onto subsequent lines) extend the previously seen
    VLAN's port list, mirroring the wrap handling in ``get_vlans()``.

    Tokens without an explicit ``(u)``/``(t)`` flag are ignored — SLX-OS
    always emits a flag for member ports in this command output.
    """
    rows: list[dict] = []
    current: dict | None = None
    for line in text.splitlines():
        m = _VLAN_ROW_RE.match(line)
        if m:
            try:
                vlan_id = int(m.group(1))
            except ValueError:
                current = None
                continue
            port_str = m.group(3) or ""
            ports = [
                (_expand_vlan_port(tok), flag.lower())
                for tok, flag in _VLAN_PORT_FLAG_RE.findall(port_str)
            ]
            current = {"vlan_id": vlan_id, "ports": ports}
            rows.append(current)
        elif current is not None and _VLAN_PORT_FLAG_RE.search(line):
            current["ports"].extend(
                (_expand_vlan_port(tok), flag.lower())
                for tok, flag in _VLAN_PORT_FLAG_RE.findall(line)
            )
    return rows


def _slx_invert_vlan_brief(rows: list[dict]) -> dict[str, dict]:
    """
    Invert per-VLAN port-membership rows into per-port aggregates.

    Returns ``{port_name: {"untagged": list[int], "tagged": list[int]}}`` keyed
    by canonical interface names (already expanded by :func:`_expand_vlan_port`).
    Each list is deduplicated. VLAN IDs are clamped to 1..4094 via
    :func:`coerce_vid`; out-of-range values are dropped silently.

    The aggregator (:func:`_slx_aggregate_to_switchport`) treats >1 untagged
    VIDs for the same port as anomalous → routed, so we preserve the full
    list rather than picking last-seen.
    """
    per_port: dict[str, dict] = {}
    for row in rows:
        vid = coerce_vid(row.get("vlan_id"))
        if vid is None:
            continue
        for name, flag in row.get("ports", []):
            entry = per_port.setdefault(name, {"untagged": [], "tagged": []})
            if flag == "u":
                if vid not in entry["untagged"]:
                    entry["untagged"].append(vid)
            elif flag == "t" and vid not in entry["tagged"]:
                entry["tagged"].append(vid)
    return per_port


def _slx_aggregate_to_switchport(per_port: dict) -> SwitchportInfo:
    """
    Map a single port's aggregated ``{untagged, tagged}`` to a SwitchportInfo.

    Membership shape implies the mode (SLX-OS ``show vlan brief`` does not
    carry an admin-mode column):

    * exactly one untagged + no tagged → access on the untagged VID.
    * exactly one untagged + ≥1 tagged → trunk with that VID as native.
    * tagged-only → trunk with no native VLAN.
    * >1 untagged → routed (anomalous; IEEE 802.1Q forbids it).
    * neither → routed/excluded (caller omits the port from output).

    Accepts the legacy scalar-untagged shape (``untagged: int|None``) for
    backwards compatibility; the inversion helper now emits the list shape.
    """
    raw_untagged = per_port.get("untagged")
    if isinstance(raw_untagged, list):
        untagged = [v for v in raw_untagged if coerce_vid(v) is not None]
    else:
        single = coerce_vid(raw_untagged)
        untagged = [single] if single is not None else []
    tagged = [v for v in (per_port.get("tagged") or []) if coerce_vid(v) is not None]

    if len(untagged) > 1:
        return SwitchportInfo(
            enabled=False,
            admin_mode=None,
            oper_mode=None,
            access_vlan=None,
            native_vlan=None,
            allowed_vlans=None,
        )
    if not untagged and not tagged:
        return SwitchportInfo(
            enabled=False,
            admin_mode=None,
            oper_mode=None,
            access_vlan=None,
            native_vlan=None,
            allowed_vlans=None,
        )
    if untagged and not tagged:
        return SwitchportInfo(
            enabled=True,
            admin_mode="access",
            oper_mode="access",
            access_vlan=untagged[0],
            native_vlan=None,
            allowed_vlans=None,
        )
    return SwitchportInfo(
        enabled=True,
        admin_mode="trunk",
        oper_mode="trunk",
        access_vlan=None,
        native_vlan=untagged[0] if untagged else None,
        allowed_vlans=tagged if tagged else None,
    )


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
        """
        Return interface details keyed by interface name.

        Per-port MAC is sourced from ``show interface`` (no port-arg) —
        SLX-OS emits one block per port in a single command, so MAC fetch
        is one extra round-trip regardless of port count.
        """
        output = self.device.send_command("show interface brief")
        if not output:
            return {}

        mac_by_intf = _parse_intf_hw_addresses(
            self.device.send_command("show interface")
        )

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
                "mac_address": mac_by_intf.get(name, ""),
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

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """Return per-interface VLAN config from `show vlan brief`."""
        try:
            raw = self.device.send_command("show vlan brief")
        except Exception:
            logger.debug("SLX show vlan brief failed", exc_info=True)
            return {}
        if not raw:
            return {}
        rows = _parse_slx_vlan_brief(raw)
        per_port = _slx_invert_vlan_brief(rows)
        result: dict[str, dict] = {}
        for port, data in per_port.items():
            info = _slx_aggregate_to_switchport(data)
            result[port] = classify_switchport(info)
        return result

    def get_network_instances(self, name: str = "") -> dict:
        """
        Return network instances (SLX-OS VRFs), NAPALM OC shape.

        Derived from the Vrf column of ``show ip interface brief`` — the
        same template-parsed rows get_interfaces_ip() consumes, so member
        names join exactly. ``default-vrf`` is the global routing table
        (DEFAULT_INSTANCE, empty membership); ``mgmt-vrf`` is a real VRF
        and is kept. Management interfaces are pre-stripped before
        template parsing (the ntc-template error-exits on those rows)
        and recovered with a dedicated regex — mirroring how
        get_interfaces_ip() recovers their addresses — so mgmt-vrf
        survives even when it appears only on Management interfaces.
        Limitations: enumeration is membership-derived (an interface-less
        VRF does not appear) and route distinguishers are not collected
        (they live in ``show vrf detail``).
        """
        instances: dict = {
            "default-vrf": {
                "name": "default-vrf",
                "type": "DEFAULT_INSTANCE",
                "state": {"route_distinguisher": ""},
                "interfaces": {"interface": {}},
            },
        }
        output = self.device.send_command("show ip interface brief")
        memberships: list[tuple[str, str]] = []
        if output and output.strip():
            memberships = _slx_vrf_memberships(output)
        for ifname, vrf_name in memberships:
            # default-vrf rows belong to the seeded DEFAULT_INSTANCE.
            if not vrf_name or not ifname or vrf_name == "default-vrf":
                continue
            instances.setdefault(
                vrf_name,
                {
                    "name": vrf_name,
                    "type": "L3VRF",
                    "state": {"route_distinguisher": ""},
                    "interfaces": {"interface": {}},
                },
            )["interfaces"]["interface"][ifname] = {}
        if name:
            return {name: instances[name]} if name in instances else {}
        return instances
