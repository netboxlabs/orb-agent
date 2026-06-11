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

from custom_napalm._vlan import (
    SwitchportInfo,
    classify_switchport,
    coerce_vid,
)

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
# Port list helpers (shared with get_interfaces_vlans)
# ---------------------------------------------------------------------------

# Tokens that introduce a physical port ID (the next token is the bare port).
# NetIron MLX/CES/CER running-config emits the short ``e``/``eth`` form
# alongside the long ``ethe``/``ethernet`` form depending on platform and
# software version, so all four are recognised.
_NETIRON_ETHE_TOKENS = frozenset({"e", "eth", "ethe", "ethernet"})

# Tokens that form a named interface together with the following numeric ID.
# e.g. ``lag 10`` → ``lag10``, ``ve 555`` → ``ve555``
_NETIRON_PREFIX_TOKENS = frozenset({"lag", "ve"})

# Matches physical port IDs including breakout (colon) notation: 1/1, 12/1, 1/2:1
_NETIRON_PORT_ID_RE = re.compile(r"^\d+(?:[/:]\d+)*$")


def _netiron_expand_port_range(start: str, end: str) -> list[str]:
    """
    Expand a NetIron port range into individual port IDs.

    Handles both chassis-style ports (``1/1 to 1/4``) and the single-component
    form sometimes seen on CES platforms (``1 to 4`` → ``["1", "2", "3",
    "4"]``). Cross-slot ranges fall back to returning only the two endpoints.

    The bare-digit form must keep its leading character — historical FastIron
    bug (#390) emitted ``["/1", "/2", ...]`` because the prefix builder
    unconditionally appended a slash even when the head list was empty.
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


def _netiron_split_port_list(port_str: str) -> list[str]:
    """
    Split a NetIron port-list string into individual port IDs.

    Handles:
    - Space-separated port IDs:  ``1/1 1/2``
    - Type-prefixed ports:       ``e 1/1 e 1/2`` / ``ethe 1/1 ethe 1/2``
    - Range notation:            ``e 1/1 to 1/4`` / ``ethe 1/1 to 1/4``
    - LAG members:               ``lag 5`` / ``lag 5 to 7``
    - Virtual interfaces:        ``ve 100``

    Ranges that share the same unit/slot prefix are fully expanded; cross-slot
    ranges yield only the two endpoints. Returns the canonical port form used
    by ``get_vlans()`` and ``get_interfaces()``: bare port IDs for physical
    ports (``1/1``), ``lag<N>`` for LAGs, ``ve<N>`` for VEs.
    """
    tokens = port_str.split()
    ports: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i].lower()
        if tok in _NETIRON_ETHE_TOKENS:
            i += 1
            continue
        if tok in _NETIRON_PREFIX_TOKENS:
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
                if _NETIRON_PORT_ID_RE.match(end_tok):
                    ports.extend(_netiron_expand_port_range(start, end_tok))
                    i += 2
                    continue
                ports.append(start)  # restore if no valid range
            i += 1
            continue
        if _NETIRON_PORT_ID_RE.match(tokens[i]):
            ports.append(tokens[i])
        i += 1
    return ports


# ---------------------------------------------------------------------------
# VLAN config regex (running-config vlan parsing)
# ---------------------------------------------------------------------------

# VLAN header — name and "by port"/"by protocol" qualifiers are optional.
# Covers: "vlan 10", "vlan 10 by port", "vlan 10 name MGMT by port"
_NETIRON_VLAN_HDR_RE = re.compile(
    r"^vlan\s+(?P<id>\d+)(?:\s+name\s+(?P<name>.+?))?(?:\s+by\s+\w+)?$"
)
_NETIRON_TAGGED_RE = re.compile(r"^\s+tagged\s+(?P<ports>.+)", re.IGNORECASE)
_NETIRON_UNTAGGED_RE = re.compile(r"^\s+untagged\s+(?P<ports>.+)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# get_interfaces_vlans helpers
# ---------------------------------------------------------------------------


def _invert_netiron_vlan_config(raw: str) -> dict[str, dict]:
    """
    Invert ``show running-config vlan`` into ``{port: {untagged, tagged}}``.

    NetIron MLX/CES/CER uses per-VLAN config blocks identical to FastIron::

        vlan 100 name DATA by port
         tagged ethe 1/1 to 1/4
         untagged ethe 1/5

    Walks the line stream tracking the active VLAN ID and folds ``tagged`` /
    ``untagged`` member lines into per-port aggregates. Uses the regex helpers
    so LAGs (``lag <N>``) and VEs are captured alongside physical ports.
    """
    per_port: dict[str, dict] = {}
    current_vid: int | None = None
    for line in raw.splitlines():
        m_hdr = _NETIRON_VLAN_HDR_RE.match(line)
        if m_hdr:
            current_vid = coerce_vid(m_hdr.group("id"))
            continue
        if current_vid is None:
            continue
        m_un = _NETIRON_UNTAGGED_RE.match(line)
        if m_un:
            for port in _netiron_split_port_list(m_un.group("ports")):
                entry = per_port.setdefault(port, {"untagged": [], "tagged": []})
                if current_vid not in entry["untagged"]:
                    entry["untagged"].append(current_vid)
            continue
        m_tg = _NETIRON_TAGGED_RE.match(line)
        if m_tg:
            for port in _netiron_split_port_list(m_tg.group("ports")):
                entry = per_port.setdefault(port, {"untagged": [], "tagged": []})
                if current_vid not in entry["tagged"]:
                    entry["tagged"].append(current_vid)
    return per_port


def _netiron_aggregate_to_switchport(per_port: dict) -> SwitchportInfo:
    """
    Map a per-port aggregate ``{untagged: list[int], tagged: list[int]}`` to a SwitchportInfo.

    NetIron has no explicit access/trunk admin field at the port level — mode
    is derived from the membership shape:

      - exactly one untagged, no tagged   → access on the untagged VID
      - exactly one untagged + ≥1 tagged  → trunk with the untagged as native
        (this is the dual-mode trunk pattern)
      - no untagged + ≥1 tagged           → trunk with no native
      - >1 untagged                       → routed (anomalous; IEEE 802.1Q
        forbids a port being untagged in multiple VLANs simultaneously)
      - no membership at all              → routed (caller normally omits)

    Accepts the legacy scalar-untagged shape (``untagged: int|None``) for
    backwards compatibility with any direct callers; the inversion helper
    above always emits the list shape.
    """
    raw_untagged = per_port.get("untagged")
    if isinstance(raw_untagged, list):
        untagged_vids = [v for v in raw_untagged if coerce_vid(v) is not None]
    else:
        single = coerce_vid(raw_untagged)
        untagged_vids = [single] if single is not None else []
    tagged_vids = [v for v in (per_port.get("tagged") or []) if coerce_vid(v) is not None]

    if len(untagged_vids) > 1:
        return SwitchportInfo(
            enabled=False,
            admin_mode=None,
            oper_mode=None,
            access_vlan=None,
            native_vlan=None,
            allowed_vlans=None,
        )
    if not untagged_vids and not tagged_vids:
        return SwitchportInfo(
            enabled=False,
            admin_mode=None,
            oper_mode=None,
            access_vlan=None,
            native_vlan=None,
            allowed_vlans=None,
        )
    if untagged_vids and not tagged_vids:
        return SwitchportInfo(
            enabled=True,
            admin_mode="access",
            oper_mode="access",
            access_vlan=untagged_vids[0],
            native_vlan=None,
            allowed_vlans=None,
        )
    return SwitchportInfo(
        enabled=True,
        admin_mode="trunk",
        oper_mode="trunk",
        access_vlan=None,
        native_vlan=untagged_vids[0] if untagged_vids else None,
        allowed_vlans=list(tagged_vids),
    )


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


# "show vrf" rows: name, default RD, A|A|A status flags, route count, then
# space-separated member interfaces wrapping onto indented continuations.
_NETIRON_VRF_ROW_RE = re.compile(
    r"^(?P<name>\S+)\s+(?P<rd>\S+(?:\s+[Ss]et)?)\s+[ADI](?:\s*\|\s*[ADI-]?){2}\s+"
    r"(?P<routes>\d+)\s*(?P<ifaces>.*)$"
)
# Member tokens in the Interfaces column: ve150, e1/5, eth 2/3, lag5,
# loopback1, po10 (case-insensitive).
_NETIRON_VRF_MEMBER_RE = re.compile(
    r"\b(e(?:th(?:ernet)?)?\s?\d+/\d+|ve\s?\d+|lag\s?\d+|loopback\s?\d+|po\s?\d+)\b",
    re.IGNORECASE,
)
# Ethernet member shorthand ("e1/5", "eth 2/3") → bare slot/port key used
# by the canonical-name map.
_NETIRON_VRF_ETH_RE = re.compile(r"^e(?:th(?:ernet)?)?\s?(\d+/\d+)$", re.IGNORECASE)
# RD column sentinels NetIron prints when no RD is configured. The row
# regex's rd group accepts an optional trailing "Set" token so the
# two-word "Not Set" form reaches this check intact.
_NETIRON_RD_UNSET = frozenset(
    {"(null)", "null", "-", "n/a", "none", "not set", "notset"}
)


def _netiron_parse_show_vrf(raw: str) -> dict[str, tuple[str, list[str]]]:
    """Parse ``show vrf`` into vrf name → (rd, raw member tokens)."""
    out: dict[str, tuple[str, list[str]]] = {}
    current: str | None = None
    for line in raw.splitlines():
        if not line.strip():
            continue
        m = _NETIRON_VRF_ROW_RE.match(line)
        if m:
            current = m.group("name")
            rd = m.group("rd").strip()
            if rd.lower() in _NETIRON_RD_UNSET:
                rd = ""
            members = _NETIRON_VRF_MEMBER_RE.findall(m.group("ifaces"))
            out[current] = (rd, members)
            continue
        if current is not None and line[:1].isspace():
            rd, members = out[current]
            members.extend(_NETIRON_VRF_MEMBER_RE.findall(line))
            out[current] = (rd, members)
        else:
            current = None
    return out


def _netiron_canonical_member(token: str, canonical_map: dict[str, str]) -> str:
    """Canonicalise a show-vrf member token via the bare-id name map."""
    token = token.strip()
    m = _NETIRON_VRF_ETH_RE.match(token)
    if m:
        bare = m.group(1)
    else:
        bare = token.replace(" ", "").lower()
    return canonical_map.get(bare, token)


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

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """
        Return per-interface VLAN configuration from ``show running-config vlan``.

        NetIron MLX/CES/CER uses per-VLAN config blocks identical to FastIron
        (``vlan <id> ... untagged ethe ... tagged ethe ...``); we invert that
        into per-port membership and then derive the access/trunk mode from
        the membership shape:

        - Port appears only as ``untagged`` in VLAN X         → access on X.
        - Port appears as ``untagged`` in X **and** ``tagged`` → trunk with
          native=X, tagged=[Y, Z] (dual-mode pattern).
        - Port appears only as ``tagged`` in some VLANs       → trunk with
          native=None, tagged=[...].
        - Port not seen anywhere → omitted (no first-class wildcard).

        Parsing uses regex rather than the ``brocade_netiron`` ntc-template
        so LAG members declared as ``tagged lag <N>`` / ``untagged lag <N>``
        are captured alongside physical ``ethe`` ports — heavily used on
        NetIron chassis platforms.

        Bare port IDs from the running-config (``1/1``, ``3/4``) are
        canonicalised to the same speed-prefixed form ``get_interfaces()``
        emits (``GigabitEthernet1/1``, ``10GigabitEthernet3/4``) using a
        bare-id → canonical lookup built from ``show interfaces`` (each
        block is headed by a canonical name like ``GigabitEthernet1/1``)
        in :meth:`_netiron_canonical_name_map` — without this
        ``apply_interface_vlans()`` would silently drop every entry due to
        exact-name mismatch with the discovered Interface entities.
        """
        try:
            raw = self.device.send_command("show running-config vlan")
        except Exception:
            logger.debug("NetIron show running-config vlan failed", exc_info=True)
            return {}

        per_port = _invert_netiron_vlan_config(raw)
        canonical_map = self._netiron_canonical_name_map()
        result: dict[str, dict] = {}
        for port, data in per_port.items():
            info = _netiron_aggregate_to_switchport(data)
            name = canonical_map.get(port, port)
            result[name] = classify_switchport(info)
        return result

    def _netiron_canonical_name_map(self) -> dict[str, str]:
        """
        Build a ``{bare_port_id: canonical_name}`` map from ``show interfaces``.

        Each NetIron interface block is headed by a canonical name. Two
        families need distinct bare-key derivation:

        * **Speed-prefixed Ethernet** (``GigabitEthernet1/1``,
          ``10GigabitEthernet3/4``, ``40GigabitEthernet...``,
          ``100GigabitEthernet...``) — bare key is the slot/port suffix
          alone (``1/1``, ``3/4``); the speed prefix may itself begin
          with digits (``10``, ``40``, ``100``, ``400``).
        * **Named non-Ethernet** (``Ve2``, ``Lag5``, ``Loopback1``) —
          bare key is the lowercase prefix + numeric suffix (``ve2``,
          ``lag5``, ``loopback1``) since :func:`_invert_netiron_vlan_config`
          and :func:`_split_port_list` emit those forms verbatim. Without
          this :func:`apply_interface_vlans` would silently drop VLAN
          mappings for VE/LAG/Loopback interfaces (Codex P1 #391).

        Returns an empty dict on parse failure — callers fall back to
        the bare IDs.
        """
        try:
            raw = self.device.send_command("show interfaces")
            parsed = parse_output(
                platform="brocade_netiron", command="show interfaces", data=raw,
            )
        except Exception:
            logger.debug("NetIron show interfaces failed for canonical map", exc_info=True)
            return {}
        # Speed-prefixed Ethernet: prefix may start with digits (10/40/100/400),
        # so allow optional leading digits. Suffix is either ``slot/port[:N]``
        # (chassis platforms) OR a bare numeric ID (CES form, e.g.
        # ``GigabitEthernet1`` — paired with the bare-digit support in
        # ``_netiron_split_port_list`` for CES running-config output).
        ethernet_re = re.compile(
            r"^(\d*[A-Za-z]+Ethernet)(\d+(?:/\d+(?::\d+)?)?)$"
        )
        # Named non-Ethernet: alpha-prefixed name with a single numeric suffix
        # (e.g. Ve2, Lag5, Loopback1, Tunnel10).
        named_re = re.compile(r"^([A-Za-z]+)(\d+)$")
        out: dict[str, str] = {}
        for row in parsed or []:
            full = (row.get("interface") or "").strip()
            m = ethernet_re.match(full)
            if m:
                out[m.group(2)] = full
                continue
            m = named_re.match(full)
            if m:
                # Skip "vlanN"-shaped names — those would be SVIs and the
                # inverter never emits keys for them.
                prefix = m.group(1)
                if prefix.lower() == "vlan":
                    continue
                out[f"{prefix.lower()}{m.group(2)}"] = full
        return out

    def get_network_instances(self, name: str = "") -> dict:
        """
        Return network instances (NetIron VRFs), NAPALM OC shape.

        Parsed driver-locally from ``show vrf`` (no ntc-template exists):
        one row per VRF with the default RD and a space-separated member
        interface list that may wrap onto indented continuation lines.
        Member tokens (``ve150``, ``e1/5``) are canonicalised through the
        same bare-id map get_interfaces_vlans() uses so they join the
        canonical names get_interfaces() emits (``Ve150``,
        ``GigabitEthernet1/5``). The global routing table is seeded as
        ``default-vrf`` (DEFAULT_INSTANCE, empty membership).

        NOTE: built from the vendor-documented output format; not yet
        validated against a live NetIron device.
        """
        instances: dict = {
            "default-vrf": {
                "name": "default-vrf",
                "type": "DEFAULT_INSTANCE",
                "state": {"route_distinguisher": ""},
                "interfaces": {"interface": {}},
            },
        }
        raw = self.device.send_command("show vrf")
        rows = _netiron_parse_show_vrf(raw or "")
        canonical_map = self._netiron_canonical_name_map() if rows else {}
        for vrf_name, (rd, members) in rows.items():
            # Never let a row overwrite the seeded DEFAULT_INSTANCE.
            if vrf_name == "default-vrf":
                continue
            interfaces = {
                _netiron_canonical_member(m, canonical_map): {} for m in members
            }
            instances[vrf_name] = {
                "name": vrf_name,
                "type": "L3VRF",
                "state": {"route_distinguisher": rd},
                "interfaces": {"interface": interfaces},
            }
        if name:
            return {name: instances[name]} if name in instances else {}
        return instances
