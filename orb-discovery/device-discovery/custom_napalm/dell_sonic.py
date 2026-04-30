# Copyright 2026 NetBox Labs Inc
"""
Custom Dell SONiC NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko with the ``dell_sonic`` device type for SSH transport.
All CLI parsing uses regex (no ntc-templates exist for this platform).
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.netmiko_helpers import netmiko_args

from custom_napalm._vlan import (
    SwitchportInfo,
    classify_switchport,
    parse_vlan_range_string,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config sanitisation — Dell SONiC sensitive patterns
# ---------------------------------------------------------------------------
_PASSWORD_RE = re.compile(
    r"((?:encrypted-password|password|auth-password)\s+)(?:\d+\s+)?\S+",
    re.IGNORECASE,
)
_TACACS_KEY_RE = re.compile(
    r"(tacacs-server\s+.*\s+key\s+)(?:\d+\s+)?\S+",
    re.IGNORECASE,
)
_RADIUS_KEY_RE = re.compile(
    r"(radius-server\s+.*\s+key\s+)(?:\d+\s+)?\S+",
    re.IGNORECASE,
)
_SNMP_COMMUNITY_RE = re.compile(
    r"(snmp-server\s+community\s+)(?:\d+\s+)?\S+",
    re.IGNORECASE,
)
_SECRET_RE = re.compile(
    r"(\bsecret\s+)(?:\d+\s+)?\S+",
    re.IGNORECASE,
)
_ENABLE_PASSWORD_RE = re.compile(
    r"(enable\s+password\s+)(?:\d+\s+)?\S+",
    re.IGNORECASE,
)
_BGP_PASSWORD_RE = re.compile(
    r"(neighbor\s+\S+\s+password\s+)(?:\d+\s+)?\S+",
    re.IGNORECASE,
)


def _sanitize_config(text: str) -> str:
    """Replace sensitive values in configuration text with ``<redacted>``."""
    text = _PASSWORD_RE.sub(r"\1<redacted>", text)
    text = _TACACS_KEY_RE.sub(r"\1<redacted>", text)
    text = _RADIUS_KEY_RE.sub(r"\1<redacted>", text)
    text = _SNMP_COMMUNITY_RE.sub(r"\1<redacted>", text)
    text = _SECRET_RE.sub(r"\1<redacted>", text)
    text = _ENABLE_PASSWORD_RE.sub(r"\1<redacted>", text)
    text = _BGP_PASSWORD_RE.sub(r"\1<redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Uptime parsing
# ---------------------------------------------------------------------------
_HOUR_SECONDS = 3600
_DAY_SECONDS = 24 * _HOUR_SECONDS
_WEEK_SECONDS = 7 * _DAY_SECONDS
_YEAR_SECONDS = 365 * _DAY_SECONDS

# Regex for interface names in SONiC CLI output.
# Covers canonical names (Ethernet0, PortChannel1, Vlan100, Loopback0, Management0),
# lowercase variants (eth0), standard Dell SONiC slot/port notation (Eth1/30),
# breakout ports (Eth1/1/1), and subinterfaces (Eth1/1.100, Ethernet0.10).
_INTF_RE = (
    r"(Ethernet\d+(?:\.\d+)?"
    r"|PortChannel\d+(?:\.\d+)?"
    r"|Vlan\d+"
    r"|Loopback\d+"
    r"|Management\d+"
    r"|Eth\d+/\d+(?:/\d+)?(?:\.\d+)?"
    r"|eth\d+(?:\.\d+)?)"
)

# Map of ``show version`` field names to extraction regexes.
# Each tuple: (field_key, compiled regex).  The first capture group is the value.
_VERSION_PATTERNS = [
    ("os_version", re.compile(r"(?:SONiC\s+)?Software\s+Version\s*[:\-]\s*(.+)", re.IGNORECASE)),
    ("hwsku", re.compile(r"HwSKU\s*[:\-]\s*(.+)", re.IGNORECASE)),
    ("product", re.compile(r"Product\s*[:\-]\s*(.+)", re.IGNORECASE)),
    ("platform", re.compile(r"Platform\s*[:\-]\s*(.+)", re.IGNORECASE)),
    ("serial_number", re.compile(r"Serial\s+Number\s*[:\-]\s*(.+)", re.IGNORECASE)),
    ("uptime", re.compile(r"(?:Up\s*[Tt]ime|Uptime)\s*[:\-]\s*(.+)", re.IGNORECASE)),
    ("hostname", re.compile(r"Hostname\s*[:\-]\s*(.+)", re.IGNORECASE)),
]

# Sentinel returned by get_facts() when show version produces no output.
_EMPTY_FACTS: dict = {
    "hostname": "Unknown",
    "vendor": "Dell",
    "model": "Unknown",
    "os_version": "Unknown",
    "serial_number": "Unknown",
    "uptime": -1.0,
    "fqdn": "Unknown",
    "interface_list": [],
}


def _parse_uptime(uptime_str: str) -> float:
    """
    Convert a SONiC uptime string to total seconds.

    Handles several formats including::

        15 days, 03:25:10
        04:53:36 up 2:05, 1 user, ...   (Linux procps — strip wall-clock prefix)
        04:53:36 up 2 days, 03:25:10
    """
    # When the string contains 'up' (Linux procps format), restrict parsing to
    # the portion after 'up' so the leading wall-clock time is not mistaken
    # for device uptime.
    m_up = re.search(r"\bup\b\s*(.*)", uptime_str, re.IGNORECASE)
    parse_str = m_up.group(1) if m_up else uptime_str

    seconds = 0.0

    for pattern, factor in (
        (r"(\d+)\s+year", _YEAR_SECONDS),
        (r"(\d+)\s+week", _WEEK_SECONDS),
        (r"(\d+)\s+day", _DAY_SECONDS),
        (r"(\d+)\s+hour", _HOUR_SECONDS),
        (r"(\d+)\s+min(?:ute)?s?", 60),
        (r"(\d+)\s+sec(?:ond)?s?", 1),
    ):
        m = re.search(pattern, parse_str, re.IGNORECASE)
        if m:
            seconds += int(m.group(1)) * factor

    # HH:MM:SS — only if no word-based components already captured hours
    if not re.search(r"\d+\s+hour", parse_str, re.IGNORECASE):
        m = re.search(r"(\d+):(\d+):(\d+)", parse_str)
        if m:
            seconds += int(m.group(1)) * _HOUR_SECONDS
            seconds += int(m.group(2)) * 60
            seconds += int(m.group(3))
        else:
            # HH:MM (Linux short format when uptime < 1 day)
            m = re.search(r"(\d+):(\d+)", parse_str)
            if m:
                seconds += int(m.group(1)) * _HOUR_SECONDS
                seconds += int(m.group(2)) * 60

    return seconds


def _parse_status(value: str) -> bool:
    """Interpret an admin/oper status field as a boolean (up = True)."""
    return value.strip().lower() == "up"


def _parse_speed(speed_str: str) -> float:
    """Convert a speed string like ``100G`` or ``1G`` to Mbps."""
    if not speed_str:
        return -1.0
    speed_str = speed_str.strip().upper()
    m = re.match(r"(\d+(?:\.\d+)?)\s*([GTM])?", speed_str)
    if not m:
        return -1.0
    val = float(m.group(1))
    unit = m.group(2) or ""
    if unit == "G":
        return val * 1000.0
    if unit == "T":
        return val * 1000000.0
    if unit == "M":
        return val
    return val


_STATUS_RE = re.compile(r"^(up|down|N/A)$", re.IGNORECASE)
_SPEED_RE = re.compile(r"^\d+(?:\.\d+)?[GTMgtm]?$")


def _parse_intf_status_header(output: str) -> dict[str, int]:
    """
    Return a mapping of uppercase column name → character start position.

    When a separator line (``----- ------- ...``) follows the header, its
    dash-group start positions are used as column boundaries — this is more
    robust than header token positions because it matches the actual column
    widths the device used to format the data rows, even when values are
    right-aligned or wider than the header label.

    Falls back to header token start positions when no separator is present.
    Accepts combined ``Admin/Oper`` tokens (both parts mapped to the same
    position).  Returns an empty dict when no header is found.
    """
    lines = output.splitlines()
    for i, line in enumerate(lines):
        if not re.search(r"\bOper\b", line, re.IGNORECASE):
            continue

        col_map: dict[str, int] = {}
        # Check for a separator line immediately after the header
        sep = lines[i + 1] if i + 1 < len(lines) else ""
        if "-" in sep and re.match(r"[\s\-=|]+$", sep):
            # Map each dash-group's start position to the overlapping header token
            for dash_m in re.finditer(r"-+", sep):
                col_start = dash_m.start()
                for tok_m in re.finditer(r"\S+", line):
                    # Token overlaps with this dash group
                    if tok_m.start() <= dash_m.end() and tok_m.end() >= col_start:
                        for part in tok_m.group().split("/"):
                            col_map[part.upper()] = col_start
                        break
        else:
            # No separator: fall back to header token start positions
            for m in re.finditer(r"\S+", line):
                for part in m.group().split("/"):
                    col_map[part.upper()] = m.start()

        return col_map
    return {}


def _col_value(line: str, start: int, sorted_starts: list[int]) -> str:
    """Slice a column value from *line* using its character start position."""
    if start < 0 or start >= len(line):
        return ""
    next_starts = [p for p in sorted_starts if p > start]
    end = next_starts[0] if next_starts else len(line)
    return line[start:end].strip()


def _parse_interface_line(line: str, col_map: dict[str, int]) -> dict | None:
    """
    Parse a ``show interfaces status`` data row into an interface dict.

    Extracts Admin, Oper, Speed, Description, and MTU values using the
    character positions supplied in *col_map* (from the header row), so any
    column containing embedded spaces is handled correctly.  Falls back to
    token-value scanning when *col_map* is empty.
    Returns ``None`` when Oper status cannot be determined.
    """
    if col_map:
        sorted_starts = sorted(col_map.values())
        oper_col = col_map.get("OPER", -1)
        admin_col = col_map.get("ADMIN", -1)
        speed_col = col_map.get("SPEED", -1)
        mtu_col = col_map.get("MTU", -1)
        desc_col = col_map.get("DESCRIPTION", col_map.get("DESC", -1))

        oper_val = _col_value(line, oper_col, sorted_starts)
        if not oper_val:
            return None
        # Handle combined "Admin/Oper" column (e.g. value "up/up" or "up/down")
        if "/" in oper_val and admin_col == oper_col:
            parts = oper_val.split("/", 1)
            admin_status = _parse_status(parts[0])
            oper_status = _parse_status(parts[1])
        else:
            oper_status = _parse_status(oper_val)
            admin_val = _col_value(line, admin_col, sorted_starts) if admin_col >= 0 else ""
            admin_status = _parse_status(admin_val) if admin_val else oper_status

        speed = _parse_speed(_col_value(line, speed_col, sorted_starts)) if speed_col >= 0 else -1.0

        mtu_str = _col_value(line, mtu_col, sorted_starts) if mtu_col >= 0 else ""
        if mtu_str and re.fullmatch(r"\d+", mtu_str) and int(mtu_str) > 64:
            mtu = int(mtu_str)
        else:
            mtu = next(
                (int(t) for t in reversed(line.split()) if re.fullmatch(r"\d+", t) and int(t) > 64),
                -1,
            )

        description = _col_value(line, desc_col, sorted_starts) if desc_col >= 0 else ""
    else:
        # Fallback: scan tokens when no header was parsed
        fields = line.split()
        status_indices = [i for i, t in enumerate(fields) if _STATUS_RE.match(t)]
        if not status_indices:
            return None
        if len(status_indices) == 1:
            oper_status = admin_status = _parse_status(fields[status_indices[0]])
            after = status_indices[0] + 1
        else:
            admin_status = _parse_status(fields[status_indices[0]])
            oper_status = _parse_status(fields[status_indices[1]])
            after = status_indices[1] + 1
        speed, desc_start = -1.0, after
        for i, token in enumerate(fields[after:], start=after):
            if _SPEED_RE.match(token):
                speed, desc_start = _parse_speed(token), i + 1
                break
        mtu = next(
            (int(t) for t in reversed(fields) if re.fullmatch(r"\d+", t) and int(t) > 64),
            -1,
        )
        description = " ".join(t for t in fields[desc_start:] if t != str(mtu))

    return {
        "is_up": oper_status,
        "is_enabled": admin_status,
        "description": description,
        "last_flapped": -1.0,
        "mtu": mtu,
        "speed": speed,
        "mac_address": "",
    }


def _parse_version_fields(output: str) -> dict:
    """Extract key/value pairs from ``show version`` output."""
    fields: dict[str, str] = {}
    for line in output.splitlines():
        stripped = line.strip()
        for key, pattern in _VERSION_PATTERNS:
            m = pattern.match(stripped)
            if m:
                fields[key] = m.group(1).strip()
                break
    return fields


class SONiCDriver(_napalm_base.NetworkDriver):
    """Dell SONiC NAPALM driver (read-only subset for device-discovery)."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Initialise connection parameters."""
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
            "dell_sonic", netmiko_optional_args=self.netmiko_optional_args
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
        output = self.device.send_command("show version")
        if not output:
            return dict(_EMPTY_FACTS)

        fields = _parse_version_fields(output)

        # Model priority: HwSKU > Product > Platform
        model = fields.get("hwsku") or fields.get("product") or fields.get("platform", "Unknown")

        uptime = _parse_uptime(fields["uptime"]) if "uptime" in fields else -1.0

        # Build interface list — try both plural and singular command forms
        intf_status_output = _send_first_nonempty(
            self.device, ("show interfaces status", "show interface status")
        )
        interface_list = _extract_interface_names(intf_status_output)

        return {
            "hostname": fields.get("hostname", "Unknown"),
            "vendor": "Dell",
            "model": model,
            "os_version": fields.get("os_version", "Unknown"),
            "serial_number": fields.get("serial_number", "Unknown"),
            "uptime": float(uptime),
            "fqdn": "Unknown",
            "interface_list": sorted(interface_list),
        }

    def get_interfaces(self) -> dict:
        """Return interface details keyed by interface name."""
        # Try both plural and singular command forms
        output = _send_first_nonempty(
            self.device, ("show interfaces status", "show interface status")
        )
        if not output:
            return {}

        # Parse header once to learn column order (Admin/Oper/Speed may vary)
        col_map = _parse_intf_status_header(output)
        interfaces = {}
        for line in output.splitlines():
            # Allow optional leading whitespace before the interface name.
            m = re.match(r"^\s*" + _INTF_RE + r"\s", line)
            if not m:
                continue
            # Pass the full line so _parse_interface_line can use character
            # positions from col_map; splitting on whitespace here would
            # break column alignment when any field contains spaces.
            parsed = _parse_interface_line(line, col_map)
            if parsed is not None:
                interfaces[m.group(1)] = parsed

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface."""
        interfaces_ip: dict = {}

        # Issue both the plural and singular forms; SONiC versions differ on which
        # command is valid, and an unsupported command returns error text (non-empty)
        # rather than an empty string, so checking for emptiness alone is unreliable.
        # Parsing both and merging ensures coverage regardless of device variant.
        # Optional non-IP token between interface name and address handles
        # VRF/Master columns (e.g. "Loopback11 Vrf-red 11.1.1.1/32").
        ipv4_re = re.compile(
            r"^\s*" + _INTF_RE + r"\s+(?:\S+\s+)?(\d+\.\d+\.\d+\.\d+)/(\d+)"
        )
        for cmd in ("show ip interfaces", "show ip interface"):
            for line in self.device.send_command(cmd).splitlines():
                m = ipv4_re.match(line)
                if m:
                    interfaces_ip.setdefault(m.group(1), {}).setdefault("ipv4", {})[m.group(2)] = {
                        "prefix_length": int(m.group(3))
                    }

        ipv6_re = re.compile(
            r"^\s*" + _INTF_RE + r"\s+(?:\S+\s+)?([0-9a-fA-F:]+)/(\d+)"
        )
        for cmd in ("show ipv6 interfaces", "show ipv6 interface"):
            for line in self.device.send_command(cmd).splitlines():
                m = ipv6_re.match(line)
                if m:
                    interfaces_ip.setdefault(m.group(1), {}).setdefault("ipv6", {})[m.group(2)] = {
                        "prefix_length": int(m.group(3))
                    }

        return interfaces_ip

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """
        Return device configuration.

        SONiC has a single active configuration store; there is no separate
        startup config command.  When ``startup`` is requested the running
        config is returned as a functional equivalent.
        """
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}

        retrieve_lower = retrieve.lower()
        if retrieve_lower in ("running", "all"):
            config["running"] = self.device.send_command("show running-configuration")

        # SONiC has no separate startup config — map it to running.
        if retrieve_lower in ("startup", "all"):
            config["startup"] = config["running"] or self.device.send_command(
                "show running-configuration"
            )

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Return VLAN information keyed by VLAN ID string."""
        output = _send_first_nonempty(self.device, ("show vlan brief", "show vlan"))
        if not output:
            return {}
        return _parse_vlan_output(output)

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """Return per-interface VLAN config from ``show interface[s] switchport``."""
        try:
            raw = _send_first_nonempty(
                self.device,
                ("show interfaces switchport", "show interface switchport"),
            )
        except Exception:
            logger.debug("SONiC show interface[s] switchport failed", exc_info=True)
            return {}
        rows = _parse_show_interface_switchport(raw)
        result: dict[str, dict] = {}
        for row in rows:
            ifname = row.get("interface")
            if not ifname:
                continue
            info = _sonic_row_to_switchport_info(row)
            result[ifname] = classify_switchport(info)
        return result


_SONIC_SWITCHPORT_HEADER_RE = re.compile(
    r"^\s*Interface\s+Mode\s+Untagged\s+Tagged\s*$",
    re.IGNORECASE,
)
_SONIC_SEPARATOR_RE = re.compile(r"^[-\s]+$")


def _parse_show_interface_switchport(text: str) -> list[dict]:
    """
    Parse SONiC ``show interface switchport`` table into row dicts.

    Returns a list of ``{interface, mode, untagged, tagged}`` dicts with the
    raw string values verbatim (including ``-`` / ``all`` tokens).
    """
    rows: list[dict] = []
    seen_header = False
    for line in text.splitlines():
        if not seen_header:
            if _SONIC_SWITCHPORT_HEADER_RE.match(line):
                seen_header = True
            continue
        stripped = line.strip()
        if not stripped or _SONIC_SEPARATOR_RE.match(stripped):
            continue
        parts = re.split(r"\s{2,}", stripped)
        if len(parts) < 4:
            parts = stripped.split()
        if len(parts) < 4:
            continue
        # Defensive: drop rows where the interface column is a dash-run
        # (table separators with internal whitespace).
        if set(parts[0]) <= {"-"}:
            continue
        rows.append({
            "interface": parts[0],
            "mode": parts[1],
            "untagged": parts[2],
            "tagged": parts[3],
        })
    return rows


def _sonic_row_to_switchport_info(row: dict) -> SwitchportInfo:
    """Map a SONiC switchport row to a SwitchportInfo."""
    mode_raw = (row.get("mode") or "").strip().lower()
    if mode_raw not in ("access", "trunk"):
        return SwitchportInfo(
            enabled=False,
            admin_mode=None,
            oper_mode=None,
            access_vlan=None,
            native_vlan=None,
            allowed_vlans=None,
        )

    untagged_raw = (row.get("untagged") or "").strip()
    tagged_raw = (row.get("tagged") or "").strip()

    def _vid(s: str) -> int | None:
        if not s or s == "-":
            return None
        try:
            return int(s)
        except ValueError:
            return None

    untagged_vid = _vid(untagged_raw)

    if mode_raw == "access":
        return SwitchportInfo(
            enabled=True,
            admin_mode="access",
            oper_mode="access",
            access_vlan=untagged_vid,
            native_vlan=None,
            allowed_vlans=None,
        )

    if tagged_raw and tagged_raw != "-":
        if tagged_raw.lower() == "all":
            allowed: list[int] | str | None = "all"
        else:
            vids, is_wildcard = parse_vlan_range_string(tagged_raw)
            allowed = "all" if is_wildcard else vids
    else:
        allowed = None

    return SwitchportInfo(
        enabled=True,
        admin_mode="trunk",
        oper_mode="trunk",
        access_vlan=None,
        native_vlan=untagged_vid,
        allowed_vlans=allowed,
    )


def _members_from_str(members_str: str) -> list[str]:
    """Split a comma-separated member-ports string into a clean list."""
    return [i.strip() for i in members_str.split(",") if i.strip()]


def _parse_vlan_output(output: str) -> dict:
    """
    Parse ``show vlan brief`` or ``show vlan`` output into a VLAN dict.

    Handles two formats:

    **Format A** (``show vlan brief``) — four columns with status last::

        VLAN ID  VLAN Name   Member Ports            Status
        100      Servers     Ethernet0,Ethernet4     active

    **Format B** (``show vlan``) — ``VLANID Status Q Ports`` layout used
    by Dell Enterprise SONiC, with optional wrapped port continuation lines::

        VLAN  Status    Q  Ports
        100   Active    A  Ethernet0
                        T  Ethernet4
        200   Active    T  Management0

    Both formats tolerate pipe delimiters and wrapped member lines.
    """
    vlans: dict = {}
    last_vlan_id: str | None = None

    for line in output.splitlines():
        # --- Format A: VLANID  [Name]  [Members]  active|suspend ---
        m_a = re.match(
            r"\s*\|?\s*(\d+)\s*(?:\|\s*|\s{2,})(.+?)\s*(?:\|\s*|\s{2,})(.*?)\s*(?:\|\s*|\s{2,})(active|suspend)\s*\|?\s*$",
            line,
            re.IGNORECASE,
        )
        if m_a:
            last_vlan_id = m_a.group(1)
            vlans[last_vlan_id] = {
                "name": m_a.group(2).strip(),
                "interfaces": _members_from_str(m_a.group(3)),
            }
            continue

        # --- Format B: VLANID  Status  [Q  Ports] (Dell SONiC show vlan) ---
        # The Q indicator and member ports are optional; inactive VLANs with no
        # members print as "30 Inactive Enable" (no Q/Ports token).
        m_b = re.match(
            r"\s*(\d+)\s+(active|suspend|inactive)(?:\s+[ATUS+]\s*(.*))?$",
            line,
            re.IGNORECASE,
        )
        if m_b:
            last_vlan_id = m_b.group(1)
            # No VLAN name in this format; use ID as name.
            # Extract only recognised interface names from the ports field;
            # extra columns (Autostate, Dynamic, …) are ignored.
            ports_raw = (m_b.group(3) or "").strip()
            vlans[last_vlan_id] = {
                "name": last_vlan_id,
                "interfaces": re.findall(_INTF_RE, ports_raw) if ports_raw else [],
            }
            continue

        # --- Continuation line: wrapped member ports from previous row ---
        if last_vlan_id:
            stripped = line.strip().strip("|").strip()
            # Skip blank lines and table-separator lines but keep context
            if not stripped or re.match(r"^[-=+|*\s]+$", stripped):
                continue
            # Format B continuation: strip optional Q indicator prefix (A/T/U/S/+)
            m_cont = re.match(r"[ATUS+]\s+(.*)", stripped)
            if m_cont:
                stripped = m_cont.group(1).strip()
            # Collect any recognised interface names on this line; if none are
            # found don't reset context — extra-column continuation lines like
            # "Vxlan_tunnel0" or "Enable No" simply contribute nothing.
            intfs = re.findall(_INTF_RE, stripped)
            if intfs:
                vlans[last_vlan_id]["interfaces"].extend(intfs)
            elif re.match(r"^\d+\s", stripped):
                # A new VLAN ID row is about to be processed in the next iteration
                last_vlan_id = None

    return vlans


_CLI_ERROR_RE = re.compile(
    r"^\s*(%\s+|Error:|Invalid input|Command not found|Incomplete command)",
    re.IGNORECASE | re.MULTILINE,
)


def _send_first_nonempty(device, commands: tuple[str, ...]) -> str:
    """
    Send *commands* in order and return the first non-error, non-empty response.

    Unsupported commands on SONiC return non-empty error text (e.g.
    ``% Invalid input detected``).  Such responses are treated as empty so
    the next command in *commands* is tried.
    """
    for cmd in commands:
        out = device.send_command(cmd)
        if out and not _CLI_ERROR_RE.search(out):
            return out
    return ""


def _extract_interface_names(output: str) -> list[str]:
    """Extract interface names from ``show interfaces status`` output."""
    names = []
    if output:
        for line in output.splitlines():
            # Allow optional leading whitespace before the interface name.
            m = re.match(r"\s*" + _INTF_RE + r"\s", line)
            if m:
                names.append(m.group(1))
    return names
