# Copyright 2026 NetBox Labs Inc
# Based on napalm-ftos (Apache-2.0): https://github.com/napalm-automation-community/napalm-ftos
"""
Custom Dell Force10 FTOS NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko (dell_force10 device type) for SSH connectivity and ntc-templates
for structured parsing wherever templates exist; falls back to regex for commands
that have no template (show interfaces, show system stack-unit 0, IPv6 interfaces).
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


_FTOS_PORT_HEADER_RE = re.compile(r"^\s*Name:\s+(\S.*?)\s*$", re.MULTILINE)
# Accept keys starting with a letter OR a digit so OS9 fields like
# ``802.1QTagged`` are captured (key normalised to ``802.1qtagged``).
_FTOS_FIELD_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9\.\- ]+?)\s*:\s*(.*?)\s*$")
# OS9 ``Vlan membership`` block — explicit per-row tagged/untagged form:
# ``U  <vid>[,<vid>...]`` and ``T  <vid>[,<vid>...|<lo>-<hi>]``.
_FTOS_OS9_VLAN_TAG_RE = re.compile(r"^\s*([UT])\s+(.+?)\s*$")
# OS9 ``Vlan membership`` block — alternate ``Vlan <vid>[, Vlan <vid>...]``
# form. Tagging is determined separately from ``802.1QTagged`` +
# ``Native VlanId``; this captures only the VID list.
_FTOS_OS9_VLAN_TOKEN_RE = re.compile(r"\bVlan\s+(\d+)\b")


def _ftos_capture_membership_line(current: dict, line: str) -> None:
    """Append OS9 membership data from a single line into the current row."""
    tag_m = _FTOS_OS9_VLAN_TAG_RE.match(line)
    if tag_m:
        bucket = "os9_untagged" if tag_m.group(1) == "U" else "os9_tagged"
        current[bucket].append(tag_m.group(2).strip())
        return
    for tok in _FTOS_OS9_VLAN_TOKEN_RE.finditer(line):
        try:
            current["os9_vlans"].append(int(tok.group(1)))
        except ValueError:
            continue


def _parse_ftos_show_interfaces_switchport(text: str) -> list[dict]:
    """
    Parse FTOS ``show interfaces switchport`` into per-port dicts.

    Each port section starts with ``Name: <iface>`` and is followed by
    ``Field: Value`` lines. Sections are separated by blank lines.
    Captures both OS10/IOS-style (``Administrative mode``,
    ``Trunking VLANs Enabled``) and OS9-style (``802.1QTagged``,
    ``Native VlanId``, ``Vlan membership`` block) formats — including
    both OS9 sub-forms (``U/T <vids>`` rows and ``Vlan <vid>, Vlan <vid>``
    comma-separated tokens). Unknown/extra fields are ignored.
    """
    rows: list[dict] = []
    current: dict | None = None
    in_vlan_membership = False
    for line in text.splitlines():
        header = _FTOS_PORT_HEADER_RE.match(line)
        if header:
            if current is not None:
                rows.append(current)
            current = {
                "interface": header.group(1).strip(),
                "os9_untagged": [],
                "os9_tagged": [],
                "os9_vlans": [],
            }
            in_vlan_membership = False
            continue
        if current is None:
            continue
        m = _FTOS_FIELD_RE.match(line)
        if m:
            key = (
                m.group(1).strip().lower().replace(" ", "_").replace("-", "_")
            )
            current[key] = m.group(2).strip()
            in_vlan_membership = key == "vlan_membership"
            continue
        if in_vlan_membership:
            _ftos_capture_membership_line(current, line)
    if current is not None:
        rows.append(current)
    return rows


def _ftos_routed() -> SwitchportInfo:
    return SwitchportInfo(
        enabled=False,
        admin_mode=None,
        oper_mode=None,
        access_vlan=None,
        native_vlan=None,
        allowed_vlans=None,
    )


def _ftos_os10_row_to_info(row: dict) -> SwitchportInfo:
    """Map an OS10/IOS-style FTOS row (``Administrative mode``: …) to a SwitchportInfo."""
    mode_raw = (
        row.get("administrative_mode") or row.get("admin_mode") or ""
    ).lower()
    if mode_raw not in ("access", "trunk", "general"):
        return _ftos_routed()

    access_vid = coerce_vid(
        row.get("access_mode_vlan") or row.get("access_vlan") or ""
    )
    native_vid = coerce_vid(
        row.get("native_vlan") or row.get("trunking_native_mode_vlan") or ""
    )

    allowed_raw = (
        row.get("trunking_vlans_enabled")
        or row.get("trunking_vlans_active")
        or row.get("allowed_vlans")
        or ""
    )
    if allowed_raw and allowed_raw.lower() != "none":
        vids, is_wildcard = parse_vlan_range_string(allowed_raw)
        allowed: list[int] | str | None = "all" if is_wildcard else vids
    else:
        allowed = None

    if mode_raw == "access":
        return SwitchportInfo(
            enabled=True,
            admin_mode="access",
            oper_mode="access",
            access_vlan=access_vid,
            native_vlan=None,
            allowed_vlans=None,
        )
    return SwitchportInfo(
        enabled=True,
        admin_mode="trunk",
        oper_mode="trunk",
        access_vlan=None,
        native_vlan=native_vid,
        allowed_vlans=allowed,
    )


def _ftos_os9_row_to_info(row: dict) -> SwitchportInfo:
    """
    Map an OS9-style FTOS row to a SwitchportInfo.

    OS9 ``show interfaces switchport`` emits ``802.1QTagged: True/False/Hybrid``
    plus a ``Vlan membership`` block in one of two forms:
      - ``U  <vids>`` / ``T  <vids>`` rows (explicit tagged/untagged), or
      - ``Vlan <vid>[, Vlan <vid>...]`` comma-separated tokens (no per-vlan
        tag annotation; tagging is derived from ``802.1QTagged`` +
        ``Native VlanId``).

    Hybrid means trunk-with-untagged-native (collapsed to trunk for our
    NetBox-aligned classification).
    """
    qtag_raw = (row.get("802.1qtagged") or "").strip().lower()

    # Explicit U/T form (preferred when present).
    untagged_vids: list[int] = []
    for spec in row.get("os9_untagged") or []:
        vids, _ = parse_vlan_range_string(spec)
        untagged_vids.extend(vids)
    tagged_vids: list[int] = []
    for spec in row.get("os9_tagged") or []:
        vids, _ = parse_vlan_range_string(spec)
        tagged_vids.extend(vids)

    # Alternate ``Vlan <vid>`` comma-separated form. Native VID (if any) is
    # the trailing-period-delimited value of ``Native VlanId``.
    vlan_tokens = [v for v in (row.get("os9_vlans") or []) if isinstance(v, int)]
    native_raw = (row.get("native_vlanid") or "").strip().rstrip(".")
    native_token_vid = coerce_vid(native_raw) if native_raw else None

    # If only the comma-separated form was captured (no U/T rows), derive
    # tagged/untagged from ``802.1QTagged``:
    #   False  → access on the single VLAN listed
    #   Hybrid → native (from ``Native VlanId``) + remaining VIDs tagged
    #   True   → all tagged, no untagged
    if vlan_tokens and not untagged_vids and not tagged_vids:
        if qtag_raw == "false":
            untagged_vids = vlan_tokens[:1]
        elif qtag_raw == "hybrid":
            if native_token_vid is not None and native_token_vid in vlan_tokens:
                untagged_vids = [native_token_vid]
                tagged_vids = [v for v in vlan_tokens if v != native_token_vid]
            else:
                tagged_vids = list(vlan_tokens)
        else:
            tagged_vids = list(vlan_tokens)

    if not qtag_raw and not untagged_vids and not tagged_vids:
        return _ftos_routed()

    if qtag_raw == "false":
        return SwitchportInfo(
            enabled=True,
            admin_mode="access",
            oper_mode="access",
            access_vlan=untagged_vids[0] if untagged_vids else None,
            native_vlan=None,
            allowed_vlans=None,
        )

    native_vid = untagged_vids[0] if untagged_vids else None
    if not tagged_vids and native_vid is None:
        return _ftos_routed()
    return SwitchportInfo(
        enabled=True,
        admin_mode="trunk",
        oper_mode="trunk",
        access_vlan=None,
        native_vlan=native_vid,
        allowed_vlans=tagged_vids if tagged_vids else None,
    )


def _ftos_row_to_switchport_info(row: dict) -> SwitchportInfo:
    """Map a parsed FTOS port section to a SwitchportInfo (OS9 + OS10)."""
    sw = (row.get("switchport") or "").lower()
    if sw in ("disabled", "off"):
        return _ftos_routed()

    if row.get("administrative_mode") or row.get("admin_mode"):
        return _ftos_os10_row_to_info(row)

    if (
        row.get("802.1qtagged")
        or row.get("os9_untagged")
        or row.get("os9_tagged")
        or row.get("os9_vlans")
    ):
        return _ftos_os9_row_to_info(row)

    return _ftos_routed()

# ---------------------------------------------------------------------------
# Config sanitization — Dell FTOS sensitive fields
# ---------------------------------------------------------------------------

# "username <name> password [<N>] <hash>" and "enable password [<N>] <hash>"
# The encryption-type digit (\d+) is optional: FTOS allows cleartext form
# "password MyPassword" (type 0) as well as the typed form "password 7 <hash>".
_PASSWORD_RE = re.compile(
    r"((?:username\s+\S+\s+)?(?:enable\s+)?password(?:\s+\d+)?)\s+\S+",
    re.IGNORECASE,
)

# "enable secret [<N>] <hash>" — encryption-type digit is optional, same as password.
_SECRET_RE = re.compile(r"(enable\s+secret)(?:\s+\d+)?\s+\S+", re.IGNORECASE)

# "snmp-server community <string> ..." — redact the community string token only.
# Anchored after the keyword so downstream access-list names are not affected.
_SNMP_COMMUNITY_RE = re.compile(
    r"(snmp-server\s+community)\s+\S+", re.IGNORECASE
)


def _sanitize_config(text: str) -> str:
    text = _PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _SECRET_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_COMMUNITY_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Uptime parsing
# ---------------------------------------------------------------------------

_WEEK_SECONDS = 7 * 24 * 3600
_DAY_SECONDS = 24 * 3600
_HOUR_SECONDS = 3600
_MINUTE_SECONDS = 60


def _parse_uptime(uptime_str: str) -> float:
    """
    Convert a Dell FTOS uptime string to total seconds.

    Handles formats emitted by 'show version' (via ntc-template) and
    'show system stack-unit 0', e.g.:
      "33 wk, 4 day, 12 hr, 4 min"
      "33 week(s), 4 day(s), 12 hour(s), 4 minute(s)"
      "1:23:45"   (hh:mm:ss — short uptime before first day rolls over)
    """
    uptime_str = uptime_str.strip()

    # hh:mm:ss short form
    m = re.fullmatch(r"(\d+):(\d+):(\d+)", uptime_str)
    if m:
        return int(m.group(1)) * _HOUR_SECONDS + int(m.group(2)) * _MINUTE_SECONDS + int(m.group(3))

    seconds = 0.0
    for pattern, factor in (
        (r"(\d+)\s+y(?:ear)?", 365 * _DAY_SECONDS),
        (r"(\d+)\s+w(?:ee)?k", _WEEK_SECONDS),
        (r"(\d+)\s+day", _DAY_SECONDS),
        (r"(\d+)\s+h(?:ou)?r", _HOUR_SECONDS),
        (r"(\d+)\s+min(?:ute)?", _MINUTE_SECONDS),
        (r"(\d+)\s+sec(?:ond)?", 1),
    ):
        hit = re.search(pattern, uptime_str, re.IGNORECASE)
        if hit:
            seconds += int(hit.group(1)) * factor

    return seconds


# ---------------------------------------------------------------------------
# Interface parsing helpers
# ---------------------------------------------------------------------------

# Matches the first line of a 'show interfaces' block:
#   "TenGigabitEthernet 0/1 is up, line protocol is up"
#   "GigabitEthernet 1/1 is administratively down, line protocol is down"
# [^,\n]+ stops at the first comma or newline so the match stays on one line.
_INTF_HDR_RE = re.compile(
    r"^(?P<name>\S+\s+\S+)\s+is\s+(?P<admin>[^,\n]+),\s*line\s+protocol\s+is\s+(?P<oper>\S+)",
    re.MULTILINE,
)


def _parse_interfaces(raw: str) -> dict:
    """
    Parse 'show interfaces' output into a dict keyed by interface name.

    Returns the NAPALM interface dict (is_up, is_enabled, description,
    last_flapped, mtu, speed, mac_address) for every interface block found.
    """
    interfaces: dict = {}
    if not raw:
        return interfaces

    # Split output into blocks on interface header lines.
    # re.split with a capturing group keeps the delimiter.
    parts = re.split(r"(?=^\S+\s+\S+\s+is\s+)", raw, flags=re.MULTILINE)

    for block in parts:
        m_hdr = _INTF_HDR_RE.match(block)
        if not m_hdr:
            continue

        name = m_hdr.group("name")
        admin_raw = m_hdr.group("admin").lower()
        oper_raw = m_hdr.group("oper").lower()

        is_enabled = "administratively" not in admin_raw
        is_up = oper_raw == "up"

        # Description
        m_desc = re.search(r"^\s*Description:\s*(.+)$", block, re.MULTILINE)
        description = m_desc.group(1).strip() if m_desc else ""

        # MAC address
        mac_address = ""
        m_mac = re.search(
            r"Hardware\s+is\s+\S+.*?address\s+is\s+([0-9a-fA-F]{2}(?:[:\-\.][0-9a-fA-F]{2}){5})",
            block,
            re.IGNORECASE,
        )
        if m_mac:
            try:
                mac_address = normalize_mac(m_mac.group(1))
            except Exception:
                mac_address = m_mac.group(1)

        # MTU — "MTU 12000 bytes"
        mtu = -1
        m_mtu = re.search(r"\bMTU\s+(\d+)\s+bytes", block, re.IGNORECASE)
        if m_mtu:
            try:
                mtu = int(m_mtu.group(1))
            except ValueError:
                pass

        # Speed — "LineSpeed 10000 Mbit" or "LineSpeed 1000 Mbit"
        speed = -1.0
        m_speed = re.search(r"LineSpeed\s+(\d+)\s+Mbit", block, re.IGNORECASE)
        if m_speed:
            try:
                speed = float(m_speed.group(1))
            except ValueError:
                pass

        interfaces[name] = {
            "is_up": is_up,
            "is_enabled": is_enabled,
            "description": description,
            "last_flapped": -1.0,
            "mtu": mtu,
            "speed": speed,
            "mac_address": mac_address,
        }

    return interfaces


class FTOSDriver(_napalm_base.NetworkDriver):
    """Dell Force10 FTOS NAPALM driver (read-only subset for device-discovery)."""

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
            "dell_force10", netmiko_optional_args=self.netmiko_optional_args
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

    def _facts_from_version(self) -> tuple[str, float, str]:
        """Return (os_version, uptime, model) from 'show version' (ntc-template)."""
        os_version = "Unknown"
        uptime = 0.0
        model = "Unknown"
        raw = self.device.send_command("show version")
        try:
            parsed = parse_output(platform="dell_force10", command="show version", data=raw)
            if parsed:
                row = parsed[0]
                os_version = row.get("os_version", "Unknown") or "Unknown"
                uptime_str = row.get("uptime", "")
                if uptime_str:
                    uptime = _parse_uptime(uptime_str)
                device_type = row.get("device_type", "")
                if device_type:
                    model = device_type
        except Exception:
            logger.debug("Failed to parse 'show version' output", exc_info=True)
        return os_version, uptime, model

    def _facts_from_stack_unit(self) -> tuple[str, str, str]:
        """
        Return (serial_number, model, vendor) from 'show system stack-unit 0'.

        serial_number and model are parsed via regex; vendor is the constant "Dell".
        """
        serial_number = "Unknown"
        model = "Unknown"
        vendor = "Dell"
        raw = self.device.send_command("show system stack-unit 0")
        for line in raw.splitlines():
            stripped = line.strip()
            if stripped.startswith("Serial Number"):
                val = stripped.split(":", 1)[-1].strip()
                if val:
                    serial_number = val
            elif stripped.startswith("Product Name"):
                val = stripped.split(":", 1)[-1].strip()
                if val:
                    model = val
        return serial_number, model, vendor

    def get_facts(self) -> dict:
        """
        Return general device facts.

        Facts are assembled from four commands:
        - 'show version'          → os_version, uptime (ntc-template)
        - 'show system stack-unit 0' → serial_number, model (regex); vendor is constant "Dell"
        - 'show running-config'   → hostname (regex on first 'hostname' line)
        - 'show interfaces'       → interface_list (regex scan for interface names)
        """
        os_version, uptime, model = self._facts_from_version()
        serial_number, stack_model, vendor = self._facts_from_stack_unit()
        # stack-unit Product Name takes precedence over show version System Type
        if stack_model != "Unknown":
            model = stack_model

        hostname = self.hostname
        cfg_raw = self.device.send_command("show running-config")
        for line in cfg_raw.splitlines():
            if line.strip().startswith("hostname "):
                hostname = line.strip().split("hostname ", 1)[1].strip()
                break

        intf_raw = self.device.send_command("show interfaces")
        seen: set[str] = set()
        interface_list: list[str] = []
        for m in _INTF_HDR_RE.finditer(intf_raw):
            name = m.group("name")
            if name not in seen:
                seen.add(name)
                interface_list.append(name)
        interface_list.sort()

        return {
            "hostname": hostname,
            "vendor": vendor,
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

        Parses 'show interfaces' blocks with regex.  No ntc-template exists
        for this command on dell_force10.
        """
        raw = self.device.send_command("show interfaces")
        return _parse_interfaces(raw)

    def _resolve_bare_ipv4(self, bare: dict, interfaces_ip: dict) -> None:
        """Resolve prefix lengths for bare IPv4 addresses using 'show running-config'."""
        cfg_raw = self.device.send_command("show running-config")
        prefix_map: dict[str, int] = {}
        for m in re.finditer(r"\bip\s+address\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", cfg_raw):
            prefix_map[m.group(1)] = int(m.group(2))
        for intf, addr in bare.items():
            if addr in prefix_map:
                interfaces_ip.setdefault(intf, {}).setdefault("ipv4", {})[addr] = {
                    "prefix_length": prefix_map[addr]
                }

    def _ipv4_from_brief(self, interfaces_ip: dict) -> None:
        """
        Populate *interfaces_ip* with IPv4 addresses from 'show ip interface brief'.

        Rows that include a CIDR prefix (the common case) are stored directly.
        Rows with a bare IP (no prefix) are resolved against 'show running-config'.
        """
        raw = self.device.send_command("show ip interface brief")
        try:
            parsed = parse_output(
                platform="dell_force10", command="show ip interface brief", data=raw
            )
        except Exception:
            logger.debug("Failed to parse 'show ip interface brief' output", exc_info=True)
            return
        bare: dict[str, str] = {}
        for row in parsed:
            intf = row.get("interface", "").strip()
            ip_addr = row.get("ip_address", "").strip()
            if not intf or not ip_addr or ip_addr.lower() in ("unassigned", ""):
                continue
            if "/" in ip_addr:
                addr, prefix_str = ip_addr.split("/", 1)
                try:
                    prefix = int(prefix_str)
                except ValueError:
                    continue
                interfaces_ip.setdefault(intf, {}).setdefault("ipv4", {})[addr] = {
                    "prefix_length": prefix
                }
            else:
                bare[intf] = ip_addr
        if bare:
            self._resolve_bare_ipv4(bare, interfaces_ip)

    def _ipv6_from_brief(self, interfaces_ip: dict) -> None:
        """Populate *interfaces_ip* with IPv6 addresses from 'show ipv6 interface brief'."""
        raw = self.device.send_command("show ipv6 interface brief")
        current_intf: str | None = None
        for line in raw.splitlines():
            m_hdr = re.match(r"^(\S+\s+\S+)\s+is\s+", line)
            if m_hdr:
                current_intf = m_hdr.group(1)
                continue
            if current_intf is None:
                continue
            m_addr = re.match(r"^\s+([0-9a-fA-F:]+(?:%\S+)?)/(\d+)", line)
            if not m_addr:
                continue
            addr = m_addr.group(1)
            try:
                prefix = int(m_addr.group(2))
            except ValueError:
                continue
            interfaces_ip.setdefault(current_intf, {}).setdefault("ipv6", {})[addr] = {
                "prefix_length": prefix
            }

    def get_interfaces_ip(self) -> dict:
        """
        Return IP addresses per interface.

        IPv4 comes from 'show ip interface brief' (ntc-template);
        IPv6 from 'show ipv6 interface brief' (regex).
        """
        interfaces_ip: dict = {}
        self._ipv4_from_brief(interfaces_ip)
        self._ipv6_from_brief(interfaces_ip)
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

        Parses 'show vlan' with the dell_force10 ntc-template.  The template
        emits one row per port (multiple rows share the same VLAN_ID), so rows
        are grouped and all non-empty port column values are aggregated into the
        'interfaces' list.
        """
        raw = self.device.send_command("show vlan")
        try:
            parsed = parse_output(platform="dell_force10", command="show vlan", data=raw)
        except Exception:
            logger.debug("Failed to parse 'show vlan' output", exc_info=True)
            return {}

        # Port columns produced by the template — each row has at most one filled.
        _PORT_KEYS = (
            "ports_u_gi", "ports_t_gi",
            "ports_u_te", "ports_t_te",
            "ports_u_fo", "ports_t_fo",
            "ports_u_ma", "ports_t_ma",
        )

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
            # Collect whichever port column is non-empty in this row.
            for key in _PORT_KEYS:
                port = row.get(key, "").strip()
                if port and port not in entry["interfaces"]:
                    entry["interfaces"].append(port)

        return vlans

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """Return per-interface VLAN config from ``show interfaces switchport``."""
        try:
            raw = self.device.send_command("show interfaces switchport")
        except Exception:
            logger.debug("FTOS show interfaces switchport failed", exc_info=True)
            return {}
        rows = _parse_ftos_show_interfaces_switchport(raw)
        result: dict[str, dict] = {}
        for row in rows:
            ifname = row.get("interface")
            if not ifname:
                continue
            info = _ftos_row_to_switchport_info(row)
            result[ifname] = classify_switchport(info)
        return result

    def get_network_instances(self, name: str = "") -> dict:
        """
        Return network instances (OS9 VRFs), NAPALM OC shape.

        Parsed driver-locally from ``show ip vrf`` (no ntc-template
        exists): one row per VRF with abbreviated comma-separated member
        interfaces that may wrap onto indented continuation lines and
        use trailing-number ranges (``Gi 1/3-1/5``). Member abbreviations
        expand to the full template forms (``Gi 1/2`` →
        ``GigabitEthernet 1/2``) because that is how this driver's
        get_interfaces()/get_interfaces_ip() key interfaces — the
        VRF→IP join is by exact name. The VRF named
        ``default`` (id 0) is the global routing table
        (DEFAULT_INSTANCE, empty membership); the ``management`` VRF
        (id 511) is a real VRF and is kept. OS9 keeps the RD in
        per-VRF BGP config — not collected in this pass.

        NOTE: built from the vendor-documented output format; not yet
        validated against a live OS9 device.
        """
        instances: dict = {
            "default": {
                "name": "default",
                "type": "DEFAULT_INSTANCE",
                "state": {"route_distinguisher": ""},
                "interfaces": {"interface": {}},
            },
        }
        raw = self.device.send_command("show ip vrf")
        for vrf_name, members in _ftos_parse_show_ip_vrf(raw or "").items():
            # Never let a row overwrite the seeded DEFAULT_INSTANCE.
            if vrf_name == "default":
                continue
            instances[vrf_name] = {
                "name": vrf_name,
                "type": "L3VRF",
                "state": {"route_distinguisher": ""},
                "interfaces": {"interface": {m: {} for m in members}},
            }
        if name:
            return {name: instances[name]} if name in instances else {}
        return instances


# "show ip vrf" rows: name, numeric VRF id, comma-separated abbreviated
# member interfaces that may wrap onto indented continuation lines. The
# header ("VRF-Name  VRF-ID  Interfaces") never matches — its second
# column is not numeric.
_FTOS_VRF_ROW_RE = re.compile(r"^\s*(?P<name>\S+)\s+(?P<vrf_id>\d+)\b(?P<rest>.*)$")
# Abbreviated member groups: one interface abbreviation followed by a
# comma-compressed number list — "Gi 1/2", "Te 1/3-1/5", and Dell's
# compressed forms "Te 0/14,16-17" / "Fo 0/48,52,56,60" where the numbers
# after the first inherit its slot head. A comma followed by a space starts
# a new group ("Gi 1/2, Vl 100"), matching the documented column layout.
_FTOS_VRF_GROUP_RE = re.compile(
    r"\b([A-Z][a-zA-Z]{0,2}) (\d[\d/.\-]*(?:,[\d/.\-]+)*)"
)


def _ftos_member_tokens(text: str) -> list[str]:
    """
    Expand abbreviated member groups into one "<Abbrev> <position>" token each.

    Within a group's comma list, items carrying a "/" set the slot head;
    bare numbers and bare ranges inherit the most recent head
    ("Te 0/14,16-17" → "Te 0/14", "Te 0/16-17").
    """
    tokens: list[str] = []
    for abbrev, numlist in _FTOS_VRF_GROUP_RE.findall(text):
        head = ""
        for item in numlist.split(","):
            item = item.strip()
            if not item:
                continue
            if "/" in item:
                # Derive the inheritable head from the LEFT side of a
                # range so "1/3-1/5" yields head "1", not "1/3-1".
                left = item.partition("-")[0]
                if "/" in left:
                    head = left.rsplit("/", 1)[0]
                tokens.append(f"{abbrev} {item}")
            elif head:
                tokens.append(f"{abbrev} {head}/{item}")
            else:
                tokens.append(f"{abbrev} {item}")
    return tokens
# show ip vrf abbreviations → the full interface names the dell_force10
# ntc-templates emit (and therefore how get_interfaces()/get_interfaces_ip()
# key interfaces — the VRF→IP join is by exact name). Unknown abbreviations
# pass through unexpanded and simply never join.
_FTOS_ABBREV_TO_FULL = {
    "Fa": "FastEthernet",
    "Gi": "GigabitEthernet",
    "Te": "TenGigabitEthernet",
    # OS9 displays the higher speeds lowercase-first ("fortyGigE 0/48
    # is up") and the getters key with device casing.
    "Tf": "twentyFiveGigE",
    "Fo": "fortyGigE",
    "Fi": "fiftyGigE",
    "Hu": "hundredGigE",
    "Ma": "ManagementEthernet",
    "Vl": "Vlan",
    "Po": "Port-channel",
    "Lo": "Loopback",
    "Tu": "Tunnel",
}


def _ftos_expand_member_range(token: str) -> list[str]:
    """
    Expand a trailing-number member range ("Gi 1/3-1/5" → Gi 1/3..1/5).

    Tokens without a range (or with an unparseable or cross-slot one —
    "Gi 1/3-2/5") pass through unchanged — an unexpanded token simply
    never joins an interface name, which is safer than guessing.
    """
    if "-" not in token:
        return [token]
    prefix, _, value = token.partition(" ")
    left, _, right = value.partition("-")
    left_head, _, left_last = left.rpartition("/")
    right_head, _, right_last = right.rpartition("/")
    if right_head and right_head != left_head:
        # Cross-slot range: expanding only the trailing number would
        # fabricate interface names that may belong to other VRFs.
        return [token]
    try:
        start, end = int(left_last), int(right_last)
    except ValueError:
        return [token]
    if end < start or end - start > 512:
        return [token]
    head = f"{left_head}/" if left_head else ""
    return [f"{prefix} {head}{n}" for n in range(start, end + 1)]


def _ftos_expand_member_name(token: str) -> str:
    """Expand "Gi 1/2" to the full "GigabitEthernet 1/2" template form."""
    abbrev, _, rest = token.partition(" ")
    full = _FTOS_ABBREV_TO_FULL.get(abbrev)
    return f"{full} {rest}" if full and rest else token


# Wrapped member lines align under the Interfaces column (far right of the
# 34-char name + id columns); VRF rows start at the left margin. Requiring
# deep indentation keeps a short uppercase VRF name row ("RED  1  Gi 1/7")
# from ever being mistaken for a continuation of the previous VRF.
_FTOS_CONTINUATION_MIN_INDENT = 8


def _ftos_is_member_continuation(line: str) -> bool:
    """
    True when a line holds only wrapped member tokens (no name/id columns).

    A continuation like ``Te 1/20`` would otherwise satisfy the row regex
    ("Te" as the name, "1" as the id) — but unlike a real row, a
    continuation is deeply indented under the Interfaces column AND
    removing every member token (plus separators) leaves nothing behind.
    """
    indent = len(line) - len(line.lstrip())
    if indent < _FTOS_CONTINUATION_MIN_INDENT:
        return False
    residue = _FTOS_VRF_GROUP_RE.sub("", line).replace(",", "").strip()
    return not residue


def _ftos_parse_show_ip_vrf(raw: str) -> dict[str, list[str]]:
    """Parse ``show ip vrf`` into vrf name → expanded member interface names."""
    members_by_vrf: dict[str, list[str]] = {}
    current: str | None = None
    for line in raw.splitlines():
        if not line.strip():
            continue
        if _ftos_is_member_continuation(line):
            # Continuation with no owning row (e.g. orphaned by a paging
            # header): drop it rather than letting the row regex turn it
            # into a phantom VRF named after an abbreviation.
            if current is None:
                continue
            member_text = line
        else:
            m = _FTOS_VRF_ROW_RE.match(line)
            if not m:
                # Header / footer / unparseable row: reset so a later
                # orphaned continuation can't attach to a stale VRF.
                current = None
                continue
            current = m.group("name")
            members_by_vrf.setdefault(current, [])
            member_text = m.group("rest")
        for token in _ftos_member_tokens(member_text):
            members_by_vrf[current].extend(
                _ftos_expand_member_name(t)
                for t in _ftos_expand_member_range(token)
            )
    return members_by_vrf
