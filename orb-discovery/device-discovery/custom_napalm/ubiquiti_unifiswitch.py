# Copyright 2026 NetBox Labs Inc
"""
Custom Ubiquiti UniFi Switch NAPALM driver.

UniFi switches run a Cisco IOS-style CLI, but the SSH session first lands at a
Linux shell; Netmiko's ubiquiti_unifiswitch driver transparently runs
'telnet localhost' to reach the network CLI before handing control over.

No ntc-templates exist for ubiquiti_unifiswitch; all parsing is done with regex.

Implements: get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.
"""

import ipaddress
import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.netmiko_helpers import netmiko_args

from custom_napalm._vlan import SwitchportInfo, classify_switchport, coerce_vid

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config sanitization — Cisco IOS-style credentials
# ---------------------------------------------------------------------------

# "username admin password 7 HASH" / "username admin secret 5 $1$..."
_USERNAME_RE = re.compile(
    r"(username\s+\S+\s+(?:password|secret)(?:\s+\d+)?)\s+\S+",
    re.IGNORECASE,
)
# "enable password 7 HASH" / "enable secret 5 $1$..."
_ENABLE_RE = re.compile(
    r"(enable\s+(?:password|secret)(?:\s+\d+)?)\s+\S+",
    re.IGNORECASE,
)
# "snmp-server community public ro"
_SNMP_RE = re.compile(
    r"(snmp-server\s+community)\s+\S+",
    re.IGNORECASE,
)


def _sanitize_config(text: str) -> str:
    text = _USERNAME_RE.sub(r"\1 <redacted>", text)
    text = _ENABLE_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# 'show version' parsing — regex (no ntc-template available)
# ---------------------------------------------------------------------------

# "Machine Model.............. US-24-250W"
_MODEL_RE = re.compile(r"Machine\s+Model[.\s]+(\S+)", re.IGNORECASE)
# "Serial Number.............. F09FC2AB1234"
_SERIAL_RE = re.compile(r"Serial\s+Number[.\s]+(\S+)", re.IGNORECASE)
# "Software Version........... 4.0.66.10832"
_VERSION_RE = re.compile(r"Software\s+Version[.\s]+(\S+)", re.IGNORECASE)


def _parse_version(raw: str) -> dict[str, str]:
    """Extract model, serial, and software version from 'show version' output."""
    result: dict[str, str] = {}
    for key, pattern in (
        ("model", _MODEL_RE),
        ("serial_number", _SERIAL_RE),
        ("os_version", _VERSION_RE),
    ):
        m = pattern.search(raw)
        result[key] = m.group(1).strip() if m else "Unknown"
    return result


# ---------------------------------------------------------------------------
# Interface status parsing — 'show interfaces status all'
# ---------------------------------------------------------------------------

# Same column layout as EdgeSwitch:
#    0/1    Copper  Enabled     Forwarding  Up      Full-100M   Full-100M   Copper
_INTF_LINE_RE = re.compile(
    r"^\s*"
    r"(?P<intf>\S+)\s+"                       # channel/interface
    r"\S+\s+"                                  # Type (Copper, Fiber)
    r"(?P<neg>Enabled|Disabled)\s+"            # Neg/admin — anchors against headers
    r"(?P<state>\S+)\s+"                       # Port state (Forwarding, Disabled, Blocking, …)
    r"(?P<link>\S+)",                           # Link state (Up/Down)
    re.IGNORECASE,
)

# "Full-100M" → 100.0 Mbps, "Full-1000M" → 1000.0, "Full-10G" → 10000.0
_SPEED_RE = re.compile(r"(?:Full|Half)-(\d+)([MG])", re.IGNORECASE)


def _parse_speed(speed_str: str) -> float:
    """Convert 'Full-100M' style string to Mbps."""
    m = _SPEED_RE.match(speed_str)
    if not m:
        return -1.0
    val, unit = int(m.group(1)), m.group(2).upper()
    return float(val * 1000 if unit == "G" else val)


# ---------------------------------------------------------------------------
# IP interface parsing — 'show ip interface'
# ---------------------------------------------------------------------------

# "192.168.1.1        255.255.255.0      VLAN 1     Valid"
_IP_INTF_RE = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<mask>[\d.]+)\s+"
    r"(?P<intf_type>\w+)\s+(?P<intf_id>\d+)\s+"
    r"Valid",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# VLAN parsing — 'show vlan' (no ntc-template, regex only)
# ---------------------------------------------------------------------------

# "1        Default                      Default"
# "100      Management                   Static"
# Name and type are separated by 2+ spaces; match any type word.
_VLAN_LINE_RE = re.compile(
    r"^(?P<id>\d+)\s+(?P<name>.*?)\s{2,}\S+\s*$",
)


# ---------------------------------------------------------------------------
# VLAN membership parsing — 'show running-config'
# ---------------------------------------------------------------------------

def _expand_vlan_tokens(token_str: str) -> list[str]:
    """Expand a comma-separated VLAN list (with optional ranges) into VLAN ID strings."""
    vids: list[str] = []
    for token in token_str.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            start, _, end = token.partition("-")
            try:
                start_vid = int(start.strip())
                end_vid = int(end.strip())
            except ValueError:
                logger.warning("Skipping malformed VLAN range token %r", token)
                continue
            if start_vid > end_vid:
                logger.warning("Skipping reversed VLAN range token %r", token)
                continue
            vids.extend(str(v) for v in range(start_vid, end_vid + 1))
        else:
            try:
                int(token)
            except ValueError:
                logger.warning("Skipping malformed VLAN token %r", token)
                continue
            vids.append(token)
    return vids


def _parse_vlan_members(config: str) -> dict[str, list[str]]:
    """
    Extract VLAN → interface membership from UniFi running-config.

    Returns {vlan_id_str: [interface_names]}.
    """
    result: dict[str, list[str]] = {}
    current_intf: str | None = None
    for line in config.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        m_intf = re.match(r"^interface\s+(.+)$", stripped)
        if m_intf:
            current_intf = m_intf.group(1)
            continue
        if stripped == "!":
            current_intf = None
            continue
        if current_intf:
            m_vlan = re.match(r"^vlan\s+participation\s+include\s+(.+)$", stripped)
            if m_vlan:
                for vid in _expand_vlan_tokens(m_vlan.group(1)):
                    result.setdefault(vid, []).append(current_intf)
    return result


# ---------------------------------------------------------------------------
# Per-VID membership parsing — `show vlan id <vid>` (driver-local regex)
# ---------------------------------------------------------------------------

# `show vlan` (no id) emits a simple VID/name/type table. The simpler form is
# the only one UniFiSwitch produces (no per-port tagging detail), so we
# enumerate VIDs here and then issue `show vlan id <vid>` per VID to obtain
# per-port tagging — same approach hp_procurve's batch-4 driver uses.
_UNIFI_VLAN_LIST_RE = re.compile(r"^\s*(?P<vid>\d+)\s+\S")

# Per-VID detail table row. Columns:
#   Interface  Current  Configured  Tagging
#   0/1        Include  Autodetect  Untagged
#   0/2        Include  Autodetect  Tagged
#   0/3        Exclude  Autodetect  Tagged
# We only care about rows whose Current column is `Include` — those are the
# actual VLAN members. The Tagging column then tells us how (Tagged or
# Untagged); anything else (e.g. blank) is ignored.
_UNIFI_VLAN_MEMBER_RE = re.compile(
    r"^\s*(?P<port>\S+)\s+(?P<current>Include|Exclude|Autodetect)\s+"
    r"\S+\s+(?P<tagging>Tagged|Untagged)\s*$",
    re.IGNORECASE,
)


def _parse_unifi_vlan_list(text: str) -> list[int]:
    """Return the list of VIDs declared by `show vlan` (simple list form)."""
    vids: list[int] = []
    for line in text.splitlines():
        m = _UNIFI_VLAN_LIST_RE.match(line)
        if not m:
            continue
        vid = coerce_vid(m.group("vid"))
        if vid is not None and vid not in vids:
            vids.append(vid)
    return vids


def _parse_unifi_vlan_detail(text: str) -> list[tuple[str, str]]:
    """
    Parse `show vlan id <vid>` membership table → ``[(port, tagging), ...]``.

    Only rows whose Current column equals ``Include`` are returned; Exclude
    rows mean the port is not a member of this VLAN. The header,
    blank lines, and the dashes separator line are skipped because they
    do not match the four-column row regex.
    """
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Skip the dashes separator line.
        if set(stripped) <= set("- "):
            continue
        m = _UNIFI_VLAN_MEMBER_RE.match(line)
        if not m:
            continue
        if m.group("current").lower() != "include":
            continue
        out.append((m.group("port"), m.group("tagging").capitalize()))
    return out


def _unifi_aggregate_to_switchport(per_port: dict) -> SwitchportInfo:
    """
    Map a single port's aggregated ``{untagged, tagged}`` to a SwitchportInfo.

    UniFiSwitch (Broadcom-fastpath derived) carries no separate Access/Trunk/
    General keyword in the per-VLAN detail; the membership shape is the only
    signal we have. Same rules as HP ProCurve:

    * exactly one untagged + no tagged → access on the untagged VID.
    * exactly one untagged + ≥1 tagged → trunk with that as native.
    * tagged-only → trunk with no native VLAN.
    * >1 untagged → routed (anomalous; IEEE 802.1Q forbids it).
    * neither → routed/excluded.

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
        allowed_vlans=tagged,
    )


class UniFiSwitchDriver(_napalm_base.NetworkDriver):
    """Ubiquiti UniFi Switch NAPALM driver (read-only subset for device-discovery)."""

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
        """Open an SSH connection via Netmiko (handles telnet-localhost tunnel internally)."""
        self.device = self._netmiko_open(
            "ubiquiti_unifiswitch", netmiko_optional_args=self.netmiko_optional_args
        )
        self._intf_status_raw: str | None = None

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
    # Internal helpers
    # ------------------------------------------------------------------

    def _hostname_from_config(self, config: str) -> str:
        """Extract hostname from 'hostname <name>' line in running-config."""
        for line in config.splitlines():
            stripped = line.strip()
            if stripped.startswith("hostname "):
                return stripped.split("hostname ", 1)[1].strip()
        return self.hostname

    def _get_intf_status_raw(self) -> str:
        """Fetch 'show interfaces status all' once and cache for this connection."""
        if not hasattr(self, "_intf_status_raw") or self._intf_status_raw is None:
            self._intf_status_raw = self.device.send_command("show interfaces status all")
        return self._intf_status_raw

    # ------------------------------------------------------------------
    # NAPALM getters
    # ------------------------------------------------------------------

    def get_facts(self) -> dict:
        """
        Return general device facts.

        Facts are assembled from three commands:
        - 'show version'               → model, serial, os_version (regex)
        - 'show running-config'        → hostname (regex on 'hostname' line)
        - 'show interfaces status all' → interface_list (regex)

        Uptime is not available without a dedicated parse; it is returned as 0.0.
        """
        raw_ver = self.device.send_command("show version")
        ver_info = _parse_version(raw_ver)

        config_raw = self.device.send_command("show running-config")
        hostname = self._hostname_from_config(config_raw)

        interface_list: list[str] = []
        for line in self._get_intf_status_raw().splitlines():
            m = _INTF_LINE_RE.match(line)
            if m:
                interface_list.append(m.group("intf"))

        return {
            "hostname": hostname,
            "vendor": "Ubiquiti",
            "model": ver_info["model"],
            "os_version": ver_info["os_version"],
            "serial_number": ver_info["serial_number"],
            "uptime": 0.0,
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """
        Return interface details from 'show interfaces status all'.

        is_enabled: Port State != 'Disabled' (Disabled = admin-shutdown)
        is_up:      Link State == 'Up'
        speed:      parsed from Physical Mode column (e.g. 'Full-100M' → 100.0 Mbps)

        Note: the Neg column reflects auto-negotiation, not admin state.
        Admin-shutdown ports show Port State == 'Disabled' regardless of Neg.
        """
        interfaces: dict = {}
        for line in self._get_intf_status_raw().splitlines():
            m = _INTF_LINE_RE.match(line)
            if not m:
                continue
            intf = m.group("intf")
            state = m.group("state").lower()
            link = m.group("link").lower()

            remainder = line[m.end():]
            speed_m = _SPEED_RE.search(remainder)
            speed = _parse_speed(speed_m.group(0)) if speed_m else -1.0

            interfaces[intf] = {
                "is_up": link == "up",
                "is_enabled": state != "disabled",
                "description": "",
                "last_flapped": -1.0,
                "mtu": -1,
                "speed": speed,
                "mac_address": "",
            }
        return interfaces

    def get_interfaces_ip(self) -> dict:
        """
        Return IP addresses per interface from 'show ip interface'.

        Interface names are normalised to lowercase (e.g. 'VLAN 1' → 'vlan1').
        """
        interfaces_ip: dict = {}
        raw = self.device.send_command("show ip interface")
        for line in raw.splitlines():
            m = _IP_INTF_RE.match(line)
            if not m:
                continue
            ip_str = m.group("ip")
            mask_str = m.group("mask")
            intf_name = f"{m.group('intf_type').lower()}{m.group('intf_id')}"
            try:
                prefix = ipaddress.IPv4Network(
                    f"0.0.0.0/{mask_str}", strict=False
                ).prefixlen
            except ValueError:
                continue
            (
                interfaces_ip
                .setdefault(intf_name, {})
                .setdefault("ipv4", {})[ip_str]
            ) = {"prefix_length": prefix}
        return interfaces_ip

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """Return device configuration from 'show running-config' and 'show startup-config'."""
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

        VLAN names are parsed from 'show vlan' with regex (no ntc-template available).
        Interface membership is parsed from 'show running-config' by scanning
        'vlan participation include <ids>' lines within interface blocks.
        """
        vlans: dict = {}

        raw_vlan = self.device.send_command("show vlan")
        for line in raw_vlan.splitlines():
            m = _VLAN_LINE_RE.match(line)
            if m:
                vid = m.group("id").strip()
                name = m.group("name").strip() or vid
                vlans[vid] = {"name": name, "interfaces": []}

        config_raw = self.device.send_command("show running-config")
        for vid, intfs in _parse_vlan_members(config_raw).items():
            if vid in vlans:
                vlans[vid]["interfaces"] = intfs
            else:
                vlans[vid] = {"name": vid, "interfaces": intfs}

        return vlans

    def _unifi_collect_per_port(self, vids: list[int]) -> dict[str, dict]:
        """Issue ``show vlan id <vid>`` per VID and return per-port aggregates."""
        per_port: dict[str, dict] = {}
        for vid in vids:
            try:
                detail = self.device.send_command(f"show vlan id {vid}")
            except Exception:
                logger.debug("UnifiSwitch show vlan id %s failed", vid, exc_info=True)
                continue
            if not detail:
                continue
            for port, tagging in _parse_unifi_vlan_detail(detail):
                entry = per_port.setdefault(port, {"untagged": [], "tagged": []})
                if tagging == "Untagged":
                    if vid not in entry["untagged"]:
                        entry["untagged"].append(vid)
                elif tagging == "Tagged" and vid not in entry["tagged"]:
                    entry["tagged"].append(vid)
        return per_port

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """
        Return per-interface VLAN config aggregated from per-VLAN port lists.

        UniFiSwitch shares the Broadcom-fastpath CLI with EdgeSwitch and
        emits only the simple ``show vlan`` list (VID/name/type) — there is
        no per-port tagging detail in that single command. We therefore
        enumerate VIDs from ``show vlan`` and issue ``show vlan id <vid>``
        per VID to read the membership table, then aggregate per-port and
        infer mode from the membership shape. This mirrors the batch-4
        ProCurve approach.
        """
        try:
            vlan_list_raw = self.device.send_command("show vlan")
        except Exception:
            logger.debug("UnifiSwitch show vlan failed", exc_info=True)
            return {}
        vids = _parse_unifi_vlan_list(vlan_list_raw)
        if not vids:
            return {}

        per_port = self._unifi_collect_per_port(vids)

        result: dict[str, dict] = {}
        for port, data in per_port.items():
            info = _unifi_aggregate_to_switchport(data)
            result[port] = classify_switchport(info)
        return result
