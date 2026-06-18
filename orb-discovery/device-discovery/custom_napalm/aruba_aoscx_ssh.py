# Copyright 2026 NetBox Labs Inc
"""
Custom Aruba AOS-CX NAPALM driver — SSH CLI via Netmiko + ntc-templates.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses the ``aruba_aoscx`` Netmiko device type and ntc-templates platform
for structured parsing of:
  show system, show interface, show vlan, show running-config, show startup-config.

IP address extraction uses the IP_ADDRESS field from the ``show interface``
template which captures the primary IPv4 address in CIDR notation.
"""

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
    parse_vlan_range_string,
)

logger = logging.getLogger(__name__)


_AOSCX_VLAN_PORT_ROW_RE = re.compile(
    r"^\s*(?P<port>\S+)\s+"
    r"(?P<mode>access|native-untagged|native-tagged|trunk|routed)\s+"
    r"(?P<native>\d+|--|-)\s+"
    r"(?P<tagged>.*?)\s*$",
    re.IGNORECASE,
)


def _parse_aoscx_show_vlan_port_config(text: str) -> list[dict]:
    """
    Parse AOS-CX ``show vlan port-config`` into per-port dicts.

    Output format (10.x):
        Port    Mode             Native VLAN   Tagged VLAN(s)
        -----   --------------   -----------   ------------------
        1/1/1   access           10            --
        1/1/2   native-untagged  99            100, 200
        1/1/3   trunk            --            100, 200
        1/1/5   routed           --            --
    """
    rows: list[dict] = []
    saw_header = False
    for line in text.splitlines():
        if not saw_header:
            if "mode" in line.lower() and "tagged" in line.lower():
                saw_header = True
            continue
        stripped = line.strip()
        if not stripped or set(stripped) <= {"-", " "}:
            continue
        m = _AOSCX_VLAN_PORT_ROW_RE.match(line)
        if not m:
            continue
        rows.append({
            "port": m.group("port"),
            "mode": m.group("mode").lower(),
            "native": m.group("native"),
            "tagged": m.group("tagged").strip(),
        })
    return rows


def _aoscx_ssh_row_to_switchport_info(row: dict) -> SwitchportInfo:
    """
    Map a parsed ``show vlan port-config`` row to a SwitchportInfo.

    AOS-CX vlan_mode semantics — same as the REST counterpart from batch 2:
      - access            : untagged-only on a single VLAN
      - native-untagged   : native VLAN + tagged list
      - native-tagged     : native VID also tagged on egress; folded into
                            tagged list with no untagged emitted
      - trunk             : tagged-only; empty tagged list ⇒ all VLANs
      - routed            : L3 (no switchport)
    """
    mode = (row.get("mode") or "").lower()
    if mode in ("routed", ""):
        return SwitchportInfo(
            enabled=False,
            admin_mode=None,
            oper_mode=None,
            access_vlan=None,
            native_vlan=None,
            allowed_vlans=None,
        )

    native_raw = row.get("native")
    native_str = native_raw.strip() if isinstance(native_raw, str) else native_raw
    native_vid = coerce_vid(native_str)

    tagged_raw = (row.get("tagged") or "").strip()
    if tagged_raw and tagged_raw not in ("--", "-"):
        spec = tagged_raw.replace(" ", "")
        vids, is_wildcard = parse_vlan_range_string(spec)
    else:
        vids, is_wildcard = [], False

    if mode == "access":
        return SwitchportInfo(
            enabled=True,
            admin_mode="access",
            oper_mode="access",
            access_vlan=native_vid,
            native_vlan=None,
            allowed_vlans=None,
        )
    if mode == "native-untagged":
        allowed: list[int] | str | None = (
            "all" if is_wildcard else (vids or None)
        )
        return SwitchportInfo(
            enabled=True,
            admin_mode="trunk",
            oper_mode="trunk",
            access_vlan=None,
            native_vlan=native_vid,
            allowed_vlans=allowed,
        )
    if mode == "native-tagged":
        merged: list[int] = list(vids)
        if native_vid is not None and native_vid not in merged:
            merged.append(native_vid)
        return SwitchportInfo(
            enabled=True,
            admin_mode="trunk",
            oper_mode="trunk",
            access_vlan=None,
            native_vlan=None,
            allowed_vlans=merged if merged else "all",
        )
    if mode == "trunk":
        if not vids and not is_wildcard:
            return SwitchportInfo(
                enabled=True,
                admin_mode="trunk",
                oper_mode="trunk",
                access_vlan=None,
                native_vlan=None,
                allowed_vlans="all",
            )
        return SwitchportInfo(
            enabled=True,
            admin_mode="trunk",
            oper_mode="trunk",
            access_vlan=None,
            native_vlan=None,
            allowed_vlans="all" if is_wildcard else vids,
        )
    return SwitchportInfo(
        enabled=False,
        admin_mode=None,
        oper_mode=None,
        access_vlan=None,
        native_vlan=None,
        allowed_vlans=None,
    )

_PLATFORM = "aruba_aoscx"

# ---------------------------------------------------------------------------
# Config sanitization
# AOS-CX CLI config uses password/passkey/secret keywords
# ---------------------------------------------------------------------------
_PASSWORD_RE = re.compile(
    r"((?:password|secret|passkey)\s+)\S+", re.IGNORECASE
)
_RADIUS_KEY_RE = re.compile(
    r"(radius-server\s+(?:host\s+\S+\s+)?key)\s+\S+", re.IGNORECASE
)
_TACACS_KEY_RE = re.compile(
    r"(tacacs-server\s+(?:host\s+\S+\s+)?key)\s+\S+", re.IGNORECASE
)
_SNMP_COMM_RE = re.compile(
    r"(snmp-server\s+community)\s+\S+", re.IGNORECASE
)


def _sanitize_config(text: str) -> str:
    text = _PASSWORD_RE.sub(r"\1<redacted>", text)
    text = _RADIUS_KEY_RE.sub(r"\1 <redacted>", text)
    text = _TACACS_KEY_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_COMM_RE.sub(r"\1 <redacted>", text)
    return text


# Uptime conversion constants
_WEEK_SECONDS = 7 * 24 * 3600
_DAY_SECONDS = 24 * 3600
_HOUR_SECONDS = 3600
_MINUTE_SECONDS = 60


def _parse_uptime(row: dict) -> float:
    """Convert ntc-template uptime fields (weeks/days/hours/minutes) to seconds."""
    seconds = 0.0
    for field, factor in (
        ("uptime_weeks", _WEEK_SECONDS),
        ("uptime_days", _DAY_SECONDS),
        ("uptime_hours", _HOUR_SECONDS),
        ("uptime_minutes", _MINUTE_SECONDS),
    ):
        val = row.get(field, "") or ""
        if val.isdigit():
            seconds += int(val) * factor
    return seconds


def _parse_speed_mbps(speed_str: str) -> float:
    """
    Convert an AOS-CX speed string to Mbps (float).

    The ntc-template captures speed as e.g. ``"1000 Mb/s"``, ``"10 Gb/s"``.
    Returns -1.0 when the string is empty or unparseable.
    """
    if not speed_str:
        return -1.0
    speed_str = speed_str.strip().lower()
    m = re.match(r"(\d+(?:\.\d+)?)\s*(gb|mb|kb)?", speed_str)
    if not m:
        return -1.0
    value = float(m.group(1))
    unit = m.group(2) or "mb"
    if unit == "gb":
        value *= 1000.0
    elif unit == "kb":
        value /= 1000.0
    return value


class AOSCXSSHDriver(_napalm_base.NetworkDriver):
    """Aruba AOS-CX NAPALM SSH driver using Netmiko + ntc-templates (read-only subset)."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Initialise driver — no network connection is made here."""
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
        """Open an SSH connection via Netmiko."""
        self.device = self._netmiko_open(
            "aruba_aoscx",
            netmiko_optional_args=self.netmiko_optional_args,
        )

    def close(self):
        """Close the SSH connection."""
        self._netmiko_close()

    def is_alive(self):
        """Return whether the SSH channel is still active."""
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

    def _send(self, command: str) -> str:
        return self.device.send_command(command)

    def _parse(self, command: str, data: str) -> list[dict]:
        return parse_output(platform=_PLATFORM, command=command, data=data)

    # ------------------------------------------------------------------
    # NAPALM getters
    # ------------------------------------------------------------------

    def get_facts(self) -> dict:
        """Return general device facts from ``show system``."""
        raw = self._send("show system")
        parsed = self._parse("show system", raw)
        if not parsed:
            return {}

        row = parsed[0]
        interface_list = []
        intf_raw = self._send("show interface")
        if intf_raw:
            intf_parsed = self._parse("show interface", intf_raw)
            interface_list = [
                r["interface"]
                for r in intf_parsed
                if r.get("interface")
            ]

        return {
            "hostname": row.get("hostname", "Unknown"),
            "vendor": "HPE",
            "model": (row.get("product", "") or "Unknown").strip(),
            "os_version": row.get("version", "Unknown"),
            "serial_number": row.get("serial", "Unknown"),
            "uptime": _parse_uptime(row),
            "fqdn": row.get("hostname", "Unknown"),
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """Return interface details from ``show interface``."""
        raw = self._send("show interface")
        if not raw:
            return {}

        parsed = self._parse("show interface", raw)
        result = {}
        for row in parsed:
            name = row.get("interface", "")
            if not name:
                continue

            mac_raw = row.get("mac_address", "")
            try:
                mac_address = normalize_mac(mac_raw) if mac_raw else ""
            except Exception:
                mac_address = mac_raw

            result[name] = {
                "is_up": row.get("link_status", "").lower() == "up",
                "is_enabled": row.get("link_admin", "").lower() == "up",
                "description": (row.get("interface_desc", "") or "").strip(),
                "last_flapped": -1.0,
                "mtu": int(row["mtu"]) if row.get("mtu", "").isdigit() else -1,
                "speed": _parse_speed_mbps(row.get("speed", "")),
                "mac_address": mac_address,
            }

        return result

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface from ``show interface``."""
        raw = self._send("show interface")
        if not raw:
            return {}

        parsed = self._parse("show interface", raw)
        result = {}
        for row in parsed:
            name = row.get("interface", "")
            if not name:
                continue

            intf_ips: dict = {}

            # Primary IPv4 (format: "x.x.x.x/prefix")
            ip_primary = row.get("ip_address", "")
            if ip_primary and "/" in ip_primary:
                addr, prefix = ip_primary.rsplit("/", 1)
                if prefix.isdigit():
                    intf_ips.setdefault("ipv4", {})[addr] = {
                        "prefix_length": int(prefix)
                    }

            # Secondary IPv4
            for ip_sec in row.get("secondary_ip_address", []):
                if ip_sec and "/" in ip_sec:
                    addr, prefix = ip_sec.rsplit("/", 1)
                    if prefix.isdigit():
                        intf_ips.setdefault("ipv4", {})[addr] = {
                            "prefix_length": int(prefix)
                        }

            if intf_ips:
                result[name] = intf_ips

        return result

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """Return device configuration from ``show running-config`` / ``show startup-config``."""
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}

        if retrieve in ("running", "all"):
            config["running"] = self._send("show running-config")

        if retrieve in ("startup", "all"):
            config["startup"] = self._send("show startup-config")

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Return VLAN information from ``show vlan``."""
        raw = self._send("show vlan")
        if not raw:
            return {}

        parsed = self._parse("show vlan", raw)
        result: dict = {}
        for row in parsed:
            vlan_id = row.get("vlan_id", "")
            if not vlan_id:
                continue
            entry = result.setdefault(
                vlan_id,
                {
                    "name": row.get("vlan_name", "") or vlan_id,
                    "interfaces": [],
                },
            )
            for intf in row.get("interfaces", []):
                intf = intf.strip()
                if intf and intf not in entry["interfaces"]:
                    entry["interfaces"].append(intf)

        return result

    def get_chassis_members(self) -> dict | None:
        """
        Return Aruba CX VSF (Virtual Switching Framework) member info.

        Parses ``show vsf detail`` via the ntc-template
        ``aruba_aoscx_show_vsf_detail`` and uses the captured ``Status``
        field both for absent-slot filtering and as the role string —
        on AOS-CX, ``Status`` in detail output IS the role
        (``Active`` / ``Standby`` / ``Member``).

        Per-member ``model`` and ``priority`` are NOT collected on this
        transport — ``show vsf detail`` doesn't surface them and the
        ``show vsf`` summary table requires column-position assumptions
        that drift across firmware revisions. Use the REST transport
        (``aruba_aoscx``) when accurate per-member model / priority
        matters (e.g. mixed-model VSF stacks).

        Standalone AOS-CX (no VSF configured) returns ``None`` — empty
        detail output, no members parsed, translate falls back to the
        single-Device path.
        """
        return _aoscx_ssh_get_chassis_members_impl(self)

    def get_modules(self) -> dict | None:
        """
        Module discovery is unsupported over the AOS-CX SSH transport.

        AOS-CX has no `show modules` CLI inventory that ntc-templates can
        parse, so modular discovery requires the REST `aruba_aoscx` driver.
        Always returns None (with a one-time debug log).
        """
        logger.debug(
            "aruba_aoscx_ssh.get_modules: modular discovery requires the REST "
            "aruba_aoscx transport; returning None"
        )
        return None

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """Return per-interface VLAN config from ``show vlan port-config``."""
        try:
            raw = self.device.send_command("show vlan port-config")
        except Exception:
            logger.debug(
                "AOS-CX-SSH show vlan port-config failed", exc_info=True
            )
            return {}
        rows = _parse_aoscx_show_vlan_port_config(raw)
        result: dict[str, dict] = {}
        for row in rows:
            port = row.get("port")
            if not port:
                continue
            info = _aoscx_ssh_row_to_switchport_info(row)
            result[port] = classify_switchport(info)
        return result


# ---------------------------------------------------------------------------
# AOS-CX VSF (Virtual Switching Framework) — chassis-members impl.
#
# Inlined here (not in a shared _aruba_cx_vsf module) so this driver stays
# self-contained alongside the vendor-neutral primitives in _chassis.py. The
# small role-alias and absent-status pieces are duplicated from
# aruba_aoscx.py (REST transport) — both are <10 lines and keeping each
# driver self-contained is preferred to a vendor-only shared module.
# ---------------------------------------------------------------------------

# Member-status values that mean "slot is reserved but no hardware is present".
# Space-separated forms (``Not Present``) get their spaces folded to underscores
# in the normalization step below, so we only need to enumerate the underscore
# canonical form here.
_AOSCX_ABSENT_STATUSES = frozenset({"missing", "not_present", "notpresent", "absent"})


def _aoscx_normalize_vsf_status(raw: str | None) -> str:
    """Lowercase + fold spaces/hyphens to underscores. Empty input → empty string."""
    if not raw:
        return ""
    return raw.strip().lower().replace(" ", "_").replace("-", "_")


def _aoscx_normalize_vsf_role(raw: str | None) -> str:
    """
    Map an AOS-CX VSF role string to {"active","standby","member"}.

    AOS-CX 10.10+ uses "conductor" / "commander" for what earlier firmware
    called "master". Both are returned directly as "active" — we don't
    detour through normalize_role's "master" → "active" lookup because the
    AOS-CX vocabulary doesn't include "master" so there's no value in the
    indirection. Empty / None / unknown → "member".

    The role on AOS-CX comes from the ``Status`` field in ``show vsf
    detail`` (the column is literally labeled "Status" but contains the
    role string: ``Active`` / ``Standby`` / ``Member``).
    """
    if not raw:
        return "member"
    lower = raw.strip().lower()
    if lower in ("conductor", "commander"):
        return "active"
    return normalize_role(lower)


def _aoscx_ssh_member_from_detail_row(detail_row: dict) -> ChassisMember | None:
    """
    Build one ChassisMember from an ntc-templates ``show vsf detail`` row.

    On AOS-CX, the ``Status`` field in detail output IS the member role
    (``Active`` / ``Standby`` / ``Member``), so role mapping uses the same
    string that drives absent-slot filtering — there's only one source of
    truth on the CLI path. Model and priority are NOT collected on the SSH
    path: ``show vsf detail`` doesn't surface them (the ntc-template stops
    at MAC / Status / Serial / CPU / Memory), and the ``show vsf`` summary
    table requires column-position assumptions that drift across firmware
    revisions. Operators who need model/priority on member devices should
    use the REST transport (``aruba_aoscx``), which gets them from the
    structured ``/system/vsf_members`` JSON. Mixed-model SSH stacks have
    member ``model`` emitted as empty (see translate_chassis's defensive
    clear of inherited chassis model) rather than misattributed.

    Returns None for absent slots (status in _AOSCX_ABSENT_STATUSES).
    """
    raw_id = (detail_row.get("member_id") or "").strip()
    try:
        mid = int(raw_id)
    except (TypeError, ValueError):
        return None
    raw_status = (detail_row.get("status") or "").strip()
    status_norm = _aoscx_normalize_vsf_status(raw_status)
    if status_norm in _AOSCX_ABSENT_STATUSES:
        return None
    return ChassisMember(
        id=mid,
        serial=(detail_row.get("serial_number") or "").strip(),
        model=None,
        role=_aoscx_normalize_vsf_role(raw_status),
        priority=None,
        mac=(detail_row.get("mac_address") or "").strip() or None,
        state=raw_status or None,
    )


def _aoscx_ssh_get_chassis_members_impl(driver) -> dict | None:
    """Implementation of AOSCXSSHDriver.get_chassis_members (factored for testability)."""
    try:
        detail_raw = driver._send("show vsf detail")
    except Exception as e:
        logger.warning(
            "aruba_aoscx_ssh.get_chassis_members: 'show vsf detail' failed: %s",
            e, exc_info=True,
        )
        return None

    if not detail_raw or not detail_raw.strip():
        return None

    try:
        detail_rows = driver._parse("show vsf detail", detail_raw)
    except Exception as e:
        logger.warning(
            "aruba_aoscx_ssh.get_chassis_members: ntc-templates parse failed: %s",
            e, exc_info=True,
        )
        return None

    if not detail_rows:
        return None

    members: list[ChassisMember] = []
    for row in detail_rows:
        m = _aoscx_ssh_member_from_detail_row(row)
        if m is not None:
            members.append(m)
    return to_payload(members, domain=None)
