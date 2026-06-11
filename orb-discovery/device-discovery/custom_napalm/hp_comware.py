# Copyright 2026 NetBox Labs Inc
# Based on napalm-h3c-cw7-ssh (Apache-2.0): https://github.com/napalm-automation-community/napalm-h3c-cw7-ssh
"""
Custom HP Comware NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko (hp_comware device type) and ntc-templates for structured
parsing wherever templates are available; falls back to regex for commands
without templates (display version).
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
from custom_napalm._modules import (
    MemberModules as _MemberModules,
)
from custom_napalm._modules import (
    ModuleBay as _ModuleBay,
)
from custom_napalm._modules import (
    ModuleEntry as _ModuleEntry,
)
from custom_napalm._modules import (
    to_payload as _modules_to_payload,
)
from custom_napalm._vlan import (
    SwitchportInfo,
    classify_switchport,
    coerce_vid,
)

logger = logging.getLogger(__name__)


# Comware abbreviates interface names in `display interface brief` and
# `display vlan all` (GE1/0/1) but emits the full names in `display interface`
# (GigabitEthernet1/0/1). The translate layer matches interface names exactly
# against `get_interfaces()` output, so we expand abbreviations here to keep
# the keys consistent across both code paths.
_COMWARE_IFACE_PREFIX_MAP = {
    "GE": "GigabitEthernet",
    "XGE": "Ten-GigabitEthernet",
    "M-GE": "M-GigabitEthernet",
    "25GE": "Twenty-FiveGigE",
    "40GE": "FortyGigE",
    "50GE": "FiftyGigE",
    "100GE": "HundredGigE",
    "200GE": "TwoHundredGigE",
    "400GE": "FourHundredGigE",
    "BAGG": "Bridge-Aggregation",
    "RAGG": "Route-Aggregation",
    "Vlan-int": "Vlan-interface",
}
# Sort by descending length so longer prefixes (e.g. ``100GE``, ``XGE``,
# ``M-GE``) are tried before the shorter ones they overlap with (``GE``).
_COMWARE_IFACE_PREFIXES_BY_LEN = sorted(
    _COMWARE_IFACE_PREFIX_MAP.items(), key=lambda kv: -len(kv[0])
)


def _expand_comware_iface(name: str) -> str:
    """
    Expand a Comware abbreviated interface name to its full form.

    ``GE1/0/1`` → ``GigabitEthernet1/0/1``; ``XGE1/0/49`` →
    ``Ten-GigabitEthernet1/0/49``; ``100GE1/0/1`` → ``HundredGigE1/0/1``.
    Names that don't match a known prefix (or already use the full form)
    are returned unchanged. The match anchors on a digit immediately after
    the prefix to avoid false positives like ``GEORGE``.
    """
    for prefix, expanded in _COMWARE_IFACE_PREFIXES_BY_LEN:
        if name.startswith(prefix):
            suffix = name[len(prefix):]
            if suffix and suffix[0].isdigit():
                return f"{expanded}{suffix}"
    return name


def _parse_comware_interface_brief_modes(rows: list[dict]) -> dict[str, dict]:
    """
    Build per-port mode + PVID dict from `display interface brief` rows.

    Bridge-mode ``Type`` values: A=access, T=trunk, H=hybrid. Route-mode
    rows omit Type/PVID and are skipped here (they map to routed via the
    merger when no entry exists for that interface).

    Interface names are expanded from their abbreviated form (``GE1/0/1``)
    into the full form (``GigabitEthernet1/0/1``) so they match what
    ``get_interfaces()`` emits — without this normalisation the translate
    layer's exact-name matching would silently drop the VLAN data.
    """
    out: dict[str, dict] = {}
    for r in rows or []:
        iface = r.get("interface")
        if not iface:
            continue
        type_letter = (r.get("type") or "").upper()
        if type_letter not in ("A", "T", "H"):
            continue
        pvid = coerce_vid(r.get("vlan_id") or "")
        mode = {"A": "access", "T": "trunk", "H": "hybrid"}[type_letter]
        out[_expand_comware_iface(iface)] = {"mode": mode, "pvid": pvid}
    return out


_COMWARE_VLAN_HEADER_RE = re.compile(r"^\s*VLAN\s+ID\s*:\s*(\d+)\s*$", re.IGNORECASE)
_COMWARE_PORT_STATUS_SUFFIX_RE = re.compile(r"\([A-Za-z]+\)$")


def _strip_comware_port_status(token: str) -> str:
    """Strip ``(U)`` / ``(D)`` / ``(T)`` style link-state suffixes from a port token."""
    return _COMWARE_PORT_STATUS_SUFFIX_RE.sub("", token)


def _comware_record_ports(
    out: dict[str, dict], vid: int, section: str, ports_line: str
) -> None:
    """
    Append ``vid`` to the appropriate per-port bucket for each port on the line.

    Port names are stripped of any trailing link-state suffix
    (``GE1/0/1(U)`` → ``GE1/0/1``) and then expanded from abbreviated form
    to match ``get_interfaces()`` output (see ``_expand_comware_iface``).
    """
    for raw in re.split(r"[,\s]+", ports_line.strip()):
        port = _strip_comware_port_status(raw.strip())
        if not port or port.lower() == "none":
            continue
        port = _expand_comware_iface(port)
        bucket = out.setdefault(port, {"tagged": [], "untagged": []})
        target = bucket[section]
        if vid not in target:
            target.append(vid)


def _parse_comware_display_vlan_all(text: str) -> dict[str, dict]:
    """
    Invert Comware ``display vlan all`` per-VLAN port lists into per-port membership.

    Returns ``{ifname: {tagged: list[int], untagged: list[int]}}``. Each VLAN
    section is delimited by ``VLAN ID: <n>`` and exposes ports under
    ``Tagged Ports:`` and ``Untagged Ports:`` headings; ``None`` is the empty
    marker.
    """
    out: dict[str, dict] = {}
    current_vid: int | None = None
    section: str | None = None
    for line in text.splitlines():
        m = _COMWARE_VLAN_HEADER_RE.match(line)
        if m:
            try:
                current_vid = int(m.group(1))
            except ValueError:
                current_vid = None
            section = None
            continue
        stripped = line.strip()
        if not stripped:
            section = None
            continue
        low = stripped.lower()
        if low.startswith("tagged ports") and current_vid is not None:
            section = "tagged"
            continue
        if low.startswith("untagged ports") and current_vid is not None:
            section = "untagged"
            continue
        if section is None or current_vid is None:
            continue
        _comware_record_ports(out, current_vid, section, stripped)
    return out


def _comware_merge_to_switchport_info(
    iface: str,
    modes: dict[str, dict],
    membership: dict[str, dict],
) -> SwitchportInfo:
    """Merge per-port mode + PVID with per-port membership into SwitchportInfo."""
    mode_entry = modes.get(iface)
    if not mode_entry:
        return SwitchportInfo(
            enabled=False,
            admin_mode=None,
            oper_mode=None,
            access_vlan=None,
            native_vlan=None,
            allowed_vlans=None,
        )
    mode = mode_entry["mode"]
    pvid = mode_entry["pvid"]
    member = membership.get(iface) or {"tagged": [], "untagged": []}
    tagged_vids = list(member["tagged"])

    if mode == "access":
        return SwitchportInfo(
            enabled=True,
            admin_mode="access",
            oper_mode="access",
            access_vlan=pvid,
            native_vlan=None,
            allowed_vlans=None,
        )

    tagged_filtered = [v for v in tagged_vids if v != pvid]
    return SwitchportInfo(
        enabled=True,
        admin_mode="trunk",
        oper_mode="trunk",
        access_vlan=None,
        native_vlan=pvid,
        allowed_vlans=tagged_filtered if tagged_filtered else None,
    )

# --- config sanitization ---
# "password cipher/simple <value>" — local user passwords
_PASSWORD_RE = re.compile(r"(password\s+(?:cipher|simple))\s+\S+", re.IGNORECASE)
# "key cipher <value>"
_KEY_CIPHER_RE = re.compile(r"(\bkey\s+cipher)\s+\S+", re.IGNORECASE)
# "pre-shared-key cipher/simple <value>"
_PSK_RE = re.compile(r"(pre-shared-key\s+(?:cipher|simple))\s+\S+", re.IGNORECASE)
# "authentication-key cipher <value>"
_AUTH_KEY_RE = re.compile(r"(authentication-key\s+cipher)\s+\S+", re.IGNORECASE)
# "snmp-agent community [read|write] [cipher|simple] <value>"
# The optional cipher/simple mode keyword must be consumed before redacting
# so that lines like "community read cipher <secret>" redact the secret,
# not the keyword.
_SNMP_COMMUNITY_RE = re.compile(
    r"(snmp-agent\s+community\s+(?:read|write)(?:\s+(?:cipher|simple))?)\s+\S+",
    re.IGNORECASE,
)


def _sanitize_config(text: str) -> str:
    text = _PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _KEY_CIPHER_RE.sub(r"\1 <redacted>", text)
    text = _PSK_RE.sub(r"\1 <redacted>", text)
    text = _AUTH_KEY_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_COMMUNITY_RE.sub(r"\1 <redacted>", text)
    return text


# Uptime conversion constants
_MINUTE_SECONDS = 60
_HOUR_SECONDS = 3600
_DAY_SECONDS = 24 * _HOUR_SECONDS
_WEEK_SECONDS = 7 * _DAY_SECONDS


def _parse_uptime(uptime_str: str) -> float:
    """
    Convert a Comware 'display version' uptime string to total seconds.

    Comware reports uptime on the device description line, e.g.::

        H3C S5560X-30C-EI uptime is 10 weeks, 5 days, 7 hours, 50 minutes

    Returns 0.0 on parse failure.
    """
    seconds = 0.0
    for pattern, factor in (
        (r"(\d+)\s+week", _WEEK_SECONDS),
        (r"(\d+)\s+day", _DAY_SECONDS),
        (r"(\d+)\s+hour", _HOUR_SECONDS),
        (r"(\d+)\s+minute", _MINUTE_SECONDS),
        (r"(\d+)\s+second", 1),
    ):
        m = re.search(pattern, uptime_str)
        if m:
            seconds += int(m.group(1)) * factor
    return seconds


def _parse_speed(speed_str: str) -> float:
    """
    Normalize Comware speed string to Mbps float.

    Examples: "100Mbps" → 100.0, "1000Mbps" → 1000.0, "10GE" → 10000.0,
    "40GE" → 40000.0, "100GE" → 100000.0. Returns -1.0 for unknown.
    """
    if not speed_str:
        return -1.0
    s = speed_str.strip().upper()
    # e.g. "10GE", "40GE", "100GE", "400GE"
    m = re.match(r"(\d+(?:\.\d+)?)GE?$", s)
    if m:
        return float(m.group(1)) * 1000
    # e.g. "100Mbps", "1000Mbps", "100M", "1G"
    m = re.match(r"(\d+(?:\.\d+)?)G(?:BPS|B/S)?$", s)
    if m:
        return float(m.group(1)) * 1000
    m = re.match(r"(\d+(?:\.\d+)?)M(?:BPS|B/S)?$", s)
    if m:
        return float(m.group(1))
    # e.g. plain number (some templates return just the digit)
    m = re.match(r"^(\d+)$", s)
    if m:
        return float(m.group(1))
    return -1.0


def _parse_version_output(raw: str) -> tuple[str, str, float]:
    """
    Parse 'display version' output into (model, os_version, uptime_seconds).

    Comware 7 example::

        H3C Comware Platform Software
        Comware Software, Version 7.1.070, Release 3506P03
        ...
        H3C S5560X-30C-EI uptime is 10 weeks, 5 days, 7 hours, 50 minutes

    HP-branded devices may say::

        HP Comware Platform Software
        Comware Software Version 5.20.99 Release 1808P10
        ...
        HP A5500-24G-PoE EI Switch uptime is 0 weeks, 1 days, 2 hours, 3 minutes
    """
    model = "Unknown"
    os_version = "Unknown"
    uptime = 0.0

    # OS version: "Version X.Y.Z, Release ABC" or "Version X.Y.Z Release ABC"
    m = re.search(r"Version\s+([\d.]+[^,\n]*?)(?:,?\s*Release\s+|$)", raw, re.IGNORECASE)
    if m:
        os_version = m.group(1).strip()

    # Uptime line (single line): "<Vendor> <Model> uptime is ..."
    # e.g. "H3C S5560X-30C-EI uptime is 2 weeks, 3 days, 4 hours, 15 minutes"
    m_uptime = re.search(
        r"^(?:H3C|HP|HPE)\s+(.+?)\s+uptime\s+is\s+(.+)$",
        raw,
        re.IGNORECASE | re.MULTILINE,
    )
    if m_uptime:
        model = m_uptime.group(1).strip()
        uptime = _parse_uptime(m_uptime.group(2))

    return model, os_version, uptime


# --- IRF (Intelligent Resilient Framework) / switch-stack discovery ----------
#
# `display irf` on Comware 7 produces a fixed-width table followed by a
# trailing settings block. A typical row looks like::
#
#   MemberID    Role        Priority  CPU-Mac           Description
#   *+1         Master      32        0023-aabb-ccdd    ---
#     2         Standby     32        0023-aabb-ccef    ---
#     3         Loading     1         0000-0000-0000    ---
#
# The leading `*` marks the master, `+` marks the device the user is logged
# into; either or both may be present. The MAC column uses the Comware-native
# 4-hex-group dashed form (3 groups of 4 hex digits). A `Loading` or `Down`
# member with no real MAC is permitted in the table but produces no usable
# join key; those rows are kept here and later dropped by ``to_payload()``
# because they end up with an empty serial.
#
# Standalone Comware switches (no IRF) print exactly one populated row — the
# translate layer's ``validate_chassis_payload`` then falls through to the
# single-Device path on a 1-member payload.

_IRF_ROW_RE = re.compile(
    r"""
    ^\s*
    [*+>]{0,3}\s*                             # optional row markers:
                                              #   `*` master, `+` user-login-point,
                                              #   `>` disabled-stack-capability.
                                              #   Any combination may appear; we
                                              #   only need to skip past them.
    (?P<id>\d+)\s+                            # MemberID
    (?:\d+\s+)?                               # optional Slot column (modular IRF
                                              #   on H3C/HPE 12500 etc. prints
                                              #   `MemberID Slot Role ...`)
    (?P<role>[A-Za-z]+)\s+                    # Role (Master/Standby/Slave/Loading/Down)
    (?P<priority>\d+)\s+                      # Priority
    (?P<mac>[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})   # CPU-Mac
    """,
    re.VERBOSE,
)

# Legend lines ('* indicates ...', '+ indicates ...') terminate the table and
# precede the trailing settings block. We stop row parsing when we see one.
_IRF_LEGEND_RE = re.compile(r"^\s*[*+]\s+indicates\b", re.IGNORECASE)

# Domain ID line in the trailing block of `display irf`. Optional — older
# Comware releases omit it, in which case payload domain stays None.
# Comware 5 / legacy outputs print this as ``Topo-domain ID`` while Comware 7
# prints just ``Domain ID``; the regex accepts both forms.
_IRF_DOMAIN_RE = re.compile(
    r"^\s*(?:Topo-)?Domain\s+ID\s*:\s*(\d+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)

def _normalize_irf_mac(raw: str | None) -> str | None:
    """
    Reduce a Comware MAC token to a canonical comparable form.

    Returns lowercase hex with no separators, or None for the all-zeroes
    sentinel / unparseable input. The join key only needs to be consistent
    across the two commands; we deliberately don't return colon-separated
    form to avoid mismatches against ``display device manuinfo`` (which
    uses dashes uppercase).
    """
    if not raw:
        return None
    stripped = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    if len(stripped) != 12 or stripped == "0" * 12:
        return None
    return stripped


def _parse_comware_irf(text: str) -> tuple[list[dict], str | None]:
    """
    Parse `display irf` into ``([{id, role, priority, mac}, ...], domain_id)``.

    Stops at the first legend line (`* indicates ...`) so the trailing
    settings block ("Bridge MAC", "Domain ID", etc.) doesn't accidentally
    re-enter row parsing. Domain id is read from the same trailing block via
    a separate regex on the full text and is independent of where row parsing
    stops.
    """
    rows: list[dict] = []
    for line in (text or "").splitlines():
        if _IRF_LEGEND_RE.match(line):
            break
        m = _IRF_ROW_RE.match(line)
        if not m:
            continue
        rows.append({
            "id": int(m.group("id")),
            "role": m.group("role"),
            "priority": int(m.group("priority")),
            "mac": m.group("mac"),
        })
    domain_match = _IRF_DOMAIN_RE.search(text or "")
    domain = domain_match.group(1) if domain_match else None
    return rows, domain


def _comware_index_manuinfo_by_mac(rows: list[dict]) -> tuple[
    dict[str, str], dict[str, str]
]:
    """
    Return ``(serial_by_mac, model_by_mac)`` keyed by normalized MAC.

    Joins ``display device manuinfo`` to IRF members via the chassis MAC the
    CPU emits on each top-level ``Slot N`` block. Subslot / Fan / Power rows
    are filtered out (they carry their own blade-level MACs that do not
    match the IRF member's CPU-Mac), so the MAC join cannot accidentally
    pick up a blade entry instead of the chassis-level row even if
    ``display device manuinfo`` re-orders them. Joining by MAC rather than
    slot id keeps fixed-switch IRF (``Slot 1`` == member 1) and
    modular-chassis IRF (``Chassis 1`` groups multiple ``Subslot`` entries
    under a single member) working through the same code path.

    Rows with no MAC, an all-zeroes MAC, or an unparseable MAC are skipped:
    they cannot be joined and the IRF member ends up with empty serial,
    which ``to_payload()`` then drops with a warning.
    """
    serial_by_mac: dict[str, str] = {}
    model_by_mac: dict[str, str] = {}
    for row in rows or []:
        # Top-level Slot rows and Chassis rows both carry the chassis-CPU
        # MAC that `display irf` prints. Subslot / Fan / Power rows carry
        # blade/component-level MACs that would never join the IRF CPU-Mac
        # anyway — filtering them explicitly makes the contract obvious
        # and forecloses on accidental joins via a future template change.
        # `get_facts()` already treats Chassis rows as authoritative for
        # the local-device serial, including those is consistent.
        slot_type = (row.get("slot_type") or "").strip().lower()
        if slot_type and slot_type not in ("slot", "chassis"):
            continue
        mac_key = _normalize_irf_mac(row.get("mac_address"))
        if not mac_key:
            continue
        sn = (row.get("device_serial_number") or "").strip()
        pid = (row.get("device_name") or "").strip()
        if sn and mac_key not in serial_by_mac:
            serial_by_mac[mac_key] = sn
        if pid and mac_key not in model_by_mac:
            model_by_mac[mac_key] = pid
    return serial_by_mac, model_by_mac


def _comware_get_chassis_members_impl(driver) -> dict | None:
    """
    Implementation of ``ComwareDriver.get_chassis_members`` (factored for testability).

    Calls ``display irf`` for member id / role / priority / CPU-Mac, then
    ``display device manuinfo`` for per-member serial + model joined by MAC.
    Errors on either command are logged and surface as None or a partial
    payload — translate decides whether to emit VC based on the validated
    member count, so a single-member payload (the standalone-Comware case)
    simply falls through to the single-Device path.
    """
    try:
        irf_out = driver.device.send_command("display irf")
    except Exception:
        logger.warning(
            "hp_comware.get_chassis_members: display irf failed", exc_info=True
        )
        return None

    rows, domain = _parse_comware_irf(irf_out or "")
    if not rows:
        # Either Comware printed an "IRF is not enabled" style banner or the
        # command isn't supported on this release. Both are the standalone
        # case — log at DEBUG and fall through quietly. ``display irf`` is
        # always available on Comware 7, so this branch is rare in practice.
        logger.debug(
            "hp_comware.get_chassis_members: no IRF rows in `display irf` output"
        )
        return None

    try:
        manuinfo_out = driver.device.send_command("display device manuinfo")
        manuinfo_rows = parse_output(
            platform="hp_comware",
            command="display device manuinfo",
            data=manuinfo_out or "",
        )
    except Exception:
        # Non-fatal: members without a manuinfo match end up with empty
        # serial and are dropped by ``to_payload()``. The IRF table itself
        # is still useful for log forensics so we keep it at WARNING.
        logger.warning(
            "hp_comware.get_chassis_members: display device manuinfo failed",
            exc_info=True,
        )
        manuinfo_rows = []

    serial_by_mac, model_by_mac = _comware_index_manuinfo_by_mac(manuinfo_rows or [])

    members: list[ChassisMember] = []
    for row in rows:
        mac_key = _normalize_irf_mac(row["mac"])
        # Canonicalize MAC for the wire payload via napalm's helper so the
        # state/mac field is consistent with other drivers (uppercase
        # colon-separated). ``normalize_mac`` accepts the Comware dashed
        # form; we only call it on MACs that already passed
        # ``_normalize_irf_mac`` validation, so a raise here is unexpected
        # and worth swallowing narrowly (netaddr's AddrFormatError extends
        # ValueError) rather than catching every Exception.
        try:
            mac_canon = normalize_mac(row["mac"]) if mac_key else None
        except (ValueError, TypeError):
            mac_canon = None
        members.append(
            ChassisMember(
                id=row["id"],
                serial=serial_by_mac.get(mac_key, "") if mac_key else "",
                model=model_by_mac.get(mac_key) if mac_key else None,
                role=normalize_role(row["role"]),
                priority=row["priority"],
                mac=mac_canon,
                state=row["role"],
            )
        )

    return to_payload(members, domain=domain)


# --- module / module bay discovery ------------------------------------------
#
# Comware modular chassis families (S7500E, S10500, S12500, S12900) print one
# row per slot in `display device manuinfo` with a full vendor SKU in
# `DEVICE_NAME`. The classifier identifies supervisors by SKU substring
# (``MPU`` / ``SUP``) rather than by family prefix, because H3C reuses the
# same family prefix for both MPU and interface cards on the same chassis.
# Anything else matching a known modular family prefix is a linecard.

# Family-token substrings. Real model strings reported by ``display version``
# vary by branding:
#   - H3C uses ``S7503E`` / ``S10510`` / ``S12508X-AF`` / ``S12916-AF`` —
#     family-prefix substrings ``S75`` / ``S105`` / ``S125`` / ``S129``
#     match each chassis-size variant.
#   - HPE FlexFabric rebrands strip the leading ``S`` (``HPE FlexFabric
#     12500``) and Comware-5 HP-branded variants use the ``A`` prefix
#     (``HP A10500``) — substrings ``7500`` / ``10500`` / ``12500`` /
#     ``12900`` match the full chassis number without the ``S``.
# Fixed pizza-box families (``S5500`` / ``S5800`` / ``S6800``) contain none of
# these substrings, so the broad set still rejects them cleanly.
_MODULAR_COMWARE_TOKENS: tuple[str, ...] = (
    "S75", "S105", "S125", "S129",
    "7500", "10500", "12500", "12900",
)

# Supervisor identification is by SKU substring, not family prefix: H3C reuses
# the same family prefix (``LSQM`` / ``LSUM`` / ``LSXM``) for BOTH the MPU
# (Main Processing Unit, supervisor) and interface cards on the same chassis.
# The MPU's role is encoded in the SKU body — e.g. ``LSQM1MPUC0`` (supervisor)
# vs ``LSQM1FH48EA`` (interface). ``MPU`` is the canonical supervisor token;
# ``SUP`` covers the rarer ``LSUM1SUPXD0`` SUP-prefixed variant.
_COMWARE_SUPERVISOR_TOKENS: tuple[str, ...] = ("MPU", "SUP")

# Family prefixes that mark the SKU as a Comware modular-chassis card. Any SKU
# matching one of these prefixes that does NOT contain a supervisor token is
# treated as a linecard (this covers MPU sibling cards: SFU/fabric ``LSXM2SF``,
# LPU ``LSXM2QGS`` / ``LSXM2FX`` / ``LSQM1FH``, etc.). Order doesn't matter
# here — we only need a non-empty match. The 4-character prefixes are listed
# first defensively; ``LSU`` follows ``LSUM`` for the same reason.
_COMWARE_FAMILY_PREFIXES: tuple[str, ...] = (
    "LSUM",  # S10500 family (MPU + interface cards)
    "LSQM",  # S7500E family (MPU + interface cards)
    "LSXM",  # S10500 / S12500X-AF / S12900 family (MPU + SFU + interface cards)
    "LSQS",  # S7500E SFU (fabric)
    "LSXS",  # S10500 / S12900 SFU (fabric)
    "LSQ1",  # S7500E LPU
    "LSQ2",  # S7500E LPU variant
    "LSQK",  # S7500E LPU variant
    "LSX1",  # S10500 / S12900 LPU
    "LSX2",  # S10500 / S12900 LPU variant
    "LSR",   # S12500 LPU SKU family
    "LSU",   # S12500 LSU — must follow LSUM (the 4-char prefix wins first)
)


def _comware_is_modular(model: str) -> bool:
    """
    True when ``model`` belongs to a Comware modular family.

    Matches by uppercased substring so vendor-prefixed model strings
    (``H3C S12500-AF``, ``HPE FlexFabric S12500``, ``HP A12500``) and
    bare model names (``S12500``) both succeed. Non-modular families
    (S5500 / S5800 / S6800) reject.
    """
    if not model:
        return False
    upper = model.upper()
    return any(token in upper for token in _MODULAR_COMWARE_TOKENS)


def _comware_classify_module(device_name: str) -> str:
    """
    Classify a Comware SKU into a module type.

    Returns ``"supervisor"`` when the SKU contains an MPU / SUP token
    (``LSQM1MPUC0``, ``LSXM2MPUD0``, ``LSUM1SUPXD0``); otherwise returns
    ``"linecard"`` when the SKU starts with a documented Comware modular
    family prefix (``LSUM`` / ``LSQM`` / ``LSXM`` / ``LSQS`` / ``LSXS`` /
    ``LSQ1`` / ``LSQ2`` / ``LSQK`` / ``LSX1`` / ``LSX2`` / ``LSR`` /
    ``LSU``). Anything else — including empty / whitespace input —
    returns ``"other"`` and is dropped by the impl.

    Why two passes? H3C reuses the same family prefix for MPU and
    interface cards on the same chassis. A pure prefix classifier
    would mis-emit every interface card as a supervisor.
    """
    sku = (device_name or "").strip().upper()
    if not sku:
        return "other"
    if any(token in sku for token in _COMWARE_SUPERVISOR_TOKENS):
        return "supervisor"
    if sku.startswith(_COMWARE_FAMILY_PREFIXES):
        return "linecard"
    return "other"


def _comware_modules_rows_from_manuinfo(
    rows: list[dict],
) -> dict[int | None, _MemberModules]:
    """
    Walk parsed manuinfo rows and partition Slot entries by chassis id.

    Drops Chassis / Subslot / Fan / Power rows, drops rows with empty
    slot id / SKU / serial, drops SKUs that don't classify as
    supervisor / linecard, and groups surviving bays by ``chassis_id``
    (defaulting to 1 for non-IRF output).
    """
    members: dict[int | None, _MemberModules] = {}
    for row in rows:
        slot_type = (row.get("slot_type") or "").strip().lower()
        if slot_type != "slot":
            continue
        slot_id = (row.get("slot_id") or "").strip()
        sku = (row.get("device_name") or "").strip()
        serial = (row.get("device_serial_number") or "").strip()
        if not slot_id or not sku or not serial:
            continue
        try:
            chassis_id = int((row.get("chassis_id") or "1").strip())
        except ValueError:
            continue
        mtype = _comware_classify_module(sku)
        if mtype not in ("supervisor", "linecard"):
            continue
        bay = _ModuleBay(
            name=slot_id,
            position=slot_id,
            module=_ModuleEntry(model=sku, serial=serial, type=mtype, description=""),
        )
        member = members.setdefault(
            chassis_id, _MemberModules(bays=[], interfaces_by_bay={})
        )
        member.bays.append(bay)
    return members


def _comware_get_modules_impl(driver) -> dict | None:
    """
    Per-chassis module / module bay discovery for HP/H3C Comware modular families.

    Reads ``display version`` for family detection; non-modular families
    short-circuit to ``None`` without touching ``display device manuinfo``.
    For modular families, reads ``display device manuinfo``, partitions
    Slot-type rows by ``chassis_id``, classifies each row's SKU, and emits
    one ``MemberModules`` envelope per surviving chassis id.

    Standalone modular chassis produce a single ``members[None]`` envelope
    (matching the single-device translate path's ``{None: device}`` map);
    IRF-of-modular emits one envelope per IRF member chassis (members[1],
    members[2], ...) for the multi-member ``translate_as_stack`` path.
    Subslot / Fan / Power rows are dropped — sub-bay discovery is a
    follow-up.
    """
    try:
        raw_version = driver.device.send_command("display version")
    except Exception:
        logger.warning("hp_comware.get_modules: display version failed", exc_info=True)
        return None

    model, _os_version, _uptime = _parse_version_output(raw_version or "")
    if not _comware_is_modular(model):
        return None

    try:
        manuinfo_out = driver.device.send_command("display device manuinfo")
        manuinfo_rows = parse_output(
            platform="hp_comware",
            command="display device manuinfo",
            data=manuinfo_out or "",
        )
    except Exception:
        logger.warning(
            "hp_comware.get_modules: display device manuinfo failed", exc_info=True
        )
        return None

    if not manuinfo_rows:
        return None

    members = _comware_modules_rows_from_manuinfo(manuinfo_rows)
    if not members:
        return None
    # Standalone modular (one chassis) MUST key by ``None`` so the
    # single-device translate path (which builds ``{None: device}``) attaches
    # the bays correctly. IRF-of-modular keeps integer keys per member chassis
    # — translate.translate_as_stack passes the multi-member device map.
    if len(members) == 1:
        only_member = next(iter(members.values()))
        return _modules_to_payload({None: only_member})
    return _modules_to_payload(members)


# "display ip vpn-instance instance-name <name>" detail fields. Parsed
# driver-locally — the ntc-template for this command error-exits on routine
# output lines it doesn't enumerate (e.g. "Route & Tunnel selection time").
_COMWARE_VPN_RD_RE = re.compile(r"^\s*Route Distinguisher\s*:\s*(\S+)\s*$")
_COMWARE_VPN_IFACES_RE = re.compile(r"^\s*Interfaces\s*:\s*(.*)$")


def _comware_parse_vpn_instance_detail(raw: str) -> tuple[str, list[str]]:
    """
    Return (rd, member interfaces) from a VPN-instance detail block.

    Interface collection starts at the "Interfaces :" line (members are
    comma-separated, possibly wrapping onto indented continuation lines)
    and stops at the first line carrying a "key : value" colon — every
    other detail field uses that layout, while wrapped interface names
    never contain a colon.
    """
    rd = ""
    interfaces: list[str] = []
    in_ifaces = False
    for line in raw.splitlines():
        m = _COMWARE_VPN_RD_RE.match(line)
        if m:
            rd = m.group(1)
            in_ifaces = False
            continue
        m = _COMWARE_VPN_IFACES_RE.match(line)
        if m:
            in_ifaces = True
            interfaces.extend(p.strip() for p in m.group(1).split(",") if p.strip())
            continue
        if in_ifaces:
            if line.strip() and ":" not in line:
                interfaces.extend(p.strip() for p in line.split(",") if p.strip())
            else:
                in_ifaces = False
    return rd, interfaces


class ComwareDriver(_napalm_base.NetworkDriver):
    """HP Comware NAPALM driver (read-only subset for device-discovery)."""

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
        # Comware has no enable mode — tell NAPALM not to call enable()
        self.force_no_enable = True

    def open(self):
        """Open an SSH connection to the device via Netmiko."""
        self.device = self._netmiko_open(
            "hp_comware", netmiko_optional_args=self.netmiko_optional_args
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
        # --- hostname from sysname in running config ---
        hostname = "Unknown"
        sysname_out = self.device.send_command("display current-configuration | include sysname")
        if "sysname " in sysname_out:
            hostname = sysname_out.split("sysname ", 1)[1].strip().splitlines()[0].strip()

        # --- model / os_version / uptime from 'display version' ---
        raw_version = self.device.send_command("display version")
        model, os_version, uptime = _parse_version_output(raw_version)

        # --- serial number from 'display device manuinfo' ---
        serial_number = "Unknown"
        raw_manuinfo = self.device.send_command("display device manuinfo")
        parsed_manuinfo = parse_output(
            platform="hp_comware", command="display device manuinfo", data=raw_manuinfo
        )
        chassis_sns = [
            row["device_serial_number"]
            for row in parsed_manuinfo
            if row.get("slot_type", "").lower() == "chassis"
            and row.get("device_serial_number")
        ]
        if chassis_sns:
            serial_number = chassis_sns[0]
        else:
            slot_sns = [
                row["device_serial_number"]
                for row in parsed_manuinfo
                if row.get("device_serial_number")
            ]
            if slot_sns:
                serial_number = slot_sns[0]

        # --- interface list from 'display interface' ---
        raw_intf = self.device.send_command("display interface")
        parsed_intf = parse_output(
            platform="hp_comware", command="display interface", data=raw_intf
        )
        interface_list = [row["interface"] for row in parsed_intf if row.get("interface")]

        return {
            "hostname": hostname,
            "vendor": "HP",
            "model": model,
            "os_version": os_version,
            "serial_number": serial_number,
            "uptime": uptime,
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """Return interface details keyed by interface name."""
        raw = self.device.send_command("display interface")
        if not raw:
            return {}

        parsed = parse_output(platform="hp_comware", command="display interface", data=raw)
        interfaces = {}
        for row in parsed:
            intf = row.get("interface", "")
            if not intf:
                continue

            line_status = row.get("line_status", "").lower()
            proto_status = row.get("protocol_status", "").lower()

            # Administratively DOWN means disabled; any other DOWN means enabled but down
            is_enabled = "administratively" not in line_status
            is_up = "up" in proto_status and "spoofing" not in proto_status

            hw_address_list = row.get("hw_address", [])
            raw_mac = hw_address_list[0] if hw_address_list else ""
            try:
                mac_address = normalize_mac(raw_mac) if raw_mac else ""
            except Exception:
                mac_address = raw_mac

            try:
                mtu = int(row.get("mtu", "") or -1)
            except ValueError:
                mtu = -1

            interfaces[intf] = {
                "is_up": is_up,
                "is_enabled": is_enabled,
                "description": row.get("description", "").strip(),
                "last_flapped": -1.0,
                "mtu": mtu,
                "speed": _parse_speed(row.get("speed", "")),
                "mac_address": mac_address,
            }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface."""
        raw = self.device.send_command("display interface")
        if not raw:
            return {}

        parsed = parse_output(platform="hp_comware", command="display interface", data=raw)
        interfaces_ip: dict = {}
        for row in parsed:
            intf = row.get("interface", "")
            if not intf:
                continue
            for cidr in row.get("ip_address", []):
                if not cidr or "/" not in cidr:
                    continue
                ip_str, prefix_str = cidr.rsplit("/", 1)
                try:
                    prefix_length = int(prefix_str)
                    addr = ipaddress.ip_address(ip_str)
                except ValueError:
                    continue
                family = "ipv4" if isinstance(addr, ipaddress.IPv4Address) else "ipv6"
                interfaces_ip.setdefault(intf, {}).setdefault(family, {})[ip_str] = {
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
        """Return device configuration."""
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}

        if retrieve.lower() in ("running", "all"):
            config["running"] = self.device.send_command("display current-configuration")

        if retrieve.lower() in ("startup", "all"):
            config["startup"] = self.device.send_command("display saved-configuration")

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Return VLAN information keyed by VLAN ID string."""
        raw = self.device.send_command("display vlan brief")
        if not raw:
            return {}

        parsed = parse_output(platform="hp_comware", command="display vlan brief", data=raw)
        vlans: dict = {}
        for row in parsed:
            vlan_id = row.get("vlan_id", "")
            if not vlan_id:
                continue
            vlan_name = row.get("vlan_name", "").strip() or vlan_id
            vlans[vlan_id] = {"name": vlan_name, "interfaces": []}

        return vlans

    def get_chassis_members(self) -> dict | None:
        """
        Return IRF member info for HP/H3C Comware switches.

        Standalone Comware (no IRF) typically prints a single populated row;
        translate's ``validate_chassis_payload`` falls through to the
        single-Device path on a 1-member payload. 2+ populated members emit
        a NetBox VirtualChassis.
        """
        return _comware_get_chassis_members_impl(self)

    def get_modules(self) -> dict | None:
        """
        Return module / module bay inventory for Comware modular chassis.

        Standalone modular families (S7500E, S10500, S12500, S12900) emit a
        single per-chassis envelope; IRF-of-modular emits one envelope per
        IRF member chassis. Non-modular families (S5500 / S5800 / S6800) and
        unparseable output return ``None``.
        """
        return _comware_get_modules_impl(self)

    def get_network_instances(self, name: str = "") -> dict:
        """
        Return network instances (VPN instances as VRFs), NAPALM OC shape.

        ``display ip vpn-instance`` (ntc-template, tolerates RD-less rows)
        enumerates the instances; one ``display ip vpn-instance
        instance-name <name>`` per instance supplies the RD and the
        member interface list, parsed driver-locally — the ntc-template
        for the detail command error-exits on routine output lines it
        doesn't enumerate (e.g. "Route & Tunnel selection time"). The
        public network (global routing table) is not a VPN instance and
        is represented by the seeded DEFAULT_INSTANCE with empty
        membership.
        """
        instances: dict = {
            "default": {
                "name": "default",
                "type": "DEFAULT_INSTANCE",
                "state": {"route_distinguisher": ""},
                "interfaces": {"interface": {}},
            },
        }
        sum_raw = self.device.send_command("display ip vpn-instance")
        sum_rows: list[dict] = []
        if sum_raw and sum_raw.strip():
            try:
                sum_rows = parse_output(
                    platform="hp_comware",
                    command="display ip vpn-instance",
                    data=sum_raw,
                )
            except Exception:
                logger.warning(
                    "Comware display ip vpn-instance parse failed", exc_info=True
                )
        for row in sum_rows:
            vpn_name = (row.get("name") or "").strip()
            # Never let a row overwrite the seeded DEFAULT_INSTANCE.
            if not vpn_name or vpn_name == "default":
                continue
            rd = (row.get("rd") or "").strip()
            det_raw = self.device.send_command(
                f"display ip vpn-instance instance-name {vpn_name}"
            )
            det_rd, det_ifaces = _comware_parse_vpn_instance_detail(det_raw or "")
            rd = det_rd or rd
            interfaces = {ifname: {} for ifname in det_ifaces}
            instances[vpn_name] = {
                "name": vpn_name,
                "type": "L3VRF",
                "state": {"route_distinguisher": rd},
                "interfaces": {"interface": interfaces},
            }
        if name:
            return {name: instances[name]} if name in instances else {}
        return instances

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """Return per-interface VLAN config from `display interface brief` + `display vlan all`."""
        try:
            brief_raw = self.device.send_command("display interface brief")
            vlan_raw = self.device.send_command("display vlan all")
        except Exception:
            logger.debug("Comware switchport command failed", exc_info=True)
            return {}
        try:
            brief_rows = parse_output(
                platform="hp_comware",
                command="display interface brief",
                data=brief_raw,
            )
        except Exception:
            logger.debug("Comware display interface brief parse failed", exc_info=True)
            return {}
        modes = _parse_comware_interface_brief_modes(brief_rows)
        membership = _parse_comware_display_vlan_all(vlan_raw or "")

        all_ifaces = set(modes.keys()) | set(membership.keys())
        result: dict[str, dict] = {}
        for iface in sorted(all_ifaces):
            info = _comware_merge_to_switchport_info(iface, modes, membership)
            result[iface] = classify_switchport(info)
        return result
