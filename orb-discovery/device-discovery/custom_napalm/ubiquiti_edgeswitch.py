# Copyright 2026 NetBox Labs Inc
"""
Custom Ubiquiti EdgeSwitch NAPALM driver.

EdgeSwitch runs a Cisco IOS-style CLI. Uses Netmiko (ubiquiti_edgeswitch) for
SSH connectivity, ntc-templates for 'show version' and 'show vlan', and regex
for interface status and IP address parsing.

Implements: get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.
"""

import ipaddress
import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

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
# Interface status parsing — 'show interfaces status all'
# ---------------------------------------------------------------------------

# Output columns (example):
#    0/1    Copper  Enabled     Forwarding  Up      Full-100M   Full-100M   Copper
# Ch = channel (0/1, 1/0/1, lag1, etc.)
# Leading whitespace is optional: some firmware variants start rows at column 1.
# Anchoring on Enabled|Disabled for the Neg column prevents false matches on
# header ("Neg") and separator ("---") lines when no indent is present.
_ES_INTF_LINE_RE = re.compile(
    r"^\s*"
    r"(?P<intf>\S+)\s+"                       # channel/interface
    r"\S+\s+"                                  # Type (Copper, Fiber)
    r"(?P<neg>Enabled|Disabled)\s+"            # Neg/admin — anchors against headers
    r"(?P<state>\S+)\s+"                       # Port state (Forwarding, Disabled, …)
    r"(?P<link>\S+)",                          # Link state (Up/Down)
    re.IGNORECASE,
)

# "Full-100M" → 100.0 Mbps, "Full-1000M" → 1000.0, "Full-10G" → 10000.0
_SPEED_RE = re.compile(r"(?:Full|Half)-(\d+)([MG])", re.IGNORECASE)


def _parse_speed(speed_str: str) -> float:
    """Convert EdgeSwitch physical mode string (e.g. 'Full-100M') to Mbps."""
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
    Extract VLAN → interface membership from EdgeSwitch running-config.

    Parses interface blocks looking for:
        vlan participation include <id>,<id>,...

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
# Switchport summary parsing — 'show interfaces switchport'
# ---------------------------------------------------------------------------

# Summary table row from EdgeSwitch ``show interfaces switchport``::
#
#                                       Acceptable Ingress     Default
#   Interface     Mode         PVID     Frame Types Filtering  Priority
#   ------------- ------------ -------- ----------- ---------- ----------
#   0/1           Access       100      Admit All   Disabled   0
#   0/2           General      10       Admit All   Disabled   0
#   0/3           Trunk        1        VLAN Only   Enabled    0
#
# Slot/port style is ``<unit>/<port>``; LAG/port-channel rows like ``lag1`` or
# ``3/1`` are accepted by the broader ``\S+`` interface match. The mode column
# anchors against ``Access|Trunk|General|Routed`` (case-insensitive) so the
# header and dashes separator never match.
_ES_SWITCHPORT_ROW_RE = re.compile(
    r"^\s*(?P<intf>\S+)\s+"
    r"(?P<mode>Access|Trunk|General|Routed)\s+"
    r"(?P<pvid>\d+)\s+",
    re.IGNORECASE,
)


def _parse_edgesw_switchport_summary(text: str) -> dict[str, dict]:
    """
    Parse 'show interfaces switchport' summary → ``{port: {mode, pvid}}``.

    Lines that don't match the row regex (header, dashes, blanks) are
    silently ignored so future column changes degrade gracefully.
    """
    out: dict[str, dict] = {}
    for line in text.splitlines():
        m = _ES_SWITCHPORT_ROW_RE.match(line)
        if not m:
            continue
        try:
            pvid = int(m.group("pvid"))
        except ValueError:
            continue
        out[m.group("intf")] = {
            "mode": m.group("mode").lower(),
            "pvid": pvid,
        }
    return out


# ---------------------------------------------------------------------------
# Per-port VLAN membership (from running-config)
# ---------------------------------------------------------------------------

# Match physical and LAG interface blocks; skip ``interface vlan <id>`` SVIs.
# EdgeSwitch CLI accepts both single-token (``interface 0/1``, ``interface lag1``)
# and split-token (``interface lag 1``) forms — capture the rest of the line and
# normalise whitespace on use so both reduce to the same key (``lag1``).
_ES_INTF_BLOCK_RE = re.compile(r"^interface\s+(.+?)\s*$")
_ES_VLAN_PVID_RE = re.compile(r"^vlan\s+pvid\s+(\d+)\s*$")
_ES_VLAN_PART_RE = re.compile(r"^vlan\s+participation\s+include\s+(.+)$")
_ES_VLAN_PART_EXCLUDE_RE = re.compile(r"^vlan\s+participation\s+exclude\s+(.+)$")
_ES_VLAN_TAG_RE = re.compile(r"^vlan\s+tagging\s+(.+)$")

# Cisco-style ``switchport ...`` directives. EdgeSwitch (Broadcom-fastpath)
# accepts both the native ``vlan ...`` syntax above and the Cisco-flavoured
# ``switchport ...`` syntax below; both express the same membership data.
_ES_SP_ACCESS_RE = re.compile(r"^switchport\s+access\s+vlan\s+(\d+)\s*$")
_ES_SP_TRUNK_NATIVE_RE = re.compile(r"^switchport\s+trunk\s+native\s+vlan\s+(\d+)\s*$")
_ES_SP_TRUNK_ALLOWED_RE = re.compile(
    r"^switchport\s+trunk\s+allowed\s+vlan(?:\s+(add|remove|except))?\s+(.+?)\s*$"
)
_ES_SP_GENERAL_PVID_RE = re.compile(r"^switchport\s+general\s+pvid\s+(\d+)\s*$")
_ES_SP_GENERAL_ALLOWED_RE = re.compile(
    r"^switchport\s+general\s+allowed\s+vlan\s+add\s+(.+?)(?:\s+(tagged|untagged))?\s*$"
)


def _apply_native_vlan_directive(entry: dict, line: str) -> bool:
    """Native ``vlan ...`` directives. Returns True if the line matched."""
    m = _ES_VLAN_PVID_RE.match(line)
    if m:
        try:
            entry["pvid"] = int(m.group(1))
        except ValueError:
            pass
        return True
    m = _ES_VLAN_PART_RE.match(line)
    if m:
        entry["participation"].extend(
            int(v) for v in _expand_vlan_tokens(m.group(1))
        )
        return True
    m = _ES_VLAN_PART_EXCLUDE_RE.match(line)
    if m:
        # ``vlan participation exclude <vlist>`` removes the VIDs from
        # both participation and tagging (an excluded VLAN is by
        # definition not a member, regardless of any earlier include
        # or tagging directive in the same block).
        excluded = {int(v) for v in _expand_vlan_tokens(m.group(1))}
        entry["participation"] = [v for v in entry["participation"] if v not in excluded]
        entry["tagging"] = [v for v in entry["tagging"] if v not in excluded]
        return True
    m = _ES_VLAN_TAG_RE.match(line)
    if m:
        entry["tagging"].extend(
            int(v) for v in _expand_vlan_tokens(m.group(1))
        )
        return True
    return False


def _apply_sp_pvid_setter(entry: dict, vid_str: str) -> None:
    """Set entry["pvid"] and append the same VID to participation."""
    try:
        vid = int(vid_str)
    except ValueError:
        return
    entry["pvid"] = vid
    if vid not in entry["participation"]:
        entry["participation"].append(vid)


def _trunk_allowed_remove(entry: dict, spec: str) -> None:
    """
    Drop every occurrence of each parsed VID from tagging + participation.

    Uses list-comprehension filtering rather than ``list.remove`` so that
    duplicate entries (which can survive in the parsed dict when an
    interface block mixes native and Cisco-style directives or repeats
    a VID across includes) are all purged. ``list.remove`` would only
    drop the first occurrence and leave the rest behind, falsely
    keeping the VLAN present after an explicit ``remove`` directive
    (Codex P2 #391 round-9).
    """
    excluded: set[int] = set()
    for v in _expand_vlan_tokens(spec):
        try:
            excluded.add(int(v))
        except ValueError:
            continue
    if not excluded:
        return
    entry["tagging"] = [v for v in entry["tagging"] if v not in excluded]
    entry["participation"] = [v for v in entry["participation"] if v not in excluded]


def _trunk_allowed_add(entry: dict, spec: str) -> None:
    """Append each parsed VID to tagging + participation (deduplicated)."""
    for v in _expand_vlan_tokens(spec):
        vid = int(v)
        if vid not in entry["tagging"]:
            entry["tagging"].append(vid)
        if vid not in entry["participation"]:
            entry["participation"].append(vid)


def _apply_sp_trunk_allowed(entry: dict, op: str, spec: str) -> None:
    """
    Apply ``switchport trunk allowed vlan [add|remove|except] <spec>``.

    EdgeSwitch supports four operations:

    * default / ``add`` → append the VIDs to tagging + participation (additive).
    * ``remove`` → drop the VIDs from tagging + participation if present.
    * ``except`` → "all VLANs except these"; we can't faithfully represent
      that with NetBox's allowed-VLAN list without enumerating, so we set
      an ``allowed_except`` flag that the row mapper translates to a
      conservative routed fallback (don't guess and clobber NetBox).
    * ``all`` keyword (in spec, no op) → wildcard → mode=tagged-all.

    When ``all`` has previously been set on the same port AND a subsequent
    ``add`` / ``remove`` directive arrives, the effective allowed set is
    "all VLANs ± some" — unrepresentable in NetBox's allowed-VLAN list
    without enumerating the chassis. Promote to the same ``allowed_except``
    routed fallback the explicit ``except`` keyword takes (Copilot
    review #391 round-10).
    """
    op = (op or "").strip().lower()
    if op == "except":
        entry["allowed_except"] = True
        entry["allowed_all"] = False
        return
    if spec.strip().lower() == "all":
        entry["allowed_all"] = True
        return
    if entry.get("allowed_all"):
        # Earlier directive set the wildcard; this add/remove makes the
        # final set unrepresentable. Fall back to the "except" routed path.
        entry["allowed_except"] = True
        entry["allowed_all"] = False
        return
    if op == "remove":
        _trunk_allowed_remove(entry, spec)
    else:
        _trunk_allowed_add(entry, spec)


def _apply_sp_general_allowed(entry: dict, vlist: str, flag: str) -> None:
    """Apply ``switchport general allowed vlan add <vlist> [tagged|untagged]``."""
    for v in _expand_vlan_tokens(vlist):
        vid = int(v)
        if vid not in entry["participation"]:
            entry["participation"].append(vid)
        if flag.lower() == "tagged" and vid not in entry["tagging"]:
            entry["tagging"].append(vid)


def _apply_switchport_directive(entry: dict, line: str) -> bool:
    """
    Cisco-style ``switchport ...`` directives. Returns True if matched.

    Maps each directive to the same ``participation``/``tagging``/``pvid``
    aggregate the native ``vlan ...`` syntax populates, so the downstream
    classifier doesn't care which CLI form the operator used:

    * ``switchport access vlan X`` → participation += [X]; pvid := X
    * ``switchport trunk native vlan X`` → participation += [X]; pvid := X
      (X is the untagged native — explicitly NOT added to tagging)
    * ``switchport trunk allowed vlan X,Y,Z[ add]`` → tagging += [X,Y,Z];
      participation += [X,Y,Z]
    * ``switchport trunk allowed vlan all`` → entry["allowed_all"] = True
      (the row mapper promotes this to ``tagged-all`` via the classifier)
    * ``switchport general pvid X`` → pvid := X
    * ``switchport general allowed vlan add X[,Y] tagged|untagged`` →
      participation += [X[,Y]]; tagging += [X[,Y]] when ``tagged``
    """
    m = _ES_SP_ACCESS_RE.match(line) or _ES_SP_TRUNK_NATIVE_RE.match(line)
    if m:
        _apply_sp_pvid_setter(entry, m.group(1))
        return True
    m = _ES_SP_TRUNK_ALLOWED_RE.match(line)
    if m:
        _apply_sp_trunk_allowed(entry, m.group(1), m.group(2))
        return True
    m = _ES_SP_GENERAL_PVID_RE.match(line)
    if m:
        try:
            entry["pvid"] = int(m.group(1))
        except ValueError:
            pass
        return True
    m = _ES_SP_GENERAL_ALLOWED_RE.match(line)
    if m:
        _apply_sp_general_allowed(entry, m.group(1), m.group(2) or "")
        return True
    return False


def _apply_membership_directive(entry: dict, line: str) -> None:
    """Update ``entry`` with one membership directive parsed from *line*."""
    if _apply_native_vlan_directive(entry, line):
        return
    _apply_switchport_directive(entry, line)


def _parse_edgesw_port_membership(config: str) -> dict[str, dict]:
    """
    Parse running-config interface blocks for per-port VLAN membership.

    Returns ``{port: {"participation": [vid,...], "tagging": [vid,...], "pvid": int|None}}``.

    EdgeSwitch (Broadcom-fastpath) per-interface VLAN config::

        interface 0/1
         vlan pvid 100
         vlan participation include 1,100
         vlan tagging 100
        !

    ``vlan participation include`` lists every VLAN the port is a member of;
    ``vlan tagging`` lists which of those are tagged egress (the rest are
    untagged egress). ``vlan pvid`` overrides the default ingress PVID
    (default 1 when absent).
    """
    out: dict[str, dict] = {}
    current: str | None = None
    for raw_line in config.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped == "!":
            current = None
            continue
        m = _ES_INTF_BLOCK_RE.match(stripped)
        if m:
            # Normalise whitespace so ``lag 1`` and ``lag1`` both reduce to
            # ``lag1`` — matches the form ``show interfaces switchport``
            # summary emits and the ``apply_interface_vlans`` lookup key.
            name = re.sub(r"\s+", "", m.group(1).strip())
            # Skip SVIs (``interface vlan 1``); only physical/LAG ports
            # carry VLAN membership configuration.
            if name.lower().startswith("vlan"):
                current = None
                continue
            current = name
            out.setdefault(
                current,
                {
                    "participation": [],
                    "tagging": [],
                    "pvid": None,
                    "allowed_all": False,
                    "allowed_except": False,
                },
            )
            continue
        if current is None:
            continue
        _apply_membership_directive(out[current], stripped)
    return out


# ---------------------------------------------------------------------------
# Switchport row → SwitchportInfo
# ---------------------------------------------------------------------------

def _dedupe_keep_order(seq: list[int]) -> list[int]:
    """Return ``seq`` with duplicates removed while preserving first-seen order."""
    seen: set[int] = set()
    out: list[int] = []
    for v in seq:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _normalise_edgesw_membership(
    membership: dict,
) -> tuple[list[int], list[int], list[int]]:
    """
    Normalise a parsed membership dict into ``(participation, tagging, untagged_members)``.

    Two corrections happen here:

    1. Duplicates in ``participation``/``tagging`` are removed (preserving
       first-seen order). When both native ``vlan participation include ...``
       and Cisco-style ``switchport ...`` directives appear in the same
       interface block — or when multiple include lines repeat a VID —
       duplicates leak into untagged_members and the access-path check
       ``len(untagged_members) != 1`` would incorrectly flip a valid
       access port to routed (Copilot P1 #391 round-8).
    2. The PVID is stripped from ``tagging`` before deriving
       ``untagged_members``. Cisco-style configs commonly list the native
       VLAN inside ``switchport trunk allowed vlan ...`` alongside the
       tagged VLANs. The native is the untagged-egress VLAN by definition,
       not tagged — without this, a config like::

           switchport trunk native vlan 1
           switchport trunk allowed vlan 1,10,20

       would mark VLAN 1 as tagged, the native lookup would find no
       untagged member, and the port would misclassify as trunk-no-native
       (Codex P1 #391 round-7).
    """
    pvid = coerce_vid(membership.get("pvid"))
    participation = _dedupe_keep_order(
        [v for v in membership.get("participation", []) if coerce_vid(v) is not None]
    )
    tagging = _dedupe_keep_order(
        [v for v in membership.get("tagging", []) if coerce_vid(v) is not None]
    )
    if pvid is not None:
        tagging = [v for v in tagging if v != pvid]
    untagged_members = [v for v in participation if v not in tagging]
    return participation, tagging, untagged_members


def _edgesw_routed() -> SwitchportInfo:
    """SwitchportInfo for a routed/unknown port."""
    return SwitchportInfo(
        enabled=False,
        admin_mode=None,
        oper_mode=None,
        access_vlan=None,
        native_vlan=None,
        allowed_vlans=None,
    )


def _edgesw_row_to_switchport_info(
    port: str, summary: dict, membership: dict | None
) -> SwitchportInfo:
    """
    Map per-port summary + membership into a SwitchportInfo.

    Mode mapping:

    * ``Access``  – exactly one untagged VID (PVID), no tagged. Multiple or
      mismatched untagged VIDs in the membership block → routed. When the
      running-config omits the port entirely (default-config ports — common
      on EdgeSwitch since ``show running-config`` only emits configured
      interfaces) we trust the summary PVID and emit access on that VID.
    * ``Trunk``   – tagged VIDs from ``vlan tagging``; native VID is the
      single untagged VID present in the membership list, or None when no
      untagged member exists. Empty membership data → routed; multiple
      untagged members → routed (defensive against NetBox PATCH clobber).
    * ``General`` – collapsed to trunk: same multi-untagged-routes guard
      as ``Trunk``. Empty participation AND empty tagging → routed.
    * ``switchport trunk allowed vlan all`` (Cisco-style wildcard) →
      tagged-all, with native from the untagged member when present.
      A subsequent ``add``/``remove`` after ``all`` flips to the same
      ``allowed_except`` routed fallback below.
    * ``switchport trunk allowed vlan except <vlist>`` → routed
      (NetBox can't represent "all VLANs except these" without
      enumerating the chassis).
    * ``Routed`` or anything else → routed.

    Defensive guards mirror the dell_powerconnect batch-4 tightening from
    #390: when the membership shape disagrees with the declared mode,
    ``apply_interface_vlans()`` would otherwise PATCH NetBox with a
    guessed VID and clobber the existing untagged_vlan / tagged_vlans,
    so we route instead.
    """
    del port  # unused; kept for parity with PowerConnect signature
    mode_raw = (summary.get("mode") or "").lower()

    if membership is None:
        membership = {"participation": [], "tagging": [], "pvid": None}
    participation, tagging, untagged_members = _normalise_edgesw_membership(membership)
    allowed_all = bool(membership.get("allowed_all"))
    allowed_except = bool(membership.get("allowed_except"))

    # ``switchport trunk allowed vlan except <vlist>`` means "all VLANs
    # except these" — we can't represent that with NetBox's allowed-VLAN
    # list without enumerating the chassis, so fall back to routed
    # defensively (avoids silently emitting wrong tagged_vlans via PATCH).
    if allowed_except and mode_raw in ("trunk", "general"):
        return _edgesw_routed()

    # Cisco-style ``switchport trunk allowed vlan all`` is the only path that
    # produces a real wildcard on EdgeSwitch — promote to ``tagged-all``.
    if allowed_all and mode_raw in ("trunk", "general"):
        native_vid = untagged_members[0] if untagged_members else None
        return SwitchportInfo(
            enabled=True,
            admin_mode="trunk",
            oper_mode="trunk",
            access_vlan=None,
            native_vlan=native_vid,
            allowed_vlans="all",
        )

    pvid_summary = coerce_vid(summary.get("pvid"))

    if mode_raw == "access":
        return _edgesw_access(participation, tagging, untagged_members, pvid_summary)
    if mode_raw == "trunk":
        return _edgesw_trunk(participation, tagging, untagged_members)
    if mode_raw == "general":
        return _edgesw_general(tagging, untagged_members)
    return _edgesw_routed()


def _edgesw_access(
    participation: list[int],
    tagging: list[int],
    untagged_members: list[int],
    pvid_summary: int | None,
) -> SwitchportInfo:
    """
    Map an EdgeSwitch Access-mode port to ``SwitchportInfo``.

    Access classification requires unambiguous shape. Two paths:

    1. Membership block present (running-config has the port): require
       exactly one untagged VID and no tagged. Anything else → routed.
    2. Membership block absent (default-config port — EdgeSwitch's
       ``show running-config`` only emits configured interfaces, so
       default ports show up in the switchport summary but have no
       running-config block): trust the summary PVID. The summary is
       authoritative for mode + PVID, so emitting access on PVID is
       safer here than dropping the entry (Codex P2 #391 round-11).
    """
    if participation or tagging:
        if len(untagged_members) != 1 or tagging:
            return _edgesw_routed()
        access_vid = untagged_members[0]
    elif pvid_summary is not None:
        access_vid = pvid_summary
    else:
        return _edgesw_routed()
    return SwitchportInfo(
        enabled=True,
        admin_mode="access",
        oper_mode="access",
        access_vlan=access_vid,
        native_vlan=None,
        allowed_vlans=None,
    )


def _edgesw_trunk(
    participation: list[int],
    tagging: list[int],
    untagged_members: list[int],
) -> SwitchportInfo:
    """
    Trunk: require explicit membership data, single untagged native.

    Empty membership data → routed (would clobber NetBox tagged_vlans).
    Multiple untagged VLANs is unrepresentable on a NetBox trunk → routed
    (Copilot P1 #391 round-11; matches multi-untagged routing in
    netiron/slx/unifiswitch/dell_powerconnect).
    """
    if not participation and not tagging:
        return _edgesw_routed()
    if len(untagged_members) > 1:
        return _edgesw_routed()
    native_vid = untagged_members[0] if untagged_members else None
    return SwitchportInfo(
        enabled=True,
        admin_mode="trunk",
        oper_mode="trunk",
        access_vlan=None,
        native_vlan=native_vid,
        allowed_vlans=tagging if tagging else None,
    )


def _edgesw_general(
    tagging: list[int], untagged_members: list[int],
) -> SwitchportInfo:
    """
    General mode collapses to trunk with the same multi-untagged routing.

    Native = single untagged member; tagged = explicit tagging list.
    No untagged member AND no tagging → routed (no signal to act on).
    """
    if len(untagged_members) > 1:
        return _edgesw_routed()
    native_vid = untagged_members[0] if untagged_members else None
    if native_vid is None and not tagging:
        return _edgesw_routed()
    return SwitchportInfo(
        enabled=True,
        admin_mode="trunk",
        oper_mode="trunk",
        access_vlan=None,
        native_vlan=native_vid,
        allowed_vlans=tagging if tagging else None,
    )


class EdgeSwitchDriver(_napalm_base.NetworkDriver):
    """Ubiquiti EdgeSwitch NAPALM driver (read-only subset for device-discovery)."""

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
        """Open an SSH connection via Netmiko."""
        self.device = self._netmiko_open(
            "ubiquiti_edgeswitch", netmiko_optional_args=self.netmiko_optional_args
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
        - 'show version'              → model, serial, os_version (ntc-template)
        - 'show running-config'       → hostname (regex on 'hostname' line)
        - 'show interfaces status all' → interface_list (regex)

        Uptime is not available from the EdgeSwitch CLI without a dedicated
        'show system' parse; it is returned as 0.0.
        """
        model = serial = os_version = "Unknown"
        raw_ver = self.device.send_command("show version")
        try:
            parsed = parse_output(
                platform="ubiquiti_edgeswitch", command="show version", data=raw_ver
            )
            if parsed:
                row = parsed[0]
                model = row.get("switch_model", "Unknown").strip()
                serial = row.get("serial", "Unknown").strip()
                os_version = row.get("version", "Unknown").strip()
        except Exception:
            logger.debug("Failed to parse 'show version'", exc_info=True)

        config_raw = self.device.send_command("show running-config")
        hostname = self._hostname_from_config(config_raw)

        interface_list: list[str] = []
        for line in self._get_intf_status_raw().splitlines():
            m = _ES_INTF_LINE_RE.match(line)
            if m:
                interface_list.append(m.group("intf"))

        return {
            "hostname": hostname,
            "vendor": "Ubiquiti",
            "model": model,
            "os_version": os_version,
            "serial_number": serial,
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
            m = _ES_INTF_LINE_RE.match(line)
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

        VLAN names are fetched via 'show vlan' (ntc-template).
        Interface membership is parsed from 'show running-config' by scanning
        'vlan participation include <ids>' lines within interface blocks.
        """
        vlans: dict = {}

        raw_vlan = self.device.send_command("show vlan")
        try:
            parsed = parse_output(
                platform="ubiquiti_edgeswitch", command="show vlan", data=raw_vlan
            )
            for row in parsed:
                vid = row.get("vlan_id", "").strip()
                if vid:
                    vlans[vid] = {
                        "name": row.get("vlan_name", vid).strip(),
                        "interfaces": [],
                    }
        except Exception:
            logger.debug("Failed to parse 'show vlan'", exc_info=True)

        config_raw = self.device.send_command("show running-config")
        for vid, intfs in _parse_vlan_members(config_raw).items():
            if vid in vlans:
                vlans[vid]["interfaces"] = intfs
            else:
                vlans[vid] = {"name": vid, "interfaces": intfs}

        return vlans

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """
        Return per-interface VLAN config from ``show interfaces switchport``.

        Two commands are combined:

        * ``show interfaces switchport`` — summary table of {Interface, Mode,
          PVID, ...}. Drives the per-port mode classification.
        * ``show running-config`` — per-interface ``vlan participation``,
          ``vlan tagging`` and ``vlan pvid`` directives. Provides the
          tagged/untagged VID membership that is missing from both the
          summary table and the ``ubiquiti_edgeswitch_show_vlan`` ntc-template
          (which exposes only ``VLAN_ID``/``VLAN_NAME``/``TYPE``).

        The bundled ntc-template for ``show vlan`` does NOT include port-list
        columns, so per-port membership cannot be inverted from there. The
        running-config view is authoritative on EdgeSwitch (Broadcom-fastpath)
        and is already fetched by other getters.
        """
        try:
            sw_raw = self.device.send_command("show interfaces switchport")
        except Exception:
            logger.debug("EdgeSwitch show interfaces switchport failed", exc_info=True)
            return {}
        summaries = _parse_edgesw_switchport_summary(sw_raw)
        if not summaries:
            return {}

        try:
            config_raw = self.device.send_command("show running-config")
        except Exception:
            logger.debug("EdgeSwitch show running-config failed", exc_info=True)
            config_raw = ""
        membership = _parse_edgesw_port_membership(config_raw) if config_raw else {}

        result: dict[str, dict] = {}
        for port, summary in summaries.items():
            info = _edgesw_row_to_switchport_info(port, summary, membership.get(port))
            result[port] = classify_switchport(info)
        return result
