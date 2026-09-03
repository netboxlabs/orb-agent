# Copyright 2026 NetBox Labs Inc
"""
IOS NAPALM driver subclass adding ``get_interfaces_vlans()`` and ``get_modules()``.

Parses ``show interfaces switchport`` via ntc-templates, normalizes each
row into a :class:`custom_napalm._vlan.SwitchportInfo`, and delegates to
the generic classifier. The classifier handles voice promotion, DTP
fallback, wildcard signaling, and clamping — none of that is duplicated here.
``get_modules()`` adds Module / module-bay discovery for modular IOS-XE chassis.
"""

import logging
import re

from napalm.base.helpers import canonical_interface_name
from napalm.ios.ios import IOSDriver as NapalmIOSDriver
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
    ModuleType as _ModuleType,
)
from custom_napalm._modules import (
    is_optic_pid,
    orphan_optic_bay,
)
from custom_napalm._modules import (
    to_payload as _modules_to_payload,
)
from custom_napalm._vlan import SwitchportInfo, classify_switchport, parse_vlan_range_string

logger = logging.getLogger(__name__)


# Cisco IOS / IOS-XE Catalyst multigig short-form override.
#
# netutils.constants.BASE_INTERFACES (the table backing
# napalm.base.helpers.canonical_interface_name) maps "Fi" to
# "FiftyGigabitEthernet". On the IOS Catalyst platforms this driver targets,
# "Fi" is the short form of FiveGigabitEthernet (5GBASE-T multigig). Without
# this override, `show interfaces switchport` rows for 5G ports canonicalize
# to "FiftyGigabitEthernet*/..." and fail to match the long-form
# "FiveGigabitEthernet*/..." names emitted by NAPALM's get_interfaces(), so
# the translator silently drops VLAN data for every 5G port.
_IOS_ADDL_NAME_MAP = {
    "Fi": "FiveGigabitEthernet",
    "FI": "FiveGigabitEthernet",
    "fi": "FiveGigabitEthernet",
}


def _maybe_int(v: object) -> int | None:
    """
    Convert a string/int to int, returning None on failure.

    Explicitly rejects ``bool`` (which is a subclass of ``int`` in Python,
    so ``int(True) == 1``). VLAN-ID fields populated from buggy upstream
    parsers must NOT silently turn ``True``/``False`` into VID 1/0 — the
    classifier's bool-rejection in ``_vlan.coerce_vid`` only fires if the
    bool reaches it un-coerced.
    """
    if isinstance(v, bool):
        return None
    try:
        return int(v)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _normalize_admin_mode(raw: str) -> str | None:
    """Map a raw IOS admin_mode string to 'access', 'trunk', 'dynamic', or None."""
    if "access" in raw:
        return "access"
    if "trunk" in raw:
        return "trunk"
    if "dynamic" in raw:
        return "dynamic"
    return None


def _normalize_oper_mode(raw: str) -> str | None:
    """Map a raw IOS operational mode string to 'access', 'trunk', 'routed', or None."""
    if "access" in raw:
        return "access"
    if "trunk" in raw:
        return "trunk"
    if "routed" in raw:
        return "routed"
    return None


def _parse_trunking_vlans(raw_trunking: list) -> list[int] | str | None:
    """
    Convert an ntc-templates trunking_vlans token list to allowed_vlans.

    Returns ``"all"`` for wildcard inputs, a list of int VIDs for explicit
    ranges, or None when the token list is empty. Logs a WARNING when the
    caller supplied non-empty, non-NONE tokens that parsed to nothing — this
    prevents silent trunk-all promotion on malformed CLI output.
    """
    if not raw_trunking:
        return None
    spec = ",".join(t for t in raw_trunking if t)
    vids, is_wildcard = parse_vlan_range_string(spec)
    if is_wildcard:
        return "all"
    has_input = any((tok or "").strip() for tok in raw_trunking)
    has_none = any((tok or "").strip().upper() == "NONE" for tok in raw_trunking)
    if has_input and not has_none and not vids:
        logger.warning(
            "trunking_vlans=%r could not be parsed; "
            "treating as plain trunk with no tagged VLANs",
            raw_trunking,
        )
    return vids


def _ios_row_to_switchport_info(row: dict) -> SwitchportInfo:
    """
    Build a SwitchportInfo from one ntc-templates ``show interfaces switchport`` row.

    Field mapping rules:
      - ``switchport`` "Disabled" / falsy   → enabled=False (routed downstream)
      - ``admin_mode`` is the trusted intent signal; "dynamic auto" /
        "dynamic desirable" map to ``"dynamic"`` so the classifier falls
        back to oper_mode.
      - ``mode`` (operational) is normalized similarly.
      - ``trunking_vlans`` is a list of tokens — flattened via comma-join
        and handed to ``parse_vlan_range_string``; literal "ALL" / "NONE"
        tokens are detected by the helper.
    """
    switchport = (row.get("switchport") or "").lower()
    if "disabled" in switchport:
        return SwitchportInfo(
            enabled=False, admin_mode=None, oper_mode=None,
            access_vlan=None, native_vlan=None, allowed_vlans=None,
        )

    admin = _normalize_admin_mode((row.get("admin_mode") or "").lower())
    oper = _normalize_oper_mode((row.get("mode") or "").lower())
    allowed = _parse_trunking_vlans(row.get("trunking_vlans") or [])

    return SwitchportInfo(
        enabled=True,
        admin_mode=admin,  # type: ignore[arg-type]
        oper_mode=oper,    # type: ignore[arg-type]
        access_vlan=_maybe_int(row.get("access_vlan", "")),
        native_vlan=_maybe_int(row.get("native_vlan", "")),
        allowed_vlans=allowed,
        voice_vlan=_maybe_int(row.get("voice_vlan", "")),
    )


class IOSDriver(NapalmIOSDriver):
    """Cisco IOS NAPALM driver with VLAN-interface association support."""

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """
        Return per-interface VLAN config.

        Output shape per interface::

            {"mode": "access"|"trunk"|"trunk-all"|"routed",
             "tagged": list[int], "untagged": int | None}

        Parses ``show interfaces switchport`` via ntc-templates. Always
        canonicalizes interface names (``Gi1/0/1`` → ``GigabitEthernet1/0/1``)
        because NAPALM IOS's default ``get_interfaces()`` returns long-form
        from ``show interfaces``, while ``show interfaces switchport`` emits
        short-form. Without canonicalization the translator's exact-name
        match silently misses associations.
        """
        output = self._send_command("show interfaces switchport")
        if not output:
            return {}

        try:
            rows = parse_output(
                platform="cisco_ios",
                command="show interfaces switchport",
                data=output,
            )
        except Exception:
            logger.debug(
                "ntc-templates failed to parse 'show interfaces switchport'",
                exc_info=True,
            )
            return {}

        result: dict[str, dict] = {}
        for row in rows or []:
            ifname = row.get("interface")
            if not ifname:
                continue
            ifname = canonical_interface_name(ifname, addl_name_map=_IOS_ADDL_NAME_MAP)
            info = _ios_row_to_switchport_info(row)
            result[ifname] = classify_switchport(info)
        return result

    def get_chassis_members(self) -> dict | None:
        """
        Return stack-member info for Cisco StackWise (Catalyst 3850/9300/2960X/...).

        Standalone IOS returns None (no stack rows, or a single populated slot).
        Stack of N populated members returns the payload shape consumed by
        device_discovery.translate's VC emission path.
        """
        return _ios_get_chassis_members_impl(self)

    def get_modules(self) -> dict | None:
        """
        Return Module / ModuleBay inventory for standalone or VC modular chassis.

        Parses ``show inventory`` for slot / FRU / transceiver rows and
        groups them by member id when ``Switch N ...`` prefixes are
        present. The driver decides between two emission shapes:

        - **Standalone modular** (e.g. Cat 9400 / 9600 single-chassis):
          inventory has plain ``Slot N <role>`` rows; the canonical
          envelope is emitted with a single ``None`` member bucket.
        - **VC-of-modular** (e.g. Cat 9300 stack with FRU uplinks, Cat
          9400/9500 StackWise Virtual): inventory has ``Switch N`` rows
          plus either ``Switch N Slot M`` (SVL) or ``Switch N FRU Uplink
          Module M`` (9300 stack) rows; the envelope is emitted with one
          member bucket per validated switch id.

        Transceiver rows (NAME = ifname) attach as ``sub_bays`` of their
        parent slot / FRU module. ``show ip interface brief`` provides
        the per-member-per-slot interface enumeration that the
        translator's interface→module routing consumes.

        Returns ``None`` when ``show inventory`` fails to parse or no
        slot / FRU row was recognized.
        """
        return _ios_get_modules_impl(self)


# Cisco IOS PID classifier. PSU / fan prefixes ("PWR-", "FAN") are
# recognized but never emitted (mirrors PR #419 contract — see spec
# Out-of-scope: PSU/fan classified for labelling only).
def classify_module_type_cisco_ios(pid: str) -> _ModuleType:
    """
    Map a Cisco IOS PID/model string to a ModuleType.

    v1: distinguish transceiver vs everything else. PSU and FAN are
    recognized so they don't accidentally classify as linecard, but
    are filtered upstream and never reach Diode emission.
    """
    if not pid:
        return "linecard"
    if is_optic_pid(pid):
        return "transceiver"
    upper = pid.strip().upper()
    if upper.startswith("PWR-") or upper.startswith("PSU-"):
        return "psu"
    if upper.startswith("FAN-") or upper == "FAN":
        return "fan"
    return "linecard"


# Stack-member table row from "show switch" / "show switch detail".
#
# Parsed driver-locally rather than via ntc-templates because
# cisco_ios_show_switch_detail.textfsm is ALL-OR-NOTHING: its STATE value is
# (\w+), so a multi-word state such as "Version Mismatch" or "Sync not
# started" raises TextFSMError and discards EVERY member row, not just the
# offending one. A physical stack mid-upgrade therefore emitted no
# VirtualChassis at all. Verified: those two states lose all rows; "Ready" and
# "Provisioned" parse fine.
#
# Requiring the MAC column is what makes this safe. No header, separator,
# banner or stack-port row carries one, which is why the stack-port data row
# "1  Ok  Ok" cannot be mistaken for a member.
#
# The version column is captured as \S+ rather than a digit-leading pattern
# because real H/W versions are often letter-leading (a 2960X reports "P2B").
# Anchoring it to digits made the version fall through into state, producing
# state="P2B     Ready". A row with no version column AND a multi-word state
# would still mis-split, but every multi-word state observed occurs on a
# present member, which always reports a version.
_SWITCH_ROW_RE = re.compile(
    r"^\s*\*?\s*(?P<id>\d{1,2})\s+"
    r"(?P<role>[A-Za-z][A-Za-z-]*)\s+"
    r"(?P<mac>[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}"
    r"|[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+"
    r"(?P<priority>\d+)"
    r"(?:\s+(?P<version>\S+))?"
    r"\s+(?P<state>[A-Za-z][A-Za-z0-9 /_-]*?)\s*$"
)

# The Stack Port / Neighbors sections follow the member table on physical
# stacks. Their rows cannot match _SWITCH_ROW_RE anyway (no MAC column), so
# this bound is defence in depth, not the primary mechanism.
_SWITCH_TABLE_END_RE = re.compile(
    r"^\s*(?:Switch#\s+Port\s+1\b|Stack\s+Port\s+Status)",
    re.IGNORECASE,
)


def _parse_switch_table(text: str) -> list[dict]:
    """
    Parse the stack-member table from "show switch" / "show switch detail".

    Returns one dict per member row, with the same keys the ntc template
    produces (switch, role, mac_address, priority, version, state) so callers
    are unchanged. ``version`` is "" when the column is absent.

    Degrades one row at a time: an unrecognised line is skipped rather than
    discarding the whole table, which is the behaviour difference from
    ntc-templates that this function exists for.
    """
    rows: list[dict] = []
    for line in (text or "").splitlines():
        if _SWITCH_TABLE_END_RE.match(line):
            break
        match = _SWITCH_ROW_RE.match(line)
        if not match:
            continue
        found = match.groupdict()
        rows.append(
            {
                "switch": found["id"],
                "role": found["role"],
                "mac_address": found["mac"],
                "priority": found["priority"],
                "version": found["version"] or "",
                "state": found["state"],
            }
        )
    return rows


# show inventory NAME rows that identify a stack/VC member CHASSIS:
#   "Switch 1"          — Catalyst 3850/9300/2960X StackWise (most common)
#   "1"                 — Some IOS / IOS-XE versions emit just the slot number
#   "Switch 1 Chassis"  — Catalyst 9400/9500/9600 StackWise Virtual
#
# ANCHORED ON PURPOSE. Loosening this to r"^Switch\s+(\d+)\b" so that any suffix
# is allowed also matches "Switch 1 Power Supply Module 0", "Switch 1 Fan Tray
# 0" and "Switch 1 Slot 1 Supervisor". On a C9500 that happens to be harmless
# because the chassis and supervisor report the same PID and serial, but on a
# modular 9400 it yields model="C9400-PWR-3200AC" and the power supply's
# serial. Serial is NetBox's device matcher, so that attaches discovery to the
# WRONG device record. Do not relax the trailing anchor.
#
# A bare "Chassis" (standalone, no member id) deliberately does not match — the
# caller treats an empty index as "no per-member inventory available" and the
# affected members are dropped by to_payload().
# The whitespace between "Switch" and the id is OPTIONAL (\s*), matching
# _INVENTORY_VC_SLOT_RE, _INVENTORY_VC_FRU_RE and _SWITCH_PREFIX_RE in this same
# file: some IOS-XE releases emit the no-space "Switch1" form. With \s+ here,
# those releases matched no chassis row at all, left serial_by_id empty, and
# to_payload dropped every member -- so an SVL pair still fell back to a single
# Device even though "show switch" had returned both members.
_INVENTORY_CHASSIS_RE = re.compile(
    r"^\s*(?:Switch\s*(\d+)(?:\s+Chassis)?|(\d+))\s*$",
    re.IGNORECASE,
)


def _index_inventory_by_switch(rows: list[dict]) -> tuple[dict[int, str], dict[int, str]]:
    """
    Return (serial_by_switch_id, model_by_switch_id) parsed from `show inventory`.

    Both fields for a member are committed from the SAME inventory row, so they
    can never be mixed across rows. When several rows claim one member id the
    winner is chosen by (has a serial, then an explicit "Chassis" suffix) rather
    than by emission order.

    On standalone IOS the NAME is 'Chassis' and this yields empty dicts — caller
    treats that as "no per-member inventory available".
    """
    # sid -> (rank, serial, model); rank orders candidate rows for one member.
    best: dict[int, tuple[tuple[int, int], str, str]] = {}
    for row in rows or []:
        name = (row.get("name") or "").strip()
        match = _INVENTORY_CHASSIS_RE.match(name)
        if not match:
            continue
        sid = int(match.group(1) or match.group(2))
        serial = (row.get("sn") or "").strip()
        model = (row.get("pid") or "").strip()
        # A serial-bearing row always beats one without, so a chassis row with a
        # blank SN cannot shadow a usable bare "Switch N" row and leave the
        # member serial-less.
        rank = (1 if serial else 0, 1 if name.lower().endswith("chassis") else 0)
        current = best.get(sid)
        if current is None or rank >= current[0]:
            best[sid] = (rank, serial, model)

    serial_by_id = {sid: s for sid, (_rank, s, _m) in best.items() if s}
    model_by_id = {sid: m for sid, (_rank, _s, m) in best.items() if m}
    return serial_by_id, model_by_id


# A CLI rejection means the platform has no stack concept at all (ISR / ASR /
# CSR, and any Catalyst predating the command). That is the expected answer for
# most of a mixed fleet, so it must not warn every discovery cycle.
_CLI_ERROR_RE = re.compile(
    r"%\s*(?:Invalid input detected|Incomplete command|Ambiguous command)",
    re.IGNORECASE,
)

# A standalone Catalyst positively says so.
_NOT_STACKED_RE = re.compile(
    r"Switch\s+is\s+not\s+(?:on|in)\s+(?:any\s+)?stack",
    re.IGNORECASE,
)

# "show stackwise-virtual" has no ntc-template (no template file, no index
# entry), so the one line we need is read directly. Only Catalyst 9400/9500/9600
# in StackWise Virtual mode answer this command; physical stacks reject it, which
# is expected and simply leaves the domain unset.
_SVL_DOMAIN_RE = re.compile(
    r"^\s*Domain\s+Number\s*:\s*(\d+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def _ios_svl_domain(driver) -> str | None:
    """
    Return the StackWise Virtual domain number, or None when unavailable.

    Purely additive: any failure (command rejected, no match, empty output)
    yields None, which is the pre-existing behaviour, so this can never turn a
    working stack into a failure.
    """
    try:
        raw = driver.device.send_command("show stackwise-virtual")
    except Exception as e:
        logger.debug(
            "ios.get_chassis_members: %s: show stackwise-virtual failed: %s",
            driver.hostname, e,
        )
        return None
    match = _SVL_DOMAIN_RE.search(raw or "")
    return match.group(1) if match else None


def _log_no_members(driver, attempts: list[tuple[str, str]]) -> None:
    """
    Explain why no stack members were found, at a level matching how odd it is.

    Fails safe: the WARNING fires unless the output was POSITIVELY identified as
    a CLI rejection or an explicit standalone answer. An unrecognised shape warns
    rather than going quiet, because a silent None is what made this class of gap
    invisible until a user noticed missing NetBox data.

    Note DEBUG is effectively silent in this backend today — the root logger is
    pinned to INFO by an import-time basicConfig and there is no log-level flag
    (see the device-discovery log-level work tracked separately). That is the
    intended outcome for the expected cases, and it removes the per-cycle
    WARNING that every non-Catalyst IOS device used to emit.
    """
    # Only non-empty output carries information. A command that returned nothing
    # tells us neither that the platform rejected it nor that anything is wrong,
    # so it must not drag the classification into the WARNING branch.
    informative = [(cmd, text) for cmd, text in attempts if text.strip()]
    rejected = bool(informative) and all(
        _CLI_ERROR_RE.search(text) or _NOT_STACKED_RE.search(text)
        for _cmd, text in informative
    )
    # Deliberately NOT also testing for the member-table header. Output that
    # looks like a table but parses to nothing already lands here via
    # "not rejected", so a header test adds nothing — and it would actively
    # misfire on a release that prints the column header above an explicit
    # "Switch is not on any stack.", turning a standalone device into a warning.
    if informative and not rejected:
        logger.warning(
            "ios.get_chassis_members: %s: no stack members parsed from %s; the device "
            "neither rejected the command nor reported itself standalone",
            driver.hostname,
            " then ".join(cmd for cmd, _text in attempts) or "no command",
        )
    else:
        logger.debug(
            "ios.get_chassis_members: %s: no stack concept on this platform "
            "(commands rejected, or reported standalone)",
            driver.hostname,
        )


def _ios_get_chassis_members_impl(driver) -> dict | None:
    """
    Implementation of IOSDriver.get_chassis_members (factored for testability).

    Tries "show switch detail" first, which is what physical StackWise platforms
    answer, then falls back to "show switch", the only form Catalyst
    9400/9500/9600 in StackWise Virtual mode supports (they reject the "detail"
    keyword outright). Both print the same member table, so one parser handles
    both.
    """
    detail_rows: list[dict] = []
    attempts: list[tuple[str, str]] = []
    for command in ("show switch detail", "show switch"):
        try:
            raw = driver.device.send_command(command)
        except Exception as e:
            logger.warning(
                "ios.get_chassis_members: %s: %s failed: %s",
                driver.hostname, command, e,
            )
            continue
        raw = raw or ""
        attempts.append((command, raw))
        # _parse_switch_table is a pure regex loop called OUTSIDE the try on
        # purpose: it cannot raise on device output, so a genuine bug in it must
        # propagate rather than be swallowed as "this host has no stack".
        detail_rows = _parse_switch_table(raw)
        if detail_rows:
            break

    if not detail_rows:
        _log_no_members(driver, attempts)
        return None

    try:
        inv_out = driver.device.send_command("show inventory")
        inv_rows = parse_output(
            platform="cisco_ios",
            command="show inventory",
            data=inv_out or "",
        )
    except Exception as e:
        logger.warning(
            "ios.get_chassis_members: %s: show inventory failed: %s",
            driver.hostname, e,
        )
        inv_rows = []

    serial_by_id, model_by_id = _index_inventory_by_switch(inv_rows or [])

    members: list[ChassisMember] = []
    for row in detail_rows:
        sid = _maybe_int(row.get("switch"))
        if sid is None:
            continue
        members.append(
            ChassisMember(
                id=sid,
                serial=serial_by_id.get(sid, ""),
                model=model_by_id.get(sid),
                role=normalize_role(row.get("role")),
                priority=_maybe_int(row.get("priority")),
                mac=row.get("mac_address") or row.get("mac") or None,
                state=row.get("state") or None,
            )
        )

    # Additive: only StackWise Virtual platforms answer this, and a None domain
    # is what physical stacks have always emitted.
    domain = _ios_svl_domain(driver) if len(members) > 1 else None
    payload = to_payload(members, domain=domain)

    emitted = len(payload["members"]) if payload else 0
    if emitted < 2:
        if len(detail_rows) >= 2:
            # The device reported a stack but we cannot represent it: to_payload
            # drops members whose serial could not be resolved from inventory.
            # That is a real gap worth an operator's attention.
            logger.warning(
                "ios.get_chassis_members: %s: the device reported %d stack member row(s) "
                "but only %d had a resolvable serial; falling back to a single Device",
                driver.hostname, len(detail_rows), emitted,
            )
        else:
            # A single-unit stack-capable Catalyst honestly reports one row. That
            # is the most common deployment in a fleet and is not a problem, so
            # it must not warn on every discovery cycle.
            logger.debug(
                "ios.get_chassis_members: %s: device reported a single unit; "
                "not a virtual chassis",
                driver.hostname,
            )
    return payload


# ---- module inventory ----------------------------------------------------
#
# `show inventory` row patterns that drive emission:
#
#   "Slot 1 Linecard"      — physical line card on a Catalyst 9400/9600 modular
#   "Slot 1 Supervisor"    — supervisor module (treated as its own type)
#   "Slot 3 - Supervisor"  — hyphenated variant seen on some IOS-XE versions
#
# Plus transceiver rows whose NAME is an interface short / long form, e.g.
# "Te1/0/1" (standalone modular 3-tuple), "TenGigabitEthernet1/0/1"
# (canonical long form), or "HundredGigE1/2/0/1" / its long form
# "HundredGigabitEthernet1/2/0/1" (Cat 9400/9500 SVL 4-tuple). The 4-tuple
# member dimension is the leading integer; transceivers attach as sub-bays
# of their member's parent slot.
#
# IMPORTANT: only ``Slot N`` is matched here. The earlier ``module|Module``
# alternation also caught ``"module 0"`` rows emitted by non-modular
# IOS-XE platforms (ISR/ASR route processors), which would falsely
# materialize a phantom slot-0 ModuleBay on every such device.
#
# The negative lookahead ``(?!\s*/)`` after the slot number rejects
# sub-slot inventory rows like ``"Slot 0/0"`` or ``"Slot 2/1/0"``
# that some platforms emit for SPA/controller positions. Without it,
# those rows would silently partial-match as a top-level slot and
# materialize phantom linecards.
_INVENTORY_SLOT_RE = re.compile(
    r"^Slot\s+(\d+)(?!\s*/)(?:\s*[-:]?\s*(\w+))?",
    re.IGNORECASE,
)

# Virtual-chassis-of-modular slot row, Cat 9400/9500 StackWise Virtual.
# `Switch 1 Slot 2 Linecard`, `Switch 2 Slot 3 - Supervisor`, or the
# no-space `Switch1 Slot 2 Linecard` form some IOS-XE versions emit
# (\s* between "Switch" and the digit). The same (?!\s*/) lookahead
# rejects sub-slot rows like `Switch 1 Slot 2/0` that encode
# controller positions rather than top-level chassis bays. The
# standalone _INVENTORY_SLOT_RE above is anchored with `^Slot` and
# so does NOT match these VC-prefixed rows — a row matches at most
# one regex.
_INVENTORY_VC_SLOT_RE = re.compile(
    r"^Switch\s*(\d+)\s+Slot\s+(\d+)(?!\s*/)(?:\s*[-:]?\s*(\w+))?",
    re.IGNORECASE,
)

# Virtual-chassis-of-modular FRU uplink, Cat 9300 stack with network
# module. `Switch 1 FRU Uplink Module 1` or `Switch1 FRU Uplink
# Module 1` (no-space form). Distinct from VC_SLOT — 9300 doesn't
# have Slot N entries; it exposes its single swappable network module
# via this NAME pattern instead.
_INVENTORY_VC_FRU_RE = re.compile(
    r"^Switch\s*(\d+)\s+FRU\s+Uplink\s+Module\s+(\d+)",
    re.IGNORECASE,
)

# Inventory row NAME that looks like an interface (transceiver row).
# Accepts 2-tuple (e.g. Te1/1), 3-tuple (Te2/0/1 — standalone modular), and
# 4-tuple (HundredGigE1/2/0/1 — Cat 9400/9500 SVL) Cisco ifnames.
#
# The prefix vocabulary is the union of parse_member_id's _CISCO_IOS_RE
# set PLUS ``FastEthernet|Fa`` and ``Ethernet|Eth``. The two extra
# prefixes are intentional here — inventory rows on older Catalyst
# chassis and some IOS-XE platforms can name transceiver-bearing ports
# with ``Fa`` (100M) or bare ``Ethernet`` even when parse_member_id
# never sees those forms (its job is stack-member extraction, which is
# limited to the higher-speed Catalyst families). The earlier broad
# pattern (`^[A-Za-z]+\d+...`) also matched non-interface rows that
# Catalyst stacks emit — e.g. ``StackPort1/1`` (the inter-switch stack
# cable port) — which then bogusly attached as transceiver sub-bays under
# slot 1 in VC mode. Even with the narrow prefix list a paranoid second
# gate is applied at the parse site: rows that DON'T classify as
# transceiver via the PID are dropped, so a non-transceiver Cisco-prefix
# row (rare but possible) doesn't materialize a wrong sub-bay.
_INVENTORY_IFNAME_RE = re.compile(
    r"""
    ^
    (?:Gi(?:gabitEthernet)?
       | Te(?:nGigabitEthernet)?
       | Fo(?:rtyGigabitEthernet)?
       | Hu(?:ndredGigE|ndredGigabitEthernet)?
       | TwentyFiveGigE | Twe
       | TwoGigabitEthernet | Tw
       | FiveGigabitEthernet | Fi
       | FastEthernet | Fa
       | Ethernet | Eth
    )
    \d+(?:/\d+){1,3}$
    """,
    re.VERBOSE,
)
_INTERFACE_SLOT_RE = re.compile(r"^[A-Za-z]+(\d+)/\d+")


# A "Switch N ..." inventory row prefix marks per-switch entries on
# IOS-XE platforms. Real virtual chassis stacks emit ≥2 distinct ids;
# some single-chassis platforms (notably some Cat 9500 versions) still
# prefix every row with `Switch 1`. The two cases differ in two
# orthogonal ways and each is gated on its own signal:
#
#   - VC mode (bucket bays by member id, dispatch to per-member Device):
#     gated on count ≥ 2 — matches what translate_chassis itself uses
#     via validate_chassis_payload.
#   - Switch-prefixed interface naming (switch/slot/sub/port — the
#     leading integer is the switch id, the slot id is the SECOND
#     integer): gated on count ≥ 1. A single-chassis 9500 with Switch
#     1 inventory rows uses the same `<speed>1/SLOT/PORT` ifname format
#     as a VC stack member; the slot extraction has to skip past the
#     switch dimension or it picks up the member id by mistake.
# ``\s*`` (not ``\s+``) and a trailing ``\b`` accept both ``Switch 1`` and
# ``Switch1`` forms while rejecting ``Switch1abc``-style garbage runs.
_SWITCH_PREFIX_RE = re.compile(r"^Switch\s*(\d+)\b", re.IGNORECASE)


def _count_distinct_switch_ids(inv_rows: list[dict]) -> int:
    """
    Return the number of distinct member ids named in inventory.

    Recognizes both the ``Switch N ...`` prefix (``_SWITCH_PREFIX_RE``) and
    the bare-numeric chassis NAME some IOS-XE releases emit instead — the
    same row shape ``_INVENTORY_CHASSIS_RE`` already accepts and
    ``get_chassis_members`` already trusts (see
    ``test_get_chassis_members/numeric_inventory_names``).

    Without the bare-numeric branch, a real stack whose only member signal
    is a bare-digit NAME never reaches switch-prefixed mode: every ifname's
    leading integer is actually the member id, but with no ``Switch N`` row
    anywhere to detect, the driver reads it as if it were the slot id
    instead. A fixed port and an uplink port on the same member then both
    resolve to the same (wrong) "slot" and become indistinguishable — see
    ``_optic_parent_is_baseboard``, which depends on this count being right
    to tell the two apart at all.
    """
    member_ids: set[str] = set()
    for row in inv_rows or []:
        name = (row.get("name") or "").strip()
        m = _SWITCH_PREFIX_RE.match(name)
        if m:
            member_ids.add(m.group(1))
            continue
        m = _INVENTORY_CHASSIS_RE.match(name)
        if m:
            member_ids.add(m.group(1) or m.group(2))
    return len(member_ids)


def _interface_member_id(ifname: str) -> int | None:
    """Extract the leading integer from a Cisco ifname (member id in VC context)."""
    m = re.match(r"^[A-Za-z]+(\d+)/", ifname)
    return int(m.group(1)) if m else None


def _interface_slot(ifname: str, *, depth: int = 1) -> str | None:
    """
    Extract a slot id from a Cisco ifname.

    ``depth=1`` returns the leading integer — that's the slot id on a
    standalone modular chassis (e.g. ``TenGigabitEthernet2/0/1`` → ``2``).
    ``depth=2`` returns the second integer — that's the slot id on a VC
    member chassis (e.g. ``TenGigabitEthernet1/1/1`` → ``1`` for a 9300
    stack FRU uplink, ``HundredGigE1/2/0/1`` → ``2`` for 9400 SVL).
    """
    if depth == 1:
        m = _INTERFACE_SLOT_RE.match(ifname)
        return m.group(1) if m else None
    m = re.match(r"^[A-Za-z]+\d+/(\d+)", ifname)
    return m.group(1) if m else None


_INTERFACE_SEGMENTS_RE = re.compile(r"^[A-Za-z]+(\d+(?:/\d+)*)$")


def _interface_segment_count(ifname: str) -> int:
    """
    Count the numeric position segments in a canonicalized Cisco ifname.

    ``GigabitEthernet1/0/1`` → 3 (switch/slot/port on a VC member, or
    slot/sub/port on a standalone modular chassis). ``Gi0/25`` → 2 (classic
    Catalyst module/port). Returns 0 for a name with no numeric segment at
    all — this driver's transceiver rows always have at least one ``/``,
    but the count is used defensively by ``_optic_parent_is_baseboard``,
    which must not guess when the shape is unrecognized.
    """
    m = _INTERFACE_SEGMENTS_RE.match(ifname)
    if not m:
        return 0
    return m.group(1).count("/") + 1


# Non-prefixed 3-tuple ifnames (``Te1/0/1``) give no per-port signal that
# the port's own parent is the chassis baseboard: on a fixed WS-C3850-48XS,
# "Te1/0/1" and on a modular C9404R, "Te1/0/1" are byte-identical, and
# ``_interface_slot``'s depth=1 reading already commits to the modular
# interpretation (leading integer = slot). The only signal left is at the
# device level: does ANYTHING in the raw inventory look modular at all?
#
#   - a ``Slot N`` / ``Subslot`` / ``FRU`` row anywhere (whatever member or
#     NAME form the platform uses for a card bay), or
#   - the chassis DESCR itself saying "<N> Slot Chassis".
#
# Either one vetoes promotion for every non-prefixed 3-tuple optic on the
# device. This is absence-grade, not immunity-grade: a modular chassis that
# omits EVERY card row AND whose chassis DESCR lacks the slot wording still
# false-promotes. That residual is accepted rather than declining the whole
# mode outright, which would silently kill fixed-port promotion on every
# standalone 3850/9300-shaped device — the exact feature this gate exists
# to protect.
_MODULAR_VETO_NAME_RE = re.compile(r"Slot\s*\d+|Subslot|FRU", re.IGNORECASE)
_MODULAR_VETO_DESCR_RE = re.compile(r"\d+\s+Slot\s+Chassis", re.IGNORECASE)

# Chassis families whose uplink ports are FIXED but are still numbered on a
# non-zero module (``Te1/1/x``). They ship no FRU row for those ports because
# there is no removable module to report, so the baseboard rule below cannot
# tell them apart from a modular chassis whose card row the vendor omitted —
# the two are byte-identical in both ifname shape and inventory. The chassis
# PID is the only signal, so recognition is an explicit allowlist rather than a
# heuristic.
#
# Membership criterion: every SKU in the family has non-removable uplinks, and
# a device capture confirms the resulting inventory shape. Two families qualify:
#
#   - Catalyst 9200L — its -4G, -4X and -2Y uplinks are all fixed (e.g.
#     C9200L-24PXG-4X, C9200L-48PXG-2Y). The plain Catalyst 9200 does NOT: it
#     takes a removable C9200-NM-* uplink module.
#   - Catalyst 9300L — fixed SFP uplinks, no network-module slot. The plain
#     C9300 and the C9300X both DO take a removable C9300-NM-* module.
#
# A removable module is reported as its own FRU row, which claims the slot and
# is matched before this gate is consulted.
_IOS_FIXED_UPLINK_PID_RE = re.compile(r"^(?:C9200L|C9300L)-", re.IGNORECASE)


def _ios_chassis_is_fixed_uplink(inv_rows: list[dict]) -> bool:
    """Return True when raw inventory names a known fixed-uplink chassis PID."""
    for row in inv_rows or []:
        if _IOS_FIXED_UPLINK_PID_RE.match((row.get("pid") or "").strip()):
            return True
    return False


def _non_prefixed_modular_veto(inv_rows: list[dict]) -> bool:
    """Return True when raw inventory shows any sign the chassis is modular."""
    for row in inv_rows or []:
        if _MODULAR_VETO_NAME_RE.search(row.get("name") or ""):
            return True
        if _MODULAR_VETO_DESCR_RE.search(row.get("descr") or ""):
            return True
    return False


def _optic_parent_is_baseboard(
    canonical: str,
    *,
    switch_prefixed: bool,
    non_prefixed_modular_veto: bool,
    fixed_uplink_chassis: bool = False,
) -> bool:
    """
    Positive-evidence check: may an unclaimed, parentless optic promote?

    Promotion to a device-rooted bay requires evidence that the port's OWN
    parent position is the chassis baseboard (module 0) — not merely the
    absence of a claim on its slot. See ``_attach_transceivers`` for why
    absence alone stopped being trustworthy (a vendor that omits the
    parent row defeats it every time).

    - Switch-prefixed ifnames (member/slot/port, or member/slot/sub/port —
      depth=2 is the slot): module 0 is the switch's own baseboard, every
      real bay is 1-based. A name with fewer than 3 segments has no
      reliable slot at depth 2 — refuse rather than read the port number
      as the slot. A non-zero module promotes only on a chassis whose PID
      says its uplinks are fixed (``fixed_uplink_chassis``); nothing in the
      ifname distinguishes that case from a modular chassis whose card row
      the vendor omitted.
    - Non-prefixed 2-tuple (module/port, depth=1 is the slot): same
      baseboard reasoning, one dimension up.
    - Non-prefixed 3-tuple: no per-port signal exists at all (a fixed
      WS-C3850-48XS and a modular C9404R report byte-identical names).
      Promotion is allowed unless a device-level veto fires.
    """
    if switch_prefixed:
        if _interface_segment_count(canonical) < 3:
            return False
        if _interface_slot(canonical, depth=2) == "0":
            return True
        # Non-zero module on a chassis whose uplinks are known to be fixed:
        # the port has no removable parent to nest under, which is why no FRU
        # row claimed its slot. Reached only after the claimed-slot check, so
        # a fixed-uplink chassis that DOES report a card row still nests.
        return fixed_uplink_chassis
    segments = _interface_segment_count(canonical)
    if segments == 2:
        return _interface_slot(canonical, depth=1) == "0"
    if segments >= 3:
        return not non_prefixed_modular_veto
    return False


def _classify_slot_module(pid: str, role_hint: str) -> str:
    """
    Pick a ModuleType for a Slot N inventory row.

    Trusts the NAME's role hint first ("Supervisor" / "Sup..." → supervisor),
    then falls back to PID-based classification. Anything not classifiable
    as a transceiver from the PID — supervisor, linecard, fabric, route
    processor — is treated as ``linecard`` for v1.
    """
    role_word = (role_hint or "").lower()
    if role_word.startswith("sup"):
        return "supervisor"
    pid_type = classify_module_type_cisco_ios(pid)
    # A "Slot N" row that PID-classifies as transceiver is almost certainly
    # an inventory mislabel — keep it a linecard rather than risk dropping
    # the bay in linecards mode.
    return "linecard" if pid_type == "transceiver" else pid_type


def _ios_claim_slot(
    claimed_slots: set[tuple[int | None, str]],
    vc_slot: re.Match | None,
    vc_fru: re.Match | None,
    slot_match: re.Match | None,
    vc_mode: bool,
) -> None:
    """
    Record the ``(member_key, slot)`` an inventory row's NAME claims.

    Called before any pid/sn usability filter, so an unusable row's slot
    claim survives — see ``_parse_inventory_rows`` for why that matters.
    The three matches are mutually exclusive (a row matches at most one),
    and each is keyed exactly like the bay it would build in
    ``_parse_inventory_rows`` below.
    """
    if vc_slot:
        claimed_slots.add((int(vc_slot.group(1)) if vc_mode else None, vc_slot.group(2)))
    elif vc_fru:
        claimed_slots.add((int(vc_fru.group(1)) if vc_mode else None, vc_fru.group(2)))
    elif slot_match:
        claimed_slots.add((None, slot_match.group(1)))


def _parse_inventory_rows(
    rows: list[dict],
    vc_mode: bool,
) -> tuple[
    dict[int | None, dict[str, _ModuleBay]],
    dict[int | None, dict[str, _ModuleEntry]],
    set[tuple[int | None, str]],
]:
    """
    Split ``show inventory`` rows into per-member slot bays and transceivers.

    Returns ``(bays_by_member_then_slot, transceivers_by_member_then_ifname,
    claimed_slots)``. In standalone mode (``vc_mode=False``) both outer dicts
    have a single ``None`` key. In VC mode the outer key is the member id
    captured from ``Switch N ...`` prefixes on the inventory row.

    ``claimed_slots`` is every ``(member_key, slot)`` pair the RAW inventory
    names via ``Switch N Slot M``, ``Switch N FRU Uplink Module M`` or plain
    ``Slot N`` — matched against ``name`` here, BEFORE the ``pid and sn``
    usability filter below and before any type/classification filter, and
    keyed exactly like ``bays_by_member``. A slot lands in this set even
    when its own row turns out unusable (blank PID or serial); the caller
    must then decline promoting any optic mapped to that slot, because the
    slot's parent exists in hardware — this row simply failed to describe
    it usably. Promoting the optic to a device-rooted bay in that case
    would invent a chassis-level parent for hardware that already has one.
    """
    bays_by_member: dict[int | None, dict[str, _ModuleBay]] = {}
    trans_by_member: dict[int | None, dict[str, _ModuleEntry]] = {}
    claimed_slots: set[tuple[int | None, str]] = set()
    for row in rows or []:
        name = (row.get("name") or "").strip()
        pid = (row.get("pid") or "").strip()
        sn = (row.get("sn") or "").strip()
        descr = (row.get("descr") or "").strip()

        # A row matches at most one of these three (see the comments above
        # _INVENTORY_SLOT_RE / _INVENTORY_VC_SLOT_RE / _INVENTORY_VC_FRU_RE).
        # Matched up front, before the pid/sn filter, so an unusable row's
        # slot claim survives even though the row itself gets skipped below.
        vc_slot = _INVENTORY_VC_SLOT_RE.match(name)
        vc_fru = _INVENTORY_VC_FRU_RE.match(name)
        slot_match = _INVENTORY_SLOT_RE.match(name)
        _ios_claim_slot(claimed_slots, vc_slot, vc_fru, slot_match, vc_mode)

        if not sn:
            continue
        # A row the device serialised but did not name. The description stands
        # in for the model and `identified` records that it did, so translate
        # can file it under a generic manufacturer rather than assert a brand
        # the device never claimed. A row with neither is skipped: NetBox needs
        # a model and there is nothing to call the part.
        #
        # `Unspecified` is a Cisco placeholder, not a model. Normalising it here
        # rather than in the shared layer is deliberate: which strings are
        # placeholders is vendor knowledge.
        identified = bool(pid) and pid != "Unspecified"
        model = pid if identified else descr
        if not model:
            logger.debug(
                "ios.get_modules: %s has a serial but no PID and no description; "
                "skipping (nothing to name the part)", name,
            )
            continue

        # VC slot pattern (Switch N Slot M [role]) is tried regardless of
        # vc_mode — some single-chassis IOS-XE versions (notably Cat 9500)
        # use the "Switch 1 Slot M" prefix too. The member id captured
        # here is discarded in standalone mode so the bay falls into the
        # None bucket the standalone translate path expects.
        if vc_slot:
            member_key = int(vc_slot.group(1)) if vc_mode else None
            slot = vc_slot.group(2)
            mtype = _classify_slot_module(model, vc_slot.group(3) or "")
            bays_by_member.setdefault(member_key, {})[slot] = _ModuleBay(
                name=slot, position=slot,
                module=_ModuleEntry(
                    model=model, serial=sn, type=mtype, description=descr,
                    identified=identified,
                ),
            )
            continue

        if vc_fru:
            member_key = int(vc_fru.group(1)) if vc_mode else None
            slot = vc_fru.group(2)
            # FRU uplink modules have no role hint in NAME, so classify from
            # `model` alone (empty role hint) via the same
            # transceiver-shaped-classification downgrade the slot branches
            # use: for an unidentified row `model` is the raw device
            # description, and a description that happens to start with a
            # recognized MSA optic prefix must not silently type the bay
            # transceiver, or it would vanish in linecards mode.
            bays_by_member.setdefault(member_key, {})[slot] = _ModuleBay(
                name=slot, position=slot,
                module=_ModuleEntry(
                    model=model, serial=sn,
                    type=_classify_slot_module(model, ""),
                    description=descr,
                    identified=identified,
                ),
            )
            continue

        if slot_match:
            # Plain "Slot N" row (no Switch prefix) — bucketed under None.
            slot = slot_match.group(1)
            mtype = _classify_slot_module(model, slot_match.group(2) or "")
            bays_by_member.setdefault(None, {})[slot] = _ModuleBay(
                name=slot, position=slot,
                module=_ModuleEntry(
                    model=model, serial=sn, type=mtype, description=descr,
                    identified=identified,
                ),
            )
            continue

        if _INVENTORY_IFNAME_RE.match(name):
            # The row's NAME being an interface is the optic signal, not the
            # PID. classify_module_type_cisco_ios returns "linecard" for both
            # "" and "Unspecified", so deriving the type from the PID would
            # file an unidentified optic as a linecard and let it survive
            # linecards mode, where a transceiver is correctly dropped. Junos
            # gates on its own NAME ("Xcvr") for the same reason.
            #
            # An identified row is still second-gated by PID class, which drops
            # a non-transceiver row whose NAME sneaked past the narrow regex.
            module_type = "transceiver"
            if identified:
                module_type = classify_module_type_cisco_ios(pid)
                if module_type != "transceiver":
                    logger.warning(
                        "ios.get_modules: %s reports PID %r, which is not a "
                        "recognized transceiver model; skipping",
                        name, pid,
                    )
                    continue
            # In VC mode the leading integer of the ifname is the
            # member id; in standalone there is no member dimension
            # and the transceiver lives in the same None bucket as
            # its parent.
            member_for_transceiver = _interface_member_id(name) if vc_mode else None
            trans_by_member.setdefault(member_for_transceiver, {})[name] = _ModuleEntry(
                model=model, serial=sn,
                type=module_type,
                description=descr,
                identified=identified,
            )
    return bays_by_member, trans_by_member, claimed_slots


def _collect_interfaces_by_member_and_slot(
    driver,
    bays_by_member: dict[int | None, dict[str, _ModuleBay]],
    vc_mode: bool,
    switch_prefixed: bool,
) -> dict[int | None, dict[str, list[str]]]:
    """
    Bin canonicalized ifnames from ``show ip interface brief`` by member then slot.

    The two signals are orthogonal:

    - ``vc_mode`` controls the MEMBER dimension. In VC mode each ifname's
      leading integer is the member id; otherwise every ifname binds to
      the single ``None`` member bucket.
    - ``switch_prefixed`` controls the SLOT dimension. If the inventory
      had any ``Switch N`` rows, interface names use the
      ``<speed><switch>/<slot>/...`` form, so the slot id is the SECOND
      integer regardless of vc_mode. Without Switch prefixes (plain
      ``Slot N`` inventory) the leading integer IS the slot id.

    Falls back to a skeleton with empty lists when the brief command
    fails — bays/modules still emit, just without per-interface routing
    for that cycle.
    """
    out: dict[int | None, dict[str, list[str]]] = {
        m: {slot: [] for slot in bays_by_member[m]} for m in bays_by_member
    }
    try:
        raw = driver.device.send_command("show ip interface brief")
        rows = parse_output(
            platform="cisco_ios",
            command="show ip interface brief",
            data=raw or "",
        )
    except Exception:
        logger.debug("ios.get_modules: show ip interface brief failed", exc_info=True)
        return out
    slot_depth = 2 if switch_prefixed else 1
    for row in rows or []:
        raw_if = (row.get("interface") or row.get("intf") or "").strip()
        if not raw_if:
            continue
        ifname = canonical_interface_name(raw_if, addl_name_map=_IOS_ADDL_NAME_MAP)
        member_id = _interface_member_id(ifname) if vc_mode else None
        slot = _interface_slot(ifname, depth=slot_depth)
        if member_id not in out or slot is None or slot not in out[member_id]:
            continue
        out[member_id][slot].append(ifname)
    return out


def _attach_transceivers(
    bays_by_member: dict[int | None, dict[str, _ModuleBay]],
    transceivers_by_member: dict[int | None, dict[str, _ModuleEntry]],
    interfaces_by_member_and_slot: dict[int | None, dict[str, list[str]]],
    switch_prefixed: bool,
    claimed_slots: set[tuple[int | None, str]],
    non_prefixed_modular_veto: bool,
    fixed_uplink_chassis: bool = False,
) -> None:
    """
    Attach each transceiver entry as a sub-bay of its member's parent slot.

    Canonicalizes the transceiver row's ifname so the sub-bay name aligns
    with the long-form name from ``get_interfaces()``. Also self-routes
    the transceiver's ifname into its own sub-bay key so the translator's
    deepest-wins logic assigns the transceiver as the interface's module
    in full mode. ``switch_prefixed`` (any ``Switch N`` row in inventory)
    determines whether the slot id is the leading integer (False) or the
    second integer (True), matching the interface-routing depth above.

    ``claimed_slots`` (see ``_parse_inventory_rows``) names every
    ``(member_id, slot)`` the RAW inventory already accounted for. An optic
    whose slot has no usable bay but IS claimed is declined rather than
    promoted — that slot's parent exists in hardware, it just didn't
    survive ``_parse_inventory_rows``'s usability filter, so promoting the
    optic here would invent a chassis-level topology instead of reporting
    the real modular one.

    An optic on an UNCLAIMED slot is no longer promoted on absence alone —
    a vendor that omits the parent row entirely (rather than reporting it
    unusably) defeats that check every time. ``_optic_parent_is_baseboard``
    supplies the positive evidence instead: promotion requires the port's
    OWN name to say its parent is the chassis baseboard, or (in the one
    mode with no such signal) the absence of any device-level sign that the
    chassis is modular at all. See that function's docstring for the
    per-mode rules, and its module-level veto comment for the residual this
    still cannot catch.
    """
    slot_depth = 2 if switch_prefixed else 1
    for member_id, transceivers in transceivers_by_member.items():
        for raw_ifname, transceiver in transceivers.items():
            canonical = canonical_interface_name(
                raw_ifname, addl_name_map=_IOS_ADDL_NAME_MAP,
            )
            slot = _interface_slot(canonical, depth=slot_depth)
            parent_bay = None
            if slot is not None:
                parent_bay = bays_by_member.get(member_id, {}).get(slot)
            if parent_bay is None or parent_bay.module is None:
                if slot is not None and (member_id, slot) in claimed_slots:
                    logger.debug(
                        "ios.get_modules: declining promotion of %s onto member %s "
                        "slot %s (inventory claims the slot but its row was unusable)",
                        canonical, member_id, slot,
                    )
                    continue
                if not _optic_parent_is_baseboard(
                    canonical,
                    switch_prefixed=switch_prefixed,
                    non_prefixed_modular_veto=non_prefixed_modular_veto,
                    fixed_uplink_chassis=fixed_uplink_chassis,
                ):
                    logger.debug(
                        "ios.get_modules: declining promotion of %s onto member %s "
                        "slot %s (no positive evidence its parent is the chassis "
                        "baseboard)",
                        canonical, member_id, slot,
                    )
                    continue
                # Fixed-port chassis, and fixed ports on a chassis whose only
                # bay is an uplink module: the optic has no parent to nest
                # under, so it becomes a bay in its own right.
                bays_by_member.setdefault(member_id, {})[canonical] = (
                    orphan_optic_bay(canonical, transceiver)
                )
            else:
                parent_bay.module.sub_bays.append(
                    _ModuleBay(name=canonical, position=canonical, module=transceiver),
                )
            interfaces_by_member_and_slot.setdefault(member_id, {}).setdefault(
                canonical, [],
            ).append(canonical)


def _ios_get_modules_impl(driver) -> dict | None:
    """Implementation of IOSDriver.get_modules (factored for testability)."""
    try:
        inv_out = driver.device.send_command("show inventory")
        inv_rows = parse_output(
            platform="cisco_ios",
            command="show inventory",
            data=inv_out or "",
        )
    except Exception as e:
        logger.warning("ios.get_modules: show inventory failed: %s", e)
        return None
    if not inv_rows:
        # Every Cisco chassis reports at least its own row, so zero parsed rows
        # means the command was rejected or its output did not parse -- a
        # different failure from "no modules on this device".
        logger.warning(
            "ios.get_modules: show inventory returned no parseable rows; "
            "emitting no modules",
        )
        return None

    distinct_switch_count = _count_distinct_switch_ids(inv_rows)
    # VC mode (bucket bays by member id, dispatch to per-member Device)
    # only fires for real stacks with ≥2 distinct ids.
    vc_mode = distinct_switch_count >= 2
    # Switch-prefixed ifname format (slot id = second integer, not the
    # leading switch id) fires whenever inventory has ANY Switch N row —
    # single-chassis 9500 with Switch 1 prefix uses the same format.
    switch_prefixed = distinct_switch_count >= 1
    # Only consulted by _optic_parent_is_baseboard in non-prefixed mode;
    # computed unconditionally anyway since scanning the rows once here is
    # cheap and keeps the veto device-level rather than per-optic.
    non_prefixed_modular_veto = _non_prefixed_modular_veto(inv_rows)
    fixed_uplink_chassis = _ios_chassis_is_fixed_uplink(inv_rows)
    bays_by_member, transceivers_by_member, claimed_slots = _parse_inventory_rows(
        inv_rows, vc_mode,
    )
    if not bays_by_member and not transceivers_by_member:
        # No aggregate warning here on purpose. A switch with no optics and no
        # cards reaches this line every cycle, and that is the correct answer,
        # not a diagnostic event. The rows that WERE candidates and got
        # rejected are each warned about individually in
        # _parse_inventory_rows, which is where the reason actually lives.
        return None

    interfaces_by_member_and_slot = _collect_interfaces_by_member_and_slot(
        driver, bays_by_member, vc_mode, switch_prefixed,
    )
    # Counted before the attach consumes them, so the warning below can say
    # how many optics the device actually reported.
    optics_found = sum(len(t) for t in transceivers_by_member.values())
    _attach_transceivers(
        bays_by_member, transceivers_by_member, interfaces_by_member_and_slot,
        switch_prefixed, claimed_slots, non_prefixed_modular_veto,
        fixed_uplink_chassis,
    )

    payload = _modules_to_payload({
        member_id: _MemberModules(
            bays=list(bays.values()),
            interfaces_by_bay=interfaces_by_member_and_slot.get(member_id, {}),
        )
        for member_id, bays in bays_by_member.items()
    })
    if payload is None and optics_found:
        # The device reported optics and not one of them survived. Declining is
        # the right call when a parent bay may exist unreported, but staying
        # silent about it makes the option look broken rather than deliberate.
        # The per-port reason stays at debug.
        logger.warning(
            "ios.get_modules: found %d transceiver(s) but declined every one "
            "(no modeled parent bay); emitting no modules. Enable debug "
            "logging on custom_napalm.ios for the per-port reason.",
            optics_found,
        )
    return payload
