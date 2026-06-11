# Copyright 2026 NetBox Labs Inc
"""
Custom Nokia/Alcatel SR-OS SSH NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans,
  get_modules.

Uses Netmiko (nokia_sros) for SSH transport and ntc-templates (alcatel_sros)
for structured parsing of show port and show router interface.
show version / show system information are parsed with regex (no templates exist).
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.helpers import mac as normalize_mac
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

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

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config sanitization — Nokia SR-OS sensitive fields
# ---------------------------------------------------------------------------

# Quoted values after keywords such as:
#   authentication-key "MyAuthKey123"
#   hmac-md5-key "MyHmacKey456"
#   password "MyS3cr3tP4ssword"
#   community "public" hash2 "c2VjcmV0" ...
_AUTH_KEY_RE = re.compile(r'(authentication-key)\s+"[^"]*"', re.IGNORECASE)
_HMAC_MD5_RE = re.compile(r'(hmac-md5-key)\s+"[^"]*"', re.IGNORECASE)
_DES_KEY_RE = re.compile(r'(des-key)\s+"[^"]*"', re.IGNORECASE)
_AES_KEY_RE = re.compile(r'(aes-key)\s+"[^"]*"', re.IGNORECASE)
_PASSWORD_RE = re.compile(r'(password)\s+"[^"]*"', re.IGNORECASE)
# SNMP community lines: community "<name>" [hash|hash2] "<hash-value>" ...
# Redact both the community name and its hash value.
_COMMUNITY_RE = re.compile(r'(community)\s+"[^"]*"', re.IGNORECASE)
_HASH2_RE = re.compile(r'(hash2?)\s+"[^"]*"', re.IGNORECASE)


def _sanitize_config(text: str) -> str:
    # SR-OS config stores secrets inside double quotes; preserve the enclosing
    # quotes so the redacted output remains syntactically valid SR-OS config.
    text = _AUTH_KEY_RE.sub(r'\1 "<redacted>"', text)
    text = _HMAC_MD5_RE.sub(r'\1 "<redacted>"', text)
    text = _DES_KEY_RE.sub(r'\1 "<redacted>"', text)
    text = _AES_KEY_RE.sub(r'\1 "<redacted>"', text)
    text = _PASSWORD_RE.sub(r'\1 "<redacted>"', text)
    text = _COMMUNITY_RE.sub(r'\1 "<redacted>"', text)
    text = _HASH2_RE.sub(r'\1 "<redacted>"', text)
    return text


# ---------------------------------------------------------------------------
# Uptime parsing
# ---------------------------------------------------------------------------

_UPTIME_RE = re.compile(r"(\d+)\s+days?,\s+(\d+):(\d+):(\d+)", re.IGNORECASE)


def _parse_uptime(uptime_str: str) -> float:
    """Convert SR-OS uptime 'N days, H:MM:SS.ms' to total seconds."""
    m = _UPTIME_RE.search(uptime_str)
    if not m:
        return 0.0
    days, hours, minutes, secs = (
        int(m.group(1)),
        int(m.group(2)),
        int(m.group(3)),
        int(m.group(4)),
    )
    return float(days * 86400 + hours * 3600 + minutes * 60 + secs)


# ---------------------------------------------------------------------------
# Per-port hardware MAC parser — ``show port detail`` output
# ---------------------------------------------------------------------------

# SR-OS prints one block per port under `show port detail`, separated by
# `=====...` banner lines. Within each block:
#
#     Classic CLI (older releases):
#         Interface          : 1/1/1
#         ...
#         Hardware Mac       : 90:ec:00:00:00:00
#
#     MD-CLI (SR-OS 19+):
#         Interface         : 1/1/c2/1
#         ...
#         Hardware Address  : 90:ec:00:00:00:00
#
# The Hardware row reports the burned-in MAC; the Configured row above it
# is the operator-overridden MAC. NetBox interface MAC matches the burned-in
# MAC by convention.
#
# The MAC capture group accepts colon-, dot-, or dash-separated forms and a
# wider length range so `napalm.base.helpers.mac()` (not the regex) does the
# validation. Length 12-17 chars covers `aabbccddeeff`, `aabb.ccdd.eeff`,
# `aa-bb-cc-dd-ee-ff`, and non-padded variants like `aa:bb:cc:dd:ee:1` that
# napalm normalises.
_PORT_INTERFACE_RE = re.compile(
    r"^\s*Interface\s*:\s*(\S+)", re.MULTILINE,
)
_PORT_HW_MAC_RE = re.compile(
    r"^\s*Hardware\s+(?:Mac|Address)\s*:\s*([0-9a-fA-F:.\-]{12,17})\s*$",
    re.MULTILINE,
)


def _parse_port_hw_mac_addresses(text: str) -> dict[str, str]:
    """
    Return ``{port_id: normalized_mac}`` parsed from ``show port detail``.

    The command emits one block per port. We split on the SR-OS banner
    (a run of `=` characters) and look for an ``Interface`` line + a
    ``Hardware Mac`` line within the same block. Blocks without both
    (e.g. summary banner, totals footer) are silently skipped — the
    caller treats a missing key as ``"" `` (no MAC).
    """
    result: dict[str, str] = {}
    if not text:
        return result
    # SR-OS uses ``=`` banners between port blocks; split on any run of one
    # or more ``=`` characters on a line by themselves.
    for block in re.split(r"^=+\s*$", text, flags=re.MULTILINE):
        iface_m = _PORT_INTERFACE_RE.search(block)
        mac_m = _PORT_HW_MAC_RE.search(block)
        if not iface_m or not mac_m:
            continue
        port_id, mac_raw = iface_m.group(1), mac_m.group(1)
        try:
            result[port_id] = normalize_mac(mac_raw)
        except Exception:
            # napalm normalize_mac rejected the value — log and skip rather
            # than emit a malformed MAC string that downstream NetBox matching
            # would silently treat as a distinct interface.
            logger.warning(
                "nokia_sros_ssh: normalize_mac rejected %r for port %s — emitting empty MAC",
                mac_raw, port_id,
            )
    return result


# ---------------------------------------------------------------------------
# get_modules — module / module bay discovery via SSH CLI
# ---------------------------------------------------------------------------

# SR-OS CLI uses === separator lines between blocks. Field rows are
# "<label> <whitespace> : <value>". Parsers split on the separator first,
# then regex-extract labeled fields per block.

_NOKIA_SROS_SEP_RE = re.compile(r"^=+\s*$", re.MULTILINE)
_NOKIA_SROS_FIELD_RE = re.compile(
    r"^\s*(?P<label>[A-Za-z][\w \-/.()]*?)\s*:\s*(?P<value>.+?)\s*$",
    re.MULTILINE,
)
# Card / MDA detail headers vary across SR-OS releases:
#   classic CLI: "Card 1" / "MDA 1/1"           (no "Detail" word)
#   classic CLI: "Card 1 Detail" / "MDA 1/1 Detail"
#   MD-CLI:      "Card 1 detail" / "MDA 1/1 detail"
# The `Detail` keyword is optional; matching uses re.IGNORECASE so case
# variants are covered. The slot pattern is restricted to a single letter
# optionally followed by digits, OR all digits, so summary headers like
# "Card Summary" are NOT mis-matched as slot="Summary".
_NOKIA_SROS_CARD_HDR_RE = re.compile(
    r"^Card\s+(?P<slot>[A-Za-z]\d*|\d+)(?:\s+Detail)?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_NOKIA_SROS_MDA_HDR_RE = re.compile(
    r"^MDA\s+(?P<slot>\d+)/(?P<mda>\d+)(?:\s+Detail)?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
# Per-SFM detail block headers. Real SR-OS labels these blocks `Fabric <N>`
# (per Nokia command reference for `show sfm <id> detail`); some test
# fixtures and older releases use `SFM <N>`. Accept both keywords.
_NOKIA_SROS_SFM_HDR_RE = re.compile(
    r"^(?:SFM|Fabric)\s+(?P<slot>\d+)(?:\s+Detail)?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
# `show card` summary-table rows. Real SR-OS variants:
#   - Two-type:    "1   iom4-e            iom4-e            up   up"
#   - Single-type: "1   iom5-e:he1200g+                     up   up"
#       (Equipped Type column is blank when it matches Provisioned Type)
#   - CPM oper-state suffix: "A   cpm5                      up   up/active"
# The equipped-type group is optional and uses a negative lookahead so
# `up` / `down` cannot be captured as the equipped type. State tokens
# accept an optional `/<suffix>` (active / standby / etc.).
_NOKIA_SROS_CARD_SUMMARY_RE = re.compile(
    r"^(?P<slot>[A-Za-z]\d*|\d+)\s+"
    r"(?P<prov>\S+)"
    r"(?:\s+(?P<equipped>(?!up\b|down\b)\S+))?"
    r"\s+(?:up|down)(?:/\S+)?"
    r"\s+(?:up|down)(?:/\S+)?",
    re.MULTILINE | re.IGNORECASE,
)
# Port id forms emitted by SR-OS `show port`:
#   classic 3-segment "1/1/1"           — slot/mda/port
#   FP4 connector-cage "1/1/c2/1"       — slot/mda/c<N>/port (SR-7s IMM)
#   breakout sub-port "1/1/1[1]" or "1/1/c2/1[1]" — QSFP/QSFP28 broken out
# The lookahead anchor allows the port id to be the last token on a line.
_NOKIA_SROS_PORT_ID_RE = r"\d+/\d+/(?:c\d+/)?\d+(?:\[\d+\])?"
_NOKIA_SROS_PORT_HDR_RE = re.compile(
    rf"Port\s+(?P<port>{_NOKIA_SROS_PORT_ID_RE})", re.IGNORECASE,
)
_NOKIA_SROS_PORT_LIST_RE = re.compile(
    rf"^\s*(?P<port>{_NOKIA_SROS_PORT_ID_RE})(?=\s|$)", re.MULTILINE,
)


def classify_module_type_nokia_sros_ssh(equipped_type: str) -> str:
    """Same classifier as the NETCONF driver (Approach A duplication)."""
    et = (equipped_type or "").strip().lower()
    if et.startswith(("iom", "imm", "xcm")):
        return "linecard"
    if et.startswith("cpm"):
        return "supervisor"
    if et.startswith("sfm"):
        return "linecard"
    return "other"


def _nokia_sros_ssh_split_blocks(text: str) -> list[str]:
    """Split CLI output on === separator lines into per-block sections."""
    return [b for b in _NOKIA_SROS_SEP_RE.split(text or "") if b.strip()]


def _nokia_sros_ssh_extract_fields(block: str) -> dict[str, str]:
    # SR-OS prints labels in mixed case across releases — classic CLI uses
    # title-case ("Card Type"), MD-CLI and SR-OS 19R8+ use sentence-case
    # ("Card type"). Store lower-cased keys so lookups can normalise too.
    """Extract 'Label : Value' rows. Keys are lower-cased for case-insensitive lookup."""
    out: dict[str, str] = {}
    for m in _NOKIA_SROS_FIELD_RE.finditer(block or ""):
        out[m.group("label").strip().lower()] = m.group("value").strip()
    return out


def _nokia_sros_ssh_parse_card_summary(text: str) -> dict[str, str]:
    """
    Parse the `Card Summary` table → slot -> equipped_type.

    Real SR-OS `show card detail` includes a top-level Card Summary block
    whose rows are the source of truth for the equipped_type — per-card
    detail blocks may not repeat the type field.
    """
    summary: dict[str, str] = {}
    for m in _NOKIA_SROS_CARD_SUMMARY_RE.finditer(text or ""):
        # When `Equipped Type` is blank (same as `Provisioned Type`), the
        # capture group is None; fall back to the provisioned-type token.
        summary[m.group("slot")] = m.group("equipped") or m.group("prov")
    return summary


def _nokia_sros_ssh_parse_cards(text: str) -> list[dict]:
    """
    Parse `show card detail`: cross-reference summary table + per-card detail.

    Real SR-OS output places `Equipped Type` in the summary table only;
    the per-card detail block exposes Part / Serial under a `Hardware Data`
    subsection. We merge the two sources, falling back to whichever has
    the field. Card headers in the detail blocks read `Card N` (with the
    `Detail` word optional and case-insensitive).
    """
    summary_types = _nokia_sros_ssh_parse_card_summary(text)
    rows: list[dict] = []
    pending_slot: str | None = None
    for block in _nokia_sros_ssh_split_blocks(text):
        hdr = _NOKIA_SROS_CARD_HDR_RE.search(block)
        if hdr is not None:
            if pending_slot is not None:
                logger.warning(
                    "nokia_sros_ssh: card %s header had no field block — dropping",
                    pending_slot,
                )
            pending_slot = hdr.group("slot")
            continue
        if pending_slot is None:
            continue
        fields = _nokia_sros_ssh_extract_fields(block)
        # Equipped type may live in the detail block (`Card Type` /
        # `Equipped Type`) or only in the summary table. Detail wins
        # when present, summary is the fallback.
        equipped = (
            fields.get("card type")
            or fields.get("equipped type")
            or summary_types.get(pending_slot, "")
        )
        rows.append({
            "slot": pending_slot,
            "equipped_type": equipped,
            "pid": fields.get("part number", ""),
            "sn": fields.get("serial number", ""),
        })
        pending_slot = None
    return rows


def _nokia_sros_ssh_parse_mdas(text: str) -> list[dict]:
    """Parse `show mda detail`. Same header/fields-across-blocks pattern as cards."""
    rows: list[dict] = []
    pending: tuple[str, str] | None = None
    for block in _nokia_sros_ssh_split_blocks(text):
        hdr = _NOKIA_SROS_MDA_HDR_RE.search(block)
        if hdr is not None:
            if pending is not None:
                logger.warning(
                    "nokia_sros_ssh: mda %s/%s header had no field block — dropping",
                    pending[0], pending[1],
                )
            pending = (hdr.group("slot"), hdr.group("mda"))
            continue
        if pending is None:
            continue
        fields = _nokia_sros_ssh_extract_fields(block)
        parent_slot, mda_slot = pending
        rows.append({
            "parent_slot": parent_slot,
            "mda_slot": mda_slot,
            "equipped_type": fields.get("mda type", ""),
            "pid": fields.get("part number", ""),
            "sn": fields.get("serial number", ""),
        })
        pending = None
    return rows


def _nokia_sros_ssh_parse_port_transceiver(text: str) -> dict | None:
    """
    Parse one `show port X/Y/Z detail`. Header/fields straddle a `===` separator.

    Returns a row dict with port_id always populated when the Port header is
    found; model / sn are empty when the optic is absent or omits those
    fields (copper port, empty cage, etc.). Returns None only when no
    `Port X/Y/Z` header is parseable from the output at all.
    """
    pending_port: str | None = None
    for block in _nokia_sros_ssh_split_blocks(text):
        hdr = _NOKIA_SROS_PORT_HDR_RE.search(block)
        if hdr is not None:
            pending_port = hdr.group("port")
            continue
        if pending_port is None:
            continue
        fields = _nokia_sros_ssh_extract_fields(block)
        # Real SR-OS Transceiver Data labels the MSA PID as "Model Number"
        # (per Nokia command reference); some older outputs and the test
        # fixtures use the shorter "Model" label. Accept both.
        model = fields.get("model number") or fields.get("model") or ""
        sn = fields.get("serial number", "")
        return {
            "port_id": pending_port,
            "model": model,
            "sn": sn,
            "pid": fields.get("part number", ""),
        }
    return None


def _nokia_sros_ssh_slot_sort_key(slot: str) -> tuple[int, int | str]:
    """Stable order: letter slots (CPM-A/B) first, then numeric (Approach A duplicate)."""
    if slot.isalpha():
        return (0, slot)
    try:
        return (1, int(slot))
    except ValueError:
        return (2, slot)


def _nokia_sros_ssh_build_card_bays(
    card_rows: list[dict],
) -> tuple[list[_ModuleBay], dict[str, _ModuleBay]]:
    """Build top-level card bays + a slot -> bay map. Sorted for stable output."""
    bays: list[_ModuleBay] = []
    bays_by_slot: dict[str, _ModuleBay] = {}
    for row in card_rows:
        slot = row.get("slot") or ""
        pid = row.get("pid") or ""
        sn = row.get("sn") or ""
        et = row.get("equipped_type") or ""
        if not (slot and pid and sn):
            continue
        mtype = classify_module_type_nokia_sros_ssh(et)
        if mtype == "other":
            continue
        bay = _ModuleBay(
            name=slot, position=slot,
            module=_ModuleEntry(model=pid, serial=sn, type=mtype, description=et),
        )
        bays.append(bay)
        bays_by_slot[slot] = bay
    bays.sort(key=lambda b: _nokia_sros_ssh_slot_sort_key(b.name))
    return bays, bays_by_slot


def _nokia_sros_ssh_attach_mdas(
    mda_rows: list[dict],
    bays_by_slot: dict[str, _ModuleBay],
) -> dict[str, _ModuleBay]:
    """Nest MDA sub-bays under their parent card. Returns mda-path -> bay map."""
    mda_bays_by_path: dict[str, _ModuleBay] = {}
    for row in mda_rows:
        parent_slot = row.get("parent_slot") or ""
        mda_slot = row.get("mda_slot") or ""
        pid = row.get("pid") or ""
        sn = row.get("sn") or ""
        et = row.get("equipped_type") or ""
        if not (parent_slot and mda_slot and pid and sn):
            continue
        parent_bay = bays_by_slot.get(parent_slot)
        if parent_bay is None or parent_bay.module is None:
            continue
        mda_bay = _ModuleBay(
            name=f"{parent_slot}/{mda_slot}",
            position=f"{parent_slot}/{mda_slot}",
            module=_ModuleEntry(model=pid, serial=sn, type="linecard", description=et),
        )
        parent_bay.module.sub_bays.append(mda_bay)
        mda_bays_by_path[f"{parent_slot}/{mda_slot}"] = mda_bay
    return mda_bays_by_path


def _nokia_sros_ssh_attach_transceivers(
    transceiver_rows: list[dict],
    mda_bays_by_path: dict[str, _ModuleBay],
) -> dict[str, list[str]]:
    """Route every port to its parent bays; emit transceiver sub-bay only when populated."""
    interfaces_by_bay: dict[str, list[str]] = {}
    for row in transceiver_rows:
        port_id = row.get("port_id") or ""
        if not port_id:
            continue
        parts = port_id.split("/")
        if len(parts) < 3:
            continue
        mda_path = f"{parts[0]}/{parts[1]}"
        mda_bay = mda_bays_by_path.get(mda_path)
        if mda_bay is None or mda_bay.module is None:
            continue
        # Routing layers are emitted for EVERY discovered port (copper,
        # empty cage, optic-without-data, …) — get_interfaces() emits the
        # physical port regardless of optic, so it needs a module to land
        # on in both linecards and full modes.
        card_slot = parts[0]
        interfaces_by_bay.setdefault(card_slot, []).append(port_id)
        interfaces_by_bay.setdefault(mda_path, []).append(port_id)
        model = row.get("model") or ""
        sn = row.get("sn") or ""
        if model and sn:
            mda_bay.module.sub_bays.append(_ModuleBay(
                name=port_id, position=port_id,
                module=_ModuleEntry(model=model, serial=sn, type="transceiver", description=""),
            ))
            interfaces_by_bay[port_id] = [port_id]
    return interfaces_by_bay


def _nokia_sros_ssh_assemble(
    card_rows: list[dict],
    mda_rows: list[dict],
    transceiver_rows: list[dict],
) -> dict | None:
    """Build the canonical envelope from parsed CLI rows."""
    bays, bays_by_slot = _nokia_sros_ssh_build_card_bays(card_rows)
    if not bays:
        return None
    mda_bays_by_path = _nokia_sros_ssh_attach_mdas(mda_rows, bays_by_slot)
    interfaces_by_bay = _nokia_sros_ssh_attach_transceivers(
        transceiver_rows, mda_bays_by_path,
    )
    return _modules_to_payload({
        None: _MemberModules(bays=bays, interfaces_by_bay=interfaces_by_bay),
    })


def _nokia_sros_ssh_parse_port_list(text: str) -> list[str]:
    """Extract port ids (slot/mda/port) from `show port` summary output."""
    return _NOKIA_SROS_PORT_LIST_RE.findall(text or "")


def _nokia_sros_ssh_parse_sfms(text: str) -> list[dict]:
    """Parse `show sfm detail`. Bay names use the `SFM <N>` prefix to avoid card-slot collision."""
    summary_types: dict[str, str] = {}
    for m in _NOKIA_SROS_CARD_SUMMARY_RE.finditer(text or ""):
        summary_types[m.group("slot")] = m.group("equipped") or m.group("prov")
    rows: list[dict] = []
    pending_slot: str | None = None
    for block in _nokia_sros_ssh_split_blocks(text):
        hdr = _NOKIA_SROS_SFM_HDR_RE.search(block)
        if hdr is not None:
            if pending_slot is not None:
                logger.warning(
                    "nokia_sros_ssh: sfm %s header had no field block — dropping",
                    pending_slot,
                )
            pending_slot = hdr.group("slot")
            continue
        if pending_slot is None:
            continue
        fields = _nokia_sros_ssh_extract_fields(block)
        equipped = (
            fields.get("sfm type")
            or fields.get("equipped type")
            or summary_types.get(pending_slot, "")
        )
        rows.append({
            "slot": f"SFM {pending_slot}",
            "equipped_type": equipped,
            "pid": fields.get("part number", ""),
            "sn": fields.get("serial number", ""),
        })
        pending_slot = None
    return rows


def _nokia_sros_ssh_fetch_and_parse_mdas(driver, card_rows: list[dict]) -> list[dict]:
    """
    Issue `show mda <slot> detail` per IOM/IMM/XCM slot and merge parsed rows.

    Nokia SR-OS rejects `show mda detail` without a slot argument; the
    documented detail syntax is `show mda <slot>[/<mda>] detail`. We
    iterate cards whose equipped_type identifies them as MDA-carrying
    linecards (IOM / IMM / XCM). CPMs (cpm*) and SFMs (sfm*) have no
    MDAs — `show mda` on those slots returns an error and would generate
    log noise / wasted round-trips.
    """
    all_rows: list[dict] = []
    for row in card_rows:
        et = (row.get("equipped_type") or "").strip().lower()
        if not et.startswith(("iom", "imm", "xcm")):
            continue
        slot = row.get("slot") or ""
        if not slot:
            continue
        try:
            raw = driver.device.send_command(f"show mda {slot} detail")
        except Exception as e:
            logger.warning(
                "nokia_sros_ssh.get_modules: show mda %s detail failed: %s", slot, e,
            )
            continue
        if not raw or not raw.strip() or "MINOR:" in raw or "Error:" in raw:
            continue
        all_rows.extend(_nokia_sros_ssh_parse_mdas(raw))
    return all_rows


def _nokia_sros_ssh_fetch_port_ids(driver, mda_count: int) -> list[str]:
    """Issue `show port`, parse port-ids. Warn if MDAs exist but no ports parse."""
    try:
        port_list_raw = driver.device.send_command("show port")
    except Exception as e:
        logger.warning("nokia_sros_ssh.get_modules: show port failed: %s", e)
        return []
    port_ids = _nokia_sros_ssh_parse_port_list(port_list_raw or "")
    if not port_ids:
        # Operators denying `show port` via AAA while permitting individual
        # `show port X/Y/Z detail` will see a silently empty transceiver pass
        # otherwise. Surface the gap so it's diagnosable from logs.
        logger.warning(
            "nokia_sros_ssh.get_modules: no ports parsed from `show port` despite "
            "%d MDA(s) — transceiver pass skipped",
            mda_count,
        )
    return port_ids


def _nokia_sros_ssh_collect_transceivers(driver, mda_rows: list[dict]) -> list[dict]:
    """Issue `show port` once + a `show port X/Y/Z detail` per known MDA port."""
    if not mda_rows:
        return []
    port_ids = _nokia_sros_ssh_fetch_port_ids(driver, len(mda_rows))
    if not port_ids:
        return []
    known_mda_paths = {
        f"{row.get('parent_slot')}/{row.get('mda_slot')}"
        for row in mda_rows
        if row.get("parent_slot") and row.get("mda_slot")
    }
    transceiver_rows: list[dict] = []
    for port_id in port_ids:
        parts = port_id.split("/")
        if len(parts) < 3:
            continue
        if f"{parts[0]}/{parts[1]}" not in known_mda_paths:
            continue
        # Default routing-only row — emitted even when `show port X detail`
        # is missing / errors out / has no Transceiver Data block, so the
        # port still gets a parent-bay entry in interfaces_by_bay.
        row: dict[str, str] = {"port_id": port_id, "model": "", "sn": ""}
        try:
            raw = driver.device.send_command(f"show port {port_id} detail")
        except Exception as e:
            logger.warning(
                "nokia_sros_ssh.get_modules: show port %s detail failed: %s",
                port_id, e,
            )
            transceiver_rows.append(row)
            continue
        if raw and raw.strip() and "MINOR:" not in raw and "Error:" not in raw:
            parsed = _nokia_sros_ssh_parse_port_transceiver(raw)
            if parsed is not None:
                row = parsed
        transceiver_rows.append(row)
    return transceiver_rows


def _nokia_sros_ssh_get_modules_impl(driver) -> dict | None:
    """
    Module discovery for Nokia SR-OS via SSH CLI.

    Command flow:
      1. ``show chassis detail``                 session-prime, result unused
      2. ``show card detail``                    cards + summary table
      3. ``show sfm detail``                     fabric modules (separate path)
      4. ``show mda <slot> detail`` per linecard CPMs and SFMs are skipped
      5. ``show port``                           enumerates every port id
      6. ``show port <port-id> detail`` only for ports under known MDAs

    Bounded at ``linecard_count + port_count + 4`` commands. FakeCLIDevice
    returns "" for missing fixture files, so dry-runs against test data
    incur no additional cost.
    """
    # `show chassis detail` doesn't feed the envelope (cards / MDAs carry all
    # the data we need) but issuing it once primes the CLI session and
    # surfaces auth / connectivity failures early.
    try:
        driver.device.send_command("show chassis detail")
    except Exception as e:
        logger.warning("nokia_sros_ssh.get_modules: show chassis failed: %s", e)
    try:
        card_raw = driver.device.send_command("show card detail")
    except Exception as e:
        logger.warning("nokia_sros_ssh.get_modules: show card failed: %s", e)
        return None
    card_rows = _nokia_sros_ssh_parse_cards(card_raw or "")
    # SFMs are a separate Nokia hardware concept — `show card` doesn't list
    # them. Issue `show sfm detail` (Nokia command-reference syntax) and
    # append the SFM rows as additional top-level bays.
    try:
        sfm_raw = driver.device.send_command("show sfm detail")
    except Exception as e:
        logger.warning("nokia_sros_ssh.get_modules: show sfm detail failed: %s", e)
        sfm_raw = ""
    if sfm_raw and sfm_raw.strip() and "MINOR:" not in sfm_raw and "Error:" not in sfm_raw:
        card_rows.extend(_nokia_sros_ssh_parse_sfms(sfm_raw))
    mda_rows = _nokia_sros_ssh_fetch_and_parse_mdas(driver, card_rows)
    transceiver_rows = _nokia_sros_ssh_collect_transceivers(driver, mda_rows)

    return _nokia_sros_ssh_assemble(card_rows, mda_rows, transceiver_rows)


# "show service service-using vprn" rows: id, type, Adm, Opr, customer id,
# optional service name. Parsed driver-locally — the ntc-template's row rule
# requires a non-empty Service Name token, and SR OS service names are
# optional, so a single unnamed VPRN error-exits the template and would
# silently drop every VPRN on the box.
_SROS_SSH_VPRN_ROW_RE = re.compile(
    r"^\s*(?P<sid>\d+)\s+VPRN\s+\S+\s+\S+\s+\d+(?:\s+(?P<name>.*\S))?\s*$"
)


def _sros_ssh_parse_vprn_services(raw: str) -> list[tuple[str, str]]:
    """Return (service_id, service_name-or-"") rows from service-using output."""
    services: list[tuple[str, str]] = []
    for line in (raw or "").splitlines():
        m = _SROS_SSH_VPRN_ROW_RE.match(line)
        if m:
            services.append((m.group("sid"), (m.group("name") or "").strip()))
    return services


def _sros_ssh_vprn_member_interfaces(device, sid: str) -> dict:
    """Return {interface_name: {}} for one VPRN from "show service id <id> interface"."""
    interfaces: dict = {}
    ifc_raw = device.send_command(f"show service id {sid} interface")
    if not (ifc_raw and ifc_raw.strip()):
        return interfaces
    try:
        ifc_rows = parse_output(
            platform="alcatel_sros",
            command=f"show service id {sid} interface",
            data=ifc_raw,
        )
    except Exception:
        logger.warning(
            "SR OS show service id %s interface parse failed", sid, exc_info=True
        )
        return interfaces
    for ifc in ifc_rows:
        ifname = (ifc.get("interface_name") or "").strip()
        if ifname:
            interfaces[ifname] = {}
    return interfaces


class SROSSSHDriver(_napalm_base.NetworkDriver):
    """Nokia/Alcatel SR-OS NAPALM driver using SSH CLI + ntc-templates (read-only subset for device-discovery)."""

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
        # SR-OS users log in with privileged access; no enable command needed.
        self.force_no_enable = True

    def open(self):
        """Open an SSH connection to the device via Netmiko."""
        self.device = self._netmiko_open(
            "nokia_sros", netmiko_optional_args=self.netmiko_optional_args
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
        except (EOFError, OSError, AttributeError):  # socket.error is OSError in Python 3.3+
            return {"is_alive": False}

    # -----------------------------------------------------------------------
    # NAPALM getters
    # -----------------------------------------------------------------------

    def get_facts(self) -> dict:
        """Return general device facts."""
        os_version = "Unknown"
        model = "Unknown"
        hostname = "Unknown"
        serial_number = "Unknown"
        uptime = 0.0

        # --- version / model ---
        ver_out = self.device.send_command("show version")
        m = re.search(r"System Version\s*:\s*(\S+)", ver_out)
        if m:
            os_version = m.group(1)
        m = re.search(r"System Type\s*:\s*(.+)", ver_out)
        if m:
            model = m.group(1).strip()

        # --- hostname / uptime / serial ---
        sysinfo_out = self.device.send_command("show system information")
        m = re.search(r"System Name\s*:\s*(\S+)", sysinfo_out)
        if m:
            hostname = m.group(1).strip()
        m = re.search(r"System Up Time\s*:\s*(.+)", sysinfo_out)
        if m:
            uptime = _parse_uptime(m.group(1))
        m = re.search(r"Chassis Serial #\s*:\s*(\S+)", sysinfo_out)
        if m:
            serial_number = m.group(1).strip()

        # --- interface list from show port ---
        port_out = self.device.send_command("show port")
        parsed_ports = parse_output(platform="alcatel_sros", command="show port", data=port_out)
        interface_list = [
            row["port_id"]
            for row in parsed_ports
            if row.get("port_id") and row.get("admin_state")
        ]

        return {
            "hostname": hostname,
            "vendor": "Nokia",
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

        Per-port MAC is sourced from ``show port detail`` (no port-id) —
        SR-OS emits one block per port in a single command, so the
        join cost is one extra round-trip regardless of port count.
        """
        port_out = self.device.send_command("show port")
        parsed = parse_output(platform="alcatel_sros", command="show port", data=port_out)

        mac_by_port = _parse_port_hw_mac_addresses(
            self.device.send_command("show port detail")
        )

        interfaces = {}
        for row in parsed:
            port_id = row.get("port_id", "")
            admin_state = row.get("admin_state", "")
            # Skip rows without a proper admin state (connector summary lines)
            if not port_id or not admin_state:
                continue

            port_state = row.get("port_state", "")
            cfg_mtu = row.get("cfg_mtu", "")
            try:
                mtu = int(cfg_mtu) if cfg_mtu else -1
            except ValueError:
                mtu = -1

            interfaces[port_id] = {
                "is_enabled": admin_state.lower() == "up",
                "is_up": port_state.lower() == "up",
                "description": "",
                "last_flapped": -1.0,
                "mtu": mtu,
                "speed": 0.0,
                "mac_address": mac_by_port.get(port_id, ""),
            }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface."""
        intf_out = self.device.send_command("show router interface")
        parsed = parse_output(
            platform="alcatel_sros", command="show router interface", data=intf_out
        )

        interfaces_ip: dict = {}
        for row in parsed:
            intf = row.get("interface", "")
            if not intf:
                continue

            ip_addresses = row.get("ip_address", [])
            if isinstance(ip_addresses, str):
                ip_addresses = [ip_addresses]

            for cidr in ip_addresses:
                if not cidr or "/" not in cidr:
                    continue
                try:
                    addr, prefix_str = cidr.split("/", 1)
                    prefix_length = int(prefix_str)
                except (ValueError, AttributeError):
                    continue

                family = "ipv6" if ":" in addr else "ipv4"
                interfaces_ip.setdefault(intf, {}).setdefault(family, {})[addr] = {
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

        if retrieve in ("all", "running"):
            config["running"] = self.device.send_command("admin display-config")

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Nokia SR-OS uses a service-based architecture — no traditional VLAN table."""
        return {}

    def get_modules(self) -> dict | None:
        """Return per-chassis module / module bay inventory or None."""
        return _nokia_sros_ssh_get_modules_impl(self)

    def get_network_instances(self, name: str = "") -> dict:
        """
        Return network instances (VPRN services as VRFs), NAPALM OC shape.

        ``show service service-using vprn`` enumerates the VPRNs, parsed
        driver-locally — SR OS service names are optional and the
        ntc-template error-exits on the unnamed form. One ``show service
        id <id> interface`` per service lists its member interfaces,
        keyed ``<service>/<interface>`` like the NETCONF sibling: SR OS
        interface names are scoped per routing instance, so plain names
        could false-join a VPRN interface onto a same-named Base router
        interface's IPs. (This driver's get_interfaces_ip() currently
        covers only the Base router, so VPRN memberships don't attach to
        IPs yet — the prefix keeps that future extension collision-free.)
        The VRF name prefers the configured service name, falling back
        to the numeric service id. Route distinguishers are not
        collected in this first pass — on the classic CLI the RD lives
        in per-service BGP config, not the templated service views. The
        Base router is the global routing table, seeded as the
        DEFAULT_INSTANCE.
        """
        instances: dict = {
            "Base": {
                "name": "Base",
                "type": "DEFAULT_INSTANCE",
                "state": {"route_distinguisher": ""},
                "interfaces": {"interface": {}},
            },
        }
        svc_raw = self.device.send_command("show service service-using vprn")
        for sid, svc_name in _sros_ssh_parse_vprn_services(svc_raw or ""):
            vrf_name = svc_name or sid
            # Never let a service overwrite the seeded DEFAULT_INSTANCE.
            if vrf_name == "Base":
                continue
            members = _sros_ssh_vprn_member_interfaces(self.device, sid)
            instances[vrf_name] = {
                "name": vrf_name,
                "type": "L3VRF",
                "state": {"route_distinguisher": ""},
                "interfaces": {
                    "interface": {f"{vrf_name}/{m}": {} for m in members},
                },
            }
        if name:
            return {name: instances[name]} if name in instances else {}
        return instances
