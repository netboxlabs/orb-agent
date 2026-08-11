# Copyright 2026 NetBox Labs Inc
"""
Cisco NX-OS NAPALM driver subclass adding ``get_interfaces_vlans()`` and ``get_modules()``.

Fetches structured switchport data via NX-API (JSON) and maps each row
through the shared NX-OS field-normalizer + generic classifier.
``get_modules()`` adds Module / module-bay discovery for Nexus modular chassis via NX-API.
"""

import logging
import re

from napalm.nxos.nxos import NXOSDriver as NapalmNXOSDriver

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
    is_optic_pid,
    orphan_optic_bay,
)
from custom_napalm._modules import (
    to_payload as _modules_to_payload,
)
from custom_napalm._vlan import SwitchportInfo, classify_switchport, parse_vlan_range_string

logger = logging.getLogger(__name__)


def _flatten_nxos_rows(payload: dict) -> list[dict]:
    """
    Flatten NX-API ``show interface switchport`` JSON into a list of row dicts.

    NX-API wraps rows in ``TABLE_interface > ROW_interface``; ``ROW_interface``
    is a dict for a single port and a list for multiple. Normalize to list.
    """
    table = (payload or {}).get("TABLE_interface") or {}
    row = table.get("ROW_interface")
    if row is None:
        return []
    if isinstance(row, list):
        return row
    return [row]


# ---- module discovery (NX-API JSON path) ---------------------------------

_NXOS_PORT_RE = re.compile(r"^Ethernet(\d+)(?:/\d+)+$", re.IGNORECASE)
# K is optional: Nexus 7700 sups are N77-SUP2E/SUP3E (no K), while N9K-/N7K- have it.
_NXOS_SUP_PID_RE = re.compile(r"^N\d+K?[-A-Z0-9]*-SUP", re.IGNORECASE)
_NXOS_SLOT_RE = re.compile(r"^Slot\s+(\d+)$", re.IGNORECASE)
# FEX ids start at 100; every Nexus chassis slot (linecard, supervisor, or
# fabric/xbar) stays well below that. ``_NXOS_PORT_RE`` matches both the
# Fabric Extender's three- and four-tuple port forms (e.g. Ethernet101/1/1,
# Ethernet101/1/0/1) and captures the FEX id as the "slot" — this threshold
# is what tells those apart from a real chassis slot.
_NXOS_FEX_MIN_ID = 100


def _nxos_is_fex_slot(slot: str) -> bool:
    """Return True when a captured port "slot" is actually a FEX id (>= 100)."""
    return slot.isdigit() and int(slot) >= _NXOS_FEX_MIN_ID


def classify_module_type_nexus(pid: str, name: str) -> str:
    """
    Map a Cisco NX-OS PID to a ModuleType.

    Supervisors match ``NxK-...-SUP``-style PIDs (N9K-SUP-A, N9K-C9504-SUP, etc).
    Fabric modules (FM) map to linecard for v1 (NetBox flat-slot model).
    PSU / fan classified but never emitted.
    """
    if not pid:
        return "linecard"
    if is_optic_pid(pid):
        return "transceiver"
    upper = pid.strip().upper()
    if _NXOS_SUP_PID_RE.match(upper):
        return "supervisor"
    if "FM-" in upper or upper.endswith("-FM"):
        return "linecard"  # fabric reported as linecard
    if upper.startswith("PWR-") or upper.startswith("PSU-"):
        return "psu"
    if upper.startswith("FAN-") or upper == "FAN":
        return "fan"
    return "linecard"


def _nxos_unquote(value: object) -> str:
    """
    Strip whitespace then surrounding double-quotes from an NX-API field.

    Cisco NX-API `show inventory` returns name/desc values with embedded
    literal quotes (e.g. the JSON value is `"Slot 1"` including the quote
    characters). Whitespace-only stripping leaves the quotes, so slot /
    optic regexes never match. Strip both.
    """
    s = str(value or "").strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1].strip()
    return s


def _flatten_table(payload: dict | None, table_key: str, row_key: str) -> list[dict]:
    """Normalize NX-API TABLE_x / ROW_x envelopes (single-row scalar vs list)."""
    if not payload or table_key not in payload:
        return []
    table = payload[table_key]
    rows = table.get(row_key) if isinstance(table, dict) else None
    if rows is None:
        return []
    if isinstance(rows, dict):
        return [rows]
    if isinstance(rows, list):
        return [r for r in rows if isinstance(r, dict)]
    return []


def _nxos_parse_inventory(
    inv_rows: list[dict],
) -> tuple[dict[str, dict[str, str]], dict[str, _ModuleEntry]]:
    """
    Split show-inventory rows into slot PID/serial lookup + transceiver map.

    ``Slot N`` rows feed the chassis-slot lookup (PID + serial in vendor
    format); ``Ethernet<slot>/<port>`` optic rows become transceiver entries
    keyed by ifname.
    """
    inv_by_slot: dict[str, dict[str, str]] = {}
    transceivers_by_ifname: dict[str, _ModuleEntry] = {}
    for row in inv_rows:
        name = _nxos_unquote(row.get("name"))
        pid = _nxos_unquote(row.get("productid"))
        sn = _nxos_unquote(row.get("serialnum"))
        descr = _nxos_unquote(row.get("desc"))
        if not (pid and sn):
            continue
        slot_match = _NXOS_SLOT_RE.match(name)
        if slot_match:
            inv_by_slot[slot_match.group(1)] = {
                "pid": pid, "sn": sn, "descr": descr, "name": name,
            }
            continue
        if _NXOS_PORT_RE.match(name) and is_optic_pid(pid):
            transceivers_by_ifname[name] = _ModuleEntry(
                model=pid, serial=sn, type="transceiver", description=descr,
            )
    return inv_by_slot, transceivers_by_ifname


def _nxos_xbar_slots(xbar_rows: list[dict]) -> list[str]:
    """
    Extract fabric-module slot numbers from show-module's Xbar table.

    Fabric modules live in a SEPARATE Xbar section (TABLE_xbarinfo), not the
    main module table, so they're missed by a modinfo-only join. Their slot
    numbers re-appear in show inventory as ``Slot <N>`` (e.g. Slot 21/22 on a
    9508), letting the inventory lookup resolve PID + serial.
    """
    slots: list[str] = []
    for row in xbar_rows:
        slot = _nxos_unquote(row.get("xbarinf") or row.get("xbar"))
        if slot:
            slots.append(slot)
    return slots


def _nxos_build_slot_bays(
    sm_rows: list[dict], xbar_rows: list[dict],
    inv_by_slot: dict[str, dict[str, str]],
) -> dict[str, _ModuleBay]:
    """
    Join show-module slots with the inventory lookup into ModuleBays.

    Main-table (modinfo) slots feed linecards / supervisors; Xbar slots feed
    fabric modules (emitted as linecards). PSU / fan slots are classified then
    dropped — they're never emitted.
    """
    bays_by_slot: dict[str, _ModuleBay] = {}
    slots = [
        _nxos_unquote(row.get("modinf") or row.get("modules"))
        for row in sm_rows
    ]
    slots.extend(_nxos_xbar_slots(xbar_rows))
    for slot in slots:
        if not slot or slot not in inv_by_slot:
            continue
        inv = inv_by_slot[slot]
        mtype = classify_module_type_nexus(inv["pid"], inv["name"])
        if mtype in ("psu", "fan"):
            continue
        bays_by_slot[slot] = _ModuleBay(
            name=slot, position=slot,
            module=_ModuleEntry(
                model=inv["pid"], serial=inv["sn"],
                type=mtype, description=inv["descr"],
            ),
        )
    return bays_by_slot


def _nxos_attach_transceivers(
    bays_by_slot: dict[str, _ModuleBay],
    transceivers_by_ifname: dict[str, _ModuleEntry],
) -> dict[str, list[str]]:
    """
    Attach each optic as a sub_bay under its parent linecard slot, or as a device-rooted bay when there is no parent (fixed switch).

    ``interfaces_by_bay`` is keyed by the linecard SLOT NAME (which equals the
    bay name) so the translator can route ifnames into the matching bay.
    Mutates ``bays_by_slot`` in place — both the matched entries' parent
    ``module.sub_bays`` and, for orphans, ``bays_by_slot`` itself.

    A FEX-attached optic (slot id >= 100) never gets promoted here even when
    it has no parent bay on this device — it lives in the FEX, a separate
    device, not on the parent Nexus.
    """
    interfaces_by_bay: dict[str, list[str]] = {}
    for ifname, optic in transceivers_by_ifname.items():
        port_match = _NXOS_PORT_RE.match(ifname)
        if not port_match:
            continue
        slot = port_match.group(1)
        parent = bays_by_slot.get(slot)
        if parent is None or parent.module is None:
            if _nxos_is_fex_slot(slot):
                logger.debug(
                    "nxos.get_modules: skipping FEX-attached optic %s (fex %s has no bay on this device)",
                    ifname, slot,
                )
                continue
            # Fixed switch, or an optic on a slot with no linecard bay.
            bays_by_slot[ifname] = orphan_optic_bay(ifname, optic)
        else:
            parent.module.sub_bays.append(_ModuleBay(
                name=ifname, position=ifname, module=optic,
            ))
            interfaces_by_bay.setdefault(slot, []).append(ifname)
        # Self-route the optic under its own sub-bay name so the translator's
        # deepest-wins logic links the interface to the transceiver (not the
        # parent linecard) in full mode. Mirrors ios.py:_attach_transceivers.
        interfaces_by_bay[ifname] = [ifname]
    return interfaces_by_bay


def _nxos_get_modules_impl(driver) -> dict | None:
    """
    NX-API-based module discovery for Cisco Nexus modular chassis.

    Joins ``show module`` (authoritative slot view + occupancy) against
    ``show inventory`` (carries PID + serial in vendor format). The
    join key is the slot number.

    Uses ``driver.device.show(cmd, raw_text=False)`` — the same API the
    existing ``get_interfaces_vlans`` path uses (see ``_flatten_nxos_rows``
    callsite above). This returns the parsed JSON payload dict directly
    (NOT wrapped in a command-keyed envelope, so no extra ``[cmd]`` lookup).

    Fixed switches report a single show-module self-row and no populated
    slot bays; their optics are promoted to device-rooted bays instead of
    being dropped (see ``_nxos_attach_transceivers``). Returns None when:
      - The NX-API calls fail.
      - show module yields zero rows — unsupported, truncated, or
        otherwise unparseable text is not proof of a fixed switch, so
        module discovery is declined rather than promoting a partial
        inventory.
      - No supervisor / linecard slots survive classification AND no
        transceiver was recognized either.
    """
    try:
        sm_payload = driver.device.show("show module", raw_text=False) or {}
        inv_payload = driver.device.show("show inventory", raw_text=False) or {}
    except Exception as e:
        logger.warning("nxos.get_modules: NX-API call failed: %s", e)
        return None

    sm_rows = _flatten_table(sm_payload, "TABLE_modinfo", "ROW_modinfo")
    xbar_rows = _flatten_table(sm_payload, "TABLE_xbarinfo", "ROW_xbarinfo")
    inv_rows = _flatten_table(inv_payload, "TABLE_inv", "ROW_inv")

    # show inventory is the reliable source for PID + serial + description.
    inv_by_slot, transceivers_by_ifname = _nxos_parse_inventory(inv_rows)

    if not sm_rows:
        logger.warning("nxos.get_modules: show module returned no parseable rows")
        return None
    # Fixed switch heuristic: EXACTLY one show-module row is the chassis
    # acting as its own "slot 1", so no slot bays are built. Optics still
    # count — a fixed switch's ports carry them with no linecard above.
    if len(sm_rows) == 1:
        bays_by_slot = {}
    else:
        bays_by_slot = _nxos_build_slot_bays(sm_rows, xbar_rows, inv_by_slot)
    if not bays_by_slot and not transceivers_by_ifname:
        return None

    interfaces_by_bay = _nxos_attach_transceivers(bays_by_slot, transceivers_by_ifname)

    return _modules_to_payload({
        None: _MemberModules(
            bays=list(bays_by_slot.values()),
            interfaces_by_bay=interfaces_by_bay,
        ),
    })


def _maybe_int(value: object) -> int | None:
    """
    Coerce to int or None.

    Returns None for the NX-OS sentinels (``None``, empty string, ``"none"``
    / ``"None"`` / ``"NONE"``). Also rejects ``bool`` explicitly — ``bool``
    is a subclass of ``int`` in Python (``int(True) == 1``), so without the
    guard a buggy upstream parser passing a bool would slip past the
    classifier's bool-rejection in ``_vlan.coerce_vid``.
    """
    if isinstance(value, bool):
        return None
    if value in (None, "", "none", "None", "NONE"):
        return None
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _normalize_admin(value: str) -> str | None:
    """Normalize a raw admin-mode string to 'access', 'trunk', 'dynamic', or None."""
    raw = (value or "").lower()
    if "access" in raw:
        return "access"
    if "trunk" in raw:
        return "trunk"
    if "dynamic" in raw:
        return "dynamic"
    return None


def _normalize_oper(value: str) -> str | None:
    """Normalize a raw oper-mode string to 'access', 'trunk', 'routed', or None."""
    raw = (value or "").lower()
    if "access" in raw:
        return "access"
    if "trunk" in raw:
        return "trunk"
    if "routed" in raw:
        return "routed"
    return None


def _read_admin_mode(row: dict) -> str:
    """Return raw admin_mode string, falling back to ``mode`` (ntc-templates alias)."""
    return row.get("admin_mode") or row.get("mode") or ""


def _read_oper_mode(row: dict) -> str:
    """Return raw oper_mode string, falling back to ``mode`` (ntc-templates alias)."""
    return row.get("oper_mode") or row.get("mode") or ""


def _read_trunk_vlans(row: dict) -> str:
    """Return raw trunk_vlans, accepting NX-API key ``trunk_vlans`` or ntc alias ``trunking_vlans``."""
    return row.get("trunk_vlans") or row.get("trunking_vlans") or ""


def nxos_row_to_switchport_info(row: dict) -> SwitchportInfo:
    """
    Build a SwitchportInfo from a normalized NX-OS row dict.

    Accepts BOTH NX-API (JSON) and ntc-templates (CLI-parsed) shapes::

        NX-API:     {"interface", "switchport", "admin_mode", "oper_mode",
                     "access_vlan", "native_vlan", "voice_vlan", "trunk_vlans"}
        ntc:        {"interface", "switchport", "mode",
                     "access_vlan", "native_vlan", "voice_vlan", "trunking_vlans"}

    NX-API uses "Enabled"/"Disabled" for ``switchport``; ntc-templates may
    emit "Enabled"/"Disabled" or other casing. Both are tolerated.

    When ntc-templates rows lack a separate ``admin_mode``, the ``mode``
    field (operational) is used as both admin AND oper signals — which
    keeps DTP-fallback correctness on the rare NX-OS deployment that
    actually negotiates DTP, and is exactly equivalent to "admin = oper"
    on the common case where DTP is disabled.
    """
    if (row.get("switchport") or "").lower() == "disabled":
        return SwitchportInfo(
            enabled=False, admin_mode=None, oper_mode=None,
            access_vlan=None, native_vlan=None, allowed_vlans=None,
        )

    trunk_vlans_raw = _read_trunk_vlans(row)
    if trunk_vlans_raw:
        vids, is_wildcard = parse_vlan_range_string(trunk_vlans_raw)
        allowed: list[int] | str | None = "all" if is_wildcard else vids
    else:
        allowed = None

    admin = _normalize_admin(_read_admin_mode(row))
    oper = _normalize_oper(_read_oper_mode(row))

    # NX-OS SSH oper-down inference.
    #
    # ntc-templates' ``cisco_nxos_show_interface_switchport`` parser does NOT
    # capture the ``Administrative Mode`` line — only ``Operational Mode``.
    # Both ``_read_admin_mode`` and ``_read_oper_mode`` therefore fall back
    # to the same ``mode`` field, and a down link reports ``mode: down`` →
    # both normalize to ``None`` → ``classify_switchport`` would emit
    # ``routed``, dropping the configured VLAN data on every disconnected
    # interface at collection time.
    #
    # Default ``admin`` to ``"access"`` when ``Switchport: Enabled`` and
    # neither admin nor oper resolves to a known mode. Access is the
    # most common default for an enabled switchport with no other signal,
    # and the access_vlan field is still populated by NX-OS even on down
    # ports. Trunks that happen to be down are misclassified as access
    # using their trunk's access_vlan field (typically VID 1) — corrected
    # automatically on the next discovery cycle once the link is up.
    # NX-API rows are unaffected because they emit ``admin_mode`` and
    # ``oper_mode`` separately, so ``admin`` is non-None and this branch
    # does not fire.
    if admin is None and oper is None:
        admin = "access"

    return SwitchportInfo(
        enabled=True,
        admin_mode=admin,  # type: ignore[arg-type]
        oper_mode=oper,    # type: ignore[arg-type]
        access_vlan=_maybe_int(row.get("access_vlan")),
        native_vlan=_maybe_int(row.get("native_vlan")),
        allowed_vlans=allowed,
        voice_vlan=_maybe_int(row.get("voice_vlan")),
    )


class NXOSDriver(NapalmNXOSDriver):
    """Cisco NX-OS NAPALM driver with VLAN-interface association support."""

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """Return per-interface VLAN config (NX-API JSON path)."""
        try:
            payload = self.device.show("show interface switchport", raw_text=False)
        except Exception:
            logger.debug("NX-OS show interface switchport failed", exc_info=True)
            return {}

        rows = _flatten_nxos_rows(payload)
        result: dict[str, dict] = {}
        for row in rows:
            ifname = row.get("interface")
            if not ifname:
                continue
            info = nxos_row_to_switchport_info(row)
            result[ifname] = classify_switchport(info)
        return result

    def get_modules(self) -> dict | None:
        """
        Return Module / ModuleBay inventory for Cisco Nexus modular chassis.

        Standalone modular only — vPC / VDC are not virtual chassis in
        NetBox terms. Fixed switches (Nexus 9300/9200) report optics with
        no linecard parent; those become device-rooted bays. Returns None
        only when neither a slot bay nor a transceiver was recognized.
        """
        return _nxos_get_modules_impl(self)
