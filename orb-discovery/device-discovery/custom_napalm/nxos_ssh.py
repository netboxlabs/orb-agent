# Copyright 2026 NetBox Labs Inc
"""
Cisco NX-OS-SSH NAPALM driver subclass adding ``get_interfaces_vlans()`` and ``get_modules()``.

Fetches ``show interface switchport`` over SSH (Netmiko), parses via
ntc-templates ``cisco_nxos`` platform, and reuses the shared NX-OS
field mapper so output is byte-identical with the NX-API path.
``get_modules()`` adds Module / module-bay discovery for Nexus modular chassis via SSH + ntc-templates.
"""

import logging
import re

from napalm.nxos_ssh.nxos_ssh import NXOSSSHDriver as NapalmNXOSSSHDriver
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
    is_optic_pid,
    orphan_optic_bay,
)
from custom_napalm._modules import (
    to_payload as _modules_to_payload,
)
from custom_napalm._vlan import SwitchportInfo, classify_switchport, parse_vlan_range_string

logger = logging.getLogger(__name__)


# ---- module discovery (NX-OS SSH path) -----------------------------------

_NXOS_SSH_PORT_RE = re.compile(r"^Ethernet(\d+)(?:/\d+)+$", re.IGNORECASE)
_NXOS_SSH_SLOT_RE = re.compile(r"^Slot\s+(\d+)$", re.IGNORECASE)
# K is optional: Nexus 7700 sups are N77-SUP2E/SUP3E (no K), while N9K-/N7K- have it.
_NXOS_SSH_SUP_PID_RE = re.compile(r"^N\d+K?[-A-Z0-9]*-SUP", re.IGNORECASE)


def classify_module_type_nexus_ssh(pid: str, name: str) -> str:
    """
    Map a Cisco NX-OS PID to a ModuleType (SSH path duplicate of NX-API).

    Intentionally duplicated from nxos.py — the ≥3-callers rule prevents a
    2-caller shared helper. If a third caller emerges, fold both into one.
    """
    if not pid:
        return "linecard"
    if is_optic_pid(pid):
        return "transceiver"
    upper = pid.strip().upper()
    if _NXOS_SSH_SUP_PID_RE.match(upper):
        return "supervisor"
    if "FM-" in upper or upper.endswith("-FM"):
        return "linecard"  # fabric reported as linecard
    if upper.startswith("PWR-") or upper.startswith("PSU-"):
        return "psu"
    if upper.startswith("FAN-") or upper == "FAN":
        return "fan"
    return "linecard"


def _nxos_ssh_parse_inventory(
    inv_rows: list[dict],
) -> tuple[dict[str, dict[str, str]], dict[str, _ModuleEntry]]:
    """
    Split show-inventory rows into slot PID/serial lookup + transceiver map.

    ntc-templates yields lowercase keys (name / pid / sn / descr); a few
    template versions emit uppercase, so both are accepted.
    """
    inv_by_slot: dict[str, dict[str, str]] = {}
    transceivers_by_ifname: dict[str, _ModuleEntry] = {}
    for row in inv_rows:
        name = (row.get("NAME") or row.get("name") or "").strip()
        pid = (row.get("PID") or row.get("pid") or "").strip()
        sn = (row.get("SN") or row.get("sn") or "").strip()
        descr = (row.get("DESCR") or row.get("descr") or "").strip()
        if not (pid and sn):
            continue
        slot_match = _NXOS_SSH_SLOT_RE.match(name)
        if slot_match:
            inv_by_slot[slot_match.group(1)] = {
                "pid": pid, "sn": sn, "descr": descr, "name": name,
            }
            continue
        if _NXOS_SSH_PORT_RE.match(name) and is_optic_pid(pid):
            transceivers_by_ifname[name] = _ModuleEntry(
                model=pid, serial=sn, type="transceiver", description=descr,
            )
    return inv_by_slot, transceivers_by_ifname


_NXOS_SSH_XBAR_HDR_RE = re.compile(r"^Xbar\s+Ports\b", re.IGNORECASE)
_NXOS_SSH_XBAR_ROW_RE = re.compile(r"^(\d+)\s+\d+\s+\S")


def _nxos_ssh_xbar_slots(sm_out: str) -> list[str]:
    """
    Scrape fabric-module slot numbers from the raw show-module Xbar section.

    cisco_nxos_show_module.textfsm Fails (NoRecords) on the ``Xbar Ports``
    header, so fabric modules never reach the parsed rows. Walk the raw text
    from the Xbar header to the next blank line and pull leading slot numbers;
    show inventory then resolves PID + serial via ``Slot <N>``.
    """
    slots: list[str] = []
    in_xbar = False
    for line in sm_out.splitlines():
        if _NXOS_SSH_XBAR_HDR_RE.match(line):
            in_xbar = True
            continue
        if not in_xbar:
            continue
        if not line.strip():
            break
        row_match = _NXOS_SSH_XBAR_ROW_RE.match(line)
        if row_match:
            slots.append(row_match.group(1))
    return slots


def _nxos_ssh_build_slot_bays(
    sm_rows: list[dict], xbar_slots: list[str],
    inv_by_slot: dict[str, dict[str, str]],
) -> dict[str, _ModuleBay]:
    """
    Join show-module slots with the inventory lookup into ModuleBays.

    ntc-templates cisco_nxos_show_module yields the slot under key ``module``
    (template field MODULE); older versions used ``mod`` / ``modinf``. Xbar
    slots feed fabric modules (emitted as linecards). PSU / fan slots are
    classified then dropped — they're never emitted.
    """
    bays_by_slot: dict[str, _ModuleBay] = {}
    slots = [
        str(row.get("module") or row.get("mod") or row.get("modinf") or "").strip()
        for row in sm_rows
    ]
    slots.extend(xbar_slots)
    for slot in slots:
        if not slot or slot not in inv_by_slot:
            continue
        inv = inv_by_slot[slot]
        mtype = classify_module_type_nexus_ssh(inv["pid"], inv["name"])
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


def _nxos_ssh_attach_transceivers(
    bays_by_slot: dict[str, _ModuleBay],
    transceivers_by_ifname: dict[str, _ModuleEntry],
) -> dict[str, list[str]]:
    """
    Attach each optic as a sub_bay under its parent linecard slot, or as a device-rooted bay when there is no parent (fixed switch).

    ``interfaces_by_bay`` is keyed by the linecard SLOT NAME (= bay name) so
    the translator can route ifnames into the matching bay. Mutates
    ``bays_by_slot`` in place — both the matched entries' parent
    ``module.sub_bays`` and, for orphans, ``bays_by_slot`` itself.
    """
    interfaces_by_bay: dict[str, list[str]] = {}
    for ifname, optic in transceivers_by_ifname.items():
        port_match = _NXOS_SSH_PORT_RE.match(ifname)
        if not port_match:
            continue
        slot = port_match.group(1)
        parent = bays_by_slot.get(slot)
        if parent is None or parent.module is None:
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


def _nxos_ssh_get_modules_impl(driver) -> dict | None:
    """
    SSH-based NX-OS module discovery — same envelope as the NX-API path.

    Parses ``show module`` and ``show inventory`` directly via ntc-templates
    (cisco_nxos_show_inventory.textfsm covers the same NAME/DESCR/PID/VID/SN
    block format). No shared helper — only 2 cross-driver callers would
    exist (ios + nxos_ssh), below the ≥3-callers threshold.

    Uses the NapalmNXOSSSHDriver._send_command wrapper (also used by
    get_interfaces_vlans, see nxos_ssh.py) — NOT driver.device.send_command
    directly. The wrapper handles enable-mode escalation, banner stripping,
    and per-command timeout normalization the raw Netmiko session exposes.

    Fixed switches report 0 or 1 show-module self-rows and no populated
    slot bays; their optics are promoted to device-rooted bays instead of
    being dropped (see ``_nxos_ssh_attach_transceivers``). Returns None
    when the SSH calls fail, show inventory yields no rows, or no
    supervisor / linecard slots survive AND no transceiver was recognized.
    """
    try:
        sm_out = driver._send_command("show module") or ""
        inv_out = driver._send_command("show inventory") or ""
    except Exception as e:
        logger.warning("nxos_ssh.get_modules: _send_command failed: %s", e)
        return None

    try:
        sm_rows = parse_output(
            platform="cisco_nxos", command="show module", data=sm_out,
        )
    except Exception as e:
        logger.warning("nxos_ssh.get_modules: show module parse failed: %s", e)
        return None

    try:
        inv_rows = parse_output(
            platform="cisco_nxos", command="show inventory", data=inv_out,
        )
    except Exception as e:
        logger.warning("nxos_ssh.get_modules: show inventory parse failed: %s", e)
        return None
    if not inv_rows:
        return None

    inv_by_slot, transceivers_by_ifname = _nxos_ssh_parse_inventory(inv_rows)

    xbar_slots = _nxos_ssh_xbar_slots(sm_out)
    # Fixed switch heuristic: 0 or 1 show-module rows is the chassis acting
    # as its own "slot 1", so no slot bays are built. Optics still count —
    # a fixed switch's ports carry them with no linecard above.
    if not sm_rows or len(sm_rows) <= 1:
        bays_by_slot = {}
    else:
        bays_by_slot = _nxos_ssh_build_slot_bays(sm_rows, xbar_slots, inv_by_slot)
    if not bays_by_slot and not transceivers_by_ifname:
        return None

    interfaces_by_bay = _nxos_ssh_attach_transceivers(
        bays_by_slot, transceivers_by_ifname,
    )

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


class NXOSSSHDriver(NapalmNXOSSSHDriver):
    """Cisco NX-OS-SSH NAPALM driver with VLAN-interface association support."""

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """Return per-interface VLAN config (CLI scrape via ntc-templates)."""
        output = self._send_command("show interface switchport")
        if not output:
            return {}
        try:
            rows = parse_output(
                platform="cisco_nxos",
                command="show interface switchport",
                data=output,
            )
        except Exception:
            logger.debug("ntc-templates failed to parse NX-OS switchport", exc_info=True)
            return {}

        result: dict[str, dict] = {}
        for row in rows or []:
            ifname = row.get("interface")
            if not ifname:
                continue
            info = nxos_row_to_switchport_info(row)
            result[ifname] = classify_switchport(info)
        return result

    def get_modules(self) -> dict | None:
        """Return Module / ModuleBay inventory for Cisco Nexus via SSH CLI."""
        return _nxos_ssh_get_modules_impl(self)
