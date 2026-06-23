# Copyright 2026 NetBox Labs Inc
"""
Arista EOS NAPALM driver subclass adding ``get_interfaces_vlans()`` and ``get_modules()``.

Fetches structured switchport data via pyeapi (eAPI JSON-RPC) and maps
each port into a :class:`custom_napalm._vlan.SwitchportInfo` for the
generic classifier. Module / module-bay inventory is built from the
structured ``show inventory`` response.
"""

import logging
import re

from napalm.eos.eos import EOSDriver as NapalmEOSDriver

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
)
from custom_napalm._modules import (
    to_payload as _modules_to_payload,
)
from custom_napalm._vlan import SwitchportInfo, classify_switchport, parse_vlan_range_string

logger = logging.getLogger(__name__)


def _maybe_int(v: object) -> int | None:
    """Coerce to int, returning None for bools and non-numeric values."""
    if isinstance(v, bool):
        return None
    try:
        return int(v)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _eos_port_to_switchport_info(port_data: dict) -> SwitchportInfo:
    """
    Build a SwitchportInfo from one entry of eAPI ``show interfaces switchport`` output.

    Arista eAPI per-port shape::

        {
            "enabled": true,
            "switchportInfo": {
                "mode": "access" | "trunk",
                "accessVlanId": 100,
                "trunkingNativeVlanId": 1,
                "trunkAllowedVlans": "1-4094" | "10,20" | "ALL" | "NONE",
                ...
            }
        }
    """
    if not port_data.get("enabled", True):
        return SwitchportInfo(
            enabled=False,
            admin_mode=None,
            oper_mode=None,
            access_vlan=None,
            native_vlan=None,
            allowed_vlans=None,
        )

    sw = port_data.get("switchportInfo") or {}
    mode_raw = (sw.get("mode") or "").lower()
    if "access" in mode_raw:
        admin: str | None = "access"
    elif "trunk" in mode_raw:
        admin = "trunk"
    else:
        # Includes "routed", empty, and any unknown mode — the generic
        # classifier maps admin_mode=None to a routed entry.
        admin = None

    trunk_spec = sw.get("trunkAllowedVlans") or ""
    if trunk_spec:
        vids, is_wildcard = parse_vlan_range_string(trunk_spec)
        allowed: list[int] | str | None = "all" if is_wildcard else vids
    else:
        allowed = None

    return SwitchportInfo(
        enabled=True,
        admin_mode=admin,  # type: ignore[arg-type]
        oper_mode=None,  # EOS does not expose DTP-style oper mode
        access_vlan=_maybe_int(sw.get("accessVlanId")),
        native_vlan=_maybe_int(sw.get("trunkingNativeVlanId")),
        allowed_vlans=allowed,
    )


# ---- module discovery (Arista EOS, eAPI JSON path) -----------------------

_EOS_LINECARD_RE = re.compile(r"^Linecard(\d+)$", re.IGNORECASE)
_EOS_SUPERVISOR_RE = re.compile(r"^Supervisor(\d+)$", re.IGNORECASE)
_EOS_FABRIC_RE = re.compile(r"^Fabric(\d+)$", re.IGNORECASE)
_EOS_PORT_RE = re.compile(r"^Ethernet(\d+)(?:/\d+)+$", re.IGNORECASE)


def classify_module_type_arista_eos(pid: str, name: str) -> str:
    """
    Map an Arista EOS cardSlot / xcvrSlot entry to a ModuleType.

    Decision order: optic PID > NAME prefix > PID prefix. Fabric and
    Linecard names both map to ``linecard`` (NetBox does not carry a
    distinct fabric concept on Module today). PSU / fan are classified
    so they don't accidentally fall through to ``linecard`` but are
    filtered upstream and never emitted as Module entities.
    """
    if not pid:
        return "linecard"
    if is_optic_pid(pid):
        return "transceiver"
    name_upper = (name or "").upper()
    if name_upper.startswith("SUPERVISOR"):
        return "supervisor"
    if name_upper.startswith("LINECARD") or name_upper.startswith("FABRIC"):
        return "linecard"
    pid_upper = pid.strip().upper()
    if pid_upper.startswith("PWR-"):
        return "psu"
    if pid_upper.startswith("FAN-") or pid_upper == "FAN":
        return "fan"
    return "linecard"


def _eos_extract_card_bays(card_slots: dict) -> tuple[dict[str, _ModuleBay], dict[str, _ModuleBay]]:
    """
    Parse ``cardSlots`` into supervisor and linecard module bays.

    Classifies each slot, drops psu/fan (recognized but never emitted),
    and keys both returned dicts on the FULL slot name so e.g.
    ``Supervisor1`` and ``Linecard1`` never collide. Returns
    ``(sup_bays, lc_bays)``.
    """
    sup_bays: dict[str, _ModuleBay] = {}
    lc_bays: dict[str, _ModuleBay] = {}
    for slot_name, entry in card_slots.items():
        if not isinstance(entry, dict):
            continue
        pid = str(entry.get("modelName") or "").strip()
        sn = str(entry.get("serialNum") or "").strip()
        descr = str(entry.get("description") or entry.get("name") or "").strip()
        if not (pid and sn):
            continue
        sup_match = _EOS_SUPERVISOR_RE.match(slot_name)
        lc_match = _EOS_LINECARD_RE.match(slot_name) or _EOS_FABRIC_RE.match(slot_name)
        if not (sup_match or lc_match):
            continue
        mtype = classify_module_type_arista_eos(pid, slot_name)
        if mtype in ("psu", "fan"):
            continue
        position = (sup_match or lc_match).group(1)
        bay = _ModuleBay(
            name=slot_name, position=position,
            module=_ModuleEntry(
                model=pid, serial=sn, type=mtype, description=descr,
            ),
        )
        if sup_match:
            sup_bays[slot_name] = bay
        else:
            lc_bays[slot_name] = bay
    return sup_bays, lc_bays


def _eos_attach_transceivers(xcvr_slots: dict, lc_bays: dict[str, _ModuleBay]) -> dict[str, list[str]]:
    """
    Attach optic sub-bays from ``xcvrSlots`` to their parent linecard.

    Matches each port's leading integer to the linecard's trailing slot
    integer (e.g. ``Ethernet1/1`` → ``Linecard1``); supervisors never
    carry transceiver sub-bays. Mutates the matched ``lc_bays`` entries'
    ``module.sub_bays`` in place and returns ``interfaces_by_bay``.
    """
    interfaces_by_bay: dict[str, list[str]] = {}
    for ifname, entry in xcvr_slots.items():
        if not isinstance(entry, dict):
            continue
        pid = str(entry.get("modelName") or "").strip()
        sn = str(entry.get("serialNum") or "").strip()
        descr = str(entry.get("description") or entry.get("name") or "").strip()
        if not (pid and sn and is_optic_pid(pid)):
            continue
        port_match = _EOS_PORT_RE.match(ifname)
        if not port_match:
            continue
        slot_num = port_match.group(1)
        parent_name = f"Linecard{slot_num}"
        parent = lc_bays.get(parent_name)
        if parent is None or parent.module is None:
            continue
        parent.module.sub_bays.append(_ModuleBay(
            name=ifname, position=ifname,
            module=_ModuleEntry(
                model=pid, serial=sn, type="transceiver", description=descr,
            ),
        ))
        interfaces_by_bay.setdefault(parent_name, []).append(ifname)
        # Self-route the optic under its own sub-bay name so the translator's
        # deepest-wins logic links the interface to the transceiver (not the
        # parent linecard) in full mode. Mirrors ios.py:_attach_transceivers.
        interfaces_by_bay[ifname] = [ifname]
    return interfaces_by_bay


def _eos_get_modules_impl(driver) -> dict | None:
    """
    Standalone-modular module discovery for Arista EOS chassis.

    Pulls structured inventory via eAPI (``self._run_commands(["show
    inventory"], encoding="json")``). Iterates ``cardSlots`` for
    Supervisor / Linecard / Fabric bays and ``xcvrSlots`` for
    transceivers. Slot collision between e.g. ``Supervisor1`` and
    ``Linecard1`` is avoided by keying separate dicts on the FULL slot
    name; the emitted bay ``name`` is the slot name (``"Supervisor1"``,
    ``"Linecard1"``) and ``position`` is the trailing integer.

    Returns None on:
      - eAPI call failure.
      - Empty cardSlots (fixed switch / unrecognized chassis).
      - No Supervisor / Linecard / Fabric entries survive classification.
    """
    try:
        response = driver._run_commands(
            ["show inventory"], encoding="json",
        )
    except Exception as e:
        logger.warning("eos.get_modules: show inventory failed: %s", e)
        return None
    if not response:
        return None
    payload = response[0] or {}
    card_slots = payload.get("cardSlots") or {}
    xcvr_slots = payload.get("xcvrSlots") or {}

    sup_bays, lc_bays = _eos_extract_card_bays(card_slots)
    if not (sup_bays or lc_bays):
        return None

    interfaces_by_bay = _eos_attach_transceivers(xcvr_slots, lc_bays)

    # Merge sup + linecard bays; supervisors listed first to match the
    # natural chassis presentation order.
    all_bays = list(sup_bays.values()) + list(lc_bays.values())
    return _modules_to_payload({
        None: _MemberModules(
            bays=all_bays,
            interfaces_by_bay=interfaces_by_bay,
        ),
    })


class EOSDriver(NapalmEOSDriver):
    """Arista EOS NAPALM driver with VLAN-interface association support."""

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """
        Return per-interface VLAN config.

        Output shape per interface::

            {"mode": "access"|"trunk"|"trunk-all"|"routed",
             "tagged": list[int], "untagged": int | None}

        Uses ``self._run_commands`` (the upstream EOSDriver wrapper) — NOT
        ``self.device.run_commands``. The wrapper bridges both eAPI
        (pyeapi ``Node.run_commands``) and SSH (Netmiko ``send_command`` +
        ``| json`` pipe). Calling pyeapi directly via ``self.device``
        breaks deployments that configure ``transport=ssh``.
        """
        try:
            response = self._run_commands(
                ["show interfaces switchport"], encoding="json"
            )
        except Exception:
            logger.debug("EOS show interfaces switchport failed", exc_info=True)
            return {}

        if not response:
            return {}
        switchports = (response[0] or {}).get("switchports") or {}

        result: dict[str, dict] = {}
        for ifname, port_data in switchports.items():
            info = _eos_port_to_switchport_info(port_data or {})
            result[ifname] = classify_switchport(info)
        return result

    def get_modules(self) -> dict | None:
        """
        Return Module / ModuleBay inventory for an Arista modular chassis.

        Standalone modular only — Arista MLAG is peer-to-peer, not a
        virtual chassis. Returns None for fixed switches and chassis
        with no recognized cardSlots entries.
        """
        return _eos_get_modules_impl(self)
