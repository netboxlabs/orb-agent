# Copyright 2026 NetBox Labs Inc
# Based on napalm-aruba-cx (Apache-2.0): https://github.com/napalm-automation-community/napalm-aruba-cx
"""
Custom Aruba AOS-CX NAPALM driver — REST API via pyaoscx v2.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Requires pyaoscx >= 2.0 and AOS-CX firmware >= 10.04.

The driver uses pyaoscx v2's Session for TLS/auth lifecycle management
and calls the AOS-CX REST API directly via session.request() to keep the
mapping between REST responses and NAPALM return types transparent.
"""

import json
import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.exceptions import ConnectionException
from napalm.base.helpers import mac as normalize_mac
from pyaoscx.session import Session

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
    is_optic_pid,
    orphan_optic_bay,
)
from custom_napalm._modules import (
    to_payload as _modules_to_payload,
)
from custom_napalm._vlan import (
    SwitchportInfo,
    classify_switchport,
)

logger = logging.getLogger(__name__)

_VLAN_URI_RE = re.compile(r".*/system/vlans/(\d+)\b")


def _vlan_uri_to_vid(value: object) -> int | None:
    """
    Extract an integer VID from a vlan_tag/vlan_trunks entry.

    Accepts AOS-CX REST reference shapes:
      - URI string: ``"/rest/v10.04/system/vlans/10"``
      - Stringified or native int VID
      - Single-entry dict reference: ``{"/rest/v10.04/system/vlans/10": ...}``
        (returned by pyaoscx at depth >= 1; the value side may be a URI
        string or the expanded VLAN object dict at depth 2).
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        m = _VLAN_URI_RE.match(value)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                return None
        try:
            return int(value)
        except ValueError:
            return None
    if isinstance(value, dict) and len(value) == 1:
        # Reference dict: {uri: uri-or-object}. The KEY carries the URI.
        only_key = next(iter(value.keys()))
        return _vlan_uri_to_vid(only_key)
    return None


def _normalize_vlan_trunks(trunks_raw: object) -> list[int]:
    """Normalize a vlan_trunks value (list/dict/None) to a list of integer VIDs."""
    if isinstance(trunks_raw, dict):
        trunk_iter: list = list(trunks_raw.keys())
    elif isinstance(trunks_raw, list):
        trunk_iter = trunks_raw
    else:
        trunk_iter = []
    return [v for v in (_vlan_uri_to_vid(t) for t in trunk_iter) if v is not None]


def _aoscx_iface_to_switchport_info(intf: dict) -> SwitchportInfo:
    """Map an AOS-CX system/interfaces entry to a SwitchportInfo."""
    if intf.get("routing") is True:
        return SwitchportInfo(
            enabled=False,
            admin_mode=None,
            oper_mode=None,
            access_vlan=None,
            native_vlan=None,
            allowed_vlans=None,
        )

    vlan_mode = intf.get("vlan_mode")
    if vlan_mode in (None, ""):
        return SwitchportInfo(
            enabled=False,
            admin_mode=None,
            oper_mode=None,
            access_vlan=None,
            native_vlan=None,
            allowed_vlans=None,
        )

    vlan_tag_vid = _vlan_uri_to_vid(intf.get("vlan_tag"))
    trunk_vids = _normalize_vlan_trunks(intf.get("vlan_trunks"))

    if vlan_mode == "access":
        return SwitchportInfo(
            enabled=True,
            admin_mode="access",
            oper_mode="access",
            access_vlan=vlan_tag_vid,
            native_vlan=None,
            allowed_vlans=None,
        )
    if vlan_mode == "native-untagged":
        allowed: list[int] | str | None = trunk_vids if trunk_vids else "all"
        return SwitchportInfo(
            enabled=True,
            admin_mode="trunk",
            oper_mode="trunk",
            access_vlan=None,
            native_vlan=vlan_tag_vid,
            allowed_vlans=allowed,
        )
    if vlan_mode == "native-tagged":
        merged: list[int] = list(trunk_vids)
        if vlan_tag_vid is not None and vlan_tag_vid not in merged:
            merged.append(vlan_tag_vid)
        return SwitchportInfo(
            enabled=True,
            admin_mode="trunk",
            oper_mode="trunk",
            access_vlan=None,
            native_vlan=None,
            allowed_vlans=merged if merged else "all",
        )
    if vlan_mode == "trunk":
        if not trunk_vids:
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
            allowed_vlans=trunk_vids,
        )

    return SwitchportInfo(
        enabled=False,
        admin_mode=None,
        oper_mode=None,
        access_vlan=None,
        native_vlan=None,
        allowed_vlans=None,
    )

_API_VERSION = "10.04"

# ---------------------------------------------------------------------------
# Config sanitization
# AOS-CX config is returned as JSON; we serialize to a string then redact.
# ---------------------------------------------------------------------------
_PASSKEY_RE = re.compile(r'("passkey"\s*:\s*)"[^"]*"', re.IGNORECASE)
_PASSWORD_RE = re.compile(r'("password"\s*:\s*)"[^"]*"', re.IGNORECASE)
_SECRET_RE = re.compile(r'("secret"\s*:\s*)"[^"]*"', re.IGNORECASE)
_COMMUNITY_NAME_RE = re.compile(r'("community_name"\s*:\s*)"[^"]*"', re.IGNORECASE)


def _sanitize_config(text: str) -> str:
    text = _PASSKEY_RE.sub(r'\1"<redacted>"', text)
    text = _PASSWORD_RE.sub(r'\1"<redacted>"', text)
    text = _SECRET_RE.sub(r'\1"<redacted>"', text)
    text = _COMMUNITY_NAME_RE.sub(r'\1"<redacted>"', text)
    return text


# ---------------------------------------------------------------------------
# Module / module bay discovery
# ---------------------------------------------------------------------------

_ARUBA_ADDR_RE = re.compile(r"^(\d+)")  # leading int of a subsystem addr "1/3" -> member 1

# Only these subsystem types ever emit a module bay. Anything else
# (power_supply, fan, chassis, mm_fan, unknown) is NOT a bay — never
# default an unrecognized subsystem to linecard.
_ARUBA_SUPERVISOR_TYPES = frozenset({"management_module"})
_ARUBA_LINECARD_TYPES = frozenset({"line_card", "fabric_module"})


def classify_module_type_aruba(subsystem_type: str, pid: str) -> str:
    """
    Classify an AOS-CX subsystem entry — whitelist only.

    management_module -> supervisor; line_card / fabric_module -> linecard.
    An optic PID -> transceiver (for the DOM-derived sub-bays). EVERYTHING
    ELSE (power_supply, fan, chassis, anything unrecognized) -> "other",
    which the impl filters out BEFORE building a bay, so PSU/fan/unknown
    subsystems can never become bogus module bays.
    """
    if pid and is_optic_pid(pid):
        return "transceiver"
    t = (subsystem_type or "").lower()
    if t in _ARUBA_SUPERVISOR_TYPES:
        return "supervisor"
    if t in _ARUBA_LINECARD_TYPES:
        return "linecard"
    return "other"  # power_supply / fan / chassis / unknown — not emitted


def _aruba_member_of(addr: str) -> int | None:
    """Member id = leading integer of a subsystem addr ('1/3' -> 1)."""
    m = _ARUBA_ADDR_RE.match(addr or "")
    return int(m.group(1)) if m else None


def _aruba_vsf_member_ids(driver) -> set[int]:
    """
    Derive the VSF member-id set from the chassis-members payload.

    `_aoscx_get_chassis_members_impl(driver)` returns the canonical
    chassis envelope `{"members": [<member dict>, ...], "domain": ...}`
    (members is a LIST, each dict carries an int "id" — see
    `_chassis.to_payload` / `ChassisMember.to_dict`) or None on a
    standalone (non-VSF) device. Extract the int member ids; an empty
    set means standalone (single None-bucket).
    """
    try:
        payload = _aoscx_get_chassis_members_impl(driver)
    except Exception:
        return set()
    if not isinstance(payload, dict):
        return set()
    out: set[int] = set()
    for m in (payload.get("members") or []):
        if not isinstance(m, dict):
            continue
        try:
            out.add(int(m["id"]))
        except (KeyError, TypeError, ValueError):
            continue
    return out


def _aruba_subsystem_member_ids(subs: dict) -> set[int]:
    """
    Member ids that own a module-bearing subsystem slot, from the addresses.

    The subsystem keys (`<type>,<member>/<slot>`) are authoritative for which
    members physically own slots, so they back-stop VSF detection when the
    vsf_members roster fetch fails or comes back empty.
    """
    out: set[int] = set()
    for key, entry in subs.items():
        if "," not in key or not isinstance(entry, dict):
            continue
        stype, addr = key.split(",", 1)
        pinfo = entry.get("product_info") or {}
        pid = str(pinfo.get("part_number") or "").strip()
        sn = str(pinfo.get("serial_number") or "").strip()
        if classify_module_type_aruba(stype.strip(), pid) == "other" or not (pid and sn):
            continue
        mid = _aruba_member_of(addr.strip())
        if mid is not None:
            out.add(mid)
    return out


def _aruba_optics_by_slot(ifaces) -> dict[str, list[tuple[str, _ModuleEntry]]]:
    """
    Build optic sub-bay entries per line-card slot from interface hw_intf_info.

    AOS-CX populates hw_intf_info.product_number / .serial_number (plus a
    `pluggable`/`connector` marker) for an inserted transceiver; copper /
    empty ports omit those keys.
    """
    optics_by_slot: dict[str, list[tuple[str, _ModuleEntry]]] = {}
    if not isinstance(ifaces, dict):
        return optics_by_slot
    for ifname, idata in ifaces.items():
        if not isinstance(idata, dict):
            continue
        hw = idata.get("hw_intf_info") or {}
        pid = str(hw.get("product_number") or "").strip()
        sn = str(hw.get("serial_number") or "").strip()
        if not (pid and sn and is_optic_pid(pid)):
            continue
        parts = ifname.split("/")
        if len(parts) < 2:
            continue
        slot = f"{parts[0]}/{parts[1]}"  # member/slot
        optics_by_slot.setdefault(slot, []).append(
            (ifname, _ModuleEntry(model=pid, serial=sn, type="transceiver", description="")),
        )
    return optics_by_slot


def _aruba_ifaces_by_slot(ifaces) -> dict[str, list[str]]:
    """
    Map "<member>/<slot>" -> every physical-port ifname on that slot.

    Lets every bay claim ALL its ports (copper + optic), so linecard-mode
    discovery attaches non-transceiver ports to the parent Module — not
    just the ones with optics. Filters out non-slot ifnames (vlanN, lagN,
    mgmt, ...) by requiring the first two `/`-segments to be digits.
    """
    out: dict[str, list[str]] = {}
    if not isinstance(ifaces, dict):
        return out
    for ifname in ifaces:
        parts = ifname.split("/")
        if len(parts) < 3 or not parts[0].isdigit() or not parts[1].isdigit():
            continue
        slot = f"{parts[0]}/{parts[1]}"
        out.setdefault(slot, []).append(ifname)
    return out


def _aruba_build_bays(
    subs: dict,
    optics_by_slot: dict[str, list[tuple[str, _ModuleEntry]]],
    ifaces_by_slot: dict[str, list[str]],
    members: set[int],
    vsf: bool,
) -> tuple[dict[int | None, list[_ModuleBay]], dict[int | None, dict[str, list[str]]]]:
    """Assemble per-member module bays (with optic sub-bays) from subsystem entries."""
    bays_by_member: dict[int | None, list[_ModuleBay]] = {}
    ifaces_by_member: dict[int | None, dict[str, list[str]]] = {}
    consumed_optic_slots: set[str] = set()
    for key, entry in subs.items():
        if "," not in key or not isinstance(entry, dict):
            continue
        stype, addr = key.split(",", 1)
        stype = stype.strip()
        addr = addr.strip()
        pinfo = entry.get("product_info") or {}
        pid = str(pinfo.get("part_number") or "").strip()
        sn = str(pinfo.get("serial_number") or "").strip()
        descr = str(pinfo.get("product_name") or "").strip()
        mtype = classify_module_type_aruba(stype, pid)
        if mtype == "other":
            continue  # power_supply / fan / chassis / unknown — never a bay
        if not (pid and sn):
            continue  # empty slot (no module) — skipped (envelope drops module-less bays)
        member = _aruba_member_of(addr) if vsf else None
        if vsf and member not in members:
            logger.warning("aruba.get_modules: subsystem member %s not in VSF set", member)
            continue
        # Claim every port on this slot for the parent bay; optic sub-bays
        # below add per-ifname self-routes so deepest-match-wins routes the
        # transceiver port to the sub-bay while copper ports stay on parent.
        slot_ifaces = ifaces_by_slot.get(addr, [])
        if slot_ifaces:
            ifaces_by_member.setdefault(member, {})[addr] = list(slot_ifaces)
        sub_bays: list[_ModuleBay] = []
        for ifname, optic in optics_by_slot.get(addr, []):
            sub_bays.append(_ModuleBay(name=ifname, position=ifname, module=optic))
            ifaces_by_member.setdefault(member, {})[ifname] = [ifname]  # self-route (sub-bay key)
        if addr in optics_by_slot:
            consumed_optic_slots.add(addr)
        bay = _ModuleBay(
            name=addr, position=addr,
            module=_ModuleEntry(model=pid, serial=sn, type=mtype, description=descr, sub_bays=sub_bays),
        )
        bays_by_member.setdefault(member, []).append(bay)

    _aruba_promote_orphan_optics(
        optics_by_slot, consumed_optic_slots, vsf, bays_by_member, ifaces_by_member,
    )
    return bays_by_member, ifaces_by_member


def _aruba_promote_orphan_optics(
    optics_by_slot: dict[str, list[tuple[str, _ModuleEntry]]],
    consumed_optic_slots: set[str],
    vsf: bool,
    bays_by_member: dict[int | None, list[_ModuleBay]],
    ifaces_by_member: dict[int | None, dict[str, list[str]]],
) -> None:
    """Promote every optic on a slot no bay claimed to a device-rooted bay, in place."""
    for slot_addr, optics in optics_by_slot.items():
        if slot_addr in consumed_optic_slots:
            continue
        for ifname, optic in optics:
            # Fixed-port CX switches expose optics on slots with no line
            # module, so the optic has no parent bay to nest under.
            member = _aruba_member_of(ifname) if vsf else None
            bays_by_member.setdefault(member, []).append(
                orphan_optic_bay(ifname, optic),
            )
            ifaces_by_member.setdefault(member, {})[ifname] = [ifname]


def _aruba_get_modules_impl(driver) -> dict | None:
    """Standalone + VSF-of-modular discovery for Aruba CX via pyaoscx REST."""
    try:
        subs = driver._get("system/subsystems?attributes=product_info&depth=2")
    except Exception as e:
        logger.warning("aruba.get_modules: subsystems fetch failed: %s", e)
        return None
    if not isinstance(subs, dict) or not subs:
        return None

    # Optics are enrichment sub-bays — a failed interface fetch must not
    # discard the chassis module bays, so degrade to no optics on error.
    try:
        ifaces = driver._get("system/interfaces?attributes=name,hw_intf_info&depth=2")
    except Exception as e:
        logger.warning("aruba.get_modules: interfaces fetch failed, emitting without optics: %s", e)
        ifaces = {}

    # VSF member set (None-bucket when standalone / single member). Union the
    # vsf_members roster with the members implied by the subsystem addresses so
    # a failed roster fetch can't collapse a real VSF down to a single chassis.
    members = _aruba_vsf_member_ids(driver) | _aruba_subsystem_member_ids(subs)
    vsf = len(members) >= 2

    optics_by_slot = _aruba_optics_by_slot(ifaces)
    ifaces_by_slot = _aruba_ifaces_by_slot(ifaces)
    bays_by_member, ifaces_by_member = _aruba_build_bays(
        subs, optics_by_slot, ifaces_by_slot, members, vsf,
    )

    if not bays_by_member:
        return None
    return _modules_to_payload({
        member: _MemberModules(bays=bays, interfaces_by_bay=ifaces_by_member.get(member, {}))
        for member, bays in bays_by_member.items()
    })


def _aoscx_build_members_by_vrf(interfaces_data: object) -> dict[str, dict]:
    """Group interface names by the VRF each one references."""
    members_by_vrf: dict[str, dict] = {}
    if isinstance(interfaces_data, dict):
        for if_name, intf in interfaces_data.items():
            if not isinstance(intf, dict):
                continue
            vrf_name = _aoscx_vrf_ref_name(intf.get("vrf"))
            if vrf_name:
                members_by_vrf.setdefault(vrf_name, {})[if_name] = {}
    return members_by_vrf


def _aoscx_vrf_ref_name(ref: object) -> str:
    """
    Resolve an interface's ``vrf`` REST reference to the VRF name.

    At depth 2 the reference is a single-key dict mapping the VRF name to
    its resource URL; tolerate a plain URL/name string defensively. A
    multi-key dict is NOT a name→URL reference (it would be an expanded
    VRF object, whose keys are attribute names) — return "" rather than
    a garbage attribute name.
    """
    if isinstance(ref, dict):
        if len(ref) == 1:
            return str(next(iter(ref)))
        return ""
    if isinstance(ref, str) and ref:
        return ref.rstrip("/").rsplit("/", 1)[-1]
    return ""


class AOSCXDriver(_napalm_base.NetworkDriver):
    """Aruba AOS-CX NAPALM driver using pyaoscx v2 REST API (read-only subset)."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Initialise driver — no network connection is made here."""
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.session = None
        if optional_args is None:
            optional_args = {}
        self._verify_ssl: bool = bool(optional_args.get("verify_ssl", False))

    def open(self):
        """Open a pyaoscx v2 session to the device."""
        try:
            self.session = Session(self.hostname, _API_VERSION)
            self.session.open(self.username, self.password)
        except Exception as exc:
            raise ConnectionException(str(exc)) from exc

    def close(self):
        """Close the pyaoscx session."""
        if self.session is not None:
            try:
                self.session.close()
            except Exception:
                pass

    def is_alive(self):
        """Return whether the REST session is still responsive."""
        if self.session is None:
            return {"is_alive": False}
        try:
            resp = self.session.request("GET", "system?attributes=hostname", verify=self._verify_ssl)
            return {"is_alive": resp.status_code == 200}
        except Exception:
            return {"is_alive": False}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get(self, path: str) -> dict | list:
        """Perform a GET and return the parsed JSON body."""
        from napalm.base.exceptions import CommandErrorException

        if self.session is None:
            raise CommandErrorException("Session is not open; call open() first.")
        resp = self.session.request("GET", path, verify=self._verify_ssl)
        if resp.status_code < 200 or resp.status_code >= 300:
            raise CommandErrorException(
                f"REST GET {path!r} returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return json.loads(resp.text)
        except json.JSONDecodeError as exc:
            raise CommandErrorException(
                f"REST GET {path!r} returned non-JSON body: {resp.text[:200]}"
            ) from exc

    # ------------------------------------------------------------------
    # NAPALM getters
    # ------------------------------------------------------------------

    def get_facts(self) -> dict:
        """Return general device facts."""
        sys_data = self._get(
            "system?attributes=hostname,software_info,boot_time"
        )
        subsystems = self._get(
            "system/subsystems?attributes=product_info&depth=2"
        )

        hostname = sys_data.get("hostname", "Unknown")
        os_version = (
            sys_data.get("software_info", {}).get("build_id", "Unknown")
        )
        # AOS-CX boot_time: milliseconds the system has been running
        boot_time_ms = sys_data.get("boot_time", 0)
        uptime = float(boot_time_ms) / 1000.0

        serial_number = "Unknown"
        model = "Unknown"
        if isinstance(subsystems, dict):
            # Prefer the chassis entry (key starts with "chassis,"); fall back to
            # the first subsystem that has product_info to handle non-modular devices.
            chassis_items = [
                v for k, v in subsystems.items()
                if k.startswith("chassis,") and isinstance(v, dict)
            ]
            fallback_items = [v for v in subsystems.values() if isinstance(v, dict)]
            for subsystem in chassis_items or fallback_items:
                product_info = subsystem.get("product_info", {}) or {}
                if product_info:
                    serial_number = product_info.get("serial_number", "Unknown")
                    model = product_info.get("product_name", "Unknown")
                    break

        interfaces_data = self._get("system/interfaces?depth=1")
        interface_list = (
            list(interfaces_data.keys())
            if isinstance(interfaces_data, dict)
            else []
        )

        return {
            "hostname": hostname,
            "vendor": "HPE",
            "model": model,
            "os_version": os_version,
            "serial_number": serial_number,
            "uptime": uptime,
            "fqdn": hostname,
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """Return interface details keyed by interface name."""
        interfaces_data = self._get("system/interfaces?depth=2")
        if not isinstance(interfaces_data, dict):
            return {}

        result = {}
        for name, intf in interfaces_data.items():
            if not isinstance(intf, dict):
                continue

            hw_info = intf.get("hw_intf_info", {}) or {}

            mac_raw = hw_info.get("mac_addr", "")
            try:
                mac_address = normalize_mac(mac_raw) if mac_raw else ""
            except Exception:
                mac_address = mac_raw

            speed_raw = hw_info.get("max_speed")
            try:
                speed = float(speed_raw) if speed_raw not in (None, "N/A", "") else -1.0
            except (ValueError, TypeError):
                speed = -1.0

            mtu_raw = intf.get("mtu")
            try:
                mtu = int(mtu_raw) if mtu_raw not in (None, "N/A", "") else -1
            except (ValueError, TypeError):
                mtu = -1

            result[name] = {
                "is_up": intf.get("link_state", "down") == "up",
                "is_enabled": intf.get("admin_state", "down") == "up",
                "description": intf.get("description", ""),
                "last_flapped": -1.0,
                "speed": speed,
                "mtu": mtu,
                "mac_address": mac_address,
            }

        return result

    @staticmethod
    def _collect_ips(intf: dict) -> dict:
        """Extract IPv4/IPv6 addresses from a single interface dict."""
        intf_ips: dict = {}

        # IPv4 primary
        ip4 = intf.get("ip4_address", "")
        if ip4 and "/" in ip4:
            addr, prefix = ip4.rsplit("/", 1)
            if prefix.isdigit():
                intf_ips.setdefault("ipv4", {})[addr] = {"prefix_length": int(prefix)}

        # IPv4 secondary
        for ip4_sec in (intf.get("ip4_address_secondary") or {}).keys():
            if "/" in ip4_sec:
                addr, prefix = ip4_sec.rsplit("/", 1)
                if prefix.isdigit():
                    intf_ips.setdefault("ipv4", {})[addr] = {"prefix_length": int(prefix)}

        # IPv6
        ip6_addresses = intf.get("ip6_addresses")
        for ip6 in (ip6_addresses if isinstance(ip6_addresses, dict) else {}).keys():
            if "/" in ip6:
                addr, prefix = ip6.rsplit("/", 1)
                if prefix.isdigit():
                    intf_ips.setdefault("ipv6", {})[addr] = {"prefix_length": int(prefix)}

        return intf_ips

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface."""
        interfaces_data = self._get("system/interfaces?depth=2")
        if not isinstance(interfaces_data, dict):
            return {}

        return {
            name: ips
            for name, intf in interfaces_data.items()
            if isinstance(intf, dict)
            for ips in [self._collect_ips(intf)]
            if ips
        }

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """Return device configuration as JSON-serialised string."""
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}

        if retrieve in ("running", "all"):
            data = self._get("fullconfigs/running-config")
            config["running"] = (
                json.dumps(data, indent=2)
                if isinstance(data, dict)
                else str(data)
            )

        if retrieve in ("startup", "all"):
            data = self._get("fullconfigs/startup-config")
            config["startup"] = (
                json.dumps(data, indent=2)
                if isinstance(data, dict)
                else str(data)
            )

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Return VLAN information keyed by VLAN ID string."""
        vlans_data = self._get("system/vlans?depth=2")
        if not isinstance(vlans_data, dict):
            return {}

        result = {}
        for vlan_id_str, vlan in vlans_data.items():
            if not isinstance(vlan, dict):
                continue

            interfaces_raw = vlan.get("interfaces") or {}
            interface_list = []
            if isinstance(interfaces_raw, dict):
                for uri in interfaces_raw.keys():
                    # URI: "/rest/v10.04/system/interfaces/1%2F1%2F1"
                    intf_name = uri.split("/")[-1].replace("%2F", "/")
                    interface_list.append(intf_name)

            result[vlan_id_str] = {
                "name": vlan.get("name", vlan_id_str),
                "interfaces": interface_list,
            }

        return result

    def get_chassis_members(self) -> dict | None:
        """
        Return Aruba CX VSF (Virtual Switching Framework) member info.

        Standalone AOS-CX (no VSF configured) returns ``None``. The driver
        treats two failure modes as "no VC":

        - HTTP 404 / "not found" → DEBUG log + None (expected on non-VSF).
        - HTTP 200 with empty body or zero members → None.

        Any other failure logs at WARNING with traceback so unexpected
        transport / pyaoscx problems still surface — mirrors the Junos
        log-level discipline from batch 2.
        """
        return _aoscx_get_chassis_members_impl(self)

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """Return per-interface VLAN config from system/interfaces REST endpoint."""
        try:
            data = self._get(
                "system/interfaces?attributes=name,vlan_mode,vlan_tag,vlan_trunks,routing&depth=2"
            )
        except Exception:
            logger.debug("AOS-CX system/interfaces fetch failed", exc_info=True)
            return {}
        if not isinstance(data, dict):
            return {}
        result: dict[str, dict] = {}
        for name, intf in data.items():
            if not isinstance(intf, dict):
                continue
            info = _aoscx_iface_to_switchport_info(intf)
            result[name] = classify_switchport(info)
        return result

    def get_modules(self) -> dict | None:
        """
        Return Module / module bay inventory for an Aruba CX modular chassis.

        Standalone (8400/6400) collapses to the None member; VSF-of-modular
        dispatches per member from the member-addressed subsystem keys.
        Returns None for fixed switches (no line_card subsystems).
        """
        return _aruba_get_modules_impl(self)

    def get_network_instances(self, name: str = "") -> dict:
        """
        Return network instances (AOS-CX VRFs), NAPALM OC shape.

        ``system/vrfs?depth=2`` enumerates the VRFs (with the EVPN route
        distinguisher when the firmware exposes an ``rd`` attribute);
        member interfaces come from each interface's ``vrf`` reference in
        ``system/interfaces?depth=2`` — the same resource the IP getter
        reads, so names join exactly. The factory VRF named ``default``
        is the global routing table and is emitted as the
        DEFAULT_INSTANCE with empty membership.
        """
        from napalm.base.exceptions import CommandErrorException

        instances: dict = {
            "default": {
                "name": "default",
                "type": "DEFAULT_INSTANCE",
                "state": {"route_distinguisher": ""},
                "interfaces": {"interface": {}},
            },
        }
        try:
            vrfs_data = self._get("system/vrfs?depth=2")
        except CommandErrorException:
            logger.warning("AOS-CX system/vrfs GET failed", exc_info=True)
            vrfs_data = {}
        try:
            interfaces_data = self._get("system/interfaces?depth=2")
        except CommandErrorException:
            logger.warning("AOS-CX system/interfaces GET failed", exc_info=True)
            interfaces_data = {}
        members_by_vrf = _aoscx_build_members_by_vrf(interfaces_data)
        if isinstance(vrfs_data, dict):
            for vrf_name, vrf_obj in vrfs_data.items():
                # The factory "default" VRF is the seeded DEFAULT_INSTANCE.
                if not vrf_name or vrf_name == "default":
                    continue
                rd_raw = vrf_obj.get("rd") if isinstance(vrf_obj, dict) else None
                rd = rd_raw.strip() if isinstance(rd_raw, str) else ""
                instances[vrf_name] = {
                    "name": vrf_name,
                    "type": "L3VRF",
                    "state": {"route_distinguisher": rd},
                    "interfaces": {"interface": members_by_vrf.get(vrf_name, {})},
                }
        if name:
            return {name: instances[name]} if name in instances else {}
        return instances


# ---------------------------------------------------------------------------
# AOS-CX VSF (Virtual Switching Framework) — chassis-members impl.
#
# Inlined here (not in a shared _aruba_cx_vsf module) so this driver stays
# self-contained alongside the vendor-neutral primitives in _chassis.py.
# The SSH transport (aruba_aoscx_ssh.py) duplicates the small role-alias /
# absent-status pieces — both are <10 lines and keeping each driver
# self-contained is preferred to a vendor-only shared module.
# ---------------------------------------------------------------------------

# Member-status values that mean "slot is reserved but no hardware is present".
# Mirrors Junos NotPrsnt — these aren't real members, just empty positions.
_AOSCX_ABSENT_STATUSES = frozenset({"missing", "not_present", "notpresent", "absent"})


def _aoscx_normalize_vsf_role(raw: str | None) -> str:
    """
    Map an AOS-CX VSF role string to {"active","standby","member"}.

    AOS-CX 10.10+ uses "conductor" / "commander" for what earlier firmware
    called "master". Both are returned directly as "active" — we don't
    detour through normalize_role's "master" → "active" lookup because the
    AOS-CX vocabulary doesn't include "master" so there's no value in the
    indirection. Everything else (active / standby / backup / member /
    empty / unknown) falls through to the vendor-neutral helper.
    """
    if not raw:
        return "member"
    lower = raw.strip().lower()
    if lower in ("conductor", "commander"):
        return "active"
    return normalize_role(lower)


def _aoscx_member_from_rest_dict(member_id: int, data: dict) -> ChassisMember | None:
    """
    Build one ChassisMember from a pyaoscx ``/system/vsf_members/<id>`` entry.

    Returns None for slots reported as physically absent. Tolerates the
    field-name drift seen across firmware revisions:
      - ``mac``         or ``mac_address``
      - ``product``     / ``product_name``     / ``model``
      - ``priority``    int or numeric string
    """
    if not isinstance(data, dict):
        return None
    raw_status = (data.get("status") or "").strip()
    # Fold spaces AND hyphens to underscores and lowercase so ``Not Present``,
    # ``Not-Present``, ``not_present`` all collapse to the underscore
    # canonical form in _AOSCX_ABSENT_STATUSES. The raw (case- and space-
    # preserving) status is kept for the emitted ChassisMember.state field
    # so operators see the device's wire value in NetBox metadata.
    status_norm = raw_status.lower().replace(" ", "_").replace("-", "_")
    if status_norm in _AOSCX_ABSENT_STATUSES:
        return None

    serial = (data.get("serial_number") or data.get("serial") or "").strip()
    model = (data.get("product_name") or data.get("product") or data.get("model") or "").strip() or None
    mac = (data.get("mac_address") or data.get("mac") or "").strip() or None

    raw_priority = data.get("priority")
    priority: int | None
    if isinstance(raw_priority, bool):
        priority = None  # bool is a subclass of int — reject before coercion.
    elif isinstance(raw_priority, int):
        priority = raw_priority
    elif isinstance(raw_priority, str):
        try:
            priority = int(raw_priority.strip())
        except (TypeError, ValueError):
            priority = None
    else:
        priority = None

    return ChassisMember(
        id=member_id,
        serial=serial,
        model=model,
        role=_aoscx_normalize_vsf_role(data.get("role")),
        priority=priority,
        mac=mac,
        state=raw_status or None,
    )


def _aoscx_coerce_member_id(raw_id: object) -> int | None:
    """Coerce a pyaoscx member-id key (int or stringified int) to int; reject bool / negatives."""
    if isinstance(raw_id, bool):
        return None
    if isinstance(raw_id, int):
        return raw_id if raw_id >= 0 else None
    if isinstance(raw_id, str):
        try:
            mid = int(raw_id)
        except (TypeError, ValueError):
            return None
        return mid if mid >= 0 else None
    return None


def _aoscx_members_from_rest_payload(payload: object, domain: str | None = None) -> dict | None:
    """
    Build the translate-ready VSF payload from the pyaoscx REST response.

    Accepts both response shapes pyaoscx returns across firmware versions:
      - A list of member dicts (each carrying an ``id`` field).
      - A dict keyed by member id (string-encoded), value = member dict.
    """
    if isinstance(payload, list):
        iterable: list[tuple[object, dict]] = [
            (entry.get("id") if isinstance(entry, dict) else None, entry)
            for entry in payload
        ]
    elif isinstance(payload, dict):
        iterable = list(payload.items())
    else:
        return None

    members: list[ChassisMember] = []
    for raw_id, raw_data in iterable:
        if not isinstance(raw_data, dict):
            continue
        mid = _aoscx_coerce_member_id(raw_id)
        if mid is None:
            logger.warning("aruba_aoscx: dropping VSF member with non-int id %r", raw_id)
            continue
        m = _aoscx_member_from_rest_dict(mid, raw_data)
        if m is not None:
            members.append(m)

    return to_payload(members, domain=domain)


def _aoscx_get_chassis_members_impl(driver) -> dict | None:
    """Implementation of AOSCXDriver.get_chassis_members (factored for testability)."""
    try:
        data = driver._get("system/vsf_members?depth=2")
    except Exception as e:
        # AOS-CX firmware without VSF returns 404 here. Don't spam WARNING
        # for the expected non-VSF case; log at DEBUG.
        msg = str(e).lower()
        if "404" in msg or "not found" in msg or "not_found" in msg:
            logger.debug(
                "aruba_aoscx.get_chassis_members: VSF endpoint not present (standalone, no VSF): %s",
                e,
            )
            return None
        logger.warning(
            "aruba_aoscx.get_chassis_members: unexpected fetch failure: %s",
            e, exc_info=True,
        )
        return None

    # Optional domain id — best-effort, helper accepts None.
    domain: str | None = None
    try:
        vsf_root = driver._get("system/vsf?attributes=domain_id")
        if isinstance(vsf_root, dict):
            raw_domain = vsf_root.get("domain_id")
            if raw_domain not in (None, 0):
                domain = str(raw_domain)
    except Exception:
        logger.debug("aruba_aoscx.get_chassis_members: domain_id fetch failed", exc_info=True)

    return _aoscx_members_from_rest_payload(data, domain=domain)
