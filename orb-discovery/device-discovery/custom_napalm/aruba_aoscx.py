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
            "vendor": "Aruba",
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
