# Copyright 2026 NetBox Labs Inc
"""
Custom Cisco FXOS NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko (cisco_nxos device type — FXOS uses NX-OS-derived CLI) combined
with ntc-templates 9.x for structured parsing.  Commands whose output is
format-compatible with NX-OS use the ``cisco_nxos`` platform template;
``show version`` uses regex because its FXOS-specific format differs from
the NX-OS equivalent.
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.helpers import mac as normalize_mac
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import ParsingException, parse_output
from textfsm.parser import TextFSMError

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

_PARSE_ERRORS = (TextFSMError, ParsingException)

logger = logging.getLogger(__name__)

# --- config sanitization (Cisco FXOS / NX-OS-lineage sensitive fields) ---
# enable password / enable secret — require the "enable" keyword so that
# directives like "password strength-check" or "password policy" are not touched.
_ENABLE_PASSWORD_RE = re.compile(
    r"^(\s*enable\s+(?:password|secret)(?:\s+\d+)?)\s+\S+",
    re.M | re.I,
)
# Standalone "secret <N> <hash>" lines (e.g. inside username / role blocks).
_SECRET_RE = re.compile(
    r"^(\s*secret(?:\s+\d+)?)\s+\S+",
    re.M | re.I,
)
_USERNAME_RE = re.compile(
    r"^(\s*username\s+\S+\s+(?:password|secret)(?:\s+\d+)?)\s+\S+",
    re.M | re.I,
)
_SNMP_COMMUNITY_RE = re.compile(
    r"^(\s*snmp-server\s+community)\s+\S+",
    re.M | re.I,
)
_KEY_STRING_RE = re.compile(
    r"^(\s*key-string(?:\s+\d+)?)\s+\S+",
    re.M | re.I,
)
_PRE_SHARED_KEY_RE = re.compile(
    r"^(\s*pre-shared-key)\s+\S+",
    re.M | re.I,
)
_TACACS_KEY_RE = re.compile(
    r"^(\s*(?:tacacs-server\b[^\n]*?\bkey|radius-server\b[^\n]*?\bkey)(?:\s+\d+)?)\s+\S+",
    re.M | re.I,
)


def _sanitize_config(text: str) -> str:
    text = _ENABLE_PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _SECRET_RE.sub(r"\1 <redacted>", text)
    text = _USERNAME_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_COMMUNITY_RE.sub(r"\1 <redacted>", text)
    text = _KEY_STRING_RE.sub(r"\1 <redacted>", text)
    text = _PRE_SHARED_KEY_RE.sub(r"\1 <redacted>", text)
    text = _TACACS_KEY_RE.sub(r"\1 <redacted>", text)
    return text


def _parse_uptime(uptime_str: str) -> float:
    """Convert FXOS uptime string to total seconds."""
    seconds = 0
    for pattern, factor in (
        (r"(\d+)\s+year", 365 * 86400),
        (r"(\d+)\s+week", 7 * 86400),
        (r"(\d+)\s+day", 86400),
        (r"(\d+)\s+hour", 3600),
        (r"(\d+)\s+min", 60),
        (r"(\d+)\s+sec", 1),
    ):
        m = re.search(pattern, uptime_str, re.IGNORECASE)
        if m:
            seconds += int(m.group(1)) * factor
    return float(seconds)


def _parse_speed(speed_raw: str) -> float:
    """Convert NX-OS speed string ('10 Gb/s', '1 Gb/s', '100 Mb/s') to float Mbps."""
    m = re.match(r"(\d+)\s*(Gb/s|Mb/s|Kb/s)", speed_raw.strip(), re.IGNORECASE)
    if not m:
        return 0.0
    num = float(m.group(1))
    unit = m.group(2).lower()
    if unit == "gb/s":
        return num * 1000.0
    if unit == "kb/s":
        return num / 1000.0
    return num  # Mb/s


def _parse_show_version(ver_raw: str, default_hostname: str) -> tuple[str, str, str, str, float]:
    """Extract (hostname, model, os_version, serial_number, uptime) from FXOS show version."""
    hostname = default_hostname
    model = "Unknown"
    os_version = "Unknown"
    serial_number = "Unknown"
    uptime = 0.0

    if not ver_raw:
        return hostname, model, os_version, serial_number, uptime

    m = re.search(r"Device name:\s+(\S+)", ver_raw)
    if m:
        hostname = m.group(1)

    m = re.search(r"FXOS\)\s+Software,\s+Version\s+(\S+)", ver_raw)
    if not m:
        # Fallback for banner text variations
        m = re.search(r"\bVersion\s+([\d.()]+)", ver_raw)
    if m:
        os_version = m.group(1)

    m = re.search(
        r"cisco\s+((?:Firepower|FPR)\S*(?:\s+\d+)?(?:\s+\S+)?)\s+(?:Security|Chassis)",
        ver_raw,
    )
    if m:
        model = m.group(1).strip()

    m = re.search(r"Chassis serial number:\s+(\S+)", ver_raw)
    if m:
        serial_number = m.group(1)

    m = re.search(r"Kernel uptime is\s+(.+?)$", ver_raw, re.M)
    if m:
        uptime = _parse_uptime(m.group(1))

    return hostname, model, os_version, serial_number, uptime


_FXOS_MODULE_RE = re.compile(r"^Module\s+(\d+)$", re.IGNORECASE)
_FXOS_NETMOD_RE = re.compile(r"^Network Module\s+(\d+)$", re.IGNORECASE)


def classify_module_type_fxos(pid: str, name: str) -> str:
    """
    Classify a Firepower show-inventory row.

    Security modules (FPR9K-SM-*) and network modules (FPR*-NM-*) are the
    line-card-equivalent FRUs. MIO/supervisor PIDs -> supervisor. PSU/fan
    recognized but never emitted.
    """
    if is_optic_pid(pid):
        return "transceiver"
    upper = pid.strip().upper()
    if "-SUP" in upper or upper.endswith("-MIO"):
        return "supervisor"
    if upper.startswith("PWR-") or "-PS-" in upper or upper.endswith("-PS-AC") or "PSU" in upper:
        return "psu"
    if "FAN" in upper:
        return "fan"
    return "linecard"


def _fxos_get_modules_impl(driver) -> dict | None:
    """Standalone module discovery for Firepower 9300/4100 chassis."""
    try:
        inv_raw = driver.device.send_command("show inventory")
    except Exception as e:
        logger.warning("fxos.get_modules: show inventory failed: %s", e)
        return None
    if not inv_raw:
        return None
    try:
        rows = parse_output(platform="cisco_nxos", command="show inventory", data=inv_raw)
    except _PARSE_ERRORS:
        logger.warning("fxos.get_modules: show inventory parse failed")
        return None

    bays: list[_ModuleBay] = []
    for row in rows or []:
        name = (row.get("name") or "").strip().strip('"')
        pid = (row.get("pid") or "").strip()
        sn = (row.get("sn") or "").strip()
        descr = (row.get("descr") or "").strip().strip('"')
        if not (pid and sn):
            continue
        mod_match = _FXOS_MODULE_RE.match(name)
        netmod_match = _FXOS_NETMOD_RE.match(name)
        if not (mod_match or netmod_match):
            continue  # chassis / PSU / fan / unrecognized rows are not slot bays
        mtype = classify_module_type_fxos(pid, name)
        if mtype in ("psu", "fan", "supervisor"):
            # FXOS show inventory can list the MIO/supervisor as `Module N`
            # with a FPR9K-SUP PID; the supervisor is the integrated Chassis
            # row in our model, never a slot bay, so skip the row even when
            # it appears under a Module name (would otherwise collide with
            # a real security-module slot N).
            continue
        # Security modules emit bay name = slot number ("1"); network
        # modules keep their full NAME ("Network Module 1") since they share
        # the chassis with security modules and could collide on bare ints.
        if mod_match:
            bay_name = mod_match.group(1)
            position = mod_match.group(1)
        else:
            bay_name = name
            position = netmod_match.group(1)
        bays.append(_ModuleBay(
            name=bay_name, position=position,
            module=_ModuleEntry(model=pid, serial=sn, type=mtype, description=descr),
        ))

    if not bays:
        return None
    return _modules_to_payload({None: _MemberModules(bays=bays, interfaces_by_bay={})})


class FXOSDriver(_napalm_base.NetworkDriver):
    """
    Cisco FXOS NAPALM driver (read-only subset for device-discovery).

    FXOS uses an NX-OS-derived CLI, so Netmiko's cisco_nxos device type is
    used for the SSH session.  Commands whose output format is shared with
    NX-OS are parsed with ntc-templates (cisco_nxos platform);
    ``show version`` is parsed with regex due to FXOS-specific output.
    """

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Initialise the driver."""
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
        """Open an SSH connection via Netmiko (cisco_nxos device type)."""
        self.device = self._netmiko_open(
            "cisco_nxos", netmiko_optional_args=self.netmiko_optional_args
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
        """
        Return general device facts.

        Data sources
        ~~~~~~~~~~~~
        * ``show version``  — hostname, model, os_version, serial_number, uptime
          (regex; FXOS format differs from NX-OS).
        * ``show inventory``  — serial_number fallback; parsed with
          ntc-templates cisco_nxos platform.
        * ``show interface``  — interface_list; parsed with
          ntc-templates cisco_nxos platform.
        """
        ver_raw = self.device.send_command("show version")
        hostname, model, os_version, serial_number, uptime = _parse_show_version(
            ver_raw, self.hostname
        )

        # serial fallback: parse chassis entry from show inventory
        if serial_number == "Unknown":
            serial_number, model = self._serial_from_inventory(model)

        # interface list from show interface (ntc-templates cisco_nxos).
        # Using show interface (not show ip interface brief) ensures names are in the
        # same canonical long form as get_interfaces() / get_interfaces_ip() output
        # (e.g. "Ethernet1/1" not the abbreviated "Eth1/1").
        intf_raw = self.device.send_command("show interface")
        interface_list: list[str] = []
        if intf_raw:
            try:
                intf_parsed = parse_output(
                    platform="cisco_nxos",
                    command="show interface",
                    data=intf_raw,
                )
                interface_list = sorted(
                    r["interface"] for r in intf_parsed if r.get("interface")
                )
            except _PARSE_ERRORS:
                logger.debug("Failed to parse show interface for interface_list; will be empty")

        return {
            "hostname": hostname,
            "vendor": "Cisco",
            "model": model,
            "os_version": os_version,
            "serial_number": serial_number,
            "uptime": uptime,
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def _serial_from_inventory(self, current_model: str) -> tuple[str, str]:
        """Return (serial_number, model) from show inventory chassis entry."""
        inv_raw = self.device.send_command("show inventory")
        if not inv_raw:
            return "Unknown", current_model
        try:
            inv_parsed = parse_output(
                platform="cisco_nxos", command="show inventory", data=inv_raw
            )
        except _PARSE_ERRORS:
            logger.debug("Failed to parse show inventory; serial_number will be Unknown")
            return "Unknown", current_model
        chassis = next(
            (r for r in inv_parsed if "chassis" in r.get("name", "").lower()),
            inv_parsed[0] if inv_parsed else None,
        )
        if not chassis:
            return "Unknown", current_model
        serial = chassis.get("sn") or "Unknown"
        # Only fall back to the inventory PID for model when show version didn't provide one.
        model = (chassis.get("pid") or "Unknown") if current_model == "Unknown" else current_model
        return serial, model

    def get_interfaces(self) -> dict:
        """
        Return interface details keyed by interface name.

        Parsed with ntc-templates cisco_nxos platform (``show interface``).
        """
        raw = self.device.send_command("show interface")
        if not raw:
            return {}

        try:
            parsed = parse_output(
                platform="cisco_nxos", command="show interface", data=raw
            )
        except _PARSE_ERRORS:
            logger.debug("Failed to parse show interface; returning empty dict")
            return {}
        interfaces = {}
        for row in parsed:
            intf = row.get("interface", "")
            if not intf:
                continue

            link_status = row.get("link_status", "").lower()
            admin_state = row.get("admin_state", "").lower()
            # is_up: physical link AND line-protocol must both be up.
            # "X is up, line protocol is down" → admin_state="down" via the template rule
            # "^${INTF} is ${LINK_STATUS}, line protocol is ${ADMIN_STATE}".
            # Use startswith("down") to also catch decorated variants like "down (suspended)".
            is_up = link_status == "up" and not admin_state.startswith("down")
            # is_enabled: interface has not been explicitly shut down by an admin action.
            # "admin" appears in link_status for both "down (admin down)" (FXOS) and
            # "administratively down" (standard NX-OS form), covering both shutdown variants.
            # "down (Link not connected)" contains no "admin" → correctly treated as enabled.
            is_enabled = "admin" not in link_status and "disable" not in admin_state

            mac_raw = row.get("mac_address", "")
            try:
                mac_address = normalize_mac(mac_raw) if mac_raw else ""
            except Exception:
                mac_address = mac_raw

            mtu_raw = row.get("mtu", "")
            try:
                mtu = int(mtu_raw) if mtu_raw else 0
            except ValueError:
                mtu = 0

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
        """
        Return IP addresses per interface.

        Parsed with ntc-templates cisco_nxos platform (``show interface``).
        The full interface output includes ``Internet address is X.X.X.X/N``
        which the template captures in ``ip_address`` + ``prefix_length`` fields,
        giving us CIDR prefix lengths without a second CLI round-trip.
        Only IPv4 addresses are returned.
        """
        raw = self.device.send_command("show interface")
        if not raw:
            return {}

        try:
            parsed = parse_output(
                platform="cisco_nxos", command="show interface", data=raw
            )
        except _PARSE_ERRORS:
            logger.debug("Failed to parse show interface for IPs; returning empty dict")
            return {}
        interfaces_ip: dict = {}
        for row in parsed:
            intf = row.get("interface", "")
            ip = row.get("ip_address", "")
            prefix_raw = row.get("prefix_length", "")
            if not intf or not ip or not prefix_raw:
                continue
            try:
                interfaces_ip.setdefault(intf, {}).setdefault("ipv4", {})[ip] = {
                    "prefix_length": int(prefix_raw)
                }
            except (ValueError, AttributeError):
                continue

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
            config["running"] = self.device.send_command("show running-config")

        if retrieve in ("all", "startup"):
            config["startup"] = self.device.send_command("show startup-config")

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """FXOS chassis does not expose a traditional switch VLAN table."""
        return {}

    def get_modules(self) -> dict | None:
        """
        Return Module / ModuleBay inventory for a Firepower modular chassis.

        Standalone only (Firepower 9300/4100 is a single chassis). Returns
        None for non-modular Firepower (1000/2100) with no Module rows.
        """
        return _fxos_get_modules_impl(self)
