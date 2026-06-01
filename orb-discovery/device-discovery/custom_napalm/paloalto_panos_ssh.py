# Copyright 2026 NetBox Labs Inc
"""
Custom PAN-OS SSH NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses ntc-templates 9.x for structured parsing.
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

_SECRET_TAG_RE = re.compile(
    r"(<(phash|password|psk|secret|hash|bind-password|api-key)>)"
    r"[^<]*"
    r"(</\2>)"
)


def _sanitize_config(text: str) -> str:
    return _SECRET_TAG_RE.sub(r"\1<redacted>\3", text)


def _parse_uptime(uptime_str: str) -> int:
    """Convert PAN-OS uptime string 'N days, H:MM:SS' to seconds."""
    m = re.match(r"(\d+)\s+days?,\s+(\d+):(\d+):(\d+)", uptime_str.strip())
    if not m:
        return 0
    days, hours, minutes, secs = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
    return days * 86400 + hours * 3600 + minutes * 60 + secs


def _netmask_to_prefix(netmask: str) -> int:
    """Convert dotted-decimal netmask to CIDR prefix length."""
    return sum(bin(int(octet)).count("1") for octet in netmask.split("."))


# ---------------------------------------------------------------------------
# get_modules — module / module bay discovery via PAN-OS SSH CLI
# ---------------------------------------------------------------------------

# Duplicated from custom_napalm.paloalto_panos per Approach A (per-driver
# bespoke). The substring table and ordering invariant are identical;
# a cross-driver test asserts the tuples stay in sync.


_MODULAR_PANOS_PREFIXES_SSH = ("PA-7050", "PA-7080", "PA-7500", "PA-5450")


def _is_modular_panos_ssh(model: str | None) -> bool:
    """Return True when PAN-OS model identifies an in-scope modular chassis."""
    upper = (model or "").strip().upper()
    return any(upper.startswith(p) for p in _MODULAR_PANOS_PREFIXES_SSH)


_PANOS_SSH_SKU_CLASSIFIER: tuple[tuple[str, str], ...] = (
    ("MPC", "supervisor"),
    ("SMC", "supervisor"),
    ("SFC", "linecard"),
    ("NPC", "linecard"),
    ("LFC", "linecard"),
    ("LPC", "linecard"),
    ("DPC", "linecard"),
    ("BC", "linecard"),
    ("NC", "linecard"),
)


def classify_module_type_panos_ssh(part_number: str) -> str:
    """Classify a PAN-OS card by hyphen-bounded token in the SKU (case-insensitive)."""
    pid = (part_number or "").upper()
    for token, mtype in _PANOS_SSH_SKU_CLASSIFIER:
        if f"-{token}-" in pid or pid.endswith(f"-{token}"):
            return mtype
    return "other"


def _panos_ssh_token_from_sku(part_number: str) -> str:
    """Extract the canonical card-type token from a PaloAlto SKU (Approach A duplicate)."""
    pid = (part_number or "").upper()
    for token, _ in _PANOS_SSH_SKU_CLASSIFIER:
        if f"-{token}-" in pid or pid.endswith(f"-{token}"):
            return token
    return ""


# `show chassis inventory` text-table row regex. The regex captures only
# the three driver-relevant columns (Slot / PID / Serial) and stops; the
# trailing Ports / Revision / Power(w) columns are left for finditer to
# skip when it advances to the next `^` anchor. The PID is anchored to
# the `PA-` prefix so header / separator lines never mis-match.
_PANOS_INVENTORY_ROW_RE = re.compile(
    # Real PAN-OS `show chassis inventory` column layout (per Palo Alto KB
    # kA14u000000wlKJCAY):
    #   Slot  Component             Serial Number   Ports  Revision  Power(w)
    # Driver-relevant columns are Slot / Component (PID) / Serial — trailing
    # Ports/Revision/Power columns are skipped via the open-ended tail.
    #
    # Slot accepts alphanumerics OR may be empty: PA-5450 Base Card rows
    # in real PAN-OS output (per Palo Alto KB kA14u000000bpuACAQ) print
    # the Slot column blank before the numbered NC/DPC/MPC slots — the
    # BC card has no slot id of its own. PA-7000 line slots are numeric;
    # PA-5450 base / system slots may carry letter labels like `BSC` /
    # `SYS`. PID matches PA-... AND the PAN-PA-... form Palo Alto's
    # compatibility docs use (PAN-PA-7000-100G-NPC-A, PAN-PA-5400-BC-A).
    # Serial accepts alphanumerics, hyphens, and dots — covers documented
    # 12-digit PA-7000/PA-5450 serials AND vendor-prefixed forms.
    r"^\s*(?P<slot>[A-Za-z0-9]*)\s*"
    r"(?P<pid>(?:PAN-)?PA-\S+)\s+"
    r"(?P<sn>[A-Za-z0-9.\-]+)"
    # No end-of-line anchor — `\s` includes `\n` even under MULTILINE, so
    # consuming trailing columns greedily would eat across rows. After the
    # serial column, finditer advances to the next `^` match.
    ,
    re.MULTILINE,
)


def _parse_chassis_inventory_text(text: str) -> list[dict]:
    """Parse `show chassis inventory` text rows; PID-anchored regex."""
    rows: list[dict] = []
    for m in _PANOS_INVENTORY_ROW_RE.finditer(text or ""):
        rows.append({
            "slot": m.group("slot"),
            "pid": m.group("pid"),
            "sn": m.group("sn"),
        })
    return rows


def _panos_ssh_build_bays(rows: list[dict]) -> list[_ModuleBay]:
    """Build one top-level bay per inventory row; description derived from SKU."""
    bays: list[_ModuleBay] = []
    for row in rows:
        slot = row.get("slot") or ""
        pid = row.get("pid") or ""
        sn = row.get("sn") or ""
        if not (pid and sn):
            continue
        mtype = classify_module_type_panos_ssh(pid)
        if mtype == "other":
            continue
        token = _panos_ssh_token_from_sku(pid)
        # PA-5450 Base Card prints with a blank Slot column in real PAN-OS
        # output — synthesize a bay name from the SKU token so the bay
        # still emits with a stable human-readable id.
        if not slot:
            slot = token
        if not slot:
            continue
        bays.append(_ModuleBay(
            name=slot, position=slot,
            module=_ModuleEntry(
                model=pid, serial=sn, type=mtype, description=token,
            ),
        ))
    return bays


# `show system info` model row, e.g. "model: PA-7080"
_PANOS_SSH_MODEL_RE = re.compile(r"^\s*model\s*:\s*(?P<model>\S+)\s*$", re.MULTILINE)


def _extract_model_from_system_info(text: str) -> str:
    """Extract `model:` field from `show system info` text output."""
    m = _PANOS_SSH_MODEL_RE.search(text or "")
    return m.group("model") if m else ""


def _panos_ssh_get_modules_impl(driver) -> dict | None:
    """
    Module discovery for PaloAlto PAN-OS via SSH CLI.

    1. Issue `show system info`, read the model.
    2. Short-circuit on non-modular models.
    3. Issue `show chassis inventory` and parse the fixed-width table.
    """
    try:
        info_text = driver.device.send_command("show system info")
    except Exception as e:
        logger.warning("paloalto_panos_ssh.get_modules: show system info failed: %s", e)
        return None
    model = _extract_model_from_system_info(info_text or "")
    if not _is_modular_panos_ssh(model):
        return None
    try:
        inv_text = driver.device.send_command("show chassis inventory")
    except Exception as e:
        logger.warning("paloalto_panos_ssh.get_modules: show chassis inventory failed: %s", e)
        return None
    rows = _parse_chassis_inventory_text(inv_text or "")
    bays = _panos_ssh_build_bays(rows)
    if not bays:
        return None
    return _modules_to_payload({
        None: _MemberModules(bays=bays, interfaces_by_bay={}),
    })


class PANOSSHDriver(_napalm_base.NetworkDriver):
    """PAN-OS NAPALM driver using SSH CLI + ntc-templates (read-only subset for device-discovery)."""

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

    def open(self):
        """Open an SSH connection to the device via Netmiko."""
        self.device = self._netmiko_open(
            "paloalto_panos", netmiko_optional_args=self.netmiko_optional_args
        )

    def close(self):
        """Close the connection."""
        self._netmiko_close()

    def is_alive(self):
        """Return connection liveness."""
        if self.device is None:
            return {"is_alive": False}
        try:
            null = chr(0)
            self.device.write_channel(null)
            return {"is_alive": self.device.remote_conn.transport.is_active()}
        except (EOFError, OSError, AttributeError):
            return {"is_alive": False}

    # ------------------------------------------------------------------
    # NAPALM getters
    # ------------------------------------------------------------------

    def get_facts(self) -> dict:
        """Return general device facts."""
        info_out = self.device.send_command("show system info")
        parsed = parse_output(platform="paloalto_panos", command="show system info", data=info_out)
        if not parsed:
            return {}

        row = parsed[0]

        hw_out = self.device.send_command("show interface hardware")
        hw_parsed = parse_output(
            platform="paloalto_panos", command="show interface hardware", data=hw_out
        )
        interface_list = sorted(r["interface"] for r in hw_parsed if r.get("interface"))

        return {
            "hostname": row.get("hostname", "Unknown"),
            "vendor": "Palo Alto Networks",
            "model": row.get("model", "Unknown"),
            "os_version": row.get("os", "Unknown"),
            "serial_number": row.get("serial", "Unknown"),
            "uptime": float(_parse_uptime(row.get("uptime", ""))),
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """
        Return interface details keyed by interface name (physical + sub-interfaces).

        Physical NICs come from ``show interface hardware`` (provides MAC,
        speed, link state). Sub-interfaces (``ethernet1/1.100``) are not
        listed by ``show interface hardware`` — they're enumerated by
        ``show interface logical``. We merge both: physical entries get the
        full hardware detail; sub-interfaces inherit their parent's MAC
        (PAN-OS sub-interfaces share the parent MAC by design) and default
        speed/state. Without this merge, sub-interfaces would have IPs
        emitted by get_interfaces_ip() but no matching interface entry,
        and the translator would drop them.
        """
        hw_out = self.device.send_command("show interface hardware")
        parsed = parse_output(
            platform="paloalto_panos", command="show interface hardware", data=hw_out
        )

        interfaces = {}
        for row in parsed:
            intf = row.get("interface", "")
            if not intf:
                continue

            state = row.get("state", "").lower()
            speed_raw = row.get("speed", "")
            try:
                speed = float(speed_raw) if speed_raw not in ("ukn", "[n/a]", "", None) else 0.0
            except ValueError:
                speed = 0.0

            mac_raw = row.get("mac_address", "")
            try:
                mac_address = normalize_mac(mac_raw) if mac_raw else ""
            except Exception:
                mac_address = mac_raw

            interfaces[intf] = {
                "is_up": state == "up",
                "is_enabled": True,
                "description": "",
                "last_flapped": -1.0,
                "mtu": 0,
                "speed": speed,
                "mac_address": mac_address,
            }

        # Merge sub-interfaces from `show interface logical`. PAN-OS
        # sub-interfaces share the parent NIC's MAC and follow the parent's
        # link state, so use parent values as the sane default when the
        # logical output doesn't expose per-sub MAC / speed.
        logical_out = self.device.send_command("show interface logical")
        try:
            logical_parsed = parse_output(
                platform="paloalto_panos", command="show interface logical", data=logical_out
            )
        except Exception:
            # Don't silently swallow — template drift would otherwise drop
            # every sub-interface without surfacing the cause. DEBUG keeps
            # the warning floor low for installs that genuinely return
            # empty / unparseable logical output.
            logger.debug("Failed to parse 'show interface logical' output", exc_info=True)
            logical_parsed = []
        for row in logical_parsed:
            intf = row.get("interface", "")
            if not intf or "." not in intf or intf in interfaces:
                continue
            parent_name = intf.split(".", 1)[0]
            if parent_name not in interfaces:
                # Orphan sub-interface — parent wasn't enumerated by
                # ``show interface hardware``. Skipping rather than
                # emitting with fake defaults so the translator doesn't
                # see an unparentable virtual interface in NetBox.
                logger.debug(
                    "Skipping orphan sub-interface %s — parent %s not found",
                    intf, parent_name,
                )
                continue
            parent_data = interfaces[parent_name]
            interfaces[intf] = {
                "is_up": parent_data["is_up"],
                "is_enabled": True,
                "description": "",
                "last_flapped": -1.0,
                "mtu": 0,
                "speed": parent_data["speed"],
                "mac_address": parent_data["mac_address"],
            }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface."""
        interfaces_ip: dict = {}

        # Logical interfaces (data-plane IPs)
        logical_out = self.device.send_command("show interface logical")
        parsed = parse_output(
            platform="paloalto_panos", command="show interface logical", data=logical_out
        )
        for row in parsed:
            intf = row.get("interface", "")
            ip_raw = row.get("ip_address", "")
            if not intf or not ip_raw or ip_raw in ("N/A", "unknown", ""):
                continue
            try:
                ip, prefix = ip_raw.split("/")
                interfaces_ip.setdefault(intf, {}).setdefault("ipv4", {})[ip] = {
                    "prefix_length": int(prefix)
                }
            except (ValueError, AttributeError):
                continue

        # Management interface
        mgmt_out = self.device.send_command("show interface management")
        mgmt_parsed = parse_output(
            platform="paloalto_panos", command="show interface management", data=mgmt_out
        )
        for row in mgmt_parsed:
            ipv4 = row.get("ipv4_address", "")
            netmask = row.get("ipv4_netmask", "")
            if ipv4 and netmask and ipv4 not in ("unknown", "N/A", ""):
                prefix = _netmask_to_prefix(netmask)
                interfaces_ip.setdefault("management", {}).setdefault("ipv4", {})[ipv4] = {
                    "prefix_length": prefix
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
            config["running"] = self.device.send_command("show config running")
        if retrieve in ("all", "candidate"):
            config["candidate"] = self.device.send_command("show config candidate")

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """PAN-OS does not expose a traditional VLAN table via SSH CLI."""
        return {}

    def get_modules(self) -> dict | None:
        """Return per-chassis module / module bay inventory or None."""
        return _panos_ssh_get_modules_impl(self)
