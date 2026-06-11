# Copyright 2026 NetBox Labs Inc
# Based on napalm-huawei-vrp (Apache-2.0): https://github.com/napalm-automation-community/napalm-huawei-vrp
"""
Custom Huawei VRP NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses ntc-templates 9.x for structured parsing wherever templates are available;
falls back to regex for commands without templates (serial number, IPv6).
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.helpers import mac as normalize_mac
from napalm.base.netmiko_helpers import netmiko_args
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
    is_optic_pid,
)
from custom_napalm._modules import (
    to_payload as _modules_to_payload,
)
from custom_napalm._vlan import (
    SwitchportInfo,
    classify_switchport,
    coerce_vid,
    parse_vlan_range_string,
)

logger = logging.getLogger(__name__)


def _huawei_row_to_switchport_info(row: dict) -> SwitchportInfo:
    """
    Map an ntc-templates ``display port vlan`` row to a SwitchportInfo.

    LINK_TYPE values from VRP: access, trunk, hybrid, desirable, auto.
    Hybrid collapses to trunk (native + tagged set). LNP-negotiated link
    types (``auto`` / ``desirable``) still carry VLAN state — mode is
    inferred from membership shape (any trunk VLAN list ⇒ trunk;
    otherwise access). Unknown / blank link-types map to routed.
    """
    link_type = (row.get("link_type") or "").strip().lower()
    pvid = coerce_vid(row.get("vlan_id"))

    trunk_list = row.get("trunk_vlan_list") or []
    if isinstance(trunk_list, str):
        trunk_list = [trunk_list]
    spec = ",".join(str(v) for v in trunk_list if v)
    if spec:
        vids, is_wildcard = parse_vlan_range_string(spec)
        allowed: list[int] | str | None = "all" if is_wildcard else vids
    else:
        allowed = None

    if link_type in ("auto", "desirable"):
        # LNP-negotiated: trunk if there's a tagged-VLAN list, otherwise access.
        link_type = "trunk" if (allowed not in (None, [])) else "access"
    elif link_type == "dot1q-tunnel":
        # QinQ tunnel ports are L2 access ports on the service VID. Q-in-Q
        # outer/inner tagging is out of scope for v1, but treat the port
        # as access on the PVID rather than dropping VLAN data entirely.
        link_type = "access"

    if link_type == "access":
        return SwitchportInfo(
            enabled=True,
            admin_mode="access",
            oper_mode="access",
            access_vlan=pvid,
            native_vlan=None,
            allowed_vlans=None,
        )
    if link_type in ("trunk", "hybrid"):
        return SwitchportInfo(
            enabled=True,
            admin_mode="trunk",
            oper_mode="trunk",
            access_vlan=None,
            native_vlan=pvid,
            allowed_vlans=allowed,
        )
    return SwitchportInfo(
        enabled=False,
        admin_mode=None,
        oper_mode=None,
        access_vlan=None,
        native_vlan=None,
        allowed_vlans=None,
    )

# "password cipher <hash>" / "psk cipher <hash>" / "key cipher <hash>"
# Excludes algorithm-list lines like "ssh server cipher aes256_ctr" where
# "cipher" introduces an algorithm name, not a credential.
_PASSWORD_CIPHER_RE = re.compile(r"(password\s+cipher)\s+\S+", re.IGNORECASE)
_PSK_CIPHER_RE = re.compile(r"(psk\s+cipher)\s+\S+", re.IGNORECASE)
_KEY_CIPHER_RE = re.compile(r"(key\s+cipher)\s+\S+", re.IGNORECASE)

# "secret <algorithm-id> <hash>" — digit required; avoids matching non-credential
# uses such as OSPF/BGP lines that happen to contain the word "secret".
_SECRET_RE = re.compile(r"(\bsecret\s+\d+)\s+\S+", re.IGNORECASE)

# Anchored to the SNMP agent command form to avoid false positives on
# BGP/OSPF community attributes.
_SNMP_COMMUNITY_RE = re.compile(
    r"(snmp-agent\s+community\s+(?:read|write))\s+\S+", re.IGNORECASE
)


def _sanitize_config(text: str) -> str:
    text = _PASSWORD_CIPHER_RE.sub(r"\1 <redacted>", text)
    text = _PSK_CIPHER_RE.sub(r"\1 <redacted>", text)
    text = _KEY_CIPHER_RE.sub(r"\1 <redacted>", text)
    text = _SECRET_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_COMMUNITY_RE.sub(r"\1 <redacted>", text)
    return text

# Uptime conversion constants
_HOUR_SECONDS = 3600
_DAY_SECONDS = 24 * _HOUR_SECONDS
_WEEK_SECONDS = 7 * _DAY_SECONDS
_YEAR_SECONDS = 365 * _DAY_SECONDS


def _parse_uptime(uptime_str: str) -> int:
    """Convert a Huawei VRP uptime string to total seconds."""
    seconds = 0

    for pattern, factor in (
        (r"(\d+)\s+year", _YEAR_SECONDS),
        (r"(\d+)\s+week", _WEEK_SECONDS),
        (r"(\d+)\s+day", _DAY_SECONDS),
        (r"(\d+)\s+hour", _HOUR_SECONDS),
        (r"(\d+)\s+minute", 60),
        (r"(\d+)\s+second", 1),
    ):
        m = re.search(pattern, uptime_str)
        if m:
            seconds += int(m.group(1)) * factor

    return seconds


def _separate_section(separator: str, content: str) -> list[str]:
    """Split CLI output into per-interface sections using a regex separator."""
    if not content:
        return []

    parts = re.split(separator, content, flags=re.M)
    if len(parts) == 1:
        return []

    parts.pop(0)  # discard empty preamble

    if len(parts) % 2 != 0:
        return []

    it = iter(parts)
    return [line + next(it, "") for line in it]


# ---------------------------------------------------------------------------
# Stack discovery — Huawei VRP iStack
# ---------------------------------------------------------------------------
#
# `display stack` on a VRP iStack-mode chassis emits a settings-block followed
# by a fixed-width row table. A typical iStack output looks like::
#
#     Stack mode: Yes
#     Stack topology type: Ring
#     Stack system MAC: 00e0-fc12-3456
#     ...
#
#     Slot   Role        Mac Address        Priority   Device Type
#     -----------------------------------------------------------------
#      1     Master      00e0-fc12-3456     100        S5720-32X-EI-AC
#      2     Standby     00e0-fc12-7890     100        S5720-32X-EI-AC
#      3     Slave       00e0-fc12-abcd     100        S5720-32X-EI-AC
#
# Note the Huawei terminology: ``Master`` / ``Standby`` / ``Slave`` — where
# ``Slave`` means "non-master, non-standby member" (the third+ unit), NOT
# "secondary master". This is the OPPOSITE of H3C Comware 5 (where Slave is
# the secondary master). We translate ``Slave`` to NetBox ``member`` here
# explicitly, BEFORE calling ``normalize_role`` (whose global map binds
# ``slave → standby`` for Comware-5 compatibility — see batch 4 PR #401).
#
# Per-member serial comes from ``display esn`` (already used by ``get_facts``);
# per-slot model is read from the same ``Device Type`` column of
# ``display stack`` (the ntc-template ``display device`` is brittle on VRP
# version skew and not required to retrieve usable data here).
#
# Standalone VRP (no iStack) returns ``Error: ...`` or empty output for
# ``display stack``; the impl logs DEBUG and returns None. CSS (Cluster
# Switch System, the modular-chassis VRP equivalent) is out of scope for
# this batch — CSS uses a different command (``display css status``) and
# requires a 4-tuple branch in ``parse_member_id`` for interface routing.

_VRP_STACK_ROW_RE = re.compile(
    r"""
    ^\s*
    (?P<id>\d+)\s+                                                   # Slot
    (?P<role>[A-Za-z]+)\s+                                           # Role
    (?P<mac>[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4})\s+          # MAC
    (?P<priority>\d+)\s+                                             # Priority
    (?P<model>\S+(?:\s+\S+)*?)                                       # Device Type — non-greedy
                                                                     #   so the optional trailing
                                                                     #   Slot/Chassis column on some
                                                                     #   VRP variants (CX310 etc.)
                                                                     #   doesn't get absorbed into
                                                                     #   the model. Multi-token
                                                                     #   model names like
                                                                     #   ``S5720-32X-EI-AC PWR-AC HW``
                                                                     #   are still captured in full
                                                                     #   because the optional
                                                                     #   `\d+/\d+` suffix doesn't
                                                                     #   match those trailing tokens.
    (?:\s+\d+/\d+)?                                                  # optional Slot/Chassis suffix
    \s*$
    """,
    re.VERBOSE,
)

# `display esn` formats. Stacked VRP repeats one block per slot.
# The serial separator is either a colon (`ESN of slot N: SN`) or — on a few
# VRP releases — `is:` (`ESN of slot N is: SN`). Anchor on an explicit
# colon-or-`is:` separator so a missing separator can't accidentally capture
# the literal `is:` as the serial token.
_VRP_ESN_SLOT_RE = re.compile(
    r"""
    ESN\s+of\s+slot\s+(?P<slot>\d+)
    \s*(?:is)?\s*:\s*
    (?P<serial>\S+)
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _normalize_vrp_istack_role(raw: str | None) -> str:
    """
    Map a Huawei iStack role token to NetBox semantics.

    Huawei iStack convention:
      - Master  → active
      - Standby → standby
      - Slave   → member  (third+ unit; differs from Comware 5 / IRF)

    Anything else falls back to the global ``normalize_role``.
    """
    raw_low = (raw or "").strip().lower()
    if raw_low == "master":
        return "active"
    if raw_low == "standby":
        return "standby"
    if raw_low == "slave":
        return "member"
    return normalize_role(raw)


def _parse_huawei_stack(text: str) -> list[dict]:
    """
    Parse ``display stack`` row table into a list of member dicts.

    Returns ``[{"id": int, "role": str, "priority": int, "mac": str,
    "model": str}, ...]``. The settings-block (Stack mode / topology /
    Bridge-MAC) and column header / separator lines all fail the regex
    and are skipped silently.
    """
    rows: list[dict] = []
    for line in (text or "").splitlines():
        m = _VRP_STACK_ROW_RE.match(line)
        if not m:
            continue
        rows.append({
            "id": int(m.group("id")),
            "role": m.group("role"),
            "priority": int(m.group("priority")),
            "mac": m.group("mac"),
            "model": (m.group("model") or "").strip(),
        })
    return rows


def _parse_vrp_esn_by_slot(text: str) -> dict[int, str]:
    """
    Return ``{slot_id: serial}`` extracted from ``display esn`` output.

    Stacked VRP devices print one line per slot (``ESN of slot N: <SN>``).
    The ``ESN of device: <SN>`` standalone form is intentionally NOT
    consumed here — chassis discovery only runs on multi-member stacks
    and a standalone payload falls through to the single-Device path.
    """
    out: dict[int, str] = {}
    for m in _VRP_ESN_SLOT_RE.finditer(text or ""):
        try:
            slot = int(m.group("slot"))
        except (TypeError, ValueError):
            continue
        sn = (m.group("serial") or "").strip()
        if sn and slot not in out:
            out[slot] = sn
    return out


def _huawei_vrp_get_chassis_members_impl(driver) -> dict | None:
    """
    Implementation of ``VRPDriver.get_chassis_members`` (factored for testability).

    Parses ``display stack`` for member id / role / priority / MAC / model
    and joins per-member serial from ``display esn``. Standalone VRP /
    non-iStack devices fall through to None at DEBUG. CSS (modular-chassis
    VRP) is out of scope for this batch and not detected; CSS-configured
    devices simply emit no `display stack` rows and fall through the same
    way as standalone — no false positives, no spurious WARN.
    """
    try:
        stack_out = driver.device.send_command("display stack")
    except Exception:
        logger.warning(
            "huawei_vrp.get_chassis_members: display stack failed", exc_info=True
        )
        return None

    rows = _parse_huawei_stack(stack_out or "")
    if not rows:
        # Standalone or CSS — neither produces parseable stack rows. Log at
        # DEBUG and fall through; CSS support is deferred to a follow-up
        # batch.
        logger.debug(
            "huawei_vrp.get_chassis_members: no stack rows in `display stack` output"
        )
        return None

    try:
        esn_out = driver.device.send_command("display esn")
    except Exception:
        logger.warning(
            "huawei_vrp.get_chassis_members: display esn failed", exc_info=True
        )
        esn_out = ""

    serial_by_slot = _parse_vrp_esn_by_slot(esn_out or "")

    members: list[ChassisMember] = []
    for row in rows:
        sid = row["id"]
        try:
            mac_canon = normalize_mac(row["mac"])
        except Exception:
            # netaddr's AddrFormatError extends Exception, not ValueError —
            # broaden the catch so a future regex relaxation doesn't crash
            # discovery on a malformed MAC.
            mac_canon = None
        members.append(
            ChassisMember(
                id=sid,
                serial=serial_by_slot.get(sid, ""),
                model=row.get("model") or None,
                role=_normalize_vrp_istack_role(row["role"]),
                priority=row["priority"],
                mac=mac_canon,
                state=row["role"],
            )
        )
    return to_payload(members, domain=None)


def classify_module_type_vrp(board: str, model: str) -> str:
    """
    Classify a Huawei VRP display-device board row.

    MPU (main processing unit) -> supervisor; LPU (line) / SFU (fabric) ->
    linecard; PWR/FAN -> psu/fan (not emitted). Board-type token is the
    primary signal (CE-MPUA, CE-L36CQ-FD, CE-SFU08D, ...). Unknown board
    types (e.g. CMU monitoring units) classify as `other` and the emit loop
    drops them — defaulting to linecard would mis-discover non-forwarding
    auxiliary FRUs as NetBox linecards.
    """
    b = (board or "").upper()
    if is_optic_pid(model):
        return "transceiver"
    if "MPU" in b:
        return "supervisor"
    if "LPU" in b or "SFU" in b or b.startswith("CE-L"):
        return "linecard"
    if "PWR" in b or "POWER" in b:
        return "psu"
    if "FAN" in b:
        return "fan"
    return "other"


def _vrp_get_modules_impl(driver) -> dict | None:
    """
    Standalone modular slot-bay discovery for Huawei CE12800.

    Joins `display device` (slot + board type) with `display esn`
    (slot -> serial). Scoped to the CloudEngine `Device status:` 8-column
    layout that the `huawei_vrp_display_device` ntc-template parses. NE40E
    `display device` uses a different 6-column layout the template does
    not match, so NE40E returns no modules in v1 (documented limitation
    alongside no optic sub-bays and no CSS-of-modular dispatch).
    """
    try:
        dev_raw = driver.device.send_command("display device")
        esn_raw = driver.device.send_command("display esn")
    except Exception as e:
        logger.warning("vrp.get_modules: display command failed: %s", e)
        return None
    try:
        rows = parse_output(platform="huawei_vrp", command="display device", data=dev_raw or "")
    except Exception:
        logger.warning("vrp.get_modules: display device parse failed")
        return None
    if not rows:
        return None
    # REUSE the existing parser. `_parse_vrp_esn_by_slot` returns {int slot: serial}
    # (int keys — already in the driver, used by get_chassis_members). Do NOT invent
    # a new ESN parser; the `ESN of slot N: SN` format it accepts matches the fixture.
    sn_by_slot = _parse_vrp_esn_by_slot(esn_raw or "")

    bays: list[_ModuleBay] = []
    for row in rows:
        slot = str(row.get("slot") or "").strip()
        # Board type lands in `pid` on the CE `Device status:` layout; `card`
        # is `-`. Verified by running the template.
        board = str(row.get("pid") or "").strip()
        if not slot or not board or board == "-":
            continue
        try:
            slot_id = int(slot)
        except ValueError:
            continue
        serial = sn_by_slot.get(slot_id, "")  # int key — matches _parse_vrp_esn_by_slot
        if not serial:
            continue  # serial-less slot is dropped by _validate_bay anyway
        mtype = classify_module_type_vrp(board, board)
        if mtype in ("psu", "fan", "other"):
            continue
        bays.append(_ModuleBay(
            name=slot, position=slot,
            module=_ModuleEntry(model=board, serial=serial, type=mtype, description=""),
        ))

    if not bays:
        return None
    return _modules_to_payload({None: _MemberModules(bays=bays, interfaces_by_bay={})})


# "display ip vpn-instance" summary rows: name, optional RD (AS:nn or
# IP:nn form), address-family column. Parsed driver-locally because the
# ntc-template for this command requires an RD on every row and
# error-exits on VPN instances without one configured. The AF column
# prints "ipv4-family" / "ipv6-family" on some VRP releases and plain
# "IPv4" / "IPv6" on others (the ntc-templates real-device fixture uses
# the latter) — both forms anchor the row.
_VRP_VPN_SUMMARY_ROW_RE = re.compile(
    r"^\s*(?P<name>\S+)\s+(?:(?P<rd>\S+:\S+)\s+)?(?i:ipv[46](?:-family)?)\s*$"
)


def _vrp_parse_vpn_instance_rds(raw: str) -> dict[str, str]:
    """
    Map VPN-instance name → RD ("" when unconfigured) from the summary.

    VRP configures the RD per address family, so an instance prints one
    row per AF and the RD may live on either — the first non-empty RD
    wins. The header line never matches (its name column is
    "VPN-Instance" and its AF column is "Address-family", which the
    ipv4/ipv6 anchor rejects).
    """
    rds: dict[str, str] = {}
    for line in raw.splitlines():
        m = _VRP_VPN_SUMMARY_ROW_RE.match(line)
        if not m:
            continue
        name = m.group("name")
        rd = m.group("rd") or ""
        if name not in rds or (rd and not rds[name]):
            rds[name] = rd
    return rds


class VRPDriver(_napalm_base.NetworkDriver):
    """Huawei VRP NAPALM driver (read-only subset for device-discovery)."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Initialize the driver."""
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.device = None

        if optional_args is None:
            optional_args = {}

        transport = optional_args.get("transport", "ssh")
        if transport not in ("ssh", "telnet"):
            raise ValueError(f"Unsupported transport '{transport}': must be 'ssh' or 'telnet'")
        self.transport = transport
        self.netmiko_optional_args = netmiko_args(optional_args)
        default_port = {"ssh": 22, "telnet": 23}
        self.netmiko_optional_args.setdefault("port", default_port[self.transport])

    def open(self):
        """Open an SSH (or Telnet) connection to the device via Netmiko."""
        device_type = "huawei_telnet" if self.transport == "telnet" else "huawei"
        self.device = self._netmiko_open(
            device_type, netmiko_optional_args=self.netmiko_optional_args
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
        vendor = "Huawei"
        hostname = os_version = model = "Unknown"
        uptime = -1
        serial_number: list[str] = []

        # --- version / model / uptime ---
        ver_output = self.device.send_command("display version")
        parsed_ver = parse_output(platform="huawei_vrp", command="display version", data=ver_output)
        if parsed_ver:
            row = parsed_ver[0]
            os_version = row.get("vrp_version", "Unknown")
            model = row.get("model", "Unknown").strip() or "Unknown"
            uptime = _parse_uptime(row.get("uptime", ""))

        # --- hostname (no template: just grep sysname) ---
        sysname_out = self.device.send_command("display current-configuration | inc sysname")
        if "sysname " in sysname_out:
            hostname = sysname_out.split("sysname ", 1)[1].strip().splitlines()[0].strip()

        # --- serial number ---
        # 'display esn' returns one line per slot for stacked devices
        esn_out = self.device.send_command("display esn")
        serial_number = re.findall(r"ESN\s+of\s+slot\s+\S+\s+(\S+)", esn_out, flags=re.M)
        if not serial_number:
            # Fallback for single devices: "ESN of device: <SN>"
            m = re.search(r"ESN\s+of\s+device\s*:\s*(\S+)", esn_out, flags=re.M)
            if m:
                serial_number = [m.group(1)]

        # --- interface list ---
        brief_out = self.device.send_command("display interface brief")
        parsed_brief = parse_output(
            platform="huawei_vrp", command="display interface brief", data=brief_out
        )
        interface_list = [row["interface"] for row in parsed_brief if row.get("interface")]

        return {
            "uptime": int(uptime),
            "vendor": vendor,
            "os_version": os_version,
            "serial_number": serial_number[0] if serial_number else "Unknown",
            "model": model,
            "hostname": hostname,
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """Return interface details keyed by interface name."""
        output = self.device.send_command("display interface")
        if not output:
            return {}

        parsed = parse_output(platform="huawei_vrp", command="display interface", data=output)
        interfaces = {}
        for row in parsed:
            intf = row.get("interface", "")
            if not intf:
                continue

            link_status = row.get("link_status", "").lower()
            proto_status = row.get("protocol_status", "").lower()

            speed_raw = row.get("speed", "")
            try:
                speed = float(speed_raw) if speed_raw else -1.0
            except ValueError:
                speed = -1.0

            mac_raw = row.get("mac_address", "")
            try:
                mac_address = normalize_mac(mac_raw) if mac_raw else ""
            except Exception:
                mac_address = mac_raw

            interfaces[intf] = {
                "is_up": "up" in proto_status,
                "is_enabled": "up" in link_status,
                "description": row.get("interface_description", "").strip(),
                "last_flapped": -1.0,
                "mtu": int(row["mtu"]) if row.get("mtu") else -1,
                "speed": speed,
                "mac_address": mac_address,
            }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface."""
        interfaces_ip: dict = {}

        # --- IPv4: display ip interface (regex, captures secondary IPs) ---
        ipv4_out = self.device.send_command("display ip interface")
        separator = r"(^(?!Line protocol).*current state.*$)"
        re_intf_name = r"^(?!Line protocol)(?P<intf_name>\S+).+current state"
        re_intf_ip = r"Internet Address is\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)"

        for section in _separate_section(separator, ipv4_out):
            m_intf = re.search(re_intf_name, section, flags=re.M)
            if not m_intf:
                continue
            intf_name = m_intf.group("intf_name")
            for ip, prefix in re.findall(re_intf_ip, section, flags=re.M):
                interfaces_ip.setdefault(intf_name, {}).setdefault("ipv4", {})[ip] = {
                    "prefix_length": int(prefix)
                }

        # --- IPv6: display ipv6 interface (regex, no template available) ---
        ipv6_out = self.device.send_command("display ipv6 interface")
        separator_v6 = r"(^(?!IPv6 protocol).*current state.*$)"
        re_intf_name_v6 = r"^(?!IPv6 protocol)(?P<intf_name>\S+).+current state"
        re_intf_ip_v6 = r"(?P<ip>\S+), subnet is.+\/(?P<prefix>\d+)"

        for section in _separate_section(separator_v6, ipv6_out):
            m_intf = re.search(re_intf_name_v6, section, flags=re.M)
            if not m_intf:
                continue
            intf_name = m_intf.group("intf_name")
            for m in re.finditer(re_intf_ip_v6, section, flags=re.M):
                interfaces_ip.setdefault(intf_name, {}).setdefault("ipv6", {})[m.group("ip")] = {
                    "prefix_length": int(m.group("prefix"))
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

        if retrieve.lower() in ("running", "all"):
            config["running"] = self.device.send_command("display current-configuration")
        if retrieve.lower() in ("startup", "all"):
            config["startup"] = self.device.send_command("display saved-configuration")

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Return VLAN information keyed by VLAN ID string."""
        output = self.device.send_command("display vlan brief")
        parsed = parse_output(platform="huawei_vrp", command="display vlan brief", data=output)

        # The template uses Filldown + List, so rows may repeat VLAN_ID.
        # Aggregate interfaces per VLAN_ID.
        vlans: dict = {}
        for row in parsed:
            vlan_id = row.get("vlan_id", "")
            if not vlan_id:
                continue
            entry = vlans.setdefault(
                vlan_id,
                {"name": row.get("vlan_name", "") or vlan_id, "interfaces": []},
            )
            for intf in row.get("interface", []):
                if intf and intf not in entry["interfaces"]:
                    entry["interfaces"].append(intf)

        return vlans

    def get_chassis_members(self) -> dict | None:
        """
        Return stack-member info for Huawei VRP iStack-mode chassis.

        Standalone VRP and CSS-mode (cluster, not iStack) return None;
        multi-member iStacks emit the payload consumed by
        ``device_discovery.translate``'s VirtualChassis emission path.
        CSS support is deferred to a follow-up batch (different command
        + 4-tuple interface-routing branch).
        """
        return _huawei_vrp_get_chassis_members_impl(self)

    def get_modules(self) -> dict | None:
        """
        Return Module / ModuleBay slot inventory for a Huawei modular chassis.

        Standalone CE12800 / NE40E only. No optic sub-bays (no display
        transceiver template) and no CSS-of-modular dispatch (documented
        v1 limitations). Returns None for non-modular / unparsable output.
        """
        return _vrp_get_modules_impl(self)

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """Return per-interface VLAN config from ``display port vlan``."""
        try:
            raw = self.device.send_command("display port vlan")
        except Exception:
            logger.debug("VRP display port vlan failed", exc_info=True)
            return {}
        try:
            rows = parse_output(
                platform="huawei_vrp", command="display port vlan", data=raw
            )
        except Exception:
            logger.debug("VRP display port vlan ntc parse failed", exc_info=True)
            return {}
        result: dict[str, dict] = {}
        for row in rows or []:
            ifname = row.get("interface")
            if not ifname:
                continue
            info = _huawei_row_to_switchport_info(row)
            result[ifname] = classify_switchport(info)
        return result

    def get_network_instances(self, name: str = "") -> dict:
        """
        Return network instances (VPN instances as VRFs), NAPALM OC shape.

        Names and member interfaces come from ``display ip vpn-instance
        interface`` (ntc-template). Route distinguishers come from a
        driver-local scan of the ``display ip vpn-instance`` summary —
        the ntc-template for that command requires an RD on every row
        and error-exits on VPN instances without one configured. The
        global routing table (``_public_``) is not a VPN instance and is
        represented by the seeded DEFAULT_INSTANCE with empty membership.
        """
        instances: dict = {
            "default": {
                "name": "default",
                "type": "DEFAULT_INSTANCE",
                "state": {"route_distinguisher": ""},
                "interfaces": {"interface": {}},
            },
        }
        ifc_raw = self.device.send_command("display ip vpn-instance interface")
        rows: list[dict] = []
        if ifc_raw and ifc_raw.strip():
            try:
                rows = parse_output(
                    platform="huawei_vrp",
                    command="display ip vpn-instance interface",
                    data=ifc_raw,
                )
            except Exception:
                logger.warning(
                    "VRP display ip vpn-instance interface parse failed",
                    exc_info=True,
                )
        rd_by_name = _vrp_parse_vpn_instance_rds(
            self.device.send_command("display ip vpn-instance") or ""
        )
        for row in rows:
            vpn_name = (row.get("name") or "").strip()
            # Never let a row overwrite the seeded DEFAULT_INSTANCE.
            if not vpn_name or vpn_name == "default":
                continue
            interfaces = {
                ifname.strip(): {}
                for ifname in (row.get("interface_list") or [])
                if ifname and ifname.strip()
            }
            instances[vpn_name] = {
                "name": vpn_name,
                "type": "L3VRF",
                "state": {"route_distinguisher": rd_by_name.get(vpn_name, "")},
                "interfaces": {"interface": interfaces},
            }
        if name:
            return {name: instances[name]} if name in instances else {}
        return instances
