# Copyright 2026 NetBox Labs Inc
"""
Custom Extreme EXOS NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko (extreme_exos device type) + ntc-templates for structured parsing.
Falls back to regex for commands without templates (show version).
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
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
from custom_napalm._vlan import (
    SwitchportInfo,
    classify_switchport,
)

logger = logging.getLogger(__name__)


_EXOS_DOT1Q_TAG_RE = re.compile(r"802\.1Q\s+Tag\s*=\s*(\d+)", re.IGNORECASE)


def _parse_exos_show_ports_membership(text: str) -> dict[str, dict]:
    """
    Parse EXOS ``show ports information detail`` into per-port VLAN membership.

    Each per-port section starts with ``Port: <id>`` and exposes:
      - ``Internal Tag = <vid>`` — the port's untagged/PVID VLAN.
      - ``802.1Q Tag = <vid>`` — one entry per tagged VLAN membership.

    Returns ``{port: {tagged: list[int], untagged: list[int]}}``. Reuses the
    same regex anchors as the existing ``get_vlans()`` path
    (``_PORT_SECTION_RE``, ``_PORT_NUM_RE``, ``_INTERNAL_TAG_RE``) so per-port
    enrichment matches the per-VLAN view exactly.
    """
    out: dict[str, dict] = {}
    for section in _PORT_SECTION_RE.split(text):
        port_m = _PORT_NUM_RE.search(section)
        if not port_m:
            continue
        port = port_m.group(1)
        bucket = out.setdefault(port, {"tagged": [], "untagged": []})
        for tag_m in _INTERNAL_TAG_RE.finditer(section):
            try:
                vid = int(tag_m.group(1))
            except ValueError:
                continue
            if vid not in bucket["untagged"]:
                bucket["untagged"].append(vid)
        for tag_m in _EXOS_DOT1Q_TAG_RE.finditer(section):
            try:
                vid = int(tag_m.group(1))
            except ValueError:
                continue
            if vid not in bucket["tagged"]:
                bucket["tagged"].append(vid)
    return out


def _exos_merge_to_switchport_info(membership: dict) -> SwitchportInfo:
    """
    Map per-port EXOS membership to a SwitchportInfo.

    EXOS does not have an explicit access/trunk mode field — we derive mode
    from membership shape:
      - exactly one untagged, no tagged   → access
      - one untagged + ≥1 tagged          → trunk with native
      - no untagged + ≥1 tagged           → trunk with no native
      - no membership                     → routed
    """
    untagged = membership.get("untagged") or []
    tagged = membership.get("tagged") or []
    if not untagged and not tagged:
        return SwitchportInfo(
            enabled=False,
            admin_mode=None,
            oper_mode=None,
            access_vlan=None,
            native_vlan=None,
            allowed_vlans=None,
        )
    if untagged and not tagged:
        return SwitchportInfo(
            enabled=True,
            admin_mode="access",
            oper_mode="access",
            access_vlan=untagged[0],
            native_vlan=None,
            allowed_vlans=None,
        )
    return SwitchportInfo(
        enabled=True,
        admin_mode="trunk",
        oper_mode="trunk",
        access_vlan=None,
        native_vlan=untagged[0] if untagged else None,
        allowed_vlans=list(tagged),
    )

# --- config sanitization -------------------------------------------------- #
# "create account admin encrypted-secret "$1$xxx""
_ENCRYPTED_SECRET_RE = re.compile(
    r"(encrypted-secret)\s+\"[^\"]*\"",
    re.IGNORECASE,
)
# "[keyword] encrypted "hash"" — covers shared-secret encrypted, etc.
_ENCRYPTED_RE = re.compile(
    r"(\S+\s+encrypted)\s+\"[^\"]*\"",
    re.IGNORECASE,
)
# "configure snmp add community readonly/readwrite "string""
_SNMP_COMMUNITY_RE = re.compile(
    r"(configure\s+snmp\s+add\s+community\s+(?:readonly|readwrite))\s+\"[^\"]*\"",
    re.IGNORECASE,
)


def _sanitize_config(text: str) -> str:
    text = _ENCRYPTED_SECRET_RE.sub(r'\1 "<redacted>"', text)
    text = _ENCRYPTED_RE.sub(r'\1 "<redacted>"', text)
    text = _SNMP_COMMUNITY_RE.sub(r'\1 "<redacted>"', text)
    return text


# --- VLAN parsing helpers -------------------------------------------------- #
# Split raw "show ports information detail" output into per-port sections.
# Matches both standalone ports (e.g. "1") and slot-qualified stack ports (e.g. "1:1").
_PORT_SECTION_RE = re.compile(r"(?=^Port:\s*[\d:]+)", re.M)
# Capture the full port identifier from the opening line of a section.
_PORT_NUM_RE = re.compile(r"^Port:\s*([\d:]+)", re.M)
# Capture the Internal Tag (untagged/native VLAN ID) from a VLAN cfg entry.
# Matches: "Name: Default, Internal Tag = 1, MAC-limit = ..."
_INTERNAL_TAG_RE = re.compile(r"Internal\s+Tag\s*=\s*(\d+)")

# --- regex fallbacks for "show ports information detail" ------------------- #
# Used when ntc-template raises TextFSMError on stacked/chassis port IDs.
_PORT_ADMIN_RE = re.compile(r"Admin\s+State\s*:\s*(\S+)", re.IGNORECASE)
_PORT_LINK_RE = re.compile(r"Link\s+State\s*:\s*(\S+)", re.IGNORECASE)
_PORT_DESC_RE = re.compile(r"Description\s+String\s*:\s*\"?(.*?)\"?\s*$", re.IGNORECASE | re.M)
# Match "802.1Q Tag = <vid>" lines — the definitive indicator of tagged VLAN membership.
# "Port-specific VLAN ID" is an optional PVID-override sub-line that is absent on many
# trunk ports, so relying on it would miss VLANs for ports that carry multiple tagged VLANs.
_PORT_8021Q_RE = re.compile(r"802\.1Q\s+Tag\s*=\s*(\d+)", re.IGNORECASE)


def _parse_interfaces_regex(output: str) -> dict:
    """Regex fallback for get_interfaces when ntc-template cannot parse the output."""
    interfaces: dict = {}
    for section in _PORT_SECTION_RE.split(output):
        port_m = _PORT_NUM_RE.search(section)
        if not port_m:
            continue
        port = port_m.group(1)
        admin_m = _PORT_ADMIN_RE.search(section)
        link_m = _PORT_LINK_RE.search(section)
        desc_m = _PORT_DESC_RE.search(section)
        interfaces[port] = {
            "is_up": link_m.group(1).lower() == "active" if link_m else False,
            "is_enabled": admin_m.group(1).lower().startswith("enabled") if admin_m else False,
            "description": desc_m.group(1).strip() if desc_m else "",
            "last_flapped": -1.0,
            "mtu": -1,
            "speed": -1.0,
            "mac_address": "",
        }
    return interfaces


def _parse_interface_list_regex(output: str) -> list:
    """
    Regex fallback for interface list from 'show ports information'.

    Each data row starts with the port identifier (numeric or slot:port such as
    '1:1') followed by whitespace.  Header and separator lines start with letters
    or '=' so they are not matched.
    """
    return [m.group(1) for m in re.finditer(r"^([\d:]+)\s", output, re.M)]


def _add_tagged_vlan_ports_regex(vlans: dict, ports_output: str) -> None:
    """Regex fallback for tagged VLAN port membership when ntc-template cannot parse."""
    for section in _PORT_SECTION_RE.split(ports_output):
        port_m = _PORT_NUM_RE.search(section)
        if not port_m:
            continue
        port = port_m.group(1)
        for vid_m in _PORT_8021Q_RE.finditer(section):
            vid = vid_m.group(1)
            if vid in vlans and port not in vlans[vid]["interfaces"]:
                vlans[vid]["interfaces"].append(port)

# --- uptime helpers -------------------------------------------------------- #
_HOUR_SECONDS = 3_600
_DAY_SECONDS = 24 * _HOUR_SECONDS
_WEEK_SECONDS = 7 * _DAY_SECONDS
_YEAR_SECONDS = 365 * _DAY_SECONDS


def _parse_uptime(uptime_str: str) -> float:
    """Convert an EXOS uptime string like '3 days 4 hours 22 minutes' to seconds."""
    seconds = 0.0
    for pattern, factor in (
        (r"(\d+)\s+year", _YEAR_SECONDS),
        (r"(\d+)\s+week", _WEEK_SECONDS),
        (r"(\d+)\s+day", _DAY_SECONDS),
        (r"(\d+)\s+hour", _HOUR_SECONDS),
        (r"(\d+)\s+minute", 60),
        (r"(\d+)\s+second", 1),
    ):
        m = re.search(pattern, uptime_str, re.IGNORECASE)
        if m:
            seconds += int(m.group(1)) * factor
    return seconds


# --- module / module bay discovery ------------------------------------------
#
# Extreme EXOS modular families publish per-slot inventory via
# ``show slot detail``. Only the BlackDiamond X8 chassis is in scope — the
# X870 / X8-X32 are fixed pizza-box switches even though their model strings
# share the ``X8`` family token, so family detection uses a negative
# lookahead to reject those variants.

# Negative lookahead: ``X8`` is the family token, but ``X8-32`` (BD-X8-X32
# stackable) and ``X870`` (fixed pizza-box) must NOT match. ``\b`` does NOT
# work here because the regex word-boundary fires between ``8`` and ``-`` in
# ``BD-X8-32``, accepting the wrong model.
_MODULAR_EXOS_RE = re.compile(
    r"(?:BD-|BLACKDIAMOND\s+)X8(?![-\w])", re.IGNORECASE
)

# Block header regex for ``show slot detail``. EXOS prints one block per
# physical slot with a header like ``Slot-1 information:``,
# ``MSM-A information:``, ``FM-2 information:``. The header vocabulary is
# a defensive over-approximation (``Slot|MSM|MM|IO|FM``) — real BD-X8 output
# only emits ``Slot-N`` / ``MSM-X`` / ``FM-N``, but matching the broader set
# costs nothing and survives future firmware variations. ``[-\s]`` separator
# accepts both ``Slot 1`` and ``Slot-1`` headers; the slot name is normalised
# below. ``IGNORECASE`` is essential — the field regexes below already match
# case-insensitively, so the header regex must do the same or it will silently
# drop every block on a future firmware that emits ``slot-1 information:``.
_EXOS_SLOT_HEADER_RE = re.compile(
    r"^(?P<slot>(?:Slot|MSM|MM|IO|FM)[-\s][A-Za-z0-9]+)\s+information:\s*$",
    re.MULTILINE | re.IGNORECASE,
)
_EXOS_HW_TYPE_RE = re.compile(
    r"^\s*Hw\s+Module\s+Type\s*:\s*(?P<type>\S+)", re.MULTILINE | re.IGNORECASE
)
# Real EXOS prints two whitespace-separated tokens on the BD-X8 serial line
# (``Serial number: 800432-00-09 1534G-01368`` — Extreme part-number plus the
# unique serial). Capture everything to end-of-line, then collapse whitespace
# so the persisted serial is the full operator-meaningful string.
_EXOS_SERIAL_RE = re.compile(
    r"^\s*Serial\s+number\s*:\s*(?P<serial>\S.*?)\s*$",
    re.MULTILINE | re.IGNORECASE,
)

# Card-family classifier. Order matters: ``BDX-MM`` (supervisor) is checked
# before the generic ``BDXA-`` / ``BDXB-`` linecard prefixes. ``BDXA-FM``
# (Fabric Modules — ``BDXA-FM20T`` / ``BDXA-FM10T``) classify as linecards
# because NetBox has no fabric module type today. Extreme's BD-X8 install
# guide lists fabric modules only under the ``BDXA-FM`` family — any future
# ``BDXB-FM*`` SKU still classifies as linecard via the generic ``BDXB-``
# fallback.
_EXOS_MODULE_CLASSIFIER: tuple[tuple[str, str], ...] = (
    ("BDX-MM", "supervisor"),
    ("BDXA-FM", "linecard"),
    ("BDXA-", "linecard"),
    ("BDXB-", "linecard"),
)


def _exos_is_modular(model: str) -> bool:
    r"""
    True when ``model`` is a BlackDiamond X8 chassis.

    Accepts ``BD-X8`` and ``BlackDiamond X8``. Rejects ``BD-X8-32`` /
    ``BD-X8-X32`` (fixed stackable) and ``X670`` / ``X870`` (fixed
    pizza-box). The negative-lookahead anchor ``(?![-\w])`` rejects any
    suffix character that would otherwise match a ``\b``-boundary.
    """
    if not model:
        return False
    return bool(_MODULAR_EXOS_RE.search(model))


def _exos_classify_module(hw_type: str) -> str:
    """
    Classify an EXOS ``Hw Module Type`` value into a module type.

    Returns ``"supervisor"`` / ``"linecard"`` per ``_EXOS_MODULE_CLASSIFIER``
    or ``"other"`` for SKUs that match no documented prefix. Empty input
    returns ``"other"``.
    """
    sku = (hw_type or "").strip().upper()
    if not sku:
        return "other"
    for prefix, mtype in _EXOS_MODULE_CLASSIFIER:
        if sku.startswith(prefix):
            return mtype
    return "other"


def _parse_show_slot_detail(text: str) -> list[dict[str, str]]:
    """
    Parse EXOS ``show slot detail`` block-per-slot output into a row list.

    Each row contains ``slot`` (normalised: whitespace → ``-``),
    ``hw_module_type``, and ``serial``. Blocks missing either Hw Module
    Type or Serial number are dropped silently (typical empty-slot output).
    """
    rows: list[dict[str, str]] = []
    matches = list(_EXOS_SLOT_HEADER_RE.finditer(text or ""))
    if not matches:
        return rows
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = text[start:end]
        hw = _EXOS_HW_TYPE_RE.search(block)
        sn = _EXOS_SERIAL_RE.search(block)
        if not hw or not sn:
            continue
        slot_name = re.sub(r"\s+", "-", m.group("slot").strip())
        # Collapse internal whitespace runs to a single space so variable
        # spacing in real EXOS output (e.g. extra padding between the
        # part-number and unique-serial tokens) never produces an
        # accidentally non-unique or ugly persisted serial.
        serial = " ".join(sn.group("serial").split())
        rows.append({
            "slot": slot_name,
            "hw_module_type": hw.group("type"),
            "serial": serial,
        })
    return rows


def _exos_get_modules_impl(driver) -> dict | None:
    """
    Per-chassis module / module bay discovery for BlackDiamond X8.

    Reads ``show version`` for family detection; non-modular pizza-boxes
    short-circuit to ``None``. For modular chassis, parses
    ``show slot detail`` block-per-slot, classifies each block's
    ``Hw Module Type``, and emits one ``MemberModules`` envelope keyed
    ``None`` (no stack-of-modular dispatch for EXOS).
    """
    try:
        ver_output = driver.device.send_command("show version")
    except Exception:
        logger.warning("exos.get_modules: show version failed", exc_info=True)
        return None

    # ``show version`` on a BD-X8 prints the System Type on a dedicated line
    # on most firmwares, but Extreme's command reference also documents BD-X8
    # output that lists ``Switch : BD-X8 ...`` / ``Chassis``/``Slot-*`` /
    # ``FM-*`` entries without an explicit ``System Type`` line. Scan the
    # full output for the BD-X8 signature rather than gating on one field —
    # the regex already rejects ``BD-X8-32`` / ``X670`` / ``X870`` variants.
    if not _exos_is_modular(ver_output or ""):
        return None

    try:
        raw = driver.device.send_command("show slot detail")
    except Exception:
        logger.warning("exos.get_modules: show slot detail failed", exc_info=True)
        return None

    rows = _parse_show_slot_detail(raw or "")
    bays: list[_ModuleBay] = []
    for row in rows:
        mtype = _exos_classify_module(row["hw_module_type"])
        if mtype not in ("supervisor", "linecard"):
            continue
        bays.append(_ModuleBay(
            name=row["slot"],
            position=row["slot"],
            module=_ModuleEntry(
                model=row["hw_module_type"],
                serial=row["serial"],
                type=mtype,
                description="",
            ),
        ))
    if not bays:
        return None
    return _modules_to_payload(
        {None: _MemberModules(bays=bays, interfaces_by_bay={})}
    )


class ExosDriver(_napalm_base.NetworkDriver):
    """Extreme EXOS NAPALM driver (read-only subset for device-discovery)."""

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
            "extreme_exos", netmiko_optional_args=self.netmiko_optional_args
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

    # ---------------------------------------------------------------------- #
    # NAPALM getters
    # ---------------------------------------------------------------------- #

    def get_facts(self) -> dict:
        """Return general device facts."""
        hostname = "Unknown"
        model = "Unknown"
        os_version = "Unknown"
        serial_number = "Unknown"
        uptime: float = -1.0

        ver_output = self.device.send_command("show version")
        if ver_output:
            m = re.search(r"^SysName\s*:\s*(\S+)", ver_output, re.M)
            if m:
                hostname = m.group(1)

            m = re.search(r"^System Type\s*:\s*(.+?)\s*$", ver_output, re.M)
            if m:
                model = m.group(1)

            # Match "Image : Version <x>" and the common variant
            # "Image : ExtremeXOS version <x>" (product token before "version").
            m = re.search(r"^Image\s*:.*?\bversion\s+(\S+)", ver_output, re.M | re.IGNORECASE)
            if m:
                os_version = m.group(1)

            # Prefer the dedicated SysSerial field, which holds the unique device serial.
            # The \d{6}-\d{2}-\d+ pattern in the Switch line is the hardware part number
            # (shared across all units of the same model) and should not be used as a
            # serial; it is kept as a last resort for output that lacks SysSerial.
            m = re.search(r"^SysSerial\s*:\s*(\S+)", ver_output, re.M)
            if not m:
                m = re.search(r"\((\d{6}-\d{2}-\d+)\)", ver_output)
            if not m:
                m = re.search(r"\b(\d{6}-\d{2}-\d+)\b", ver_output)
            if m:
                serial_number = m.group(1)

            # Uptime: "Up 3 days 4 hours 22 minutes ago"
            m = re.search(r"\bUp\s+(.*?)\s+ago\b", ver_output)
            if m:
                uptime = _parse_uptime(m.group(1))

        # Fetch interface list separately; this command succeeds even when
        # `show version` returns nothing (e.g. on devices where the template
        # is unavailable), so we always populate interface_list.
        # Guard against TextFSMError: on stacked devices ports are "slot:port"
        # (e.g. "1:1"), which the ntc-template's \d+ rule cannot match and
        # raises TextFSMError.  Fall back to regex rather than returning [].
        ports_output = self.device.send_command("show ports information")
        try:
            parsed_ports = parse_output(
                platform="extreme_exos", command="show ports information", data=ports_output
            )
            interface_list = [row["interface"] for row in parsed_ports if row.get("interface")]
        except Exception:
            logger.warning(
                "exos: ntc-template failed for 'show ports information'; "
                "falling back to regex (stacked port IDs?)"
            )
            interface_list = _parse_interface_list_regex(ports_output)

        return {
            "hostname": hostname,
            "vendor": "Extreme",
            "model": model,
            "os_version": os_version,
            "serial_number": serial_number,
            "uptime": uptime,
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """Return interface details keyed by port number."""
        output = self.device.send_command("show ports information detail")
        if not output:
            return {}

        try:
            parsed = parse_output(
                platform="extreme_exos", command="show ports information detail", data=output
            )
        except Exception:
            logger.warning(
                "exos: ntc-template failed for 'show ports information detail'; "
                "falling back to regex (stacked port IDs?)"
            )
            return _parse_interfaces_regex(output)
        interfaces = {}
        for row in parsed:
            port = row.get("interface", "")
            if not port:
                continue
            admin_state = row.get("admin_state", "")
            link_state = row.get("link_state", "").lower()
            interfaces[port] = {
                "is_up": link_state == "active",
                "is_enabled": admin_state.lower().startswith("enabled"),
                "description": row.get("description", ""),
                "last_flapped": -1.0,
                "mtu": -1,
                "speed": -1.0,
                "mac_address": "",
            }
        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per VLAN interface."""
        output = self.device.send_command("show ipconfig")
        if not output:
            return {}

        parsed = parse_output(
            platform="extreme_exos", command="show ipconfig", data=output
        )
        # The ntc-template emits one aggregated row with list-valued fields
        # (INTERFACE, IP, SUBNET are all List values in a single record).
        # If a future template version emits one row per interface, those fields
        # will be plain strings; zip() over strings iterates character-by-character,
        # so we normalise scalars to single-element lists before zipping.
        interfaces_ip: dict = {}
        for row in parsed:
            interfaces = row.get("interface", [])
            ips = row.get("ip", [])
            subnets = row.get("subnet", [])
            if not isinstance(interfaces, (list, tuple)):
                interfaces = [interfaces]
            if not isinstance(ips, (list, tuple)):
                ips = [ips]
            if not isinstance(subnets, (list, tuple)):
                subnets = [subnets]
            for intf, ip, subnet in zip(interfaces, ips, subnets):
                try:
                    prefix_len = int(subnet.lstrip("/"))
                except (ValueError, AttributeError):
                    # Skip entries whose subnet token cannot be parsed; storing
                    # prefix_length=-1 would cause ip_network() to raise ValueError
                    # in the downstream translate layer.
                    logger.warning("exos: skipping IP %s on %s — unparseable subnet %r", ip, intf, subnet)
                    continue
                interfaces_ip.setdefault(intf, {}).setdefault("ipv4", {})[ip] = {
                    "prefix_length": prefix_len
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

        # EXOS has no distinct startup configuration; "show configuration" outputs
        # the effective saved config. Populate both running and startup from the same
        # command to avoid emitting empty startup data when startup capture is enabled.
        if retrieve in ("all", "running", "startup"):
            config_text = self.device.send_command("show configuration")
            if retrieve in ("all", "running"):
                config["running"] = config_text
            if retrieve in ("all", "startup"):
                config["startup"] = config_text

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Return VLAN information keyed by VLAN ID string, with port membership."""
        vlan_output = self.device.send_command("show vlan description")
        parsed_vlans = parse_output(
            platform="extreme_exos", command="show vlan description", data=vlan_output
        )

        vlans: dict = {}
        for row in parsed_vlans:
            vlan_id = row.get("vlan_id", "")
            if not vlan_id:
                continue
            vlans[vlan_id] = {
                "name": row.get("vlan_name", vlan_id),
                "interfaces": [],
            }

        if vlans:
            ports_output = self.device.send_command("show ports information detail")
            self._add_tagged_vlan_ports(vlans, ports_output)
            self._add_untagged_vlan_ports(vlans, ports_output)

        return vlans

    def get_modules(self) -> dict | None:
        """
        Return module / module bay inventory for BlackDiamond X8.

        Modular BD-X8 chassis emit a single ``members[None]`` envelope
        containing MSM / FM / I/O blades parsed from ``show slot detail``.
        Non-modular pizza-boxes (X670 / X870 / BD-X8-X32) and unparseable
        output return ``None``.
        """
        return _exos_get_modules_impl(self)

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """Return per-interface VLAN config from ``show ports information detail``."""
        try:
            raw = self.device.send_command("show ports information detail")
        except Exception:
            logger.debug("EXOS show ports information detail failed", exc_info=True)
            return {}
        membership = _parse_exos_show_ports_membership(raw or "")
        result: dict[str, dict] = {}
        for port, member in membership.items():
            info = _exos_merge_to_switchport_info(member)
            result[port] = classify_switchport(info)
        return result

    def _add_tagged_vlan_ports(self, vlans: dict, ports_output: str) -> None:
        """
        Add tagged 802.1Q port memberships to *vlans*.

        Pass 1a — ntc-template: reads the ``vlan_id`` field populated from
        ``Port-specific VLAN ID`` lines (optional sub-line; absent on trunk ports
        without a PVID override → empty list even when the template succeeds).

        Pass 1b — regex (always runs): scans ``802.1Q Tag = <vid>`` lines which
        are present for every tagged VLAN membership, covering the trunk-port gap.
        Duplicates are prevented by the ``if port not in`` check.
        """
        try:
            parsed_ports = parse_output(
                platform="extreme_exos",
                command="show ports information detail",
                data=ports_output,
            )
            for row in parsed_ports:
                port = row.get("interface", "")
                if not port:
                    continue
                for vid in row.get("vlan_id", []):
                    if vid in vlans and port not in vlans[vid]["interfaces"]:
                        vlans[vid]["interfaces"].append(port)
        except Exception:
            logger.warning(
                "exos: ntc-template failed for 'show ports information detail' (tagged VLANs); "
                "regex pass will cover membership (stacked port IDs?)"
            )
        # Always supplement with 802.1Q Tag regex: the ntc-template only captures
        # Port-specific VLAN ID (an optional sub-line), so tagged VLANs on trunk
        # ports without that sub-line are missed by the template pass alone.
        _add_tagged_vlan_ports_regex(vlans, ports_output)

    def _add_untagged_vlan_ports(self, vlans: dict, ports_output: str) -> None:
        """Pass 2 — regex: add untagged/native VLAN memberships via Internal Tag lines."""
        for section in _PORT_SECTION_RE.split(ports_output):
            port_m = _PORT_NUM_RE.search(section)
            if not port_m:
                continue
            port = port_m.group(1)
            for tag_m in _INTERNAL_TAG_RE.finditer(section):
                vid = tag_m.group(1)
                if vid in vlans and port not in vlans[vid]["interfaces"]:
                    vlans[vid]["interfaces"].append(port)
