# Copyright 2026 NetBox Labs Inc
"""
Custom Cisco Small Business S300 NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko (cisco_s300) and ntc-templates for structured CLI parsing.
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output as _parse_output_raw

from custom_napalm._vlan import SwitchportInfo, classify_switchport, parse_vlan_range_string

logger = logging.getLogger(__name__)

# Config sanitization — S300 sensitive CLI fields:
#   username <name> [privilege <n>] password [<enc-type>] <hash>
#   enable password [level <n>] [<enc-type>] <hash>
#   snmp-server community <community-string> [ro|rw] ...
_USERNAME_PASSWORD_RE = re.compile(
    r"(username\s+\S+(?:\s+privilege\s+\d+)?\s+password)\s+.*",
    re.IGNORECASE,
)
_ENABLE_PASSWORD_RE = re.compile(
    r"(enable\s+password(?:\s+level\s+\d+)?)\s+.*",
    re.IGNORECASE,
)
_SNMP_COMMUNITY_RE = re.compile(
    r"(snmp-server\s+community)\s+\S+",
    re.IGNORECASE,
)


def _sanitize_config(text: str) -> str:
    text = _USERNAME_PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _ENABLE_PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_COMMUNITY_RE.sub(r"\1 <redacted>", text)
    return text


def _ntc_parse(platform: str, command: str, data: str) -> list:
    """Wrap parse_output with error handling so a bad template never crashes discovery."""
    try:
        return _parse_output_raw(platform=platform, command=command, data=data)
    except Exception:
        logger.debug("ntc-templates failed to parse %r on %r", command, platform, exc_info=True)
        return []


def _parse_uptime(uptime_str: str) -> float:
    """Convert S300 uptime string 'DD,HH:MM:SS' to total seconds."""
    m = re.match(r"(\d+),(\d+):(\d+):(\d+)", uptime_str.strip())
    if not m:
        return 0.0
    days, hours, minutes, secs = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
    return float(days * 86400 + hours * 3600 + minutes * 60 + secs)


def _expand_interface_range(range_str: str) -> list[str]:
    """
    Expand a comma-separated interface list with optional ranges into individual names.

    Examples:
        "fa1-2,fa4-8,gi1" -> ["fa1", "fa2", "fa4", "fa5", "fa6", "fa7", "fa8", "gi1"]
        "gi1" -> ["gi1"]
        "" -> []

    """
    if not range_str:
        return []
    result = []
    for token in range_str.strip().rstrip(",").split(","):
        token = token.strip()
        if not token:
            continue
        # Match "prefix<start>-<end>" e.g. "fa1-2", "fa4-8"
        m = re.match(r"([a-zA-Z]+)(\d+)-(\d+)$", token)
        if m:
            prefix = m.group(1)
            start, end = int(m.group(2)), int(m.group(3))
            result.extend(f"{prefix}{i}" for i in range(start, end + 1))
        else:
            result.append(token)
    return result


# Matches a VLAN data row (leading optional space, digits, then a space).
_VLAN_ROW_RE = re.compile(r"^\s*(\d+)\s")
# Detects the column-separator line and captures the start of the Ports dash group,
# e.g. "---- ----------------- --------------------------- ----------------"
#       ^id   ^name              ^ports (group 1)           ^created-by
_VLAN_SEP_RE = re.compile(r"^-{4}\s+-+\s+(-+)")
# Interface token (with optional range) used inside the Ports column only.
_INTF_TOKEN_RE = re.compile(r"\b((?:fa|gi|te|po)\d+(?:-\d+)?)\b", re.IGNORECASE)


def _parse_portchannel_status_raw(raw: str) -> dict[str, dict]:
    """
    Extract port-channel (``Po*``) rows from raw ``show interfaces status`` output.

    The cisco_s300 ntc-template transitions to ``End`` when it hits the
    ``Ch Type Duplex Speed Neg control State`` section header, so port-channel
    rows are never returned by ``parse_output``. This function parses the
    port-channel section directly so that active LAGs appear in
    ``get_interfaces`` and ``get_facts``.

    Port-channels with state ``Not Present`` (no member ports assigned) are
    included in the return value so callers can apply their own filtering.

    """
    result: dict[str, dict] = {}
    in_section = False

    for line in raw.splitlines():
        stripped = line.strip()
        if re.match(r"^Ch\s+Type\s+Duplex", stripped):
            in_section = True
            continue
        if not in_section:
            continue
        if not stripped or re.match(r"^-+", stripped) or re.match(r"^\s+", line):
            continue
        if not stripped.startswith("Po"):
            break  # out of the port-channel section

        parts = stripped.split()
        if len(parts) < 2:
            continue

        po_name = parts[0]
        # State is "Up", "Down", or the two-word "Not Present"
        if len(parts) >= 2 and parts[-2:] == ["Not", "Present"]:
            linkstate = "not present"
        else:
            linkstate = parts[-1].lower()

        speed_raw = parts[3] if len(parts) > 3 else "--"
        try:
            speed = float(speed_raw) if speed_raw != "--" else -1.0
        except ValueError:
            speed = -1.0

        result[po_name] = {
            "is_up": linkstate == "up",
            "is_enabled": linkstate != "not present",
            "speed": speed,
        }

    return result


_S300_BLOCK_RE = re.compile(r"^Name:\s*(\S+)\s*$", re.MULTILINE)


def _maybe_int(s: object) -> int | None:
    """
    Convert a string/int to int, returning None on failure.

    Rejects ``bool`` explicitly: ``bool`` is a subclass of ``int`` in Python,
    so ``int(True) == 1`` — without this guard a buggy upstream parser
    passing a bool would slip past the classifier's bool-rejection in
    ``_vlan.coerce_vid``.
    """
    if isinstance(s, bool):
        return None
    try:
        return int(s)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return None


def _s300_block_to_switchport_info(fields: dict[str, str]) -> SwitchportInfo:
    """
    Build a SwitchportInfo from one parsed ``show interfaces switchport`` block.

    The S300 CLI emits multi-line key:value blocks per interface; this function
    consumes the parsed dict (key strings exactly as printed by the device).
    """
    if fields.get("Switchport", "").lower() != "enable":
        return SwitchportInfo(
            enabled=False, admin_mode=None, oper_mode=None,
            access_vlan=None, native_vlan=None, allowed_vlans=None,
        )

    admin_raw = fields.get("Administrative Mode", "").lower()
    if admin_raw == "access":
        admin: str | None = "access"
    elif admin_raw in ("trunk", "general"):
        admin = "trunk"  # 'general' collapses to trunk semantics
    else:
        admin = None

    access_vid = _maybe_int(fields.get("Access Mode VLAN", ""))
    native_vid = _maybe_int(fields.get("Trunking Native Mode VLAN", ""))

    trunk_spec = fields.get("Trunking VLANs Enabled", "")
    if trunk_spec:
        vids, is_wildcard = parse_vlan_range_string(trunk_spec)
        if is_wildcard:
            allowed: list[int] | str | None = "all"
        else:
            allowed = vids
            # Malformed trunk input must NOT silently widen to trunk-all.
            # Warn from the cisco_s300 logger so operators can spot vendor
            # output drift.
            raw_lower = trunk_spec.strip().lower()
            if raw_lower and raw_lower != "none" and not vids:
                logger.warning(
                    "Trunking VLANs Enabled=%r could not be parsed; "
                    "treating as plain trunk with no tagged VLANs",
                    trunk_spec,
                )
    else:
        allowed = None

    return SwitchportInfo(
        enabled=True,
        admin_mode=admin,  # type: ignore[arg-type]
        oper_mode=None,    # S300 doesn't expose oper-mode separately
        access_vlan=access_vid,
        native_vlan=native_vid,
        allowed_vlans=allowed,
    )


def _parse_vlan_ports_raw(raw: str) -> dict[str, list[str]]:
    """
    Extract VLAN → expanded port list from raw ``show vlan`` output.

    The cisco_s300 ntc-template only captures the first line of the port column;
    when VLANs have many members the device wraps the port list across several
    continuation lines and those extra ports are silently discarded by the template.
    This function scans every line of the raw output and appends any interface
    tokens found on continuation lines to the last-seen VLAN, giving a complete
    membership list regardless of how many ports a VLAN has.

    Only the Ports column (and onwards) is scanned for tokens — the VLAN name
    column is excluded so that interface-like names (e.g. ``gi1-uplink``) are
    never mistaken for member ports. The column offset is derived from the
    separator line (``---- -...-- -...-``).

    """
    vlan_ports: dict[str, list[str]] = {}
    current_id: str | None = None
    ports_col: int | None = None

    for line in raw.splitlines():
        # Detect the Ports column offset from the separator line, e.g.:
        # "---- ----------------- --------------------------- ----------------"
        sep_m = _VLAN_SEP_RE.match(line)
        if sep_m:
            ports_col = sep_m.start(1)
            continue

        m = _VLAN_ROW_RE.match(line)
        if m:
            current_id = m.group(1)
        if current_id is None:
            continue

        # Restrict token search to the Ports column so that interface-like
        # tokens in the VLAN name are not treated as member ports.
        search_text = line[ports_col:] if ports_col is not None else line
        for token in _INTF_TOKEN_RE.findall(search_text):
            expanded = _expand_interface_range(token)
            entry = vlan_ports.setdefault(current_id, [])
            for intf in expanded:
                if intf not in entry:
                    entry.append(intf)

    return vlan_ports


class S300Driver(_napalm_base.NetworkDriver):
    """Cisco Small Business S300 NAPALM driver (read-only subset for device-discovery)."""

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
            "cisco_s300", netmiko_optional_args=self.netmiko_optional_args
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
        """Return general device facts."""
        sys_out = self.device.send_command("show system")
        parsed_sys = _ntc_parse("cisco_s300", "show system", sys_out)

        hostname = "Unknown"
        model = "Unknown"
        uptime = 0.0

        if parsed_sys:
            row = parsed_sys[0]
            hostname = row.get("hostname", "Unknown") or "Unknown"
            model = row.get("description", "Unknown") or "Unknown"
            uptime = _parse_uptime(row.get("up_time", ""))

        ver_out = self.device.send_command("show version")
        parsed_ver = _ntc_parse("cisco_s300", "show version", ver_out)
        os_version = "Unknown"
        if parsed_ver:
            os_version = parsed_ver[0].get("sw_version", "Unknown") or "Unknown"

        id_out = self.device.send_command("show system id")
        parsed_id = _ntc_parse("cisco_s300", "show system id", id_out)
        serial_number = "Unknown"
        if parsed_id:
            serial_number = parsed_id[0].get("serial_number", "Unknown") or "Unknown"

        status_out = self.device.send_command("show interfaces status")
        parsed_status = _ntc_parse("cisco_s300", "show interfaces status", status_out)
        interface_list = [
            row["port"]
            for row in parsed_status
            if row.get("port") and row.get("linkstate", "").lower() != "not present"
        ]
        # ntc-template stops before the port-channel section; add configured LAGs.
        po_status = _parse_portchannel_status_raw(status_out)
        interface_list += [po for po, data in po_status.items() if data["is_enabled"]]

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

    def get_interfaces(self) -> dict:
        """Return interface details keyed by interface name."""
        status_out = self.device.send_command("show interfaces status")
        parsed_status = _ntc_parse("cisco_s300", "show interfaces status", status_out)

        desc_out = self.device.send_command("show interfaces description")
        parsed_desc = _ntc_parse("cisco_s300", "show interfaces description", desc_out)
        desc_map = {row["interface"]: row.get("description", "") for row in parsed_desc}

        interfaces = {}
        for row in parsed_status:
            port = row.get("port", "")
            if not port:
                continue

            linkstate = row.get("linkstate", "").lower()
            speed_raw = row.get("speed", "")
            try:
                speed = float(speed_raw) if speed_raw and speed_raw != "--" else -1.0
            except ValueError:
                speed = -1.0

            interfaces[port] = {
                "is_up": linkstate == "up",
                "is_enabled": linkstate != "not present",
                "description": desc_map.get(port, ""),
                "last_flapped": -1.0,
                "mtu": -1,
                "speed": speed,
                "mac_address": "",
            }

        # ntc-template stops before the port-channel section; add configured LAGs.
        po_status = _parse_portchannel_status_raw(status_out)
        for po_name, po_data in po_status.items():
            if not po_data["is_enabled"]:
                continue  # skip "Not Present" port-channels
            interfaces[po_name] = {
                "is_up": po_data["is_up"],
                "is_enabled": True,
                "description": desc_map.get(po_name, ""),
                "last_flapped": -1.0,
                "mtu": -1,
                "speed": po_data["speed"],
                "mac_address": "",
            }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface."""
        ip_out = self.device.send_command("show ip interface")
        parsed = _ntc_parse("cisco_s300", "show ip interface", ip_out)

        interfaces_ip: dict = {}
        for row in parsed:
            ip_with_prefix = row.get("ip", "")
            intf = row.get("interface", "")
            if not ip_with_prefix or not intf or "/" not in ip_with_prefix:
                continue
            try:
                ip, prefix_str = ip_with_prefix.split("/", 1)
                prefix_length = int(prefix_str)
            except (ValueError, AttributeError):
                continue
            interfaces_ip.setdefault(intf, {}).setdefault("ipv4", {})[ip] = {
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
            config["running"] = self.device.send_command("show running-config")
        if retrieve in ("all", "startup"):
            config["startup"] = self.device.send_command("show startup-config")

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Return VLAN information keyed by VLAN ID string."""
        vlan_out = self.device.send_command("show vlan")

        # ntc-templates provides VLAN ID and name but silently drops ports from
        # wrapped continuation lines (the template comment acknowledges this).
        parsed = _ntc_parse("cisco_s300", "show vlan", vlan_out)
        name_map = {
            row["vlan_id"]: row.get("vlan_name", "") or row["vlan_id"]
            for row in parsed
            if row.get("vlan_id")
        }

        # Raw line scan captures every port token including wrapped continuations.
        port_map = _parse_vlan_ports_raw(vlan_out)

        vlans: dict = {}
        for vlan_id in sorted(set(name_map) | set(port_map), key=lambda x: int(x)):
            vlans[vlan_id] = {
                "name": name_map.get(vlan_id, vlan_id),
                "interfaces": port_map.get(vlan_id, []),
            }

        return vlans

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """
        Return per-interface VLAN config.

        Parses ``show interfaces switchport`` from the S300 CLI. Modes:
        access | trunk | trunk-all | routed (PVLAN/customer/etc. → routed in v1).
        General mode collapses to trunk with explicit untagged + tagged sets.
        """
        output = self.device.send_command("show interfaces switchport")
        if not output:
            return {}

        blocks: dict[str, dict[str, str]] = {}
        current: str | None = None
        last_key: str | None = None
        for line in output.splitlines():
            m = _S300_BLOCK_RE.match(line)
            if m:
                current = m.group(1)
                last_key = None
                blocks[current] = {}
                continue
            if current is None:
                continue
            if ":" in line:
                k, _, v = line.partition(":")
                last_key = k.strip()
                blocks[current][last_key] = v.strip()
            elif last_key is not None and line.strip():
                # Continuation of the previous field's value. S300 wraps long
                # `Trunking VLANs Enabled` values across indented lines.
                blocks[current][last_key] = (
                    blocks[current][last_key] + line.strip()
                )

        result: dict[str, dict] = {}
        for ifname, fields in blocks.items():
            info = _s300_block_to_switchport_info(fields)
            result[ifname] = classify_switchport(info)
        return result
