# Copyright 2026 NetBox Labs Inc
"""
Custom Cisco APIC NAPALM driver — SSH CLI via Netmiko + ntc-templates/regex.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Connection uses the ``cisco_apic`` Netmiko device type.  ntc-templates provides
the ``cisco_apic`` platform for ``get_vlans`` (``fabric show vlan extended``).
All other commands are parsed with compiled regular expressions, as no
ntc-templates exist for those commands under the cisco_apic platform.
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

logger = logging.getLogger(__name__)

_PLATFORM = "cisco_apic"

# ---------------------------------------------------------------------------
# Config sanitization — Cisco APIC sensitive fields
# ---------------------------------------------------------------------------

# "password <v>" / "secret <v>" as the first non-whitespace token (indented account lines)
_PASSWORD_RE = re.compile(r"^(\s*(?:password|secret))\s+\S+.*", re.IGNORECASE | re.MULTILINE)

# "enable password/secret [type] <v>" and "username <u> [privilege N] password/secret [type] <v>"
# Uses \S+.* to capture the type indicator AND hash (e.g. "5 $1$abc$hash") in one pass.
_INLINE_PASSWORD_RE = re.compile(
    r"(\b(?:enable\s+(?:password|secret)|username\s+\S+(?:\s+\S+)*?\s+(?:password|secret)))\s+\S+.*",
    re.IGNORECASE | re.MULTILINE,
)

# RADIUS / TACACS+ "... key [<type>] <value>" — ".*" consumes optional type indicator + secret
_KEY_LINE_RE = re.compile(
    r"^(\s*(?:radius-server|tacacs-server)\b.*\bkey)\s+\S+.*",
    re.IGNORECASE | re.MULTILINE,
)

# SNMP community — optional type indicator digit before the actual community string
# e.g. "snmp-server community public ro" or "snmp-server community 7 ABC123 ro"
_COMMUNITY_RE = re.compile(
    r"^(\s*snmp-server\s+community)(?:\s+\d+)?\s+\S+",
    re.IGNORECASE | re.MULTILINE,
)

# Standalone "key <value>" — excludes "key chain X" and bare key-chain identifiers ("key 1")
# but redacts typed keys ("key 7 <hash>") by treating the leading digit as an optional type
# indicator.  The (?!\d+\s*$) lookahead only fires when a lone digit ends the line, so
# "key 7 HashedSecret" is matched and "key 1" (a key-chain entry number) is excluded.
# ".*" at the end consumes the type indicator + secret in a single pass.
_BARE_KEY_RE = re.compile(
    r"^(\s*key)\s+(?!chain\b)(?!\d+\s*$)\S+.*",
    re.IGNORECASE | re.MULTILINE,
)

# "key-string [<type>] <v>" inside a Cisco key-chain block
# ".*" consumes an optional type indicator (e.g. "7") followed by the actual secret.
_KEY_STRING_RE = re.compile(r"^(\s*key-string)\s+\S+.*", re.IGNORECASE | re.MULTILINE)


def _sanitize_config(text: str) -> str:
    text = _PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _INLINE_PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _KEY_LINE_RE.sub(r"\1 <redacted>", text)
    text = _COMMUNITY_RE.sub(r"\1 <redacted>", text)
    text = _BARE_KEY_RE.sub(r"\1 <redacted>", text)
    text = _KEY_STRING_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Uptime helpers
# ---------------------------------------------------------------------------

_DAY_SECONDS = 86400
_HOUR_SECONDS = 3600
_MINUTE_SECONDS = 60

_UPTIME_RE = re.compile(
    r"(?:(?P<days>\d+)\s+days?(?:\(s\))?(?:,\s*)?)?"
    r"(?:(?P<hours>\d+)\s+hours?(?:\(s\))?(?:,\s*)?)?"
    r"(?:(?P<minutes>\d+)\s+minutes?(?:\(s\))?(?:,\s*)?)?"
    r"(?:(?P<seconds>\d+)\s+seconds?(?:\(s\))?)?",
    re.IGNORECASE,
)


def _parse_uptime(uptime_str: str) -> float:
    """Convert an APIC uptime string to total seconds."""
    m = _UPTIME_RE.search(uptime_str)
    total = 0.0
    if m.group("days"):
        total += int(m.group("days")) * _DAY_SECONDS
    if m.group("hours"):
        total += int(m.group("hours")) * _HOUR_SECONDS
    if m.group("minutes"):
        total += int(m.group("minutes")) * _MINUTE_SECONDS
    if m.group("seconds"):
        total += int(m.group("seconds"))
    return total


# ---------------------------------------------------------------------------
# Interface parsing helpers
# ---------------------------------------------------------------------------

# Opening line: "Interface eth2-1 is up, line protocol is up"  (IOS style)
#           or: "Ethernet1/1 is up"  (NX-OS / APIC leaf style)
# group(2) captures the operational/admin-state token including optional "administratively " prefix.
#   IOS:   group(2) = admin state; group(3) = line-protocol (operational) state on the header.
#   NX-OS: group(2) = operational state (header token); admin state is in the stanza body.
# group(3) is None in NX-OS style — its absence signals that the NX-OS parsing path should be used.
_INTF_HEADER_RE = re.compile(
    r"^(?:Interface\s+)?(\S+)\s+is\s+((?:administratively\s+)?(?:up|down))"
    r"(?:.*?line\s+protocol\s+is\s+(up|down))?",
    re.IGNORECASE | re.MULTILINE,
)

# "admin state is up/down" — NX-OS stanza body line for the administrative (enabled) state
_ADMIN_STATE_BODY_RE = re.compile(r"admin\s+state\s+is\s+(up|down)", re.IGNORECASE)

# MAC address — "address is <mac>" (IOS) or "address: <mac>" (NX-OS)
# \s* allows for "address:" with no intervening space before the colon.
# Matches colon-separated (00:11:22:aa:bb:cc) and Cisco dotted (7c69.f60f.aa60) formats.
_MAC_RE = re.compile(
    r"address\s*(?:is\s+|:\s*)([0-9a-f]{2}(?:[:.][0-9a-f]{2}){5}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})",
    re.IGNORECASE,
)

# IPv4 address in CIDR notation
_IPV4_RE = re.compile(r"Internet\s+address\s+is\s+(\d+\.\d+\.\d+\.\d+/\d+)", re.IGNORECASE)

# IPv6 address: "IPv6 address: 2001:db8::1/64"
_IPV6_RE = re.compile(r"IPv6\s+address:\s+([0-9a-fA-F:]+/\d+)", re.IGNORECASE)

# MTU
_MTU_RE = re.compile(r"MTU\s+(\d+)\s+bytes", re.IGNORECASE)

# Speed: "Speed: 1000 Mbps", "1000 Gbps", or APIC leaf "full-duplex, 40 Gb/s, ..."
# The "Speed:" prefix is optional so the bare "<value> <unit>" form is also matched.
# Units accept both condensed (Gbps/Mbps/Kbps) and slash-separated (Gb/s/Mb/s/Kb/s) forms.
_SPEED_RE = re.compile(
    r"(?:Speed[:\s]+)?(\d+(?:\.\d+)?)\s*([MmGgKk]b(?:ps?|/s))",
    re.IGNORECASE,
)

# Interface description: "Description: <text>" (IOS) or "Port description is <text>" (APIC NX-OS)
_DESC_RE = re.compile(r"(?:Description:|Port\s+description\s+is)\s+(.+)", re.IGNORECASE)


def _split_cidr(cidr: str) -> tuple[str, int]:
    """Split 'addr/prefix' into (addr, prefix_length). Returns ('', -1) on failure."""
    if not cidr or "/" not in cidr:
        return "", -1
    addr, _, prefix_str = cidr.partition("/")
    if not addr:
        return "", -1
    try:
        return addr, int(prefix_str)
    except ValueError:
        return addr, -1


def _speed_mbps(value: str, unit: str) -> float:
    """Convert speed value + unit string to Mbps float; -1.0 if unparseable."""
    try:
        v = float(value)
    except ValueError:
        return -1.0
    unit_lower = unit.lower()
    if unit_lower.startswith("g"):
        return v * 1000.0
    if unit_lower.startswith("k"):
        return v / 1000.0
    return v


def _parse_interfaces(raw: str) -> list[dict]:
    """
    Parse ``show interface`` output into a list of per-interface dicts.

    Each dict contains: name, is_up, is_enabled, description, mac_address,
    mtu, speed, ipv4 (list of CIDR strings), ipv6 (list of CIDR strings).
    Stanzas are separated by blank lines; each must start with an interface
    header line matching ``_INTF_HEADER_RE``.
    """
    interfaces = []
    stanzas = re.split(r"\n\s*\n", raw.strip())

    for stanza in stanzas:
        if not stanza.strip():
            continue
        header = _INTF_HEADER_RE.search(stanza)
        if not header:
            continue
        name = header.group(1)

        if header.group(3) is not None:
            # IOS / APIC controller style:
            #   "Interface X is [administratively] <admin> ... line protocol is <proto>"
            # group(2) = admin state, group(3) = line-protocol (operational) state
            admin_token = header.group(2).lower()
            admin_up = "administratively" not in admin_token
            proto_up = header.group(3).lower() == "up"
        else:
            # NX-OS / APIC leaf style:
            #   "EthernetX/Y is <oper>"  followed by "  admin state is <admin>" in body
            # group(2) = operational state; admin state is in the stanza body
            proto_up = header.group(2).lower() == "up"
            admin_body_m = _ADMIN_STATE_BODY_RE.search(stanza)
            if admin_body_m:
                admin_up = admin_body_m.group(1).lower() == "up"
            else:
                # No body admin-state line; fall back to treating "administratively" in
                # the header token as the admin-down indicator
                admin_up = "administratively" not in header.group(2).lower()

        mac_m = _MAC_RE.search(stanza)
        mac = mac_m.group(1) if mac_m else ""

        mtu_m = _MTU_RE.search(stanza)
        mtu = int(mtu_m.group(1)) if mtu_m else -1

        speed_m = _SPEED_RE.search(stanza)
        speed = _speed_mbps(speed_m.group(1), speed_m.group(2)) if speed_m else -1.0

        desc_m = _DESC_RE.search(stanza)
        description = desc_m.group(1).strip() if desc_m else ""

        ipv4 = [m.group(1) for m in _IPV4_RE.finditer(stanza)]
        ipv6 = [m.group(1) for m in _IPV6_RE.finditer(stanza)]

        interfaces.append(
            {
                "name": name,
                "is_up": proto_up,
                "is_enabled": admin_up,
                "description": description,
                "mac_address": mac,
                "mtu": mtu,
                "speed": speed,
                "ipv4": ipv4,
                "ipv6": ipv6,
            }
        )

    return interfaces


# ---------------------------------------------------------------------------
# Facts parsing helpers
# ---------------------------------------------------------------------------

_HOSTNAME_RE = re.compile(r"^(?:hostname|Hostname)\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_VERSION_RE = re.compile(
    r"^\s*(?:Software\s+Version|System\s+Version|Firmware\s+Version|Version)\s*:\s*(\S+)",
    re.IGNORECASE | re.MULTILINE,
)
_MODEL_RE = re.compile(r"^(?:Model|APIC\s+Model|Platform)\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_SERIAL_RE = re.compile(r"^(?:Serial\s+Number|Serial)\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_UPTIME_LINE_RE = re.compile(r"^(?:System\s+uptime|Uptime)\s*:\s*(.+)", re.IGNORECASE | re.MULTILINE)

# Tabular format emitted by some APIC versions for "show version":
#   Two-column ID form (Pod + Node):  controller  1  1  apic1  6.0(3f)
#   Single-column ID form (Id only):  controller  1  apic1     6.0(3f)
# The second numeric column is optional so both table layouts are matched.
# group(1) = node name, group(2) = version string
_TABULAR_CTRL_RE = re.compile(
    r"^\s*controller\s+\d+\s+(?:\d+\s+)?(\S+)\s+(\S+)",
    re.IGNORECASE | re.MULTILINE,
)

# Serial number from "show inventory" output:
#   PID: APIC-M2, VID: V01, SN: FOX2516P100
_INVENTORY_SERIAL_RE = re.compile(r"\bSN:\s*(\S+)", re.IGNORECASE)

_SERIAL_PLACEHOLDERS = frozenset({"none", "n/a", "na", "null", "unknown", "-"})


def _extract(text: str, pattern: re.Pattern) -> str:
    """Return first capture group from *pattern* match, or empty string."""
    m = pattern.search(text)
    return m.group(1).strip() if m else ""


class APICDriver(_napalm_base.NetworkDriver):
    """Cisco APIC NAPALM SSH driver (read-only subset for device-discovery)."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Initialise driver state; no connection is opened yet."""
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.device = None

        if optional_args is None:
            optional_args = {}
        self.netmiko_optional_args = netmiko_args(optional_args)
        self.netmiko_optional_args.setdefault("port", 22)
        self._intf_cache: list[dict] | None = None

    def open(self):
        """Open an SSH connection to the APIC via Netmiko."""
        self._intf_cache = None  # invalidate any stale cache from a previous session
        self.device = self._netmiko_open(
            _PLATFORM, netmiko_optional_args=self.netmiko_optional_args
        )
        # Derive the connected controller's name from the SSH prompt so that
        # _tabular_controller_row() can identify the local node in multi-controller
        # fabrics.  self.hostname is typically an IP in device-discovery policies.
        prompt = self.device.find_prompt().strip()
        self._prompt_hostname = re.sub(r"[\s#>$%:]+$", "", prompt) or self.hostname

    def close(self):
        """Close the SSH connection."""
        self._netmiko_close()

    def is_alive(self):
        """Return whether the SSH channel is still active."""
        if self.device is None:
            return {"is_alive": False}
        try:
            self.device.write_channel(chr(0))
            return {"is_alive": self.device.remote_conn.transport.is_active()}
        except (OSError, EOFError, AttributeError):
            return {"is_alive": False}

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _send(self, command: str) -> str:
        return self.device.send_command(command)

    def _parsed_interfaces(self) -> list[dict]:
        """Run ``show interface`` and return parsed interface list (cached per session)."""
        if getattr(self, "_intf_cache", None) is None:
            raw = self._send("show interface")
            self._intf_cache = _parse_interfaces(raw) if raw else []
        return self._intf_cache

    # -----------------------------------------------------------------------
    # NAPALM getters
    # -----------------------------------------------------------------------

    def _tabular_controller_row(self, raw: str):
        """
        Return the best-matching controller row from a tabular ``show version``.

        Uses ``_prompt_hostname`` (the name extracted from the SSH prompt at
        ``open()`` time) to identify the local node, because ``self.hostname``
        is typically an IP address in device-discovery policies and will not
        match the controller name column in the table.  Falls back to the first
        row when no name matches.
        Returns a regex match object or ``None`` if the table is absent.
        """
        local_name = getattr(self, "_prompt_hostname", self.hostname)
        for m in _TABULAR_CTRL_RE.finditer(raw):
            if m.group(1).lower() == local_name.lower():
                return m
        return _TABULAR_CTRL_RE.search(raw)

    def _parse_show_version(self, raw: str) -> dict:
        """
        Parse ``show version`` raw text into a facts dict.

        Tries key-value format first, then falls back to the tabular
        ``controller <pod> <node> <name> <version>`` row.  Returns a dict
        with keys: hostname, os_version, model, serial_number, uptime.
        Missing fields are returned as their ``"Unknown"`` / ``0.0`` defaults.
        """
        hostname = self.hostname
        os_version = "Unknown"
        model = "Unknown"
        serial_number = "Unknown"
        uptime = 0.0

        # Key-value format (primary)
        hostname_val = _extract(raw, _HOSTNAME_RE)
        if hostname_val:
            hostname = hostname_val
        version_val = _extract(raw, _VERSION_RE)
        if version_val:
            os_version = version_val
        model_val = _extract(raw, _MODEL_RE)
        if model_val:
            model = model_val
        serial_val = _extract(raw, _SERIAL_RE)
        if serial_val and serial_val.lower() not in _SERIAL_PLACEHOLDERS:
            serial_number = serial_val
        uptime_line = _extract(raw, _UPTIME_LINE_RE)
        if uptime_line:
            uptime = _parse_uptime(uptime_line)

        # Tabular format fallback
        if os_version == "Unknown":
            tab_m = self._tabular_controller_row(raw)
            if tab_m:
                if hostname == self.hostname:
                    hostname = tab_m.group(1)
                os_version = tab_m.group(2)

        # If the device was not identified as an APIC (os_version still Unknown),
        # discard any serial extracted by _SERIAL_RE: generic "Serial Number:" lines
        # appear in non-APIC Cisco "show version" output, and returning a non-Unknown
        # serial here would cause discover_device_driver() to accept this driver for
        # the wrong device type.
        if os_version == "Unknown":
            serial_number = "Unknown"

        return {
            "hostname": hostname,
            "os_version": os_version,
            "model": model,
            "serial_number": serial_number,
            "uptime": uptime,
        }

    def _fetch_serial_from_inventory(self) -> str:
        """
        Return serial number from ``show inventory``, or ``"Unknown"`` if unavailable.

        Called as a fallback when ``show version`` does not carry a serial (e.g.
        in the tabular format).  ``discover_device_driver()`` rejects drivers
        whose ``get_facts()`` returns ``"Unknown"`` for serial_number, so this
        call is important for auto-discovery to work.
        """
        inv_raw = self._send("show inventory")
        if inv_raw:
            inv_m = _INVENTORY_SERIAL_RE.search(inv_raw)
            if inv_m and inv_m.group(1).lower() not in _SERIAL_PLACEHOLDERS:
                return inv_m.group(1)
        return "Unknown"

    def get_facts(self) -> dict:
        """
        Return general device facts from ``show version`` and ``show interface``.

        Hostname, OS version, model, and serial number are regex-parsed from
        ``show version`` (key-value or tabular format).  When the serial is
        absent from ``show version`` output, ``show inventory`` is queried as a
        fallback.  The interface list is derived from ``show interface``.
        """
        ver_raw = self._send("show version")
        ver_facts = self._parse_show_version(ver_raw) if ver_raw else {}

        hostname = ver_facts.get("hostname", self.hostname)
        os_version = ver_facts.get("os_version", "Unknown")
        model = ver_facts.get("model", "Unknown")
        serial_number = ver_facts.get("serial_number", "Unknown")
        uptime = ver_facts.get("uptime", 0.0)

        # Only query inventory when show version positively identified this device as an
        # APIC (os_version resolved).  If both remain Unknown the driver should not
        # claim the device, so we skip the inventory call to avoid accepting non-APIC
        # Cisco devices that happen to expose a parseable serial via show inventory.
        if serial_number == "Unknown" and os_version != "Unknown":
            serial_number = self._fetch_serial_from_inventory()

        parsed_intfs = self._parsed_interfaces()
        interface_list = sorted({r["name"] for r in parsed_intfs if r.get("name")})

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
        """
        Return interface details from ``show interface``.

        Each entry includes operational/admin state, description, MAC address,
        MTU, and speed.  IP information is returned by ``get_interfaces_ip``.
        """
        parsed = self._parsed_interfaces()
        result: dict = {}
        for row in parsed:
            name = row["name"]
            if not name or name in result:
                continue
            result[name] = {
                "is_up": row["is_up"],
                "is_enabled": row["is_enabled"],
                "description": row["description"],
                "last_flapped": -1.0,
                "mtu": row["mtu"],
                "speed": row["speed"],
                "mac_address": row["mac_address"],
            }
        return result

    def get_interfaces_ip(self) -> dict:
        """
        Return IP addresses per interface from ``show interface``.

        Both IPv4 and IPv6 addresses in CIDR notation are included.
        """
        parsed = self._parsed_interfaces()
        result: dict = {}
        for row in parsed:
            name = row["name"]
            if not name or name in result:
                continue
            intf_ips: dict = {}

            for cidr in row.get("ipv4", []):
                addr, prefix = _split_cidr(cidr)
                if addr and prefix >= 0:
                    intf_ips.setdefault("ipv4", {})[addr] = {"prefix_length": prefix}

            for cidr in row.get("ipv6", []):
                addr, prefix = _split_cidr(cidr)
                if addr and prefix >= 0:
                    intf_ips.setdefault("ipv6", {})[addr] = {"prefix_length": prefix}

            if intf_ips:
                result[name] = intf_ips

        return result

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """
        Return device configuration from ``show running-config``.

        APIC does not expose a separate candidate or startup config via SSH CLI;
        those keys are always returned as empty strings.
        """
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}
        retrieve = retrieve.lower()

        if retrieve in ("all", "running"):
            config["running"] = self._send("show running-config")

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """
        Return VLAN information from ``fabric show vlan extended`` via ntc-templates.

        The ``cisco_apic`` ntc-templates platform parses per-node VLAN entries
        including VLAN ID, name, encapsulation, and port membership.  Entries
        are aggregated across all fabric nodes; duplicate VLAN IDs are merged
        with interfaces deduplicated.

        Returns an empty dict when the command produces no output or the
        ntc-templates parser returns no rows.
        """
        raw = self._send("fabric show vlan extended")
        if not raw:
            return {}

        try:
            rows = parse_output(
                platform=_PLATFORM,
                command="fabric show vlan extended",
                data=raw,
            )
        except Exception:
            logger.debug("Failed to parse 'fabric show vlan extended' output", exc_info=True)
            return {}

        # Build intermediate result with sets for O(1) port deduplication.
        # Each value is {"name": str, "ports": set[str]}.
        intermediate: dict = {}
        for row in rows:
            vlan_id = row.get("vlan_id", "").strip()
            if not vlan_id:
                continue

            raw_name = row.get("vlan_name")
            vlan_name = (raw_name[0].strip() if isinstance(raw_name, list) and raw_name else str(raw_name or "").strip()) or vlan_id

            entry = intermediate.setdefault(vlan_id, {"name": vlan_id, "ports": set()})

            # Update the name when a better (non-placeholder) name is found in a later row.
            if vlan_name and vlan_name != vlan_id:
                entry["name"] = vlan_name

            # VLAN_PORTS is a List in the template; each element may be a
            # comma-separated string — normalise to a flat deduplicated set.
            raw_ports: list = row.get("vlan_ports") or []
            for port_token in raw_ports:
                for port in re.split(r"[,\s]+", port_token):
                    port = port.strip().rstrip(",")
                    if port:
                        entry["ports"].add(port)

        return {
            vid: {"name": e["name"], "interfaces": sorted(e["ports"])}
            for vid, e in intermediate.items()
        }
