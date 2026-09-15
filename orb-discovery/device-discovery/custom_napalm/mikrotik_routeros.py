# Copyright 2026 NetBox Labs Inc
"""
Custom MikroTik RouterOS NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko mikrotik_routeros device type and ntc-templates for structured
parsing of commands where templates are compatible across v6 and v7.  Falls
back to regex for commands whose template breaks on one of the two major
RouterOS versions (system resource print build-time format, interface print
detail Flags header).
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.helpers import mac as normalize_mac
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config sanitization — MikroTik RouterOS /export sensitive fields
# ---------------------------------------------------------------------------
# RouterOS /export uses key=value or key="value with spaces" syntax.
# We match both quoted ("...") and unquoted (\S+) forms.

_PASS_RE = re.compile(
    r'\b(password=)(?:"[^"]*"|\S+)',
    re.IGNORECASE,
)
_SECRET_RE = re.compile(
    r'\b(secret=)(?:"[^"]*"|\S+)',
    re.IGNORECASE,
)
_PASSPHRASE_RE = re.compile(
    r'\b(passphrase=)(?:"[^"]*"|\S+)',
    re.IGNORECASE,
)


def _sanitize_config(text: str) -> str:
    text = _PASS_RE.sub(r"\1<redacted>", text)
    text = _SECRET_RE.sub(r"\1<redacted>", text)
    text = _PASSPHRASE_RE.sub(r"\1<redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Uptime helpers
# ---------------------------------------------------------------------------

_WEEK_SECONDS = 7 * 86400
_DAY_SECONDS = 86400
_HOUR_SECONDS = 3600
_MINUTE_SECONDS = 60


def _parse_uptime(uptime_str: str) -> float:
    """
    Parse a RouterOS compact uptime string to total seconds.

    Handles the compact RouterOS format:  "20w5d14h23m42s"
    All components are optional; missing components contribute zero.
    """
    seconds = 0.0
    for pattern, factor in (
        (r"(\d+)w", _WEEK_SECONDS),
        (r"(\d+)d", _DAY_SECONDS),
        (r"(\d+)h", _HOUR_SECONDS),
        (r"(\d+)m", _MINUTE_SECONDS),
        (r"(\d+)s", 1),
    ):
        m = re.search(pattern, uptime_str)
        if m:
            seconds += int(m.group(1)) * factor
    return seconds


# ---------------------------------------------------------------------------
# Interface detail parsing
# ---------------------------------------------------------------------------
# RouterOS v6 and v7 differ in their "Flags:" header line:
#   v6:  "Flags: D - dynamic, X - disabled, R - running, S - slave"
#   v7:  "Flags: D - dynamic; X - disabled; I - inactive, R - running; …"
#
# The ntc-template for "interface print detail" only matches the v6 comma
# form, so we use regex instead across both versions.
#
# Each interface block starts with a row index line (" 0   R   …").  Blocks
# are normally separated by blank lines, but RouterOS can omit those blank
# lines in some output modes.  We therefore split on the index anchor rather
# than on blank lines.  A block may span multiple lines when a description
# comment precedes the name= line:
#
#   14   R   ;;; defconf
#            name="bridge" type="bridge" …
#
# Splitting on the index anchor handles both formats because continuation
# lines (comments, wrapped attributes) never start with a bare digit.

_INTF_INDEX_FLAGS_RE = re.compile(
    r"^\s*\d+\s*(?P<flags>[DXIRSP]*)",
    re.MULTILINE,
)
_INTF_NAME_RE = re.compile(r'name="(?P<name>[^"]+)"')
_INTF_TYPE_RE = re.compile(r'type="(?P<type>[^"]+)"')
_INTF_MTU_RE = re.compile(r"(?<![a-zA-Z0-9-])mtu=(?P<mtu>\d+|auto)")
_INTF_MAC_RE = re.compile(
    r"mac-address=(?P<mac>[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"
)


def _parse_interfaces_detail(output: str) -> list[dict]:
    """
    Parse 'interface print detail' output into a list of attribute dicts.

    Works for both RouterOS v6 and v7 output formats, and handles both
    blank-line-separated and tightly-packed (no blank lines) output by
    anchoring on the row-index line rather than on blank-line delimiters.
    Returns an empty list when output is empty or unparseable.
    """
    if not output:
        return []

    results: list[dict] = []
    # Locate each interface block by the start of its index line
    # (e.g. " 0   R   …" or " 14  X   …").  The Flags:/Columns: header
    # and continuation lines (comments, wrapped attributes) never start
    # with a bare digit, so they are naturally excluded.
    block_starts = [m.start() for m in re.finditer(r"(?m)^\s*\d+\s", output)]
    if not block_starts:
        return []

    for i, start in enumerate(block_starts):
        end = block_starts[i + 1] if i + 1 < len(block_starts) else len(output)
        block = output[start:end].strip()
        if not block:
            continue

        m_name = _INTF_NAME_RE.search(block)
        if not m_name:
            continue
        name = m_name.group("name")

        # Flags come from the first line of the block (the index line).
        first_line = block.splitlines()[0]
        m_flags = _INTF_INDEX_FLAGS_RE.match(first_line)
        flags = m_flags.group("flags").upper() if m_flags else ""

        m_type = _INTF_TYPE_RE.search(block)
        intf_type = m_type.group("type") if m_type else "ether"

        m_mtu = _INTF_MTU_RE.search(block)
        if m_mtu and m_mtu.group("mtu") != "auto":
            mtu = int(m_mtu.group("mtu"))
        else:
            mtu = -1

        m_mac = _INTF_MAC_RE.search(block)
        mac_raw = m_mac.group("mac") if m_mac else ""
        try:
            mac = normalize_mac(mac_raw) if mac_raw else ""
        except Exception:
            mac = mac_raw

        results.append(
            {
                "name": name,
                "type": intf_type,
                # X = disabled in both v6 and v7
                "is_enabled": "X" not in flags,
                # R = running in both v6 and v7
                "is_up": "R" in flags,
                "mtu": mtu,
                "mac_address": mac,
            }
        )

    return results


# ---------------------------------------------------------------------------
# VLAN table parsing
# ---------------------------------------------------------------------------
# RouterOS "interface vlan print" produces a tabular format (not the detail
# format expected by the ntc-template).  Both v6 and v7 follow the same
# column order:  # [FLAGS] NAME  MTU  ARP  VLAN-ID  INTERFACE
#
#   v6:   0 R 111     1500 enabled  111 bridge
#   v7:   0 R Huis    1500 enabled   10 bridge

# An interface comment is printed as a ";;; text" line between the index
# and flags and the row itself, which then starts on the next line:
#
#    0 R  ;;; uplink
#         vlan10   1500 enabled   10 ether1
#
# The optional comment group below accepts that layout so a commented VLAN
# interface is not skipped.
_VLAN_ROW_RE = re.compile(
    r"^\s*\d+\s+"             # row index
    r"(?:[A-Z]+\s+)?"         # optional flags (R, X, D, I, H, RH, … — must be followed by whitespace)
    r"(?:;;;[^\n]*\n\s*)?"    # optional interface comment line preceding the row
    r"(?P<name>\S+)\s+"       # VLAN name
    r"\d+\s+"                 # MTU (ignored)
    r"\S+\s+"                 # ARP setting (ignored)
    r"(?P<vlan_id>\d+)\s+"    # VLAN ID
    r"(?P<interface>\S+)",    # parent interface
    re.MULTILINE,
)


def _parse_vlans(output: str) -> dict:
    """
    Parse 'interface vlan print' tabular output into the NAPALM VLAN dict.

    Both v6 and v7 column orders are handled by a single regex.
    Returns an empty dict when output is empty or unparseable.
    """
    vlans: dict = {}
    for m in _VLAN_ROW_RE.finditer(output):
        vlan_id = m.group("vlan_id")
        intf = m.group("interface")
        if vlan_id in vlans:
            if intf not in vlans[vlan_id]["interfaces"]:
                vlans[vlan_id]["interfaces"].append(intf)
        else:
            vlans[vlan_id] = {
                "name": m.group("name"),
                "interfaces": [intf],
            }
    return vlans


_ROS_TYPE_TO_NETBOX = {
    "bond": "lag",
    "bridge": "bridge",
    "vlan": "virtual",
    "vxlan": "virtual",
    "vpls": "virtual",
    "vrrp": "virtual",
    "eoip": "virtual",
    "eoipv6": "virtual",
    "gre-tunnel": "virtual",
    "gre6-tunnel": "virtual",
    "ipip-tunnel": "virtual",
    "ipipv6-tunnel": "virtual",
    "6to4-tunnel": "virtual",
    "ppp-out": "virtual",
    "pppoe-out": "virtual",
    "l2tp-out": "virtual",
    "pptp-out": "virtual",
    "sstp-out": "virtual",
    "ovpn-out": "virtual",
    "wg": "virtual",
    "veth": "virtual",
}


def _ros_type_to_netbox(ros_type: str) -> str | None:
    """
    Map a RouterOS interface type to a NetBox interface type.

    Structural / logical types are mapped (bond->lag, vlan->virtual,
    bridge->bridge, tunnels/ppp->virtual). Physical (ether) and wireless are
    left unset so the pipeline's name/speed/if_type logic applies.
    """
    return _ROS_TYPE_TO_NETBOX.get((ros_type or "").strip().lower())



# 'ip address print' columns differ by RouterOS version: v6 prints ADDRESS,
# NETWORK and INTERFACE, and v7 adds VRF. The device declares its own columns
# in one of two header lines, so the count is read from the device rather than
# guessed, and an interface name containing spaces still resolves.
_IP_COLUMNS_RE = re.compile(r"^\s*Columns:\s*(?P<columns>.+?)\s*$", re.IGNORECASE)
_IP_HEADER_RE = re.compile(r"^\s*#\s+ADDRESS\s+(?P<columns>.+?)\s*$", re.IGNORECASE)

# One address row: an index, optional flag letters, the address and prefix,
# then the remaining columns. Everything after the prefix is split positionally
# against the column count, so a column RouterOS adds later is ignored rather
# than fatal.
_IP_ROW_RE = re.compile(
    r"^\s*(?P<num>\d+)\s+"
    r"(?:(?P<flags>[A-Za-z]+)\s+)?"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<prefix>\d{1,2})\s+"
    r"(?P<rest>\S.*?)\s*$"
)

# RouterOS address flags. X is an address the operator disabled and I one the
# device could not apply; neither is active, and SNMP does not report them, so
# emitting them would make the two backends disagree about the same device.
# D is a dynamic address, from DHCP or similar, which is active and is kept.
_IP_FLAGS_NOT_ACTIVE = frozenset("XI")


def _parse_ip_addresses(raw: str) -> list[dict]:
    """
    Parse 'ip address print' into address rows, across RouterOS 6 and 7.

    Returns one dict per active address with "ip", "prefix_length",
    "interface" and "vrf" (None where the device publishes no VRF column).
    Rows the device flags as disabled or invalid are skipped.
    """
    has_vrf = False
    rows: list[dict] = []

    for line in raw.splitlines():
        if not line.strip():
            continue

        header = _IP_COLUMNS_RE.match(line) or _IP_HEADER_RE.match(line)
        if header:
            has_vrf = "VRF" in header.group("columns").upper()
            continue

        match = _IP_ROW_RE.match(line)
        if not match:
            # Flags legends, comment rows (";;; text") and anything else the
            # device prints are not address rows. Skipped rather than fatal:
            # an unrecognised line must not cost the addresses around it.
            continue

        flags = match.group("flags") or ""
        if set(flags.upper()) & _IP_FLAGS_NOT_ACTIVE:
            continue

        fields = match.group("rest").split()
        if len(fields) < 2:
            continue
        # NETWORK first, VRF last where the device has that column, and
        # whatever lies between is the interface name, which RouterOS permits
        # to contain spaces.
        vrf = fields[-1] if has_vrf and len(fields) >= 3 else None
        interface = " ".join(fields[1:-1] if vrf is not None else fields[1:])
        if not interface:
            continue

        rows.append(
            {
                "ip": match.group("ip"),
                "prefix_length": int(match.group("prefix")),
                "interface": interface,
                "vrf": vrf,
            }
        )

    return rows


class ROSDriver(_napalm_base.NetworkDriver):
    """MikroTik RouterOS (ros) NAPALM driver (read-only subset for device-discovery)."""

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

    def open(self):
        """Open an SSH connection to the device via Netmiko."""
        self.device = self._netmiko_open(
            "mikrotik_routeros", netmiko_optional_args=self.netmiko_optional_args
        )

    def close(self):
        """Close the SSH connection."""
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

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _resource_facts(self) -> tuple[str, str, float]:
        """
        Parse 'system resource print' and return (os_version, model, uptime).

        Uses regex because the ntc-template's BUILD_TIME pattern only matches
        the RouterOS v6 date format and raises TextFSMError on v7 output.
        Returns ("Unknown", "Unknown", 0.0) when the command yields no output.
        """
        os_version = "Unknown"
        model = "Unknown"
        uptime = 0.0

        raw = self.device.send_command("system resource print")
        if not raw:
            return os_version, model, uptime

        m = re.search(r"version\s*:\s*(.+)", raw)
        if m:
            os_version = m.group(1).strip()

        m = re.search(r"uptime\s*:\s*(\S+)", raw)
        if m:
            uptime = _parse_uptime(m.group(1).strip())

        m = re.search(r"board-name\s*:\s*(.+)", raw)
        if m:
            model = m.group(1).strip()

        return os_version, model, uptime

    def _routerboard_facts(self) -> tuple[str, str]:
        """
        Parse 'system routerboard print' and return (model, serial_number).

        The ntc-template extracts ``hardware_model`` and ``serial_number``
        from routerboard output (physical hardware devices only).  Returns
        ("Unknown", "Unknown") when the command yields no output (e.g. on
        CHR / virtual devices that have no routerboard), which causes
        ``get_facts`` to fall back to the ``board-name`` from
        ``system resource print``.
        """
        model = "Unknown"
        serial_number = "Unknown"

        raw = self.device.send_command("system routerboard print")
        if not raw:
            return model, serial_number

        try:
            parsed = parse_output(
                platform="mikrotik_routeros",
                command="system routerboard print",
                data=raw,
            )
            if parsed:
                row = parsed[0]
                if row.get("hardware_model"):
                    model = row["hardware_model"]
                if row.get("serial_number"):
                    serial_number = row["serial_number"]
        except Exception:
            logger.warning(
                "mikrotik_routeros: could not parse 'system routerboard "
                "print'; model and serial will be missing",
                exc_info=True,
            )

        return model, serial_number

    def _identity_hostname(self) -> str | None:
        """
        Parse 'system identity print' and return the device hostname.

        Returns ``None`` when the command yields no output or parsing fails,
        so the caller can fall back to ``self.hostname``.
        """
        raw = self.device.send_command("system identity print")
        if not raw:
            return None

        try:
            parsed = parse_output(
                platform="mikrotik_routeros",
                command="system identity print",
                data=raw,
            )
            if parsed and parsed[0].get("name"):
                return parsed[0]["name"]
        except Exception:
            logger.warning(
                "mikrotik_routeros: could not parse 'system identity print'; "
                "the device hostname will be missing",
                exc_info=True,
            )

        return None

    def _interfaces_detail(self) -> list[dict]:
        """
        Send 'interface print detail' once and return the parsed interface list.

        The result is cached on the instance so that both get_facts and
        get_interfaces can share it without issuing a second SSH round-trip.
        Returns an empty list on failure or empty output.
        """
        if not hasattr(self, "_cached_interfaces_detail"):
            raw = self.device.send_command("interface print detail")
            if not raw:
                self._cached_interfaces_detail: list[dict] = []
            else:
                try:
                    self._cached_interfaces_detail = _parse_interfaces_detail(raw)
                except Exception:
                    logger.warning(
                        "mikrotik_routeros: could not parse 'interface print "
                        "detail'; interface detail will be missing",
                        exc_info=True,
                    )
                    self._cached_interfaces_detail = []
        return self._cached_interfaces_detail

    # -----------------------------------------------------------------------
    # NAPALM getters
    # -----------------------------------------------------------------------

    def get_facts(self) -> dict:
        """
        Return general device facts.

        Uptime, OS version, and board name come from 'system resource print'
        (regex-parsed; the ntc-template breaks on RouterOS v7 due to a
        different build-time date format).  Serial number and hardware model
        come from 'system routerboard print' (ntc-template works on both
        versions).  Hostname comes from 'system identity print'.  Interface
        list is derived from 'interface print detail'.
        """
        os_version, model, uptime = self._resource_facts()

        rb_model, serial_number = self._routerboard_facts()
        if rb_model != "Unknown":
            model = rb_model

        hostname = self._identity_hostname() or self.hostname

        interface_list = sorted(row["name"] for row in self._interfaces_detail())

        return {
            "hostname": hostname,
            "vendor": "MikroTik",
            "model": model,
            "os_version": os_version,
            "serial_number": serial_number,
            "uptime": uptime,
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """
        Return interface details keyed by interface name.

        Parsed from 'interface print detail'.  The X flag means disabled; the
        R flag means running.  MAC addresses are normalised to the standard
        XX:XX:XX:XX:XX:XX form.  MTU is -1 when set to 'auto' (bridge
        interfaces) or absent.
        """
        intfs = self._interfaces_detail()
        result: dict = {}
        for row in intfs:
            name = row["name"]
            if name in result:
                continue
            result[name] = {
                "is_up": row["is_up"],
                "is_enabled": row["is_enabled"],
                "description": "",
                "last_flapped": -1.0,
                "mtu": row["mtu"],
                "speed": -1.0,
                "mac_address": row["mac_address"],
            }
            nb_type = _ros_type_to_netbox(row.get("type", ""))
            if nb_type:
                result[name]["type"] = nb_type
        return result

    def get_interfaces_ip(self) -> dict:
        """
        Return IPv4 addresses per interface.

        Parsed in this driver rather than through the shared ntc-template.
        RouterOS 7 adds a fourth column, VRF, to 'ip address print', and the
        template anchors its two header lines to exactly three columns, so the
        parse aborts on the first of them and the device reports no addresses
        at all.  Relaxing those anchors is not enough either: the template's
        interface field runs to end of line, so it swallows the VRF value and
        yields interface names like "Loopback           main".

        IPv6 addresses are not returned.  There is no ntc-template for
        'ipv6 address print' covering both RouterOS 6 and 7, and this driver
        does not parse that command.
        """
        raw = self.device.send_command("ip address print")
        if not raw:
            logger.warning(
                "mikrotik_routeros: 'ip address print' returned no output; "
                "no IP addresses will be discovered for this device"
            )
            return {}

        interfaces_ip: dict = {}
        for address in _parse_ip_addresses(raw):
            interfaces_ip.setdefault(address["interface"], {}).setdefault("ipv4", {})[
                address["ip"]
            ] = {"prefix_length": address["prefix_length"]}
        if not interfaces_ip:
            logger.warning(
                "mikrotik_routeros: no address rows read from 'ip address "
                "print'; the output format may have changed. First line: %r",
                raw.splitlines()[0] if raw.splitlines() else "",
            )
        return interfaces_ip

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """
        Return device configuration.

        RouterOS 'export' produces the running configuration in a format that
        can be re-applied with '/import'.  There is no separate candidate or
        startup config.
        """
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}

        if retrieve in ("all", "running"):
            config["running"] = self.device.send_command("export")

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """
        Return VLAN information keyed by VLAN ID string.

        Parsed from 'interface vlan print' tabular output (compatible with
        both RouterOS v6 and v7).  Multiple rows for the same VLAN ID are
        aggregated into the 'interfaces' list.
        """
        raw = self.device.send_command("interface vlan print")
        if not raw:
            return {}
        try:
            return _parse_vlans(raw)
        except Exception:
            logger.warning(
                "mikrotik_routeros: could not parse 'interface vlan print'; "
                "no VLANs will be discovered for this device",
                exc_info=True,
            )
            return {}
