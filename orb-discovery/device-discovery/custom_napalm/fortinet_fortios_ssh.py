# Copyright 2026 NetBox Labs Inc
"""
Custom FortiOS SSH NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses ntc-templates 9.x for structured parsing where templates exist;
falls back to regex parsing where they do not (uptime).
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.helpers import mac as normalize_mac
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

logger = logging.getLogger(__name__)

_SET_FIELDS_RE = re.compile(
    r"(set\s+(?:password|passwd|psk|psksecret|secret|auth-password))\s+.*",
    re.IGNORECASE,
)
_ENC_RE = re.compile(r"(\bENC\b)\s+\S+")

# A field marker is `key:` anchored on both sides: preceded by start-of-line or
# whitespace, followed by whitespace or end-of-line. Both anchors are load-bearing.
# Without the left one, `(Duplex:` in `speed: 1000Mbps (Duplex: full)` reads as a key
# on every up interface, 27 of the 73 blocks in tests/.../corpus/. Without the right
# one, a colon inside free text such as `description: site-a:core` splits the value.
# The cost is that `status:up` with no space is not a field; it is counted as an
# anomaly rather than guessed at.
_FIELD_MARKER_RE = re.compile(r"(?:^|(?<=\s))([A-Za-z][A-Za-z0-9_.-]*):(?=\s|$)")


def _scan_fields(line: str) -> tuple[dict[str, str], int]:
    """
    Return the ``key: value`` pairs on one line, plus an anomaly count.

    Keys are lowercased and keep their hyphens, so this yields ``netbios-forward``
    where the replaced ntc-template yielded ``netbios_forward``. A key's first
    occurrence wins; a repeat is counted rather than silently resolved, because
    first-wins and last-wins are both defensible and would report different
    interfaces to NetBox.
    """
    marks = list(_FIELD_MARKER_RE.finditer(line))
    fields: dict[str, str] = {}
    anomalies = 0
    for index, mark in enumerate(marks):
        key = mark.group(1).lower()
        end = marks[index + 1].start() if index + 1 < len(marks) else len(line)
        if key in fields:
            anomalies += 1
            continue
        fields[key] = line[mark.end():end].strip()
    return fields, anomalies


# Interface headers are matched against the stripped line, as a FULL match. The
# trailing anchor is what makes `==[port2] (SFP+)` an unreadable line rather than a
# header with trailing text, which is what stops its fields landing on the interface
# above it. The `:` in the name class is untested insurance; `.` is exercised by
# names such as l2t.root in the sibling command.
_PHYS_HEADER_RE = re.compile(r"^==\s*\[\s*([A-Za-z0-9][A-Za-z0-9_.:-]*)\s*\]$")
_SPEED_RE = re.compile(r"^(\d+)\s*Mbps\b")


def _normalise_speed(value: str) -> str:
    """
    Return the digits of an Mbps speed, the ``n/a`` sentinel, or an empty string.

    ``get_interfaces`` tests for the literal ``n/a`` and then calls ``float()``, so
    both forms the replaced template produced are preserved. A unit that is not Mbps
    yields empty rather than its digits: ``10Gbps`` read as ``10`` would reach NetBox
    as 10 Mbps on a 10G port.
    """
    value = value.strip()
    if value.lower().startswith("n/a"):
        return "n/a"
    match = _SPEED_RE.match(value)
    return match.group(1) if match else ""


def _parse_physical(raw: str | None) -> tuple[list[dict[str, str]], int]:  # noqa: C901 - one flat state machine reads clearer than split helpers
    """
    Parse ``get system interface physical`` into rows, plus an anomaly count.

    Unknown fields are kept and ignored; that tolerance is the point. A block is
    emitted only when it scanned both ``status`` and ``speed``, the two fields
    ``get_interfaces`` consumes, so a half-read block is absent rather than reported
    as down with no speed. End of input closes the open block, which is load-bearing:
    every capture under tests/.../corpus/ ends on a field line.
    """
    rows: list[dict[str, str]] = []
    anomalies = 0
    block: dict[str, str] | None = None

    def close() -> None:
        nonlocal block, anomalies
        if block is None:
            return
        if "status" in block and "speed" in block:
            rows.append(block)
        else:
            anomalies += 1
        block = None

    for line in (raw or "").splitlines():
        if not line.strip():
            continue
        header = _PHYS_HEADER_RE.match(line.strip())
        if header:
            close()
            # An indented header names an interface; a non-indented one is a group
            # header such as `== [onboard]`, which is normal output, not an anomaly.
            if line[:1].isspace():
                block = {"name": header.group(1)}
            continue
        if block is not None:
            fields, duplicates = _scan_fields(line)
            anomalies += duplicates
            if fields:
                if "speed" in fields:
                    fields["speed"] = _normalise_speed(fields["speed"])
                block.update(fields)
                continue
        close()
        anomalies += 1

    close()
    return rows, anomalies


def _sanitize_config(text: str) -> str:
    text = _SET_FIELDS_RE.sub(r"\1 <redacted>", text)
    text = _ENC_RE.sub(r"\1 <redacted>", text)
    return text


def _parse_uptime(output: str) -> int:
    """
    Parse uptime seconds from 'get system performance status' output.

    Expected line: 'Uptime: 10 days,  3 hours,  12 minutes'
    """
    m = re.search(
        r"Uptime:\s+(\d+)\s+days?,\s+(\d+)\s+hours?,\s+(\d+)\s+minutes?",
        output,
    )
    if not m:
        return 0
    days, hours, minutes = int(m.group(1)), int(m.group(2)), int(m.group(3))
    return days * 86400 + hours * 3600 + minutes * 60


# --- fnsysctl ifconfig MAC parser ------------------------------------------ #
# FortiOS ``fnsysctl ifconfig`` is a shell-passthrough wrapper for Linux
# ifconfig. It emits all NICs in one shot, e.g.::
#
#   port1   Link encap:Ethernet  HWaddr 00:09:0F:09:00:01
#           inet addr:192.168.1.1  Bcast:192.168.1.255  Mask:255.255.255.0
#           UP BROADCAST RUNNING ALLMULTI MULTICAST  MTU:1500  Metric:1
#           ...
#
#   port2   Link encap:Ethernet  HWaddr 00:09:0F:09:00:02
#           ...
#
# Pairs ``<name> Link encap:Ethernet`` header with the ``HWaddr`` value on
# the same line. Loopback / non-ethernet interfaces emit a different encap
# (``Link encap:Local Loopback``) and don't carry HWaddr — silently skipped.
#
# HA caveat: FortiGate HA-secondary nodes report the *current* (operational)
# MAC rather than the burned-in MAC. ``get hardware nic <port>`` returns
# permanent MAC but is per-port. The current MAC is what NetBox matches
# against L2 neighbours so we accept it as the right value.
_FNSYSCTL_IFACE_RE = re.compile(
    # End-of-token boundary (\b) prevents the capture group from greedily
    # absorbing trailing trash on the same line. ifconfig output ends the
    # HWaddr line at the MAC, but the explicit boundary is defensive.
    r"^(\S+)\s+Link\s+encap:Ethernet\s+HWaddr\s+([0-9a-fA-F:.\-]{12,17})\b",
    re.M,
)


def _parse_fnsysctl_mac_addresses(text: str) -> dict[str, str]:
    """
    Parse ``fnsysctl ifconfig`` output → ``{interface_name: normalised_mac}``.

    Loopback / non-ethernet interfaces (``Link encap:Local Loopback``,
    GRE tunnels, etc.) don't match the Ethernet-only header and are
    silently skipped. Empty / None input is tolerated.
    """
    result: dict[str, str] = {}
    if not text:
        return result
    for m in _FNSYSCTL_IFACE_RE.finditer(text):
        name, raw = m.group(1), m.group(2)
        try:
            result[name] = normalize_mac(raw)
        except Exception:
            # napalm normalize_mac rejected the value — log and skip rather
            # than emit a malformed MAC string that downstream NetBox matching
            # would silently treat as a distinct interface.
            logger.warning(
                "fortinet_fortios_ssh: normalize_mac rejected %r for interface %s — emitting empty MAC",
                raw, name,
            )
    return result


def _netmask_to_prefix(netmask: str) -> int:
    """Convert dotted-decimal netmask to CIDR prefix length."""
    return sum(bin(int(octet)).count("1") for octet in netmask.split("."))


class FortiOSSSHDriver(_napalm_base.NetworkDriver):
    """FortiOS NAPALM driver using SSH CLI + ntc-templates (read-only subset for device-discovery)."""

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
            "fortinet", netmiko_optional_args=self.netmiko_optional_args
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
        # The ntc-template for 'get system status' has ^. -> Error and does not cover all
        # lines real FortiOS devices emit (e.g. 'Secure Boot:'). Use regex directly.
        status_raw = self.device.send_command("get system status")

        m_host = re.search(r"^Hostname:\s+(\S+)", status_raw, re.MULTILINE)
        m_ser = re.search(r"^Serial-Number:\s+(\S+)", status_raw, re.MULTILINE)
        m_ver = re.search(r"^Version:\s+(\S+)\s+v([\d.]+)", status_raw, re.MULTILINE)

        hostname = m_host.group(1) if m_host else "Unknown"
        serial_number = m_ser.group(1) if m_ser else "Unknown"
        model = m_ver.group(1) if m_ver else "Unknown"
        os_version = m_ver.group(2) if m_ver else "Unknown"

        # Uptime via a separate command (no ntc-template for this)
        perf_raw = self.device.send_command("get system performance status")
        uptime = float(_parse_uptime(perf_raw))

        # Interface list from physical interfaces
        intf_raw = self.device.send_command("get system interface physical")
        interface_list: list[str] = []
        try:
            intf_parsed = parse_output(
                platform="fortinet", command="get system interface physical", data=intf_raw
            )
            interface_list = sorted(r["name"] for r in intf_parsed if r.get("name"))
        except Exception:
            logger.debug("Failed to parse 'get system interface physical' output", exc_info=True)

        return {
            "hostname": hostname,
            "vendor": "Fortinet",
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

        Per-port MAC is sourced from ``fnsysctl ifconfig`` — a single shell
        passthrough call that lists every Ethernet NIC with HWaddr. Non-
        Ethernet interfaces (Loopback, tunnels) and admin profiles without
        shell access return no MAC; the field stays ``"" `` for those.

        HA caveat: secondary HA nodes report the *current* (operational) MAC
        rather than the burned-in MAC — see _parse_fnsysctl_mac_addresses.
        """
        raw = self.device.send_command("get system interface physical")
        try:
            parsed = parse_output(
                platform="fortinet", command="get system interface physical", data=raw
            )
        except Exception:
            logger.debug("Failed to parse 'get system interface physical' output", exc_info=True)
            return {}

        mac_by_intf = _parse_fnsysctl_mac_addresses(
            self.device.send_command("fnsysctl ifconfig")
        )

        interfaces = {}
        for row in parsed:
            name = row.get("name", "")
            if not name:
                continue

            status = (row.get("status") or "").lower()
            speed_raw = row.get("speed") or ""
            try:
                speed = float(speed_raw) if speed_raw and speed_raw != "n/a" else 0.0
            except ValueError:
                speed = 0.0

            interfaces[name] = {
                "is_up": status == "up",
                "is_enabled": status != "disabled",
                "description": "",
                "last_flapped": -1.0,
                "mtu": 0,
                "speed": speed,
                "mac_address": mac_by_intf.get(name, ""),
            }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface."""
        raw = self.device.send_command("get system interface")
        try:
            parsed = parse_output(platform="fortinet", command="get system interface", data=raw)
        except Exception:
            logger.debug("Failed to parse 'get system interface' output", exc_info=True)
            return {}

        interfaces_ip: dict = {}
        for row in parsed:
            name = row.get("name", "")
            ip = row.get("ip_address", "")
            netmask = row.get("netmask", "")
            if not name or not ip or ip == "0.0.0.0":
                continue
            try:
                prefix = _netmask_to_prefix(netmask) if netmask else 0
                interfaces_ip.setdefault(name, {}).setdefault("ipv4", {})[ip] = {
                    "prefix_length": prefix
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
            config["running"] = self.device.send_command("show full-configuration")

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """FortiOS does not expose a traditional VLAN table via SSH CLI."""
        return {}
