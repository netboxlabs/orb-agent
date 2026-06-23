# Copyright 2026 NetBox Labs Inc
"""
Custom Huawei SmartAX (CloudEngine OLT) NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses ntc-templates 9.x for structured parsing where templates are available
(display version, display board serial-number, display service-port all);
falls back to regex for commands without SmartAX-specific templates.
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.helpers import mac as normalize_mac
from napalm.base.netmiko_helpers import netmiko_args
from netmiko.huawei.huawei_smartax import HuaweiSmartAXSSH
from netmiko.ssh_dispatcher import CLASS_MAPPER, platforms
from ntc_templates.parse import parse_output

# ---------------------------------------------------------------------------
# Netmiko device type — extends the upstream class so that '#' is accepted as
# an initial prompt.  Huawei SmartAX enable-mode already uses '#', but the
# upstream prompt_pattern only matches '>' and '$', causing session_preparation
# to time out when the SSH server (e.g. mockit) presents a '#' prompt
# immediately at login.  Registering a private device-type key means we don't
# mutate the global 'huawei_smartax' mapping.
# ---------------------------------------------------------------------------

_NETMIKO_DEVICE_TYPE = "_huawei_smartax_smart"


class _SmartAXSSH(HuaweiSmartAXSSH):
    """HuaweiSmartAXSSH with '#' added to the initial prompt pattern."""

    prompt_pattern = r"[>#$]"


def _ensure_netmiko_device_type_registered() -> None:
    """Register the custom Netmiko device type only when it is actually needed."""
    if _NETMIKO_DEVICE_TYPE not in CLASS_MAPPER:
        CLASS_MAPPER[_NETMIKO_DEVICE_TYPE] = _SmartAXSSH
    if _NETMIKO_DEVICE_TYPE not in platforms:
        platforms.append(_NETMIKO_DEVICE_TYPE)


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config sanitization — same credential patterns as Huawei VRP
# ---------------------------------------------------------------------------

_PASSWORD_CIPHER_RE = re.compile(r"(password\s+cipher)\s+\S+", re.IGNORECASE)
_PSK_CIPHER_RE = re.compile(r"(psk\s+cipher)\s+\S+", re.IGNORECASE)
_KEY_CIPHER_RE = re.compile(r"(key\s+cipher)\s+\S+", re.IGNORECASE)
_SECRET_RE = re.compile(r"(\bsecret\s+\d+)\s+\S+", re.IGNORECASE)
_SNMP_COMMUNITY_RE = re.compile(
    r"(snmp-agent\s+community\s+(?:read|write))\s+.+", re.IGNORECASE
)


def _sanitize_config(text: str) -> str:
    text = _PASSWORD_CIPHER_RE.sub(r"\1 <redacted>", text)
    text = _PSK_CIPHER_RE.sub(r"\1 <redacted>", text)
    text = _KEY_CIPHER_RE.sub(r"\1 <redacted>", text)
    text = _SECRET_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_COMMUNITY_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Uptime helpers
# ---------------------------------------------------------------------------

_HOUR_SECONDS = 3600
_DAY_SECONDS = 24 * _HOUR_SECONDS
_WEEK_SECONDS = 7 * _DAY_SECONDS
_YEAR_SECONDS = 365 * _DAY_SECONDS


def _parse_uptime(uptime_str: str) -> int:
    """
    Convert a Huawei SmartAX uptime string to total seconds.

    Handles formats: ``"10 day 2 hour 30 minute 15 second"`` and
    ``"10 day(s), 2 hour(s), 30 minute(s), ..."`` (display version inline).
    """
    seconds = 0
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


# ---------------------------------------------------------------------------
# Interface parsing helpers
# ---------------------------------------------------------------------------

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


class SmartDriver(_napalm_base.NetworkDriver):
    """Huawei SmartAX (CloudEngine OLT) NAPALM driver (read-only subset for device-discovery)."""

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
        _ensure_netmiko_device_type_registered()
        self.device = self._netmiko_open(
            _NETMIKO_DEVICE_TYPE, netmiko_optional_args=self.netmiko_optional_args
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
        except (OSError, EOFError, AttributeError):
            return {"is_alive": False}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_version_info(self) -> tuple[str, str]:
        """Return (os_version, model) from ``display version``."""
        raw = self.device.send_command("display version")
        try:
            parsed = parse_output(platform="huawei_smartax", command="display version", data=raw)
            if parsed:
                row = parsed[0]
                return (
                    row.get("olt_version", "Unknown") or "Unknown",
                    (row.get("product", "Unknown") or "Unknown").strip(),
                )
        except Exception:
            logger.debug("ntc-templates failed for 'display version'; falling back to regex", exc_info=True)
        m_ver = re.search(r"VERSION\s*:\s*(\S+)", raw)
        m_prod = re.search(r"PRODUCT\s*:\s*(\S+)", raw)
        return (
            m_ver.group(1) if m_ver else "Unknown",
            m_prod.group(1) if m_prod else "Unknown",
        )

    def _get_serial_number(self) -> str:
        """Return the main board serial number from ``display board serial-number``."""
        raw = self.device.send_command("display board serial-number")
        try:
            parsed = parse_output(
                platform="huawei_smartax", command="display board serial-number", data=raw
            )
            for row in parsed:
                if row.get("serial_number"):
                    return row["serial_number"]
        except Exception:
            logger.debug("ntc-templates failed for 'display board serial-number'; using regex", exc_info=True)
        m_sn = re.search(r"\b0\s+\w+\s+(\w+)", raw)
        return m_sn.group(1) if m_sn else "Unknown"

    # ------------------------------------------------------------------
    # NAPALM getters
    # ------------------------------------------------------------------

    def get_facts(self) -> dict:
        """Return general device facts."""
        os_version, model = self._get_version_info()

        # --- uptime (regex — avoids fragile ^. -> Error template) ---
        uptime = -1
        uptime_out = self.device.send_command("display sysuptime")
        m_uptime = re.search(r"System\s+up\s+time:\s+(.*)", uptime_out, re.IGNORECASE)
        if m_uptime:
            uptime = _parse_uptime(m_uptime.group(1))

        # --- hostname (grep sysname from running config) ---
        hostname = "Unknown"
        sysname_out = self.device.send_command(
            "display current-configuration | inc sysname"
        )
        if "sysname " in sysname_out:
            hostname = (
                sysname_out.split("sysname ", 1)[1].strip().splitlines()[0].strip()
            )

        # --- interface list (regex over display interface brief) ---
        brief_out = self.device.send_command("display interface brief")
        interface_list = re.findall(
            r"^([A-Za-z][\w/.-]+)\s+(?:up|down)",
            brief_out,
            re.M | re.IGNORECASE,
        )

        return {
            "uptime": int(uptime),
            "vendor": "Huawei",
            "os_version": os_version,
            "serial_number": self._get_serial_number(),
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

        # Each interface block starts with "<IntfName> current state : <state>".
        # Guard against "Line protocol current state" lines (same pattern as get_interfaces_ip).
        separator = r"(^(?!Line protocol)\S+.*current\s+state\s*:.*$)"
        interfaces: dict = {}

        for section in _separate_section(separator, output):
            # Header line: "<IntfName> current state : UP/DOWN/..."
            m_hdr = re.match(
                r"^(?P<intf>\S+).*current\s+state\s*:\s*(?P<link>\S+)", section, re.I
            )
            if not m_hdr:
                continue
            intf_name = m_hdr.group("intf")
            link_state = m_hdr.group("link").lower()

            # Protocol status: "Line protocol current state : UP/DOWN"
            m_proto = re.search(
                r"Line\s+protocol\s+current\s+state\s*:\s*(\S+)", section, re.I
            )
            proto_state = m_proto.group(1).lower() if m_proto else link_state

            # Description
            m_desc = re.search(
                r"Description\s*[:\-]\s*(.*)", section, re.I
            )
            description = m_desc.group(1).strip() if m_desc else ""

            # Speed (Mbit/s or Gbit/s)
            speed = -1.0
            m_speed = re.search(
                r"(?:speed|Speed)\s*[:\-]?\s*(\d+)\s*(G|M|K)?bit", section
            )
            if m_speed:
                val = float(m_speed.group(1))
                unit = (m_speed.group(2) or "M").upper()
                if unit == "G":
                    val *= 1000
                elif unit == "K":
                    val /= 1000
                speed = val

            # MAC address
            mac_address = ""
            m_mac = re.search(
                r"(?:Hardware\s+address|MAC\s+address)\s*[:\-]\s*(\S+)", section, re.I
            )
            if m_mac:
                try:
                    mac_address = normalize_mac(m_mac.group(1))
                except Exception:
                    mac_address = m_mac.group(1)

            # MTU
            mtu = -1
            m_mtu = re.search(r"MTU\s+(\d+)", section, re.I)
            if m_mtu:
                mtu = int(m_mtu.group(1))

            interfaces[intf_name] = {
                "is_up": "up" in proto_state,
                "is_enabled": "administratively" not in link_state,
                "description": description,
                "last_flapped": -1.0,
                "mtu": mtu,
                "speed": speed,
                "mac_address": mac_address,
            }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface."""
        interfaces_ip: dict = {}

        # --- IPv4: display ip interface ---
        ipv4_out = self.device.send_command("display ip interface")
        separator = r"(^(?!\s*Line protocol).*current state.*$)"
        re_intf_name = r"^(?!\s*Line protocol)(?P<intf_name>\S+).+current state"
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

        # --- IPv6: display ipv6 interface ---
        ipv6_out = self.device.send_command("display ipv6 interface")
        separator_v6 = r"(^(?!\s*IPv6 protocol).*current state.*$)"
        re_intf_name_v6 = r"^(?!\s*IPv6 protocol)(?P<intf_name>\S+).+current state"
        re_intf_ip_v6 = r"(?P<ip>\S+), subnet is.+\/(?P<prefix>\d+)"

        for section in _separate_section(separator_v6, ipv6_out):
            m_intf = re.search(re_intf_name_v6, section, flags=re.M)
            if not m_intf:
                continue
            intf_name = m_intf.group("intf_name")
            for m in re.finditer(re_intf_ip_v6, section, flags=re.M):
                interfaces_ip.setdefault(intf_name, {}).setdefault("ipv6", {})[
                    m.group("ip")
                ] = {"prefix_length": int(m.group("prefix"))}

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
        """
        Return VLAN information keyed by VLAN ID string.

        Uses ``display service-port all`` (ntc-templates) to discover which
        physical PON ports carry each VLAN.  Falls back to regex on
        ``display vlan`` for the VLAN name.
        """
        vlans: dict = {}

        # --- service-port table → interfaces per VLAN (ntc-templates) ---
        sp_output = self.device.send_command("display service-port all")
        try:
            parsed_sp = parse_output(
                platform="huawei_smartax",
                command="display service-port all",
                data=sp_output,
            )
            for row in parsed_sp:
                vlan_id = row.get("vlan_id", "")
                if not vlan_id:
                    continue
                fsp = row.get("fsp", "").strip()
                port_type = row.get("port_type", "").strip().upper()
                intf = f"{port_type}{fsp}" if port_type and fsp else fsp
                entry = vlans.setdefault(
                    vlan_id,
                    {"name": vlan_id, "interfaces": []},
                )
                if intf and intf not in entry["interfaces"]:
                    entry["interfaces"].append(intf)
        except Exception:
            logger.debug(
                "ntc-templates failed for 'display service-port all'; skipping",
                exc_info=True,
            )

        # --- vlan names from display vlan (regex) ---
        vlan_out = self.device.send_command("display vlan")
        for m in re.finditer(
            r"^\s*(\d+)\s+\S+\s+\S+\s+(\S+)\s*$", vlan_out, re.M
        ):
            vlan_id, vlan_name = m.group(1), m.group(2)
            if vlan_id in vlans:
                vlans[vlan_id]["name"] = vlan_name
            else:
                vlans[vlan_id] = {"name": vlan_name, "interfaces": []}

        return vlans
