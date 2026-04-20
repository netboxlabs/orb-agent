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
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

logger = logging.getLogger(__name__)

_SET_FIELDS_RE = re.compile(
    r"(set\s+(?:password|passwd|psk|psksecret|secret|auth-password))\s+.*",
    re.IGNORECASE,
)
_ENC_RE = re.compile(r"(\bENC\b)\s+\S+")


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
        """Return interface details keyed by interface name."""
        raw = self.device.send_command("get system interface physical")
        try:
            parsed = parse_output(
                platform="fortinet", command="get system interface physical", data=raw
            )
        except Exception:
            logger.debug("Failed to parse 'get system interface physical' output", exc_info=True)
            return {}

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
                "mac_address": "",
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
