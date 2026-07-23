# Copyright 2026 NetBox Labs Inc
"""
Custom Ciena SAOS NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko (ciena_saos / ciena_saos10 device types) and ntc-templates for
structured CLI parsing.  Supports both SAOS 6/8 and SAOS 10 via the
``saos_version`` optional arg (default: "6").

Sanitizes config output for:
  - ``set user <name> password <hash>``
  - ``set user <name> auth-key <type> <material>`` — SSH public keys
  - SNMP community strings: ``snmp-server community <str>``
"""

import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config sanitisation
# ---------------------------------------------------------------------------

# "set user <name> password <hash>" — SAOS 6/8 local user password
_USER_PASSWORD_RE = re.compile(
    r"(set\s+user\s+\S+\s+password)\s+\S+",
    re.IGNORECASE,
)

# "snmp-server community <string> [ro|rw]" — SNMP community string
_SNMP_COMMUNITY_RE = re.compile(
    r"(snmp-server\s+community)\s+(\S+)",
    re.IGNORECASE,
)

# "set user <name> auth-key <type> <material>" — SSH public-key entry.
# Consumes algorithm token + base64 key material in one pass so the full
# credential (not just the algorithm word) is redacted.
_AUTH_KEY_RE = re.compile(
    r"(set\s+user\s+\S+\s+auth-key)\s+.+",
    re.IGNORECASE,
)


def _sanitize_config(text: str) -> str:
    """Redact credential fields from a SAOS configuration block."""
    text = _USER_PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_COMMUNITY_RE.sub(r"\1 <redacted>", text)
    text = _AUTH_KEY_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Speed conversion
# ---------------------------------------------------------------------------

_SPEED_UNIT_RE = re.compile(r"(\d+)\s*(G|g|M|m|K|k)?")
_MULTIPLIERS = {"g": 1000.0, "m": 1.0, "k": 0.001}


def _speed_to_mbps(speed_str: str) -> float:
    """
    Convert a speed string to float Mbps.

    Examples: "1000/FD" → 1000.0, "10G" → 10000.0, "100" → 100.0.
    Returns -1.0 when not parseable.
    """
    if not speed_str:
        return -1.0
    # "1000/FD" → take the numeric part before '/'
    speed_str = speed_str.split("/")[0].strip()
    m = _SPEED_UNIT_RE.match(speed_str)
    if not m:
        return -1.0
    value = float(m.group(1))
    unit = (m.group(2) or "m").lower()
    return value * _MULTIPLIERS.get(unit, 1.0)


def _saos_port_type_to_netbox(saos_type: str) -> str | None:
    """
    Map a SAOS ``port show`` TYPE value to a NetBox interface type.

    Only aggregation ports are asserted (TYPE ``LAG`` -> ``lag``); physical
    ports are left unset so the pipeline's speed-based detection assigns an
    accurate physical type.
    """
    return "lag" if saos_type.strip().upper() == "LAG" else None


def _apply_saos_port_types(interfaces: dict, port_parsed: list) -> None:
    """
    Set each interface's NetBox type from the SAOS ``port show`` TYPE column.

    Mutates ``interfaces`` in place, adding ``type`` only where
    ``_saos_port_type_to_netbox`` returns a value (aggregation ports).
    """
    saos_type_by_name = {
        r.get("name", ""): r.get("type", "") for r in port_parsed if r.get("name")
    }
    for name, info in interfaces.items():
        nb_type = _saos_port_type_to_netbox(saos_type_by_name.get(name, ""))
        if nb_type:
            info["type"] = nb_type


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


class SAOSDriver(_napalm_base.NetworkDriver):
    """
    Ciena SAOS NAPALM driver (read-only subset for device-discovery).

    Supports SAOS 6/8 (``ciena_saos``) and SAOS 10 (``ciena_saos10``).
    Set ``optional_args={"saos_version": "10"}`` to enable SAOS 10 mode.
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

        saos_version = str(optional_args.get("saos_version", "6"))
        self._device_type = "ciena_saos10" if saos_version == "10" else "ciena_saos"

        self.netmiko_optional_args = netmiko_args(optional_args)
        self.netmiko_optional_args.setdefault("port", 22)

    def open(self):
        """Open an SSH connection to the device via Netmiko."""
        self.device = self._netmiko_open(
            self._device_type, netmiko_optional_args=self.netmiko_optional_args
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
        # --- software version ---
        sw_raw = self.device.send_command("software show")
        try:
            sw_parsed = parse_output(
                platform="ciena_saos", command="software show", data=sw_raw
            )
        except Exception:
            logger.warning("saos: ntc-template failed for 'software show'")
            sw_parsed = []
        os_version = sw_parsed[0].get("version_running", "Unknown") if sw_parsed else "Unknown"

        # --- chassis info (hostname, model, serial) via regex ---
        chassis_raw = self.device.send_command("chassis show")
        hostname = self._parse_chassis_field(chassis_raw, "Host Name")
        model = self._parse_chassis_field(chassis_raw, "Product ID")
        serial_number = self._parse_chassis_field(chassis_raw, "Serial Number")

        # --- interface list ---
        port_raw = self.device.send_command("port show")
        try:
            port_parsed = parse_output(
                platform="ciena_saos", command="port show", data=port_raw
            )
            interface_list = [r["name"] for r in port_parsed if r.get("name")]
        except Exception:
            logger.warning("saos: ntc-template failed for 'port show'")
            interface_list = []

        return {
            "hostname": hostname,
            "vendor": "Ciena",
            "model": model,
            "os_version": os_version,
            "serial_number": serial_number,
            "uptime": -1.0,
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """Return interface details keyed by interface name."""
        # Admin (enabled/disabled) state from ethernet config
        eth_raw = self.device.send_command("port show ethernet-config")
        try:
            eth_parsed = parse_output(
                platform="ciena_saos", command="port show ethernet-config", data=eth_raw
            )
        except Exception:
            logger.warning("saos: ntc-template failed for 'port show ethernet-config'")
            eth_parsed = []

        # Build admin-state lookup by port name
        admin_map: dict[str, bool] = {}
        for row in eth_parsed:
            name = row.get("name", "")
            if name:
                admin_map[name] = row.get("admin_status", "").lower() == "ena"

        # Operational status + description + speed/MTU from port show status.
        # Guard against TextFSMError: the ciena_saos template uses \S* for the
        # description field and raises TextFSMError on descriptions with spaces
        # (common in real configs).  Fall back to port show when this occurs.
        status_raw = self.device.send_command("port show status")
        try:
            status_parsed = parse_output(
                platform="ciena_saos", command="port show status", data=status_raw
            )
        except Exception:
            status_parsed = []
            logger.warning(
                "saos: ntc-template failed for 'port show status' "
                "(description with spaces?); falling back to 'port show'"
            )

        if status_parsed:
            interfaces = self._build_interfaces_from_status(status_parsed, admin_map)
        else:
            logger.warning("saos: 'port show status' returned no rows; falling back to 'port show'")
            interfaces = {}

        # Always run port show to catch interfaces absent from port show status
        # (e.g. LAG/aggregation ports that SAOS omits from the status table).
        port_raw = self.device.send_command("port show")
        try:
            port_parsed = parse_output(
                platform="ciena_saos", command="port show", data=port_raw
            )
        except Exception:
            logger.warning("saos: ntc-template failed for 'port show'")
            port_parsed = []

        for row in port_parsed:
            name = row.get("name", "")
            if not name or name in interfaces:
                continue
            is_up = row.get("link", "").lower() == "up"
            is_enabled = admin_map.get(name, row.get("admin_link", "").lower() == "ena")
            speed = _speed_to_mbps(row.get("mode", ""))
            interfaces[name] = {
                "is_up": is_up,
                "is_enabled": is_enabled,
                "description": "",
                "last_flapped": -1.0,
                "mtu": -1,
                "speed": speed,
                "mac_address": "",
            }

        # Assert a NetBox type from the SAOS port TYPE column where meaningful
        # (aggregation ports -> "lag"). Physical ports are left for speed-based
        # detection downstream.
        _apply_saos_port_types(interfaces, port_parsed)

        return interfaces

    def _build_interfaces_from_status(
        self, status_parsed: list, admin_map: dict[str, bool]
    ) -> dict:
        """Build the interfaces dict from a parsed 'port show status' result."""
        interfaces: dict = {}
        for row in status_parsed:
            name = row.get("name", "")
            if not name:
                continue

            is_up = row.get("link", "").lower() == "up"
            # Default to True when admin state is unknown: admin-up-but-link-down
            # ports must not be reported as disabled. Link state ≠ admin state.
            is_enabled = admin_map.get(name, True)

            speed_raw = row.get("speed_duplex", "")
            speed = _speed_to_mbps(speed_raw)

            mtu_raw = row.get("mtu", "")
            try:
                mtu = int(mtu_raw) if mtu_raw else -1
            except ValueError:
                mtu = -1

            interfaces[name] = {
                "is_up": is_up,
                "is_enabled": is_enabled,
                "description": row.get("description", "").strip(),
                "last_flapped": -1.0,
                "mtu": mtu,
                "speed": speed,
                "mac_address": "",
            }
        return interfaces

    def get_interfaces_ip(self) -> dict:
        """
        Return IP addresses per interface.

        SAOS is a carrier-ethernet platform; IP interfaces are management-only
        and this driver does not currently collect or parse interface IP
        address information. Returns an empty dict.
        """
        return {}

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
            config["running"] = self.device.send_command("configuration show")

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Return VLAN information keyed by VLAN ID string."""
        raw = self.device.send_command("vlan show")
        try:
            parsed = parse_output(platform="ciena_saos", command="vlan show", data=raw)
        except Exception:
            logger.warning("saos: ntc-template failed for 'vlan show'")
            return {}

        vlans: dict = {}
        for row in parsed:
            vlan_id = row.get("vlan_id", "")
            if not vlan_id:
                continue
            vlans[vlan_id] = {
                "name": row.get("vlan_name", "") or vlan_id,
                "interfaces": [],
            }

        return vlans

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_chassis_field(text: str, field: str) -> str:
        """
        Extract a value from a SAOS chassis show table row.

        Matches lines like: ``| Host Name            | saos7200-1    |``
        Returns "Unknown" when not found.
        """
        pattern = re.compile(
            r"\|\s*" + re.escape(field) + r"\s*\|\s*([^|]+?)\s*\|",
            re.IGNORECASE,
        )
        m = pattern.search(text)
        return m.group(1).strip() if m else "Unknown"
