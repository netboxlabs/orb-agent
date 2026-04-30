# Copyright 2026 NetBox Labs Inc
# Based on napalm-cumulus (Apache-2.0): https://github.com/orange-cloudfoundry/napalm-cumulus
"""
Custom Cumulus Linux NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses Netmiko (cumulus_linux) for SSH transport and ntc-templates (linux)
for structured parsing of `ip link show` and `ip address show`. Facts are
collected from standard Linux commands (`hostname`, `cat /etc/os-release`,
`cat /proc/uptime`) with `decode-syseeprom` for serial/model on real Cumulus
hardware.
"""

import ipaddress
import json as _json
import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.helpers import mac as normalize_mac
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output

from custom_napalm._vlan import (
    SwitchportInfo,
    classify_switchport,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config sanitization — Cumulus Linux / NCLU sensitive fields
# ---------------------------------------------------------------------------

# FRR / Quagga BGP: `neighbor <peer> password <secret>`
_BGP_PASSWORD_RE = re.compile(
    r"(neighbor\s+\S+\s+password)\s+\S+",
    re.IGNORECASE,
)
# `ip ospf authentication-key <key>` / `ip ospf message-digest-key N md5 <key>`
_OSPF_AUTH_KEY_RE = re.compile(
    r"(ip\s+ospf\s+authentication-key)\s+\S+",
    re.IGNORECASE,
)
_OSPF_MD5_KEY_RE = re.compile(
    r"(ip\s+ospf\s+message-digest-key\s+\d+\s+md5)\s+\S+",
    re.IGNORECASE,
)
# FRR key chains (OSPF/ISIS/BFD): `key-string <secret>`.
_KEY_STRING_RE = re.compile(r"(\bkey-string)\s+\S+", re.IGNORECASE)
# FRR vty `enable password <pw>` and `password <level|type> <pw>` lines.
_ENABLE_PASSWORD_RE = re.compile(r"(\benable\s+password)\s+\S+", re.IGNORECASE)
_FRR_PASSWORD_RE = re.compile(
    r"(^\s*password(?:\s+\d+)?)\s+\S+",
    re.IGNORECASE | re.MULTILINE,
)
# NCLU/NVUE SNMP community fields and the native snmpd.conf syntax.
_SNMP_COMMUNITY_RE = re.compile(
    r"((?:readonly|readwrite|trap-destination)-community)\s+\S+",
    re.IGNORECASE,
)
_SNMP_SERVER_COMMUNITY_RE = re.compile(
    r"(snmp-server\s+community)\s+\S+",
    re.IGNORECASE,
)
_SNMPD_ROCOMM_RE = re.compile(
    r"(^\s*(?:rocommunity|rwcommunity|rocommunity6|rwcommunity6))\s+\S+",
    re.IGNORECASE | re.MULTILINE,
)
# `com2sec[6] <secname> <source> <community>` — community is the last token.
_SNMPD_COM2SEC_RE = re.compile(
    r"(^\s*com2sec6?\s+\S+\s+\S+)\s+\S+",
    re.IGNORECASE | re.MULTILINE,
)
# TACACS+ shared secrets.
_TACACS_KEY_RE = re.compile(
    r"(tacacs(?:[-+]server)?\s+(?:host\s+\S+\s+)?key)\s+\S+",
    re.IGNORECASE,
)
# RADIUS shared secrets — covers:
#   `radius-server host X key <secret>`
#   `net add dot1x radius shared-secret <secret>`
#   `net add dot1x radius das-client-secret <secret>`
_RADIUS_KEY_RE = re.compile(
    r"(radius(?:-server)?\s+(?:host\s+\S+\s+)?key)\s+\S+",
    re.IGNORECASE,
)
_RADIUS_SHARED_SECRET_RE = re.compile(
    r"((?:radius\s+)?(?:shared-secret|das-client-secret))\s+\S+",
    re.IGNORECASE,
)
# Wireguard keys: `PrivateKey = ...` / `PresharedKey = ...` (wg-quick)
# and `wg set ... private-key <path-or-value>` / `... preshared-key <path-or-value>`.
_WG_KEY_INI_RE = re.compile(
    r"((?:PrivateKey|PresharedKey))\s*=\s*\S+",
    re.IGNORECASE,
)
_WG_KEY_CLI_RE = re.compile(
    r"(\b(?:private-key|preshared-key))\s+\S+",
    re.IGNORECASE,
)
# MACsec CAK/CKN material — NCLU/NVUE: `pre-shared-key cak <hex>` / `pre-shared-key ckn <hex>`
# Redact the hex value, keep the `cak`/`ckn` keyword for readability.
_MACSEC_KEY_RE = re.compile(
    r"(pre-shared-key\s+(?:cak|ckn))\s+\S+",
    re.IGNORECASE,
)
# Debian ifupdown wireless / PPP credentials in /etc/network/interfaces.
_WPA_RE = re.compile(
    r"(^\s*(?:wpa-psk|wpa-passphrase|wireless-key[^\s]*))\s+\S+",
    re.IGNORECASE | re.MULTILINE,
)
# NTP auth key lines: `key <n> <type> <secret>` inside /etc/ntp.keys.
_NTP_KEY_RE = re.compile(
    r"(^\s*key\s+\d+\s+\S+)\s+\S+",
    re.IGNORECASE | re.MULTILINE,
)


def _sanitize_config(text: str) -> str:
    """Redact BGP/OSPF/FRR keys, TACACS/RADIUS keys, WG/MACsec/wireless PSKs, SNMP communities, and NTP keys from a Cumulus config dump."""
    # Order matters: more specific patterns first so they don't get
    # masked by the broader FRR `password` matcher.
    text = _BGP_PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _ENABLE_PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _OSPF_AUTH_KEY_RE.sub(r"\1 <redacted>", text)
    text = _OSPF_MD5_KEY_RE.sub(r"\1 <redacted>", text)
    text = _KEY_STRING_RE.sub(r"\1 <redacted>", text)
    text = _TACACS_KEY_RE.sub(r"\1 <redacted>", text)
    text = _RADIUS_KEY_RE.sub(r"\1 <redacted>", text)
    text = _RADIUS_SHARED_SECRET_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_COMMUNITY_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_SERVER_COMMUNITY_RE.sub(r"\1 <redacted>", text)
    text = _SNMPD_ROCOMM_RE.sub(r"\1 <redacted>", text)
    text = _SNMPD_COM2SEC_RE.sub(r"\1 <redacted>", text)
    text = _MACSEC_KEY_RE.sub(r"\1 <redacted>", text)
    text = _WG_KEY_INI_RE.sub(r"\1 = <redacted>", text)
    text = _WG_KEY_CLI_RE.sub(r"\1 <redacted>", text)
    text = _WPA_RE.sub(r"\1 <redacted>", text)
    text = _NTP_KEY_RE.sub(r"\1 <redacted>", text)
    text = _FRR_PASSWORD_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_uptime(proc_uptime: str) -> float:
    """Return the first float from the two-field `/proc/uptime` output."""
    try:
        return float(proc_uptime.split()[0])
    except (ValueError, IndexError):
        return 0.0


_OS_RELEASE_KV_RE = re.compile(r'^([A-Z_]+)=(.*)$', re.MULTILINE)


def _parse_os_release(output: str) -> dict:
    """Parse `/etc/os-release` into a dict, stripping surrounding quotes."""
    result: dict = {}
    for m in _OS_RELEASE_KV_RE.finditer(output):
        key = m.group(1)
        value = m.group(2).strip().strip('"').strip("'")
        result[key] = value
    return result


def _parse_decode_syseeprom(output: str) -> dict:
    """Pick common TLVs (product name, part number, serial, manufacturer) out of `decode-syseeprom` output."""
    fields = {
        "product_name": re.compile(r"^Product\s+Name\s+\S+\s+\S+\s+(.+)$", re.MULTILINE),
        "part_number": re.compile(r"^Part\s+Number\s+\S+\s+\S+\s+(\S+)", re.MULTILINE),
        "serial_number": re.compile(r"^Serial\s+Number\s+\S+\s+\S+\s+(\S+)", re.MULTILINE),
        "manufacturer": re.compile(r"^Manufacturer\s+\S+\s+\S+\s+(.+)$", re.MULTILINE),
    }
    data: dict = {}
    for key, pattern in fields.items():
        m = pattern.search(output)
        if m:
            data[key] = m.group(1).strip()
    return data


class CumulusDriver(_napalm_base.NetworkDriver):
    """Cumulus Linux NAPALM driver (read-only subset for device-discovery)."""

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
        """Open an SSH connection via Netmiko using the cumulus_linux device type."""
        self.device = self._netmiko_open(
            "cumulus_linux", netmiko_optional_args=self.netmiko_optional_args
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

    # ------------------------------------------------------------------
    # NAPALM getters
    # ------------------------------------------------------------------

    def get_facts(self) -> dict:
        """Return general device facts collected from standard Linux commands and `decode-syseeprom`."""
        hostname_out = self.device.send_command("hostname").strip()
        hostname = hostname_out.splitlines()[0] if hostname_out else "Unknown"

        os_version = "Unknown"
        os_info = _parse_os_release(self.device.send_command("cat /etc/os-release"))
        version_id = os_info.get("VERSION_ID") or os_info.get("VERSION")
        name = os_info.get("NAME") or os_info.get("PRETTY_NAME", "")
        if version_id and name:
            os_version = f"{name} {version_id}".strip()
        elif version_id:
            os_version = version_id
        elif name:
            os_version = name

        uptime = _parse_uptime(self.device.send_command("cat /proc/uptime"))

        eeprom = _parse_decode_syseeprom(self.device.send_command("decode-syseeprom"))
        model = eeprom.get("product_name") or eeprom.get("part_number") or "Unknown"
        # Use the EEPROM vendor when present; Nvidia is the default for ONIE/Cumulus hardware.
        vendor = eeprom.get("manufacturer") or "Nvidia"
        # Prefer EEPROM serial; fall back to DMI sysfs (available on VMs without decode-syseeprom).
        serial_number = eeprom.get("serial_number") or ""
        if not serial_number:
            dmi_serial = self.device.send_command("cat /sys/class/dmi/id/product_serial").strip()
            # Only accept clean serial-like strings (alphanumeric + hyphens/dots, no whitespace).
            # Rejects shell error output ("No such file or directory", "Permission denied", etc.)
            if dmi_serial and re.match(r'^[\w\-\.]+$', dmi_serial) and dmi_serial.lower() not in ("none", "not specified", "unknown"):
                serial_number = dmi_serial
        if not serial_number:
            serial_number = "Unknown"

        link_out = self.device.send_command("ip link show")
        try:
            parsed_links = parse_output(platform="linux", command="ip link show", data=link_out)
            interface_list = [row["interface"] for row in parsed_links if row.get("interface")]
        except Exception:
            logger.debug("Failed to parse 'ip link show' for interface_list", exc_info=True)
            interface_list = []

        return {
            "hostname": hostname,
            "vendor": vendor,
            "model": model,
            "os_version": os_version,
            "serial_number": serial_number,
            "uptime": uptime,
            "fqdn": "Unknown",
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict:
        """Return interface details keyed by interface name (speed is reported as -1.0, not exposed by `ip link show`)."""
        link_out = self.device.send_command("ip link show")
        try:
            parsed = parse_output(platform="linux", command="ip link show", data=link_out)
        except Exception:
            logger.debug("Failed to parse 'ip link show'", exc_info=True)
            return {}

        interfaces: dict = {}
        for row in parsed:
            intf = row.get("interface", "").strip()
            if not intf:
                continue

            flags = row.get("flags", "") or ""
            state = (row.get("state", "") or "").upper()

            mac_raw = row.get("mac_address", "") or ""
            try:
                mac_address = normalize_mac(mac_raw) if mac_raw else ""
            except Exception:
                mac_address = mac_raw

            try:
                mtu = int(row.get("mtu") or -1)
            except ValueError:
                mtu = -1

            # Loopback and some tunnel interfaces report state=UNKNOWN but are
            # forwarding; treat "LOWER_UP" in flags as the authoritative
            # indicator of link presence.
            flag_set = {f.strip() for f in flags.split(",") if f.strip()}
            is_enabled = "UP" in flag_set
            is_up = "LOWER_UP" in flag_set or state == "UP"

            interfaces[intf] = {
                "is_up": bool(is_up),
                "is_enabled": bool(is_enabled),
                "description": (row.get("alias") or "").strip(),
                "last_flapped": -1.0,
                "mtu": mtu,
                "speed": -1.0,
                "mac_address": mac_address,
            }

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IPv4/IPv6 addresses per interface, parsed from `ip address show` via ntc-templates."""
        addr_out = self.device.send_command("ip address show")
        try:
            parsed = parse_output(platform="linux", command="ip address show", data=addr_out)
        except Exception:
            logger.debug("Failed to parse 'ip address show'", exc_info=True)
            return {}

        interfaces_ip: dict = {}
        for row in parsed:
            intf = row.get("interface", "").strip()
            if not intf:
                continue

            self._merge_ip_family(
                interfaces_ip, intf, "ipv4",
                row.get("ip_addresses") or [],
                row.get("ip_masks") or [],
            )
            self._merge_ip_family(
                interfaces_ip, intf, "ipv6",
                row.get("ipv6_addresses") or [],
                row.get("ipv6_masks") or [],
            )

        return interfaces_ip

    @staticmethod
    def _merge_ip_family(interfaces_ip: dict, intf: str, family: str,
                         addrs: list, masks: list) -> None:
        for ip, mask in zip(addrs, masks):
            if not ip:
                continue
            try:
                prefix_length = int(mask)
                # Validate the address; skip malformed entries silently.
                ipaddress.ip_address(ip)
            except (ValueError, TypeError):
                continue
            interfaces_ip.setdefault(intf, {}).setdefault(family, {})[ip] = {
                "prefix_length": prefix_length
            }

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """Return device configuration (NCLU dump if available, otherwise `/etc/network/interfaces`)."""
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}

        if retrieve in ("all", "running"):
            running = self.device.send_command("net show configuration commands").strip()
            if (not running) or running.lower().startswith("error") or "command not found" in running.lower():
                running = self.device.send_command("cat /etc/network/interfaces").strip()
            config["running"] = running

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Return VLAN info keyed by VLAN ID string by parsing `bridge vlan show`; VLAN ranges are expanded."""
        output = self.device.send_command("bridge vlan show")
        if not output:
            return {}

        vlans: dict = {}
        current_port = ""
        # First token on a port block is the interface name; subsequent lines
        # start with whitespace and carry the VLAN id (possibly a range).
        for raw_line in output.splitlines():
            line = raw_line.rstrip()
            if not line:
                continue
            if not line.startswith((" ", "\t")):
                tokens = line.split()
                # Skip the header row (`port  vlan ids` / `port vlan-id`).
                if tokens[0].lower() == "port":
                    current_port = ""
                    continue
                current_port = tokens[0]
                vlan_token = tokens[1] if len(tokens) > 1 else ""
            else:
                if not current_port:
                    continue
                tokens = line.split()
                vlan_token = tokens[0] if tokens else ""

            if not vlan_token or not current_port:
                continue
            for vid in _expand_vlan_token(vlan_token):
                entry = vlans.setdefault(str(vid), {"name": str(vid), "interfaces": []})
                if current_port not in entry["interfaces"]:
                    entry["interfaces"].append(current_port)

        return vlans

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """Return per-interface VLAN config from ``bridge -j vlan show``."""
        try:
            raw = self.device.send_command("bridge -j vlan show")
        except Exception:
            logger.debug("Cumulus bridge -j vlan show failed", exc_info=True)
            return {}
        if not raw or not raw.strip():
            return {}
        try:
            entries = _json.loads(raw)
        except _json.JSONDecodeError:
            logger.debug("Cumulus bridge JSON parse failed: %r", raw[:200])
            return {}
        if not isinstance(entries, list):
            return {}
        result: dict[str, dict] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            ifname = entry.get("ifname")
            if not ifname:
                continue
            info = _bridge_json_to_switchport_info(entry)
            result[ifname] = classify_switchport(info)
        return result


def _split_bridge_vlans(vlans: list) -> tuple[int | None, list[int]]:
    """
    Split a ``bridge -j vlan show`` vlans list into ``(pvid, tagged_vids)``.

    Rejects bool VIDs (bool is a subclass of int) and silently drops malformed
    rows. The PVID flag — when present — moves a VID into the pvid slot;
    everything else accumulates into the tagged list.
    """
    pvid: int | None = None
    tagged: list[int] = []
    for v in vlans:
        if not isinstance(v, dict):
            continue
        vid_raw = v.get("vlan")
        if isinstance(vid_raw, bool):
            continue
        try:
            vid = int(vid_raw)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
        flags = v.get("flags") or []
        is_pvid = any(f == "PVID" for f in flags) if isinstance(flags, list) else False
        if is_pvid:
            pvid = vid
        else:
            tagged.append(vid)
    return pvid, tagged


def _bridge_json_to_switchport_info(entry: dict) -> SwitchportInfo:
    """
    Map a ``bridge -j vlan show`` entry to a SwitchportInfo.

    Linux bridge VLAN model — no Cisco-style 'switchport mode'. We infer:
      - PVID-only with no tagged VIDs → access
      - PVID + tagged VIDs            → trunk with native = PVID
      - No PVID + ≥1 tagged VIDs      → trunk with no native
      - No VIDs                       → routed
    """
    vlans = entry.get("vlans") or []
    if not isinstance(vlans, list) or not vlans:
        return SwitchportInfo(
            enabled=False,
            admin_mode=None,
            oper_mode=None,
            access_vlan=None,
            native_vlan=None,
            allowed_vlans=None,
        )

    pvid, tagged = _split_bridge_vlans(vlans)

    if pvid is not None:
        tagged = [v for v in tagged if v != pvid]

    if pvid is not None and not tagged:
        return SwitchportInfo(
            enabled=True,
            admin_mode="access",
            oper_mode="access",
            access_vlan=pvid,
            native_vlan=None,
            allowed_vlans=None,
        )
    if pvid is not None and tagged:
        return SwitchportInfo(
            enabled=True,
            admin_mode="trunk",
            oper_mode="trunk",
            access_vlan=None,
            native_vlan=pvid,
            allowed_vlans=tagged,
        )
    if pvid is None and tagged:
        return SwitchportInfo(
            enabled=True,
            admin_mode="trunk",
            oper_mode="trunk",
            access_vlan=None,
            native_vlan=None,
            allowed_vlans=tagged,
        )
    return SwitchportInfo(
        enabled=False,
        admin_mode=None,
        oper_mode=None,
        access_vlan=None,
        native_vlan=None,
        allowed_vlans=None,
    )


def _expand_vlan_token(token: str) -> list[int]:
    """Expand a VLAN token like ``100`` or ``100-104`` into a list of ints."""
    token = token.strip()
    if not token or not re.match(r"^\d+(-\d+)?$", token):
        return []
    if "-" in token:
        start, end = token.split("-", 1)
        try:
            return list(range(int(start), int(end) + 1))
        except ValueError:
            return []
    try:
        return [int(token)]
    except ValueError:
        return []
