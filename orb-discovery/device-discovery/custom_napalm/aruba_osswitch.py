# Copyright 2026 NetBox Labs Inc
# Based on napalm-arubaos-switch (Apache-2.0): https://github.com/napalm-automation-community/napalm-arubaos-switch
"""
Custom ArubaOS-Switch NAPALM driver — REST API (WB.16.x+).

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses the ArubaOS-Switch REST API (https://<host>/rest/v6/) with cookie-based
authentication.  Requires firmware WB.16.x or later on 2930/3810/5400R series.
For older HP ProCurve switches accessed over SSH, use the ``procurve`` driver.

Note: uptime is not exposed by the REST API and is always returned as -1.0.
"""

import base64
import ipaddress
import logging
import re

import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.exceptions import ConnectionException

from custom_napalm._vlan import (
    SwitchportInfo,
    classify_switchport,
)

logger = logging.getLogger(__name__)


def _invert_vlan_port_rows(rows: list[dict]) -> dict[str, dict]:
    """
    Invert per-VLAN port rows into a per-port aggregate.

    Returns ``{port_id: {"untagged": int|None, "tagged": list[int],
    "forbidden": list[int]}}``. Tolerates upper- and lower-case POM_*
    enum values and silently skips malformed rows.
    """
    out: dict[str, dict] = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        port = row.get("port_id")
        vid = row.get("vlan_id")
        mode = (row.get("port_mode") or "").upper()
        if not port or not isinstance(vid, int) or isinstance(vid, bool):
            continue
        bucket = out.setdefault(port, {"untagged": None, "tagged": [], "forbidden": []})
        if mode == "POM_UNTAGGED":
            bucket["untagged"] = vid
        elif mode == "POM_TAGGED":
            if vid not in bucket["tagged"]:
                bucket["tagged"].append(vid)
        elif mode == "POM_FORBIDDEN":
            if vid not in bucket["forbidden"]:
                bucket["forbidden"].append(vid)
    return out


def _osswitch_port_to_switchport_info(bucket: dict) -> SwitchportInfo:
    """Map an inverted-port bucket to a SwitchportInfo."""
    untagged = bucket.get("untagged")
    tagged = bucket.get("tagged") or []
    if untagged is None and not tagged:
        return SwitchportInfo(
            enabled=False,
            admin_mode=None,
            oper_mode=None,
            access_vlan=None,
            native_vlan=None,
            allowed_vlans=None,
        )
    if untagged is not None and not tagged:
        return SwitchportInfo(
            enabled=True,
            admin_mode="access",
            oper_mode="access",
            access_vlan=untagged,
            native_vlan=None,
            allowed_vlans=None,
        )
    return SwitchportInfo(
        enabled=True,
        admin_mode="trunk",
        oper_mode="trunk",
        access_vlan=None,
        native_vlan=untagged,
        allowed_vlans=list(tagged),
    )

_DEFAULT_API = "v6"

# ---------------------------------------------------------------------------
# Config sanitization — same format as procurve SSH config
# ---------------------------------------------------------------------------

# "password manager [sha1] <hash>" / "password operator [sha1] <hash>"
_PASSWORD_RE = re.compile(r"(password\s+(?:manager|operator))\s+.*", re.IGNORECASE)

# 'snmp-server community "string" ...' or unquoted
_SNMP_COMM_RE = re.compile(r'(snmp-server\s+community)\s+(?:"[^"]*"|\S+)', re.IGNORECASE)

# "radius-server key <secret>" or "radius-server host <ip> key <secret>"
_RADIUS_KEY_RE = re.compile(r"(radius-server\b[^\n]*?\bkey)\s+\S+", re.IGNORECASE)

# "tacacs-server key <secret>" or "tacacs-server host <ip> key <secret>"
_TACACS_KEY_RE = re.compile(r"(tacacs-server\b[^\n]*?\bkey)\s+\S+", re.IGNORECASE)


def _sanitize_config(text: str) -> str:
    text = _PASSWORD_RE.sub(r"\1 <redacted>", text)
    text = _SNMP_COMM_RE.sub(r"\1 <redacted>", text)
    text = _RADIUS_KEY_RE.sub(r"\1 <redacted>", text)
    text = _TACACS_KEY_RE.sub(r"\1 <redacted>", text)
    return text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _decode_cli(response_json: dict) -> str:
    """Decode base64-encoded CLI output from the /cli endpoint response."""
    encoded = response_json.get("result_base64_encoded", "")
    if not encoded:
        return ""
    try:
        return base64.b64decode(encoded).decode("utf-8")
    except Exception:
        return ""


def _strip_config_header(text: str) -> str:
    """
    Strip the ArubaOS-Switch '; ... Configuration Editor; ...' preamble.

    ProCurve/ArubaOS-Switch prepends a banner line and semicolon comment lines
    before the actual config body. Strip them so callers receive clean config text.
    """
    parts = re.split(r"^;.*Configuration Editor.*$", text, maxsplit=1, flags=re.MULTILINE)
    body = parts[-1]
    lines = body.splitlines()
    start = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.startswith(";"):
            start = i
            break
    return "\n".join(lines[start:]).strip()


def _mask_to_prefix(netmask: str) -> int:
    """Convert dotted-decimal subnet mask to prefix length integer."""
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask}", strict=False).prefixlen
    except (ValueError, TypeError):
        return -1


# ---------------------------------------------------------------------------
# REST session wrapper — thin adapter over requests.Session
# ---------------------------------------------------------------------------


class _ArubaOSSDevice:
    """
    Thin wrapper around a requests.Session for ArubaOS-Switch REST API.

    Handles URL construction and CLI base64 decoding.
    Designed to be replaceable with a fake in unit tests.
    """

    def __init__(self, session, base_url: str, timeout: int) -> None:
        self._session = session
        self._base_url = base_url.rstrip("/") + "/"
        self._timeout = timeout

    def get(self, endpoint: str) -> object:
        """HTTP GET to base_url + endpoint."""
        return self._session.get(self._base_url + endpoint, timeout=self._timeout)

    def post(self, endpoint: str, payload: dict | None = None) -> object:
        """HTTP POST to base_url + endpoint."""
        return self._session.post(
            self._base_url + endpoint, json=payload, timeout=self._timeout
        )

    def delete(self, endpoint: str) -> object:
        """HTTP DELETE to base_url + endpoint."""
        return self._session.delete(self._base_url + endpoint, timeout=self._timeout)

    def cli(self, cmd: str) -> str:
        """Run a single CLI command via /cli and return decoded text output."""
        resp = self.post("cli", payload={"cmd": cmd})
        if not resp.ok:
            return ""
        return _decode_cli(resp.json())

    def close(self) -> None:
        """Close the underlying HTTP session."""
        self._session.close()


# ---------------------------------------------------------------------------
# NAPALM driver
# ---------------------------------------------------------------------------


class ArubaOSSDriver(_napalm_base.NetworkDriver):
    """ArubaOS-Switch NAPALM driver — REST API (WB.16.x+)."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Initialise driver — no network connection is made here."""
        if optional_args is None:
            optional_args = {}

        # Wrap IPv6 addresses in brackets for URL construction
        try:
            ipaddress.IPv6Address(hostname)
            hostname = f"[{hostname}]"
        except ValueError:
            pass

        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.device = None  # _ArubaOSSDevice, set in open()

        api = optional_args.get("api", _DEFAULT_API)
        proto = "https" if optional_args.get("ssl", True) else "http"
        port = optional_args.get("port")
        host_part = f"{hostname}:{port}" if port else hostname
        self._base_url = f"{proto}://{host_part}/rest/{api}/"
        self._ssl_verify = optional_args.get("ssl_verify", True)

        if optional_args.get("disable_ssl_warnings", False):
            try:
                import urllib3

                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except ImportError:
                pass

    def open(self):
        """Open an authenticated REST session to the device."""
        import requests as _requests

        session = _requests.Session()
        session.verify = self._ssl_verify
        session.headers.update({"Content-Type": "application/json", "Connection": "close"})

        url = self._base_url + "login-sessions"
        try:
            resp = session.post(
                url,
                json={"userName": self.username, "password": self.password},
                timeout=self.timeout,
            )
        except Exception as exc:
            raise ConnectionException(str(exc)) from exc

        if resp.status_code != 201:
            raise ConnectionException(
                f"Login failed: HTTP {resp.status_code} from {self.hostname}"
            )
        try:
            cookie = resp.json()["cookie"]
            if not cookie:
                raise ValueError("empty cookie")
        except (ValueError, KeyError, TypeError) as exc:
            raise ConnectionException(
                f"Login failed: invalid login response from {self.hostname}"
            ) from exc
        session.headers["cookie"] = cookie
        self.device = _ArubaOSSDevice(session, self._base_url, self.timeout)

    def close(self):
        """Logout and close the REST session."""
        if self.device is not None:
            try:
                self.device.delete("login-sessions")
            except Exception:
                pass
            try:
                self.device.close()
            except Exception:
                pass
            self.device = None

    def is_alive(self):
        """Return whether the REST session is still responsive."""
        if self.device is None:
            return {"is_alive": False}
        try:
            resp = self.device.get("system")
            return {"is_alive": resp.ok}
        except Exception:
            return {"is_alive": False}

    # ------------------------------------------------------------------
    # NAPALM getters
    # ------------------------------------------------------------------

    def get_facts(self) -> dict:
        """Return general device facts."""
        hostname = os_version = serial_number = model = "Unknown"
        fqdn = "Unknown"

        # Primary system info — falls back to global_info for stacked switches
        resp = self.device.get("system/status")
        if resp.status_code == 404:
            resp = self.device.get("system/status/global_info")
        if resp.ok:
            data = resp.json()
            hostname = data.get("name", "Unknown") or "Unknown"
            os_version = data.get("firmware_version", "Unknown") or "Unknown"
            serial_number = data.get("serial_number", "Unknown") or "Unknown"
            model = data.get("product_model", "Unknown") or "Unknown"

        # FQDN from DNS domain names
        dns_resp = self.device.get("dns")
        if dns_resp.ok:
            domain_names = dns_resp.json().get("dns_domain_names", [])
            if domain_names:
                fqdn = f"{hostname}.{domain_names[0]}"

        # Interface list and stack serial/model override
        serial_number, model, interface_list = self._facts_from_switch_status(
            serial_number, model
        )

        return {
            "hostname": hostname,
            "vendor": "HPE",
            "model": model,
            "os_version": os_version,
            "serial_number": serial_number,
            # REST API does not expose uptime
            "uptime": -1.0,
            "fqdn": fqdn,
            "interface_list": interface_list,
        }

    def _facts_from_switch_status(
        self, serial_number: str, model: str
    ) -> tuple[str, str, list[str]]:
        """Fetch interface list from system/status/switch; resolve stack member info."""
        interface_list: list[str] = []
        switch_resp = self.device.get("system/status/switch")
        if not switch_resp.ok:
            return serial_number, model, interface_list
        sw = switch_resp.json()
        if sw.get("switch_type", "") == "ST_STACKED":
            member_resp = self.device.get("system/status/members/1")
            if member_resp.ok:
                m = member_resp.json()
                serial_number = m.get("serial_number", serial_number) or serial_number
                model = m.get("product_model", model) or model
        for blade in sw.get("blades", []):
            for port in blade.get("data_ports", []):
                name = port.get("port_name", "")
                if name:
                    interface_list.append(name)
        return serial_number, model, interface_list

    def get_interfaces(self) -> dict:
        """Return interface details keyed by interface name."""
        interfaces: dict = {}

        ports_resp = self.device.get("ports")
        if ports_resp.ok:
            for port in ports_resp.json().get("port_element", []):
                pid = port.get("id", "")
                if not pid:
                    continue
                interfaces[pid] = {
                    "is_up": bool(port.get("is_port_up", False)),
                    "is_enabled": bool(port.get("is_port_enabled", False)),
                    "description": port.get("name", ""),
                    "last_flapped": -1.0,
                    "mtu": -1,
                    "speed": -1.0,
                    "mac_address": "",
                }

        stats_resp = self.device.get("port-statistics")
        if stats_resp.ok:
            for stat in stats_resp.json().get("port_statistics_element", []):
                pid = stat.get("id", "")
                speed = stat.get("port_speed_mbps")
                if pid in interfaces and speed is not None:
                    interfaces[pid]["speed"] = float(speed)

        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IP addresses per interface."""
        interfaces_ip: dict = {}
        resp = self.device.get("ipaddresses")
        if not resp.ok:
            return interfaces_ip

        for entry in resp.json().get("ip_address_subnet_element", []):
            vlan_id = entry.get("vlan_id", "")
            if not vlan_id:
                continue
            iface = f"VLAN{vlan_id}"
            ip_addr = (entry.get("ip_address") or {}).get("octets", "")
            ip_mask = (entry.get("ip_mask") or {}).get("octets", "")
            if not ip_addr or not ip_mask:
                continue
            prefix_len = _mask_to_prefix(ip_mask)
            if prefix_len < 0:
                continue
            interfaces_ip.setdefault(iface, {}).setdefault("ipv4", {})[ip_addr] = {
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
        """Return device configuration via CLI commands over the REST /cli endpoint."""
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}

        if retrieve.lower() in ("running", "all"):
            config["running"] = _strip_config_header(self.device.cli("show running-config"))
        if retrieve.lower() in ("startup", "all"):
            config["startup"] = _strip_config_header(self.device.cli("show config"))

        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])

        return config

    def get_vlans(self) -> dict:
        """Return VLAN information keyed by VLAN ID string."""
        vlans: dict = {}
        resp = self.device.get("vlans")
        if not resp.ok:
            return vlans

        for entry in resp.json().get("vlan_element", []):
            vlan_id = str(entry.get("vlan_id", ""))
            if not vlan_id:
                continue
            name = entry.get("name", "").strip() or vlan_id
            vlans[vlan_id] = {"name": name, "interfaces": []}

        return vlans

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """Return per-port VLAN config from /rest/vN/vlans-ports."""
        try:
            resp = self.device.get("vlans-ports")
        except Exception:
            logger.debug("ArubaOS-Switch vlans-ports fetch failed", exc_info=True)
            return {}
        if not getattr(resp, "ok", False):
            return {}
        body = resp.json() or {}
        rows = body.get("vlans_port_element") or []
        if not isinstance(rows, list):
            return {}
        per_port = _invert_vlan_port_rows(rows)
        result: dict[str, dict] = {}
        for port_id, bucket in per_port.items():
            info = _osswitch_port_to_switchport_info(bucket)
            result[port_id] = classify_switchport(info)
        return result
