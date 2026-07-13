# Copyright 2026 NetBox Labs Inc
"""
Custom Cisco ASA REST API NAPALM driver.

Requires ASA 9.3.2+ with REST API enabled (5500-X, ASAv, ASA on Firepower, ISA 3000).
Enable the REST API on the device with: rest-api agent

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Supported optional_args:
  port        REST API port (default 443)
  ssl_verify  validate the device TLS certificate against the system CA
              store (default False — ASA management interfaces typically
              present self-signed certificates)

Reference: https://github.com/napalm-automation-community/napalm-asa
"""

import ipaddress
import json
import logging
import re
import ssl
import warnings

import napalm.base as _napalm_base
import requests
import urllib3
from napalm.base import models
from napalm.base.exceptions import CommandErrorException, ConnectionException
from requests.adapters import HTTPAdapter

logger = logging.getLogger(__name__)

# Suppress InsecureRequestWarning inline per-call (see _no_tls_warnings context manager)
# rather than globally so other HTTPS clients in the same process are unaffected.
_InsecureRequestWarning = urllib3.exceptions.InsecureRequestWarning

# ssl.OP_LEGACY_SERVER_CONNECT was added in Python 3.12 / OpenSSL 3.0.
# Falls back to 0 (no-op) on older runtimes — the driver still works but
# may fail TLS handshake on ASA 9.15+ with default OpenSSL settings.
_OP_LEGACY_SERVER_CONNECT = getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0)

# REST API endpoints covering all interface types
_INTERFACE_ENDPOINTS = (
    "/interfaces/physical",
    "/interfaces/vlan",
    "/interfaces/redundant",
    "/interfaces/portchannel",
)

# ---------------------------------------------------------------------------
# Config sanitization — ported from napalm-asa constants.py with:
#   • <removed> → <redacted> for codebase consistency
#   • pre-shared-key pattern added (was absent from reference)
#   • each pattern redacts only the secret token, preserving trailing context
# ---------------------------------------------------------------------------
_SANITIZE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^(\s*enable\s+password)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*passwd)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*username\s+\S+\s+(?:password|secret))\s+(?:\d\s+)?\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*snmp-server\s+community)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*snmp-server\s+host\s+\S+(?:\s+vrf\s+\S+)?(?:\s+version\s+\S+)?)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*(?:password|secret))\s+(?:\d\s+)?\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(.*wpa-psk\s+ascii\s+\d)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(.*\bkey\s+7)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*tacacs-server\b[^\n]*?\bkey)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*crypto\s+isakmp\s+key)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*ip\s+ospf\s+message-digest-key\s+\d+\s+md5)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*ip\s+ospf\s+authentication-key)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*neighbor\s+\S+\s+password)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*vrrp\s+\d+\s+authentication\s+text)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*standby\s+\d+\s+authentication\s+md5\s+key-string)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*standby\s+\d+\s+authentication)\s+\S{1,8}$", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*key-string)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*(?:tacacs|radius)\s+server\s+\S+\s+key)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*ppp\s+(?:chap|pap)\s+password\s+\d)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    (re.compile(r"^(\s*pre-shared-key)\s+\S+", re.M | re.I), r"\1 <redacted>"),
    # Indented "key <secret>" lines inside aaa-server / radius-server config blocks
    (re.compile(r"^(\s+key)\s+\S+", re.M), r"\1 <redacted>"),
]


def _sanitize_config(text: str) -> str:
    """Redact sensitive fields from ASA config text."""
    for pattern, replacement in _SANITIZE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# ---------------------------------------------------------------------------
# TLS adapter
# ---------------------------------------------------------------------------


class _LegacyTLSAdapter(HTTPAdapter):
    """
    HTTPAdapter enabling legacy TLS renegotiation for ASA 9.15+ firmware.

    ASA 9.15+ uses an older TLS renegotiation mode that Python/OpenSSL 3.0
    rejects by default. Setting OP_LEGACY_SERVER_CONNECT restores the old
    behaviour. See napalm-asa issue #37.

    With verify=False (the default) certificate validation is disabled, as ASA
    management interfaces typically present self-signed certificates. With
    verify=True the system CA store validates the chain and hostname.
    """

    def __init__(self, verify: bool = False, **kwargs: object) -> None:
        """Store the verification mode before HTTPAdapter builds the pool manager."""
        self._verify = verify
        super().__init__(**kwargs)

    def init_poolmanager(self, *args: object, **kwargs: object) -> None:
        """Create an SSL context with legacy renegotiation support."""
        if self._verify:
            ctx = ssl.create_default_context()
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        ctx.options |= _OP_LEGACY_SERVER_CONNECT
        kwargs["ssl_context"] = ctx
        super().init_poolmanager(*args, **kwargs)


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------


class _ASARest:
    """Private HTTP helper: session management, token auth, paginated requests."""

    def __init__(self, username: str, password: str, base_url: str, timeout: int, ssl_verify: bool = False) -> None:
        """Initialise session and mount the legacy-TLS adapter."""
        self.username = username
        self.password = password
        self.base_url = base_url
        self.timeout = timeout
        self.ssl_verify = ssl_verify
        self.token = ""
        self.session = requests.Session()
        self.session.mount("https://", _LegacyTLSAdapter(verify=ssl_verify))
        self.session.headers.update({"Content-Type": "application/json"})

    def get_auth_token(self) -> tuple[bool, int | None]:
        """POST /api/tokenservices — store X-Auth-Token on success."""
        full_url = self.base_url + "/tokenservices"
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", _InsecureRequestWarning)
                resp = self.session.post(
                    full_url,
                    auth=(self.username, self.password),
                    data="",
                    timeout=self.timeout,
                    verify=self.ssl_verify,
                )
            if resp.status_code == 204 and "X-Auth-Token" in resp.headers:
                self.token = resp.headers["X-Auth-Token"]
                self.session.headers.update({"X-Auth-Token": self.token})
                return (True, None)
            return (False, resp.status_code)
        except requests.exceptions.RequestException as exc:
            raise ConnectionException(str(exc)) from exc

    def delete_token(self) -> tuple[bool, int | None]:
        """DELETE /api/tokenservices/<token> on close."""
        full_url = f"{self.base_url}/tokenservices/{self.token}"
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", _InsecureRequestWarning)
                resp = self.session.delete(
                    full_url,
                    auth=(self.username, self.password),
                    timeout=self.timeout,
                    verify=self.ssl_verify,
                )
            if resp.status_code == 204:
                self.session.headers.pop("X-Auth-Token", None)
                return (True, None)
            return (False, resp.status_code)
        except requests.exceptions.RequestException as exc:
            raise ConnectionException(str(exc)) from exc

    def get_resp(
        self,
        endpoint: str = "",
        data: str | None = None,
        params: dict | None = None,
        throw: bool = True,
    ) -> dict | bool:
        """GET or POST *endpoint*; return parsed JSON or False on non-200."""
        full_url = self.base_url + endpoint
        params = params or {}
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", _InsecureRequestWarning)
                if data is not None:
                    resp = self.session.post(full_url, data=data, timeout=self.timeout, params=params, verify=self.ssl_verify)
                else:
                    resp = self.session.get(full_url, timeout=self.timeout, params=params, verify=self.ssl_verify)
            if resp.status_code != 200:
                if throw:
                    raise CommandErrorException(f"Operation returned an error: {resp.status_code}")
                return False
            return resp.json()
        except requests.exceptions.RequestException as exc:
            if throw:
                raise ConnectionException(str(exc)) from exc
            return False

    def close_session(self) -> None:
        """Close the underlying requests.Session to release pooled connections."""
        self.session.close()

    def has_active_token(self) -> bool:
        """Return True if the current auth token is still valid."""
        if "X-Auth-Token" not in self.session.headers:
            return False
        response = self.get_resp("/monitoring/serialnumber", throw=False)
        return bool(response and isinstance(response, dict) and response.get("kind") == "object#QuerySerialNumber")


# ---------------------------------------------------------------------------
# NAPALM driver
# ---------------------------------------------------------------------------


class ASADriver(_napalm_base.NetworkDriver):
    """Cisco ASA NAPALM driver using REST API (read-only subset for device-discovery)."""

    def __init__(self, hostname: str, username: str, password: str, timeout: int = 60, optional_args: dict | None = None) -> None:
        """Initialise driver and create the HTTP helper."""
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        if optional_args is None:
            optional_args = {}
        port = optional_args.get("port", 443)
        self.device = _ASARest(
            username=username,
            password=password,
            base_url=f"https://{hostname}:{port}/api",
            timeout=timeout,
            ssl_verify=bool(optional_args.get("ssl_verify", False)),
        )

    def open(self) -> None:
        """Authenticate and obtain an API token."""
        ok, code = self.device.get_auth_token()
        if not ok:
            raise ConnectionException(f"Cannot connect to {self.hostname}. Error {code}")

    def close(self) -> None:
        """Delete the API token and close the session (best-effort; logs on failure)."""
        try:
            ok, code = self.device.delete_token()
            if not ok:
                logger.warning("Failed to delete API token for %s (status %s); session may linger", self.hostname, code)
        except ConnectionException as exc:
            logger.warning("Exception deleting API token for %s: %s", self.hostname, exc)
        finally:
            self.device.close_session()

    def is_alive(self) -> dict:
        """Return token liveness."""
        return {"is_alive": self.device.has_active_token()}

    def _send_request(self, endpoint: str, data: dict | None = None, throw: bool = True) -> dict:
        """Send a request and transparently handle pagination via rangeInfo."""
        json_data = json.dumps(data) if data is not None else None
        response = self.device.get_resp(endpoint, json_data, throw=throw)
        if not response:
            return {"rangeInfo": {"total": 0, "limit": 0, "offset": 0}, "items": []}
        if "rangeInfo" in response:
            total = response["rangeInfo"].get("total", 0)
            limit = response["rangeInfo"].get("limit", total)
            if limit < total:
                fetched = len(response.get("items", []))
                while fetched < total:
                    r = self.device.get_resp(endpoint, json_data, params={"offset": fetched}, throw=throw)
                    if not r or not r.get("items"):
                        break
                    response["items"].extend(r["items"])
                    fetched += len(r["items"])
        return response

    def _get_interface_names(self) -> list[str]:
        """Return a list of hardwareIDs across all interface endpoint types."""
        names: list[str] = []
        for endpoint in _INTERFACE_ENDPOINTS:
            resp = self._send_request(endpoint, throw=False)
            for item in resp.get("items", []):
                hw_id = item.get("hardwareID", "")
                if hw_id:
                    names.append(hw_id)
        return names

    def _get_interfaces_details(self, names: list[str]) -> dict[str, dict]:
        """POST show interface <name> for each name; parse MAC, link-state, MTU."""
        if not names:
            return {}
        commands = [f"show interface {name}" for name in names]
        response = self._send_request("/cli", {"commands": commands})
        outputs = response.get("response", [])
        details: dict[str, dict] = {}
        for i, name in enumerate(names):
            raw = outputs[i] if i < len(outputs) else ""
            match_mac = re.search(r"MAC address (.{14}),", raw)
            mac = match_mac.group(1) if match_mac else ""
            match_status = re.search(r"line protocol is (.{2,4})\r?\n", raw)
            is_up = match_status.group(1).strip() == "up" if match_status else False
            match_mtu = re.search(r"MTU (.{1,4})\r?\n", raw)
            mtu = int(match_mtu.group(1)) if match_mtu else 0
            details[name] = {"mac_address": mac, "is_up": is_up, "mtu": mtu}
        return details

    def get_facts(self) -> dict:
        """Return general device facts."""
        serial_resp = self._send_request("/monitoring/serialnumber")
        ver_resp = self._send_request("/monitoring/device/components/version")
        cli_resp = self._send_request("/cli", {"commands": ["show hostname", "show hostname fqdn"]})
        cli_outputs = cli_resp.get("response", [])
        hostname = cli_outputs[0].strip() if len(cli_outputs) > 0 else "Unknown"
        fqdn = cli_outputs[1].strip() if len(cli_outputs) > 1 else "Unknown"
        return {
            "hostname": hostname,
            "vendor": "Cisco",
            "model": ver_resp.get("deviceType", "Unknown"),
            "os_version": ver_resp.get("asaVersion", "Unknown"),
            "serial_number": serial_resp.get("serialNumber", "Unknown"),
            "uptime": float(ver_resp.get("upTimeinSeconds", 0)),
            "fqdn": fqdn,
            "interface_list": self._get_interface_names(),
        }

    def get_interfaces(self) -> dict:
        """Return interface details keyed by interface name."""
        interfaces: dict = {}
        for endpoint in _INTERFACE_ENDPOINTS:
            resp = self._send_request(endpoint, throw=False)
            for item in resp.get("items", []):
                hw_id = item.get("hardwareID", "")
                if hw_id:
                    interfaces[hw_id] = {
                        "is_up": False,
                        "is_enabled": not item.get("shutdown", False),
                        "description": item.get("interfaceDesc", ""),
                        "last_flapped": -1.0,
                        "speed": 0,
                        "mtu": 0,
                        "mac_address": "",
                    }
        details = self._get_interfaces_details(list(interfaces.keys()))
        for name, d in details.items():
            if name in interfaces:
                interfaces[name]["mac_address"] = d["mac_address"]
                interfaces[name]["is_up"] = d["is_up"]
                interfaces[name]["mtu"] = d["mtu"]
        return interfaces

    def get_interfaces_ip(self) -> dict:
        """Return IPv4 and IPv6 addresses per interface."""
        interfaces_ip: dict = {}
        for endpoint in _INTERFACE_ENDPOINTS:
            resp = self._send_request(endpoint, throw=False)
            for item in resp.get("items", []):
                hw_id = item.get("hardwareID", "")
                if not hw_id:
                    continue
                ip_addr = item.get("ipAddress", "NoneSelected")
                if ip_addr != "NoneSelected" and isinstance(ip_addr, dict):
                    ip = ip_addr.get("ip", {}).get("value", "")
                    mask = ip_addr.get("netMask", {}).get("value", "")
                    if ip and mask:
                        try:
                            prefix = ipaddress.ip_network(f"{ip}/{mask}", strict=False).prefixlen
                            interfaces_ip.setdefault(hw_id, {}).setdefault("ipv4", {})[ip] = {
                                "prefix_length": prefix
                            }
                        except ValueError:
                            pass
                for ipv6 in item.get("ipv6Info", {}).get("ipv6Addresses", []):
                    ip6 = ipv6.get("address", {}).get("value", "")
                    prefix6 = ipv6.get("prefixLength", 0)
                    if ip6:
                        interfaces_ip.setdefault(hw_id, {}).setdefault("ipv6", {})[ip6] = {
                            "prefix_length": prefix6
                        }
        return interfaces_ip

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """Return running / startup config via CLI, with optional sanitization."""
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}
        commands: list[str] = []
        if retrieve.lower() in ("startup", "all"):
            commands.append("show startup-config")
        if retrieve.lower() in ("running", "all"):
            commands.append("show running-config")
        if commands:
            resp = self._send_request("/cli", {"commands": commands})
            outputs = resp.get("response", [])
            idx = 0
            if retrieve.lower() in ("startup", "all") and idx < len(outputs):
                config["startup"] = outputs[idx]
                idx += 1
            if retrieve.lower() in ("running", "all") and idx < len(outputs):
                config["running"] = outputs[idx]
        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])
        return config

    def get_vlans(self) -> dict:
        """Cisco ASA has no traditional L2 VLAN table."""
        return {}
