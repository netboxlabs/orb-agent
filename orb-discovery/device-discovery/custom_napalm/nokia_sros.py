# Copyright 2026 NetBox Labs Inc
# Based on napalm-sros (Apache-2.0): https://github.com/napalm-automation-community/napalm-sros
"""
Custom Nokia SR-OS NETCONF NAPALM driver.

Implements only the methods used by device-discovery:
  get_facts, get_interfaces, get_interfaces_ip, get_config, get_vlans.

Uses ncclient for NETCONF/YANG transport and lxml for structured XML parsing
against Nokia's YANG models (urn:nokia.com:sros:ns:yang:sr:*).

Modernisations over the community napalm-sros driver:
  - logging.exception() replaces print() + traceback
  - lxml.etree used directly (not ncclient.xml_ shims)
  - Inline NETCONF filters (no separate nc_filters module)
  - Multiple IPv4 secondary addresses handled via loop
  - No config-write methods (read-only subset)
  - No extra paramiko SSH channel
  - Type hints throughout
"""

import logging
import re
from datetime import datetime

import napalm.base as _napalm_base
from lxml import etree
from napalm.base import models
from napalm.base.helpers import convert

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Nokia YANG namespaces
# ---------------------------------------------------------------------------

_NS_STATE = "urn:nokia.com:sros:ns:yang:sr:state"
_NS_CONF = "urn:nokia.com:sros:ns:yang:sr:conf"
_NS_NC = "urn:ietf:params:xml:ns:netconf:base:1.0"

_NSMAP: dict[str, str] = {
    "state_ns": _NS_STATE,
    "configure_ns": _NS_CONF,
}

# ---------------------------------------------------------------------------
# NETCONF filters
# ---------------------------------------------------------------------------

_FILTER_FACTS = f"""
<filter xmlns="{_NS_NC}">
    <state xmlns="{_NS_STATE}">
        <chassis>
            <hardware-data>
                <serial-number/>
            </hardware-data>
        </chassis>
        <system>
            <oper-name/>
            <up-time/>
            <platform/>
            <version>
                <version-number/>
            </version>
        </system>
        <port>
            <port-id/>
        </port>
        <router>
            <router-name/>
            <interface>
                <interface-name/>
            </interface>
        </router>
    </state>
</filter>
"""

# R19 uses <if-oper-status> instead of <oper-state> for router interfaces.
# The tag is injected at runtime via .format().
_FILTER_INTERFACES_TMPL = """\
<filter xmlns="{ns_nc}">
    <state xmlns="{ns_state}">
        <port>
            <port-id/>
            <oper-state/>
            <hardware-mac-address/>
            <ethernet>
                <oper-speed/>
            </ethernet>
        </port>
        <router>
            <router-name/>
            <interface>
                <interface-name/>
                <oper-ip-mtu/>
                {oper_state_tag}
                <last-oper-change/>
            </interface>
        </router>
        <chassis>
            <hardware-data>
                <base-mac-address/>
            </hardware-data>
        </chassis>
    </state>
    <configure xmlns="{ns_conf}">
        <port>
            <port-id/>
            <description/>
            <admin-state/>
            <ethernet>
                <mtu/>
            </ethernet>
        </port>
        <router>
            <router-name/>
            <interface>
                <interface-name/>
                <admin-state/>
                <description/>
                <mac/>
                <port/>
                <loopback/>
            </interface>
        </router>
    </configure>
</filter>"""

_FILTER_INTERFACES_IP = f"""
<filter xmlns="{_NS_NC}">
    <configure xmlns="{_NS_CONF}">
        <router>
            <router-name/>
            <interface>
                <interface-name/>
                <ipv4>
                    <primary>
                        <address/>
                        <prefix-length/>
                    </primary>
                    <secondary>
                        <address/>
                        <prefix-length/>
                    </secondary>
                </ipv4>
                <ipv6>
                    <address>
                        <ipv6-address/>
                        <prefix-length/>
                    </address>
                </ipv6>
            </interface>
        </router>
        <service>
            <vprn>
                <service-name/>
                <interface>
                    <interface-name/>
                    <ipv4>
                        <primary>
                            <address/>
                            <prefix-length/>
                        </primary>
                        <secondary>
                            <address/>
                            <prefix-length/>
                        </secondary>
                    </ipv4>
                    <ipv6>
                        <address>
                            <ipv6-address/>
                            <prefix-length/>
                        </address>
                    </ipv6>
                </interface>
            </vprn>
        </service>
    </configure>
</filter>
"""

# ---------------------------------------------------------------------------
# Config sanitization — Nokia SR-OS YANG XML sensitive element content
# ---------------------------------------------------------------------------
# Pattern: (<tag>)[^<]*(</tag>)  →  \1REDACTED\2
# Covers both plain-text and encrypted values inside XML elements.
# Note: replacement is the plain word REDACTED (not XML tags) so the output
# remains well-formed XML and can be re-parsed without errors.

_AUTH_KEY_RE = re.compile(r"(<authentication-key>)[^<]*(</authentication-key>)", re.IGNORECASE)
_HMAC_MD5_RE = re.compile(r"(<hmac-md5-key>)[^<]*(</hmac-md5-key>)", re.IGNORECASE)
_DES_KEY_RE = re.compile(r"(<des-key>)[^<]*(</des-key>)", re.IGNORECASE)
_AES_KEY_RE = re.compile(r"(<aes-key>)[^<]*(</aes-key>)", re.IGNORECASE)
_PASSWORD_RE = re.compile(r"(<password>)[^<]*(</password>)", re.IGNORECASE)
_SECRET_RE = re.compile(r"(<secret>)[^<]*(</secret>)", re.IGNORECASE)
_COMMUNITY_STR_RE = re.compile(r"(<community-string>)[^<]*(</community-string>)", re.IGNORECASE)
_PRIVATE_KEY_RE = re.compile(r"(<private-key>)[^<]*(</private-key>)", re.IGNORECASE)
_PSK_RE = re.compile(r"(<pre-shared-key>)[^<]*(</pre-shared-key>)", re.IGNORECASE)


def _sanitize_config(text: str) -> str:
    """Redact Nokia SR-OS YANG XML secret values, replacing content with REDACTED."""
    text = _AUTH_KEY_RE.sub(r"\1REDACTED\2", text)
    text = _HMAC_MD5_RE.sub(r"\1REDACTED\2", text)
    text = _DES_KEY_RE.sub(r"\1REDACTED\2", text)
    text = _AES_KEY_RE.sub(r"\1REDACTED\2", text)
    text = _PASSWORD_RE.sub(r"\1REDACTED\2", text)
    text = _SECRET_RE.sub(r"\1REDACTED\2", text)
    text = _COMMUNITY_STR_RE.sub(r"\1REDACTED\2", text)
    text = _PRIVATE_KEY_RE.sub(r"\1REDACTED\2", text)
    text = _PSK_RE.sub(r"\1REDACTED\2", text)
    return text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Safe XML parser — disables external entity expansion and network access to prevent
# XXE (XML External Entity) injection attacks on untrusted NETCONF responses.
_SAFE_XML_PARSER = etree.XMLParser(resolve_entities=False, no_network=True)


def _parse_xml(data_xml: str | bytes) -> etree._Element:
    """Parse a NETCONF data_xml payload into an lxml Element."""
    if isinstance(data_xml, str):
        data_xml = data_xml.encode("utf-8")
    return etree.fromstring(data_xml, parser=_SAFE_XML_PARSER)


def _with_defaults_kwarg(capabilities: list[str]) -> dict:
    """
    Return ``{"with_defaults": "report-all"}`` only when the server advertises it.

    ncclient raises ``MissingCapabilityError`` if ``with_defaults`` is passed to a
    server that has not announced the ``:with-defaults`` capability, so we must
    gate the argument on the negotiated capability set.
    """
    if any("with-defaults" in c for c in capabilities):
        return {"with_defaults": "report-all"}
    return {}


def _find_txt(xml_tree: etree._Element, xpath: str, default: str = "") -> str:
    """Extract the text of the first XPath match; return *default* on miss."""
    try:
        results = xml_tree.xpath(xpath, namespaces=_NSMAP)
        if results:
            node = results[0]
            if hasattr(node, "text") and node.text is not None:
                return node.text.strip()
            if isinstance(node, str):
                return node.strip()
    except Exception:
        logger.debug("XPath '%s' returned nothing", xpath)
    return default


def _xpath_one(xml_tree: etree._Element, xpath: str) -> etree._Element | None:
    """Return the first XPath match as an Element, or None."""
    try:
        results = xml_tree.xpath(xpath, namespaces=_NSMAP)
        return results[0] if results else None
    except Exception:
        return None


def _port_ref_from_cfg(cfg_block: etree._Element | None) -> str:
    """
    Extract the bare port-id from a configure/router/interface block.

    SR-OS encodes sub-interface references as ``port-id:channel`` (e.g. ``1/1/1:0``).
    The channel suffix after the colon is stripped so the result matches the
    top-level port-id key used in the state tree.
    """
    if cfg_block is None:
        return ""
    port_ref = _find_txt(cfg_block, "configure_ns:port")
    return port_ref.split(":")[0] if ":" in port_ref else port_ref


def _resolve_if_mac(
    result: etree._Element,
    cfg_block: etree._Element | None,
    if_name: str,
    chassis_mac: str,
) -> str:
    """Resolve MAC for a logical router interface: cfg override → port MAC → chassis MAC."""
    if cfg_block is not None:
        cfg_mac = _find_txt(cfg_block, "configure_ns:mac")
        if cfg_mac:
            return cfg_mac
    if_port = _port_ref_from_cfg(cfg_block)
    if if_port:
        port_state = _xpath_one(result, f'state_ns:state/state_ns:port[state_ns:port-id="{if_port}"]')
        if port_state is not None:
            port_mac = _find_txt(port_state, "state_ns:hardware-mac-address")
            if port_mac:
                return port_mac
    if if_name == "system":
        return chassis_mac
    return ""


def _resolve_if_speed(result: etree._Element, cfg_block: etree._Element | None) -> float:
    """Resolve speed for a logical router interface from its associated port."""
    if_port = _port_ref_from_cfg(cfg_block)
    if not if_port:
        return -1.0
    port_state = _xpath_one(result, f'state_ns:state/state_ns:port[state_ns:port-id="{if_port}"]')
    if port_state is None:
        return -1.0
    return convert(float, _find_txt(port_state, "state_ns:ethernet/state_ns:oper-speed"), default=-1.0)


def _extract_if_addrs(interface: etree._Element) -> dict:
    """Build the IP address dict for a single configure/interface element."""
    entry: dict = {}

    # IPv4 primary
    ipv4_primary = _find_txt(interface, "configure_ns:ipv4/configure_ns:primary/configure_ns:address")
    if ipv4_primary:
        entry.setdefault("ipv4", {})[ipv4_primary] = {
            "prefix_length": convert(
                int,
                _find_txt(interface, "configure_ns:ipv4/configure_ns:primary/configure_ns:prefix-length"),
                default=0,
            )
        }

    # IPv4 secondaries (can be multiple)
    for secondary in interface.xpath("configure_ns:ipv4/configure_ns:secondary", namespaces=_NSMAP):
        sec_addr = _find_txt(secondary, "configure_ns:address")
        if sec_addr:
            entry.setdefault("ipv4", {})[sec_addr] = {
                "prefix_length": convert(int, _find_txt(secondary, "configure_ns:prefix-length"), default=0)
            }

    # IPv6 addresses (can be multiple)
    for ipv6_entry in interface.xpath("configure_ns:ipv6/configure_ns:address", namespaces=_NSMAP):
        ipv6_addr = _find_txt(ipv6_entry, "configure_ns:ipv6-address")
        if ipv6_addr:
            entry.setdefault("ipv6", {})[ipv6_addr] = {
                "prefix_length": convert(int, _find_txt(ipv6_entry, "configure_ns:prefix-length"), default=0)
            }

    return entry


def _merge_if_addrs(interfaces_ip: dict, key: str, entry: dict) -> None:
    """Merge *entry* address families into *interfaces_ip[key]*."""
    if not entry:
        return
    existing = interfaces_ip.setdefault(key, {})
    for family, addrs in entry.items():
        existing.setdefault(family, {}).update(addrs)


# strptime format fallbacks for Nokia last-oper-change timestamps.
# %f accepts 1–6 fractional-second digits (unlike Python 3.10 fromisoformat),
# so ".0" and ".123" are both handled correctly.
# %z accepts "+HHMM" / "+HH:MM" forms; "Z" is normalised to "+0000" before parsing.
_FLAP_FMTS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",  # with fractional seconds  (e.g. 2021-06-01T08:00:00.0Z)
    "%Y-%m-%dT%H:%M:%S%z",     # without fractional seconds (e.g. 2021-06-01T08:00:00Z)
)


def _parse_last_flapped(flap_str: str) -> float:
    """
    Convert a Nokia last-oper-change timestamp to a UTC epoch float.

    Accepts RFC 3339 variants with or without fractional seconds, and with
    either a ``Z`` suffix or a numeric UTC offset.
    """
    if not flap_str:
        return -1.0
    # strptime %z needs "+HHMM"; normalise the UTC "Z" designator.
    s = flap_str[:-1] + "+0000" if flap_str.endswith("Z") else flap_str
    for fmt in _FLAP_FMTS:
        try:
            return datetime.strptime(s, fmt).timestamp()
        except ValueError:
            continue
    logger.debug("Cannot parse last-oper-change: %s", flap_str)
    return -1.0


class SROSDriver(_napalm_base.NetworkDriver):
    """Nokia SR-OS NAPALM driver using NETCONF/YANG (read-only subset for device-discovery)."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Initialise driver — no network connection is made here."""
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.conn = None
        if optional_args is None:
            optional_args = {}
        self.port: int = int(optional_args.get("port", 830))
        # Accept both the ncclient-canonical "hostkey_verify" and the underscore
        # form "host_key_verify" so that either convention works in optional_args.
        self.hostkey_verify: bool = bool(
            optional_args.get("hostkey_verify", optional_args.get("host_key_verify", False))
        )
        # R19 = True for SR-OS < 21.x (older YANG revision 2016-07-06)
        self.R19: bool = False

    def open(self) -> None:
        """Open a NETCONF session to the device."""
        from ncclient import manager  # deferred: not needed until connection time

        self.conn = manager.connect(
            host=self.hostname,
            port=self.port,
            username=self.username,
            password=self.password,
            hostkey_verify=self.hostkey_verify,
            timeout=self.timeout,
        )
        # Detect legacy R19 YANG revision (SR-OS < 21.x firmware).
        # Capability URIs look like: urn:...nokia-state?module=nokia-state&revision=YYYY-MM-DD
        # Use a non-greedy match anchored to the revision parameter to avoid capturing
        # any subsequent query parameters (e.g. &features=...).
        _rev_re = re.compile(r"[?&]revision=([^&]+)")
        revisions = [
            m.group(1)
            for c in self.conn.server_capabilities
            if "nokia-state" in c and (m := _rev_re.search(c))
        ]
        self.R19 = "2016-07-06" in revisions

    def close(self) -> None:
        """Close the NETCONF session."""
        if self.conn is not None:
            self.conn.close_session()
            self.conn = None

    def is_alive(self) -> dict:
        """Return NETCONF session liveness by probing ncclient's connection state."""
        if self.conn is None:
            return {"is_alive": False}

        connected = getattr(self.conn, "connected", None)
        if connected is not None:
            return {"is_alive": bool(connected)}

        session = getattr(self.conn, "_session", None)
        if session is not None:
            session_connected = getattr(session, "connected", None)
            if session_connected is not None:
                return {"is_alive": bool(session_connected)}

            transport = getattr(session, "_transport", None)
            if transport is not None:
                is_active = getattr(transport, "is_active", None)
                if callable(is_active):
                    return {"is_alive": bool(is_active())}

        return {"is_alive": False}

    # -----------------------------------------------------------------------
    # NAPALM getters
    # -----------------------------------------------------------------------

    def get_facts(self) -> dict:
        """Return general device facts via NETCONF state tree."""
        try:
            result = _parse_xml(self.conn.get(filter=_FILTER_FACTS).data_xml)
            hostname = _find_txt(result, "state_ns:state/state_ns:system/state_ns:oper-name")
            uptime_ms_str = _find_txt(result, "state_ns:state/state_ns:system/state_ns:up-time")
            # Nokia YANG up-time is milliseconds (integer string)
            uptime = convert(float, uptime_ms_str, default=0.0) / 1000.0 if uptime_ms_str else 0.0
            # Build interface list using the same scoping as get_interfaces():
            # Base router → bare name, non-Base routers → "{router}/{if_name}".
            # Physical port-ids are also included.
            interface_names: set[str] = set()
            for router_el in result.xpath("state_ns:state/state_ns:router", namespaces=_NSMAP):
                router_name = _find_txt(router_el, "state_ns:router-name")
                for if_el in router_el.xpath("state_ns:interface", namespaces=_NSMAP):
                    if_name = _find_txt(if_el, "state_ns:interface-name")
                    if not if_name:
                        continue
                    if router_name and router_name != "Base":
                        interface_names.add(f"{router_name}/{if_name}")
                    else:
                        interface_names.add(if_name)
            for port_el in result.xpath(
                "state_ns:state/state_ns:port/state_ns:port-id", namespaces=_NSMAP
            ):
                if port_el.text:
                    interface_names.add(port_el.text.strip())
            interface_list = sorted(interface_names)
            return {
                "hostname": hostname,
                "vendor": "Nokia",
                "model": _find_txt(result, "state_ns:state/state_ns:system/state_ns:platform"),
                "os_version": _find_txt(
                    result,
                    "state_ns:state/state_ns:system/state_ns:version/state_ns:version-number",
                ),
                "serial_number": _find_txt(
                    result,
                    "state_ns:state/state_ns:chassis/state_ns:hardware-data/state_ns:serial-number",
                ),
                "uptime": uptime,
                "fqdn": hostname,
                "interface_list": interface_list,
            }
        except Exception:
            logger.exception("get_facts failed")
            return {}

    def get_interfaces(self) -> dict:
        """
        Return interface details keyed by name (physical ports + logical router interfaces).

        Physical ports and logical interfaces from all router VRFs (Base router and named VRFs)
        are included. VPRN service interfaces are not enumerated here because they lack
        port-state (speed/MAC) data in the YANG model; their IP addresses are available via
        get_interfaces_ip().
        """
        try:
            oper_state_tag = "<if-oper-status/>" if self.R19 else "<oper-state/>"
            nc_filter = _FILTER_INTERFACES_TMPL.format(
                ns_nc=_NS_NC,
                ns_state=_NS_STATE,
                ns_conf=_NS_CONF,
                oper_state_tag=oper_state_tag,
            )
            get_kwargs = _with_defaults_kwarg(self.conn.server_capabilities)
            result = _parse_xml(self.conn.get(filter=nc_filter, **get_kwargs).data_xml)
            interfaces: dict = {}

            # --- Physical ports ---
            for port in result.xpath("state_ns:state/state_ns:port", namespaces=_NSMAP):
                port_id = _find_txt(port, "state_ns:port-id")
                if not port_id:
                    continue
                cfg_block = _xpath_one(
                    result,
                    f'configure_ns:configure/configure_ns:port[configure_ns:port-id="{port_id}"]',
                )
                interfaces[port_id] = {
                    "is_up": _find_txt(port, "state_ns:oper-state") == "up",
                    "is_enabled": (
                        _find_txt(cfg_block, "configure_ns:admin-state") == "enable"
                        if cfg_block is not None
                        else False
                    ),
                    "description": (
                        _find_txt(cfg_block, "configure_ns:description")
                        if cfg_block is not None
                        else ""
                    ),
                    "last_flapped": -1.0,
                    "speed": convert(
                        float,
                        _find_txt(port, "state_ns:ethernet/state_ns:oper-speed"),
                        default=-1.0,
                    ),
                    "mtu": convert(
                        int,
                        _find_txt(cfg_block, "configure_ns:ethernet/configure_ns:mtu")
                        if cfg_block is not None
                        else "",
                        default=-1,
                    ),
                    "mac_address": _find_txt(port, "state_ns:hardware-mac-address"),
                }

            # --- Logical router interfaces ---
            chassis_mac = _find_txt(
                result,
                "state_ns:state/state_ns:chassis/state_ns:hardware-data/state_ns:base-mac-address",
            )
            oper_state_xpath = "state_ns:if-oper-status" if self.R19 else "state_ns:oper-state"

            for router_state in result.xpath("state_ns:state/state_ns:router", namespaces=_NSMAP):
                router_name = _find_txt(router_state, "state_ns:router-name")
                for if_state in router_state.xpath("state_ns:interface", namespaces=_NSMAP):
                    self._add_router_if(
                        interfaces, if_state, result, router_name, oper_state_xpath, chassis_mac
                    )

            return interfaces
        except Exception:
            logger.exception("get_interfaces failed")
            return {}

    def _add_router_if(
        self,
        interfaces: dict,
        if_state: "etree._Element",
        result: "etree._Element",
        router_name: str,
        oper_state_xpath: str,
        chassis_mac: str,
    ) -> None:
        """Populate *interfaces* with one logical router interface entry."""
        if_name = _find_txt(if_state, "state_ns:interface-name")
        if not if_name:
            return
        # Qualify config lookup by router-name to avoid cross-router collisions.
        cfg_block = _xpath_one(
            result,
            f"configure_ns:configure/configure_ns:router"
            f'[configure_ns:router-name="{router_name}"]'
            f'/configure_ns:interface[configure_ns:interface-name="{if_name}"]',
        )
        # Key by plain interface-name for Base router; prefix with router-name for
        # named VRF routers so same-named interfaces across contexts don't collide.
        key = if_name if router_name == "Base" else f"{router_name}/{if_name}"
        interfaces[key] = {
            "is_up": _find_txt(if_state, oper_state_xpath) == "up",
            "is_enabled": _find_txt(cfg_block, "configure_ns:admin-state") == "enable"
            if cfg_block is not None
            else False,
            "description": _find_txt(cfg_block, "configure_ns:description")
            if cfg_block is not None
            else "",
            "last_flapped": _parse_last_flapped(_find_txt(if_state, "state_ns:last-oper-change")),
            "speed": _resolve_if_speed(result, cfg_block),
            "mtu": convert(int, _find_txt(if_state, "state_ns:oper-ip-mtu"), default=-1),
            "mac_address": _resolve_if_mac(result, cfg_block, if_name, chassis_mac),
        }

    def get_interfaces_ip(self) -> dict:
        """
        Return all configured IP addresses per interface (configure tree).

        Keys use the same scoping convention as ``get_interfaces()``: Base router
        interfaces are keyed by bare interface-name; non-Base router VRF interfaces
        are prefixed as ``{router_name}/{if_name}``; VPRN service interfaces are
        prefixed as ``{service_name}/{if_name}``.
        """
        try:
            get_kwargs = _with_defaults_kwarg(self.conn.server_capabilities)
            result = _parse_xml(self.conn.get(filter=_FILTER_INTERFACES_IP, **get_kwargs).data_xml)
            interfaces_ip: dict = {}

            # Router interfaces (Base router + named VRF routers)
            for router in result.xpath("configure_ns:configure/configure_ns:router", namespaces=_NSMAP):
                router_name = _find_txt(router, "configure_ns:router-name")
                for iface in router.xpath("configure_ns:interface", namespaces=_NSMAP):
                    if_name = _find_txt(iface, "configure_ns:interface-name")
                    if not if_name:
                        continue
                    key = if_name if router_name == "Base" else f"{router_name}/{if_name}"
                    _merge_if_addrs(interfaces_ip, key, _extract_if_addrs(iface))

            # VPRN service interfaces
            for vprn in result.xpath(
                "configure_ns:configure/configure_ns:service/configure_ns:vprn", namespaces=_NSMAP
            ):
                svc_name = _find_txt(vprn, "configure_ns:service-name")
                for iface in vprn.xpath("configure_ns:interface", namespaces=_NSMAP):
                    if_name = _find_txt(iface, "configure_ns:interface-name")
                    if not if_name:
                        continue
                    _merge_if_addrs(interfaces_ip, f"{svc_name}/{if_name}", _extract_if_addrs(iface))

            return interfaces_ip
        except Exception:
            logger.exception("get_interfaces_ip failed")
            return {}

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """Return Nokia SR-OS running configuration as NETCONF XML."""
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}
        try:
            if retrieve in ("all", "running"):
                data = _parse_xml(self.conn.get_config(source="running").data_xml)
                cfg_nodes = data.xpath("configure_ns:configure", namespaces=_NSMAP)
                if cfg_nodes:
                    config["running"] = etree.tostring(
                        cfg_nodes[0], pretty_print=True
                    ).decode("utf-8")
        except Exception:
            logger.exception("get_config failed")
        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])
        return config

    def get_vlans(self) -> dict:
        """Nokia SR-OS uses a service-based architecture — no traditional VLAN table."""
        return {}
