#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Interface translation utilities for device discovery."""

import ipaddress
import logging
import re
from collections.abc import Iterable

from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb
from netboxlabs.diode.sdk.ingester import Device, Entity, Interface, IPAddress, Location, Prefix

from device_discovery.defaults import DEFAULT_INTERFACE_PATTERNS
from device_discovery.interface_types import VALID_INTERFACE_TYPES
from device_discovery.policy.models import Defaults, Options

logger = logging.getLogger(__name__)


def detect_type_by_speed(speed_mbps: float) -> str:
    """
    Determine interface type based on speed.

    Uses speed ranges from SNMP discovery reference implementation.
    Speed in Mbps (from NAPALM).

    Args:
    ----
        speed_mbps: Interface speed in Mbps

    Returns:
    -------
        NetBox interface type string

    """
    # Speed thresholds and their corresponding interface types (ordered by speed)
    speed_thresholds = [
        (100, "100base-tx"),
        (1000, "1000base-t"),
        (2500, "2.5gbase-t"),
        (5000, "5gbase-t"),
        (10000, "10gbase-x-sfpp"),
        (25000, "25gbase-x-sfp28"),
        (40000, "40gbase-x-qsfpp"),
        (50000, "50gbase-x-sfp56"),
        (100000, "100gbase-x-qsfp28"),
        (200000, "200gbase-x-qsfp56"),
        (400000, "400gbase-x-qsfp112"),
    ]

    for threshold, interface_type in speed_thresholds:
        if speed_mbps <= threshold:
            return interface_type

    # Default to highest speed for anything above 400G
    return "800gbase-x-qsfpdd"


def merge_interface_patterns(
    user_patterns: list | None,
    include_defaults: bool = True
) -> list:
    """
    Merge user-defined patterns with built-in defaults.

    User patterns have priority and are checked first.
    Built-in patterns serve as intelligent fallback.

    Args:
    ----
        user_patterns: Patterns from policy configuration (or None)
        include_defaults: Whether to include built-in patterns (default: True)

    Returns:
    -------
        Merged list of patterns with user patterns first

    """
    if not include_defaults:
        return user_patterns or []

    merged = []

    # User patterns first (highest priority)
    if user_patterns:
        merged.extend(user_patterns)

    # Built-in patterns as fallback
    merged.extend(DEFAULT_INTERFACE_PATTERNS)

    return merged


def match_interface_type(
    interface_name: str,
    patterns: list | None,
    user_pattern_count: int = 0
) -> str | None:
    """
    Match interface name against patterns with priority-aware matching.

    When both user and built-in patterns are present, user patterns ALWAYS
    take priority. The "most specific match wins" rule (longest match) only
    applies within the same priority level:
    1. First, check all user patterns - if any match, return most specific
    2. Only if no user pattern matches, check built-in patterns

    Args:
    ----
        interface_name: The name of the interface to match.
        patterns: List of InterfacePattern objects to match against.
        user_pattern_count: Number of user patterns at the start of the list.

    Returns:
    -------
        The matched interface type, or None if no pattern matches.

    """
    if not patterns:
        return None

    # Separate user patterns from built-in patterns
    user_patterns = patterns[:user_pattern_count] if user_pattern_count > 0 else []
    builtin_patterns = patterns[user_pattern_count:] if user_pattern_count > 0 else patterns

    def find_best_match(pattern_list):
        """Find the most specific (longest) match in a pattern list."""
        best_match_length = 0
        best_match_type = None

        for pattern in pattern_list:
            try:
                compiled_pattern = re.compile(pattern.match)
                match = compiled_pattern.search(interface_name)

                if match:
                    match_length = len(match.group(0))
                    if match_length > best_match_length:
                        best_match_length = match_length
                        best_match_type = pattern.type

            except re.error as e:
                logger.warning(
                    f"Error compiling pattern '{pattern.match}': {e}. Skipping pattern."
                )
                continue

        return best_match_type

    # Priority 1: Check user patterns first
    if user_patterns:
        user_match = find_best_match(user_patterns)
        if user_match:
            return user_match

    # Priority 2: Check built-in patterns only if no user pattern matched
    return find_best_match(builtin_patterns)


def int32_overflows(number: int) -> bool:
    """
    Check if an integer is overflowing the int32 range.

    Args:
    ----
        number (int): The integer to check.

    Returns:
    -------
        bool: True if the integer is overflowing the int32 range, False otherwise.

    """
    INT32_MIN = -2147483648
    INT32_MAX = 2147483647
    return not (INT32_MIN <= number <= INT32_MAX)


def _resolve_non_subinterface_type(
    if_name: str,
    interface_info: dict,
    defaults: Defaults,
) -> str:
    """
    Resolve a non-subinterface type by descending priority.

    user patterns -> driver-provided type -> built-in patterns -> speed ->
    if_type. A driver-provided type is honored only when it is a valid NetBox
    interface type; an invalid value is ignored (with a warning) so an invalid
    type is never emitted.
    """
    # Tier 2: user-defined patterns (explicit operator override)
    user_patterns = defaults.interface_patterns or []
    if user_patterns:
        matched = match_interface_type(if_name, user_patterns, len(user_patterns))
        if matched:
            return matched

    # Tier 3: type asserted by the driver from device state
    driver_type = interface_info.get("type")
    if driver_type:
        if driver_type in VALID_INTERFACE_TYPES:
            return driver_type
        logger.warning(
            "Driver-provided interface type %r for %s is not a valid NetBox "
            "interface type; ignoring.",
            driver_type,
            if_name,
        )

    # Tier 4: built-in patterns
    matched = match_interface_type(if_name, DEFAULT_INTERFACE_PATTERNS, 0)
    if matched:
        return matched

    # Tier 5: speed-based detection
    speed = interface_info.get("speed")
    if speed and speed > 0:
        return detect_type_by_speed(speed)

    # Tier 6: configured default
    return defaults.if_type


def translate_interface(
    device: Device,
    if_name: str,
    interface_info: dict,
    defaults: Defaults,
    parent: Interface | None = None,
) -> Interface:
    """
    Translate interface information from NAPALM format to Diode SDK Interface entity.

    Args:
    ----
        device (Device): The device to which the interface belongs.
        if_name (str): The name of the interface.
        interface_info (dict): Dictionary containing interface information.
        defaults (Defaults): Default configuration.
        parent (Interface | None): Parent interface, if any.

    Returns:
    -------
        Interface: Translated Interface entity.

    """
    tags = list(defaults.tags) if defaults.tags else []
    description = None

    if defaults.interface:
        tags.extend(defaults.interface.tags or [])
        description = defaults.interface.description

    description = interface_info.get("description", description)
    mac_address = (
        interface_info.get("mac_address")
        if interface_info.get("mac_address") != ""
        else None
    )

    # Determine interface type by descending priority:
    # 1. Subinterface (has parent) -> "virtual" (structural)
    # 2. User-defined pattern match
    # 3. Driver-provided type (validated against NetBox interface types)
    # 4. Built-in pattern match
    # 5. Speed-based detection
    # 6. Fallback -> defaults.if_type
    is_subinterface = parent is not None

    if is_subinterface:
        # Tier 1: Subinterfaces always get "virtual" type (structural)
        interface_type = "virtual"
        parent = Interface(
            device=device,
            name=parent.name,
            type=parent.type,
        )
    else:
        interface_type = _resolve_non_subinterface_type(
            if_name, interface_info, defaults
        )

    interface = Interface(
        device=device,
        name=if_name,
        enabled=interface_info.get("is_enabled"),
        primary_mac_address=mac_address,
        description=description,
        parent=parent,
        tags=tags,
        type=interface_type,
    )

    # Convert napalm interface speed from Mbps to Netbox Kbps
    speed = interface_info.get("speed")
    if speed is not None:
        speed_kbps = int(speed) * 1000
        if speed_kbps > 0 and not int32_overflows(speed_kbps):
            interface.speed = speed_kbps

    mtu = interface_info.get("mtu")
    if mtu is not None and mtu > 0 and not int32_overflows(mtu):
        interface.mtu = mtu

    return interface


def _resolve_prefix_scope_kwargs(
    defaults: Defaults,
    options: "Options | None",
) -> dict[str, str]:
    """
    Pick a single Prefix scope_* kwarg honoring the protobuf oneof.

    Reads the two explicit scope fields off ``defaults.prefix`` and, when
    ``options.propagate_defaults_to_prefix_scope`` is True, falls back to
    ``defaults.site`` (skipping the "undefined" placeholder) and
    ``defaults.location``. Explicit per-prefix scope always wins over the
    cascade.

    ``Prefix.scope_{site,location}`` is a protobuf oneof, so only one value
    travels on the wire — picks the most-specific non-empty candidate
    (location > site) so callers don't accidentally clobber a granular
    scope with a broader one.
    """
    prefix_scope_site: str | None = None
    prefix_scope_location: str | None = None

    if defaults.prefix:
        # getattr fallback so a caller that bypasses Pydantic and assigns
        # a bare IpamParameters (missing scope_*) to defaults.prefix
        # post-construction doesn't crash with AttributeError mid-discovery.
        # Normal YAML / Pydantic-validation paths get PrefixParameters with
        # the attributes already present — getattr is the no-op fast path.
        prefix_scope_site = getattr(defaults.prefix, "scope_site", None) or None
        prefix_scope_location = getattr(defaults.prefix, "scope_location", None) or None

    # Opt-in cascade: defaults.site / defaults.location → Prefix scope.
    # Any explicit defaults.prefix.scope_* puts the operator in "explicit
    # mode" and the cascade is skipped wholesale — otherwise a cascaded
    # more-specific scope (e.g. cascaded scope_location) could win the
    # oneof precedence over an operator's explicit less-specific choice
    # (e.g. explicit scope_site). The literal "undefined" placeholder for
    # defaults.site is treated as no-value (see Defaults model).
    any_explicit_prefix_scope = bool(prefix_scope_site or prefix_scope_location)
    if (
        options
        and options.propagate_defaults_to_prefix_scope
        and not any_explicit_prefix_scope
    ):
        if defaults.site and defaults.site != "undefined":
            prefix_scope_site = defaults.site
        if defaults.location:
            prefix_scope_location = defaults.location

    # NetBox Locations are unique within their parent site, not globally —
    # emit Location(name=..., site=...) when a site is available so the
    # Diode plugin can disambiguate "Floor-1 in DC-East" from "Floor-1 in
    # DC-West". Mirrors translate_device's Location(name=..., site=...).
    scope_kwargs: dict[str, str | Location] = {}
    for scope_name, scope_val in (
        ("scope_location", prefix_scope_location),
        ("scope_site", prefix_scope_site),
    ):
        if not scope_val:
            continue
        if scope_name == "scope_location" and prefix_scope_site:
            scope_kwargs[scope_name] = Location(name=scope_val, site=prefix_scope_site)
        else:
            scope_kwargs[scope_name] = scope_val
        break
    return scope_kwargs


def _undesirable_prefix_reason(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    emit_host_prefixes: bool = False,
) -> str | None:
    """
    Return why ``network`` must not be emitted as a Prefix, or None to emit it.

    A Prefix is derived from the network of every discovered interface IP, but
    two shapes carry no IPAM value and only add noise:

    - **Host prefixes** (IPv4 /32, IPv6 /128) restate the address itself. A
      router loopback of 10.0.0.1/32 yields the "prefix" 10.0.0.1/32, which
      duplicates the IPAddress entity that is emitted alongside it. Operators
      who do track loopback /32s as NetBox prefixes can set the
      ``emit_host_prefixes`` option to keep them.
    - **IPv6 link-locals** (fe80::/10) are per-link and not globally
      meaningful, so a prefix per link-local address is pure churn. There is
      no opt-in for these: an fe80:: prefix is never useful IPAM data, and
      ``emit_host_prefixes`` deliberately does not resurrect them.

    IPv4 link-local (169.254.0.0/16) and the loopback net (127.0.0.0/8) are
    deliberately NOT suppressed — they are ordinary networks by mask, so they
    keep the existing behavior.

    Suppression applies only to the derived Prefix. The IPAddress entity is
    always still emitted, so the interface and its address stay documented.
    """
    # The link-local rule is not gated on emit_host_prefixes, which is what
    # keeps an fe80::x/128 address suppressed even when the opt-in is on: it
    # is a link-local that happens to carry host length, not a loopback an
    # operator wants tracked. Checked first only so the logged reason names
    # link-local rather than host length; either order suppresses the same set.
    # Only IPv6: ipaddress treats 169.254.0.0/16 as link-local too, and that
    # one stays in scope for emission.
    if network.version == 6 and network.is_link_local:
        return "IPv6 link-local"
    if not emit_host_prefixes and network.prefixlen == network.max_prefixlen:
        return "host prefix"
    return None


def translate_interface_ips(
    interface: Interface,
    interfaces_ip: dict,
    defaults: Defaults,
    options: "Options | None" = None,
    iface_vrf_map: dict[str, pb.VRF] | None = None,
) -> Iterable[Entity]:
    """
    Translate IP address and Prefixes information for an interface.

    Args:
    ----
        interface (Interface): The interface entity.
        interfaces_ip (dict): Dictionary containing interface IP information.
        defaults (Defaults): Default configuration.
        options (Options | None): Policy options; when
            ``propagate_defaults_to_prefix_scope`` is True the top-level
            ``defaults.site`` / ``defaults.location`` cascade onto the
            emitted Prefix scope.
        iface_vrf_map (dict[str, pb.VRF] | None): Interface name → discovered
            VRF map built from get_network_instances(). When the interface
            appears in the map, the discovered VRF wins over the defaults
            vrf / vrf_ipv4 / vrf_ipv6 for both IPAddress and Prefix.

    Returns:
    -------
        Iterable[Entity]: Iterable of translated IP address and Prefixes entities.

    """
    from device_discovery.translate import translate_tenant, translate_vrf

    tags = defaults.tags if defaults.tags else []
    ip_tags = list(tags)
    ip_comments = None
    ip_description = None
    ip_role = None
    ip_tenant = None
    ip_vrf = None

    prefix_tags = list(tags)
    prefix_comments = None
    prefix_description = None
    prefix_role = None
    prefix_tenant = None
    prefix_vrf = None

    # Per-address-family VRF overrides: when `defaults.ipaddress.vrf_ipv4`
    # / `vrf_ipv6` (or the prefix equivalents) are set, the family-specific
    # value wins for that AF; otherwise we fall back to the AF-agnostic
    # `defaults.ipaddress.vrf` / `defaults.prefix.vrf`. Computed once here
    # and picked inside the per-IP loop below by the existing `ip_version`
    # discriminator.
    ip_vrf_ipv4 = None
    ip_vrf_ipv6 = None
    prefix_vrf_ipv4 = None
    prefix_vrf_ipv6 = None

    if defaults.ipaddress:
        ip_tags.extend(defaults.ipaddress.tags or [])
        ip_comments = defaults.ipaddress.comments
        ip_description = defaults.ipaddress.description
        ip_role = defaults.ipaddress.role
        ip_tenant = translate_tenant(defaults.ipaddress.tenant)
        ip_vrf = translate_vrf(defaults.ipaddress.vrf)
        ip_vrf_ipv4 = translate_vrf(defaults.ipaddress.vrf_ipv4)
        ip_vrf_ipv6 = translate_vrf(defaults.ipaddress.vrf_ipv6)

    if defaults.prefix:
        prefix_tags.extend(defaults.prefix.tags or [])
        prefix_comments = defaults.prefix.comments
        prefix_description = defaults.prefix.description
        prefix_role = defaults.prefix.role
        prefix_tenant = translate_tenant(defaults.prefix.tenant)
        prefix_vrf = translate_vrf(defaults.prefix.vrf)
        prefix_vrf_ipv4 = translate_vrf(defaults.prefix.vrf_ipv4)
        prefix_vrf_ipv6 = translate_vrf(defaults.prefix.vrf_ipv6)

    scope_kwargs = _resolve_prefix_scope_kwargs(defaults, options)
    # Opt-in: host prefixes are not derived unless the operator asks for them.
    emit_host_prefixes = bool(options and options.emit_host_prefixes)

    # Device state beats policy defaults: a VRF discovered for this
    # interface overrides every configured vrf default for its IPs and
    # prefixes. Interfaces outside the map keep the defaults fallback.
    discovered_vrf = (iface_vrf_map or {}).get(interface.name)

    ip_entities = []

    for if_ip_name, ip_info in interfaces_ip.items():
        if interface.name == if_ip_name:
            for ip_version, default_prefix in (("ipv4", 32), ("ipv6", 128)):
                # Resolve the per-AF VRF: discovered VRF wins, then the
                # AF-specific override, then the AF-agnostic default.
                af_ip_vrf = discovered_vrf or (
                    ip_vrf_ipv4 if ip_version == "ipv4" else ip_vrf_ipv6
                ) or ip_vrf
                af_prefix_vrf = discovered_vrf or (
                    prefix_vrf_ipv4 if ip_version == "ipv4" else prefix_vrf_ipv6
                ) or prefix_vrf
                for ip, details in ip_info.get(ip_version, {}).items():
                    ip_address = f"{ip}/{details.get('prefix_length', default_prefix)}"
                    network = ipaddress.ip_network(ip_address, strict=False)
                    skip_reason = _undesirable_prefix_reason(
                        network, emit_host_prefixes
                    )
                    if skip_reason:
                        logger.debug(
                            "%s: not deriving a prefix from %s (%s)",
                            interface.name,
                            ip_address,
                            skip_reason,
                        )
                    else:
                        ip_entities.append(
                            Entity(
                                prefix=Prefix(
                                    prefix=str(network),
                                    vrf=af_prefix_vrf,
                                    role=prefix_role,
                                    tenant=prefix_tenant,
                                    tags=prefix_tags,
                                    comments=prefix_comments,
                                    description=prefix_description,
                                    **scope_kwargs,
                                )
                            )
                        )
                    ip_entities.append(
                        Entity(
                            ip_address=IPAddress(
                                address=ip_address,
                                assigned_object_interface=Interface(
                                    device=interface.device,
                                    name=interface.name,
                                    type=interface.type,
                                ),
                                role=ip_role,
                                tenant=ip_tenant,
                                vrf=af_ip_vrf,
                                tags=ip_tags,
                                comments=ip_comments,
                                description=ip_description,
                            )
                        )
                    )

    return ip_entities


def extract_parent_interface_name(interface_name: str) -> str | None:
    """Return the parent interface name if the supplied name represents a subinterface."""
    for separator in (".", ":"):
        if separator in interface_name:
            parent, child = interface_name.rsplit(separator, 1)
            if parent and child:
                return parent
    return None


def _compile_exclude_patterns(patterns: list[str]) -> list[re.Pattern]:
    compiled = []
    for p in patterns:
        p = p.strip()
        if not p:
            logger.warning("Empty interface exclude pattern, skipping.")
            continue
        try:
            compiled.append(re.compile(p))
        except re.error as e:
            logger.warning(f"Invalid interface exclude pattern '{p}': {e}. Skipping.")
    return compiled


def _attach_module_ref(
    iface: Interface,
    name: str,
    iface_module_map: dict[str, pb.Module],
) -> None:
    """
    Attach a module ref on an interface when iface_module_map covers it.

    Free helper (not nested in build_interface_entities) so the parent
    function stays under the McCabe complexity limit. No-op when the
    name has no entry in the map.
    """
    module = iface_module_map.get(name)
    if module is not None:
        iface.module.CopyFrom(module)


def build_interface_entities(
    device: Device,
    interfaces: dict,
    interfaces_ip: dict,
    defaults: Defaults,
    iface_module_map: dict[str, pb.Module] | None = None,
    options: "Options | None" = None,
    iface_vrf_map: dict[str, pb.VRF] | None = None,
) -> list[Entity]:
    """
    Create interface entities from interface definitions and IP data.

    When ``iface_module_map`` is provided (populated by
    ``translate_modules.emit_modules_if_requested``), the matching
    interface entity carries a ``module=`` reference alongside its
    ``device=`` reference, so NetBox knows which line card / sub-module
    physically owns the port.

    When ``iface_vrf_map`` is provided (populated by
    ``vrf.build_discovered_vrfs``), IP addresses and prefixes on a mapped
    interface carry that discovered VRF instead of the configured defaults.
    """
    exclude_patterns = _compile_exclude_patterns(defaults.interface_exclude_patterns or [])
    iface_module_map = iface_module_map or {}

    def is_excluded(name: str) -> bool:
        # Uses search (not match) so patterns match anywhere in the name.
        # Use ^ to anchor to start, e.g. "^tap.*"
        return any(pat.search(name) for pat in exclude_patterns)

    interface_entities: dict[str, Interface] = {}
    entities: list[Entity] = []
    defined_interface_names = set(interfaces.keys())

    def interface_sort_key(name: str) -> tuple[int, str]:
        separator_score = name.count(".") + name.count(":")
        return (separator_score, name)

    def resolve_parent(name: str) -> Interface | None:
        parent_name = extract_parent_interface_name(name)
        if not parent_name or parent_name not in defined_interface_names:
            return None
        return interface_entities.get(parent_name)

    for if_name, interface_info in sorted(
        interfaces.items(), key=lambda item: interface_sort_key(item[0])
    ):
        if is_excluded(if_name):
            continue
        parent = resolve_parent(if_name)
        interface = translate_interface(
            device, if_name, interface_info, defaults, parent=parent
        )
        _attach_module_ref(interface, if_name, iface_module_map)
        interface_entities[if_name] = interface
        entities.append(Entity(interface=interface))
        entities.extend(
            translate_interface_ips(
                interface,
                interfaces_ip,
                defaults,
                options=options,
                iface_vrf_map=iface_vrf_map,
            )
        )

    for if_name in sorted(interfaces_ip.keys(), key=interface_sort_key):
        if if_name in interface_entities:
            continue
        if is_excluded(if_name):
            continue
        parent = resolve_parent(if_name)
        interface = translate_interface(device, if_name, {}, defaults, parent=parent)
        _attach_module_ref(interface, if_name, iface_module_map)
        interface_entities[if_name] = interface
        entities.append(Entity(interface=interface))
        entities.extend(
            translate_interface_ips(
                interface,
                interfaces_ip,
                defaults,
                options=options,
                iface_vrf_map=iface_vrf_map,
            )
        )

    return entities
