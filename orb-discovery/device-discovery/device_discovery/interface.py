#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Interface translation utilities for device discovery."""

import ipaddress
import logging
import re
from collections.abc import Iterable

from netboxlabs.diode.sdk.ingester import Device, Entity, Interface, IPAddress, Prefix

from device_discovery.defaults import DEFAULT_INTERFACE_PATTERNS
from device_discovery.policy.models import Defaults

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
    return "800gbase-x-qsfp-dd"


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

    # Determine interface type with five-tier priority:
    # 1. Subinterface (has parent) -> "virtual"
    # 2. User-defined pattern match -> matched type
    # 3. Built-in pattern match -> matched type
    # 4. Speed-based detection -> type from speed
    # 5. Fallback -> defaults.if_type
    interface_type = defaults.if_type
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
        # Tier 2 & 3: Try pattern matching (user + built-in merged)
        # Use getattr for backward compatibility with SimpleNamespace in tests
        user_patterns = getattr(defaults, 'interface_patterns', None)
        merged_patterns = merge_interface_patterns(user_patterns, include_defaults=True)

        # Count user patterns to maintain priority during matching
        user_pattern_count = len(user_patterns) if user_patterns else 0
        matched_type = match_interface_type(if_name, merged_patterns, user_pattern_count)
        if matched_type:
            interface_type = matched_type
        else:
            # Tier 4: Speed-based detection fallback
            speed = interface_info.get("speed")
            if speed and speed > 0:
                interface_type = detect_type_by_speed(speed)
            # Else: Tier 5 - interface_type already has defaults.if_type fallback

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


def translate_interface_ips(
    interface: Interface, interfaces_ip: dict, defaults: Defaults
) -> Iterable[Entity]:
    """
    Translate IP address and Prefixes information for an interface.

    Args:
    ----
        interface (Interface): The interface entity.
        if_name (str): The name of the interface.
        interfaces_ip (dict): Dictionary containing interface IP information.
        defaults (Defaults): Default configuration.

    Returns:
    -------
        Iterable[Entity]: Iterable of translated IP address and Prefixes entities.

    """
    from device_discovery.translate import translate_tenant

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

    if defaults.ipaddress:
        ip_tags.extend(defaults.ipaddress.tags or [])
        ip_comments = defaults.ipaddress.comments
        ip_description = defaults.ipaddress.description
        ip_role = defaults.ipaddress.role
        ip_tenant = translate_tenant(defaults.ipaddress.tenant)
        ip_vrf = defaults.ipaddress.vrf

    if defaults.prefix:
        prefix_tags.extend(defaults.prefix.tags or [])
        prefix_comments = defaults.prefix.comments
        prefix_description = defaults.prefix.description
        prefix_role = defaults.prefix.role
        prefix_tenant = translate_tenant(defaults.prefix.tenant)
        prefix_vrf = defaults.prefix.vrf

    ip_entities = []

    for if_ip_name, ip_info in interfaces_ip.items():
        if interface.name == if_ip_name:
            for ip_version, default_prefix in (("ipv4", 32), ("ipv6", 128)):
                for ip, details in ip_info.get(ip_version, {}).items():
                    ip_address = f"{ip}/{details.get('prefix_length', default_prefix)}"
                    network = ipaddress.ip_network(ip_address, strict=False)
                    ip_entities.append(
                        Entity(
                            prefix=Prefix(
                                prefix=str(network),
                                vrf=prefix_vrf,
                                role=prefix_role,
                                tenant=prefix_tenant,
                                tags=prefix_tags,
                                comments=prefix_comments,
                                description=prefix_description,
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
                                vrf=ip_vrf,
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


def build_interface_entities(
    device: Device,
    interfaces: dict,
    interfaces_ip: dict,
    defaults: Defaults,
) -> list[Entity]:
    """Create interface entities from interface definitions and IP data."""
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
        parent = resolve_parent(if_name)
        interface = translate_interface(
            device, if_name, interface_info, defaults, parent=parent
        )
        interface_entities[if_name] = interface
        entities.append(Entity(interface=interface))
        entities.extend(translate_interface_ips(interface, interfaces_ip, defaults))

    for if_name in sorted(interfaces_ip.keys(), key=interface_sort_key):
        if if_name in interface_entities:
            continue
        parent = resolve_parent(if_name)
        interface = translate_interface(device, if_name, {}, defaults, parent=parent)
        interface_entities[if_name] = interface
        entities.append(Entity(interface=interface))
        entities.extend(translate_interface_ips(interface, interfaces_ip, defaults))

    return entities
