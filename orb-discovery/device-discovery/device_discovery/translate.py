#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""Translate from NAPALM output format to Diode SDK entities."""

import ipaddress
from collections.abc import Iterable

from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb
from netboxlabs.diode.sdk.ingester import (
    VLAN,
    Device,
    DeviceType,
    Entity,
    Interface,
    IPAddress,
    Location,
    Platform,
    Prefix,
    Tenant,
    TenantGroup,
)

from device_discovery.policy.models import Defaults, Options, TenantParameters


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


def translate_tenant(
    tenant: str | TenantParameters | pb.Tenant | None,
) -> pb.Tenant | None:
    """Convert tenant input into a Diode Tenant message."""
    if tenant is None or isinstance(tenant, pb.Tenant):
        return tenant

    if isinstance(tenant, TenantParameters):
        tenant_group = TenantGroup(name=tenant.group) if tenant.group else None
        return Tenant(
            name=tenant.name,
            group=tenant_group,
            comments=tenant.comments,
            description=tenant.description,
            tags=tenant.tags,
        )

    return Tenant(name=tenant)


def translate_device(device_info: dict, defaults: Defaults) -> Device:
    """
    Translate device information from NAPALM format to Diode SDK Device entity.

    Args:
    ----
        device_info (dict): Dictionary containing device information.
        defaults (Defaults): Default configuration.

    Returns:
    -------
        Device: Translated Device entity.

    """
    tags = list(defaults.tags) if defaults.tags else []
    model = device_info.get("model")
    manufacturer = device_info.get("vendor")
    platform = device_info.get("platform")
    description = None
    comments = None
    location = None

    if defaults.device:
        tags.extend(defaults.device.tags or [])
        description = defaults.device.description
        comments = defaults.device.comments
        model = defaults.device.model or model
        manufacturer = defaults.device.manufacturer or manufacturer
        platform = defaults.device.platform or platform

    if defaults.location:
        location = Location(name=defaults.location, site=defaults.site)

    serial_number = device_info.get("serial_number")
    if isinstance(serial_number, list | tuple):
        if not serial_number:
            serial_number = None
        else:
            string_values = [
                value
                for value in serial_number
                if isinstance(value, str | bytes) and value
            ]
            if string_values:
                serial_number = string_values[0]
            else:
                serial_number = str(serial_number[0])
    elif serial_number is not None and not isinstance(serial_number, str | bytes):
        serial_number = str(serial_number)

    device = Device(
        name=device_info.get("hostname"),
        device_type=DeviceType(model=model, manufacturer=manufacturer),
        platform=Platform(name=platform, manufacturer=manufacturer),
        role=defaults.role,
        serial=serial_number,
        status="active",
        site=defaults.site,
        tags=tags,
        location=location,
        tenant=translate_tenant(defaults.tenant),
        description=description,
        comments=comments,
    )
    return device


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

    interface_type = defaults.if_type
    if parent is not None:
        interface_type = "virtual"
        parent = Interface(
            device=device,
            name=parent.name,
            type=parent.type,
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


def translate_vlan(vid: str, vlan_name: str, defaults: Defaults) -> VLAN | None:
    """
    Translate VLAN information for a given VLAN ID.

    Args:
    ----
        vid (str): VLAN ID.
        vlan_name (str): VLAN name.
        defaults (Defaults): Default configuration.

    """
    try:
        vid_int = int(vid)
    except (ValueError, TypeError):
        return None
    tags = list(defaults.tags) if defaults.tags else []
    comments = None
    description = None
    group = None
    tenant = None
    role = None

    if defaults.vlan:
        tags.extend(defaults.vlan.tags or [])
        comments = defaults.vlan.comments
        description = defaults.vlan.description
        group = defaults.vlan.group
        tenant = translate_tenant(defaults.vlan.tenant)
        role = defaults.vlan.role

    clean_name = " ".join(vlan_name.strip().split())
    vlan = VLAN(
        vid=vid_int,
        name=clean_name,
        group=group,
        tenant=tenant,
        role=role,
        tags=tags,
        comments=comments,
        description=description,
    )

    return vlan


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


def translate_data(data: dict) -> Iterable[Entity]:
    """
    Translate data from NAPALM format to Diode SDK entities.

    Args:
    ----
        data (dict): Dictionary containing data to be translated.

    Returns:
    -------
        Iterable[Entity]: Iterable of translated entities.

    """
    entities = []

    defaults = data.get("defaults") or Defaults()
    options = data.get("options") or Options()

    device_info = data.get("device", {})
    interfaces = data.get("interface") or {}
    interfaces_ip = data.get("interface_ip") or {}
    if device_info:
        if options.platform_omit_version:
            device_info["platform"] = data.get("driver")
        else:
            device_info["platform"] = (
                f"{data.get('driver', '').upper()} {device_info.get('os_version')}"
            )
            if len(device_info["platform"]) > 100:
                device_info["platform"] = device_info.get('os_version')[:100]
        device = translate_device(device_info, defaults)
        entities.append(Entity(device=device))

        interface_related_entities = build_interface_entities(
            device, interfaces, interfaces_ip, defaults
        )
        entities.extend(interface_related_entities)

    if data.get("vlan"):
        for vid, vlan_info in data.get("vlan").items():
            vlan = translate_vlan(vid, vlan_info.get("name"), defaults)
            if vlan:
                entities.append(Entity(vlan=vlan))

    return entities
