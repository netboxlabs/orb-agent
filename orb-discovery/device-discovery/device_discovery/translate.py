#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""Translate from NAPALM output format to Diode SDK entities."""

import ipaddress
from collections.abc import Iterable

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
)

from device_discovery.policy.models import Defaults, Options


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

    device = Device(
        name=device_info.get("hostname"),
        device_type=DeviceType(model=model, manufacturer=manufacturer),
        platform=Platform(name=platform, manufacturer=manufacturer),
        role=defaults.role,
        serial=device_info.get("serial_number"),
        status="active",
        site=defaults.site,
        tags=tags,
        location=location,
        tenant=defaults.tenant,
        description=description,
        comments=comments,
    )
    return device


def translate_interface(
    device: Device, if_name: str, interface_info: dict, defaults: Defaults
) -> Interface:
    """
    Translate interface information from NAPALM format to Diode SDK Interface entity.

    Args:
    ----
        device (Device): The device to which the interface belongs.
        if_name (str): The name of the interface.
        interface_info (dict): Dictionary containing interface information.
        defaults (Defaults): Default configuration.

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

    interface = Interface(
        device=device,
        name=if_name,
        enabled=interface_info.get("is_enabled"),
        primary_mac_address=mac_address,
        description=description,
        tags=tags,
        type=defaults.if_type,
    )

    # Convert napalm interface speed from Mbps to Netbox Kbps
    speed = int(interface_info.get("speed")) * 1000
    if speed > 0 and not int32_overflows(speed):
        interface.speed = speed

    mtu = interface_info.get("mtu")
    if mtu > 0 and not int32_overflows(mtu):
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
        ip_tenant = defaults.ipaddress.tenant
        ip_vrf = defaults.ipaddress.vrf

    if defaults.prefix:
        prefix_tags.extend(defaults.prefix.tags or [])
        prefix_comments = defaults.prefix.comments
        prefix_description = defaults.prefix.description
        prefix_role = defaults.prefix.role
        prefix_tenant = defaults.prefix.tenant
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
                                assigned_object_interface=interface,
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
    except ValueError:
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
        tenant = defaults.vlan.tenant
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

    defaults = data.get("defaults", Defaults())
    options = data.get("options", Options())

    device_info = data.get("device", {})
    interfaces = data.get("interface", {})
    interfaces_ip = data.get("interface_ip", {})
    if device_info:
        if options.platform_omit_version:
            device_info["platform"] = data.get("driver")
        else:

            device_info["platform"] = (
                f"{data.get('driver', '').upper()} {device_info.get('os_version')}"
            )
        device = translate_device(device_info, defaults)
        entities.append(Entity(device=device))

        for if_name, interface_info in interfaces.items():
            interface = translate_interface(device, if_name, interface_info, defaults)
            entities.append(Entity(interface=interface))
            entities.extend(translate_interface_ips(interface, interfaces_ip, defaults))

    if data.get("vlan"):
        for vid, vlan_info in data.get("vlan").items():
            vlan = translate_vlan(vid, vlan_info.get("name"), defaults)
            if vlan:
                entities.append(Entity(vlan=vlan))

    return entities
