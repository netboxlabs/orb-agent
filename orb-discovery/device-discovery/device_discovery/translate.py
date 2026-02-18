#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""Translate from NAPALM output format to Diode SDK entities."""

import copy
from collections.abc import Iterable

from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb
from netboxlabs.diode.sdk.ingester import (
    VLAN,
    Device,
    DeviceConfig,
    DeviceType,
    Entity,
    Location,
    Platform,
    Tenant,
    TenantGroup,
)

from device_discovery.interface import build_interface_entities
from device_discovery.policy.models import Defaults, Options, TenantParameters


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


def translate_device(
    device_info: dict,
    defaults: Defaults,
    config_info: dict | None = None,
    options: Options | None = None,
) -> Device:
    """
    Translate device information from NAPALM format to Diode SDK Device entity.

    Args:
    ----
        device_info (dict): Dictionary containing device information.
        defaults (Defaults): Default configuration.
        config_info (dict | None): Dictionary containing configuration data from NAPALM.
        options (Options | None): Discovery options.

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

    device_config = None
    if config_info and options:
        device_config = translate_device_config(config_info, options)

    # Build Device parameters
    device_params = {
        "name": device_info.get("hostname"),
        "device_type": DeviceType(model=model, manufacturer=manufacturer),
        "platform": Platform(name=platform, manufacturer=manufacturer),
        "role": defaults.role,
        "serial": serial_number,
        "status": "active",
        "site": defaults.site,
        "tags": tags,
        "location": location,
        "tenant": translate_tenant(defaults.tenant),
        "description": description,
        "comments": comments,
    }

    if device_config is not None:
        device_params["config"] = device_config
    device = Device(**device_params)
    return device


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


def translate_device_config(config_info: dict, options: Options) -> DeviceConfig | None:
    """
    Translate device configuration from NAPALM format to Diode SDK DeviceConfig entity.

    Args:
    ----
        config_info (dict): Dictionary containing configuration data from NAPALM.
        options (Options): Discovery options with config capture flags.

    Returns:
    -------
        DeviceConfig | None: Translated DeviceConfig entity or None if no config data.

    """
    if not config_info:
        return None

    # Check if any config capture is enabled
    if not (options.capture_running_config or options.capture_startup_config):
        return None

    # Extract only the requested config components
    startup = None
    running = None

    if options.capture_startup_config:
        startup = config_info.get("startup")
        # Convert strings to bytes if needed (DeviceConfig expects bytes)
        # Check isinstance first to handle empty strings correctly
        if isinstance(startup, str):
            startup = startup.encode("utf-8")

    if options.capture_running_config:
        running = config_info.get("running")
        # Convert strings to bytes if needed (DeviceConfig expects bytes)
        # Check isinstance first to handle empty strings correctly
        if isinstance(running, str):
            running = running.encode("utf-8")

    # Skip if no actual config data present
    if startup is None and running is None:
        return None

    # Metadata is not captured for device configs - device association is via
    # the Device entity's device_config field when SDK support is enabled
    return DeviceConfig(
        startup=startup,
        running=running,
        candidate=None,
        metadata=None,
    )


def translate_data(data: dict) -> Iterable[Entity]:
    """
    Translate data from NAPALM format to Diode SDK entities.

    Args:
    ----
        data (dict): Dictionary containing device, interface and VLAN data from NAPALM.

    Returns:
    -------
        Iterable[Entity]: Iterable of translated Diode SDK entities.

    """
    entities = []

    defaults = data.get("defaults") or Defaults()
    options = data.get("options") or Options()
    device_info = data.get("device", {})
    config_info = data.get("config") or {}
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
                device_info["platform"] = device_info.get("os_version")[:100]
        device = translate_device(device_info, defaults, config_info, options)
        entities.append(Entity(device=device))
        device_for_interfaces = copy.deepcopy(device)
        device_for_interfaces.ClearField("config")
        interface_related_entities = build_interface_entities(
            device_for_interfaces, interfaces, interfaces_ip, defaults
        )
        entities.extend(interface_related_entities)

    if data.get("vlan"):
        for vid, vlan_info in data.get("vlan").items():
            vlan = translate_vlan(vid, vlan_info.get("name"), defaults)
            if vlan:
                entities.append(Entity(vlan=vlan))

    return entities
