#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""NetBox Labs - Translate Unit Tests."""

import pytest

from device_discovery.policy.models import (
    Defaults,
    DeviceParameters,
    IpamParameters,
    ObjectParameters,
    Options,
    VlanParameters,
)
from device_discovery.translate import (
    translate_data,
    translate_device,
    translate_interface,
    translate_interface_ips,
    translate_vlan,
)


@pytest.fixture
def sample_device_info():
    """Sample device information for testing."""
    return {
        "hostname": "router1",
        "model": "ISR4451",
        "vendor": "Cisco",
        "serial_number": "123456789",
        "os_version": "v15.2",
        "platform": "ios",
        "interface_list": ["GigabitEthernet0/0", "GigabitEthernet0/0/1"],
    }


@pytest.fixture
def sample_interface_info():
    """Sample interface information for testing."""
    return {
        "GigabitEthernet0/0": {
            "is_enabled": True,
            "mtu": 1500,
            "mac_address": "00:1C:58:29:4A:71",
            "speed": 1000,
            "description": "Uplink Interface",
        },
        "GigabitEthernet0/0/1": {
            "is_enabled": True,
            "mtu": 1500,
            "mac_address": "00:1C:58:29:4A:72",
            "speed": 10000,
            "description": "Uplink Interface",
        },
    }


@pytest.fixture
def sample_interface_overflows_info():
    """Sample interface information for testing."""
    return {
        "GigabitEthernet0/0": {
            "is_enabled": True,
            "mtu": 150000000000,
            "mac_address": "00:1C:58:29:4A:71",
            "speed": 10000000000,
            "description": "Uplink Interface",
        }
    }


@pytest.fixture
def sample_interfaces_ip():
    """Sample interface IPs for testing."""
    return {"GigabitEthernet0/0/1": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}}


@pytest.fixture
def sample_defaults():
    """Sample defaults for testing."""
    return Defaults(
        site="New York",
        tags=["tag1", "tag2"],
        if_type="other",
        location="local",
        tenant="test",
        device=DeviceParameters(comments="testing", tags=["devtag"]),
        interface=ObjectParameters(description="testing", tags=["inttag"]),
        ipaddress=IpamParameters(description="ip test", tags=["iptag"]),
        prefix=IpamParameters(description="prefix test", tags=["prefixtag"]),
        vlan=VlanParameters(comments="test"),
    )


@pytest.fixture
def sample_override_defaults(sample_defaults):
    """Sample defaults with device overrides."""
    sample_defaults.device.model = "Catalyst"
    return sample_defaults


def test_translate_device(sample_device_info, sample_defaults):
    """Ensure device translation is correct."""
    device = translate_device(sample_device_info, sample_defaults)
    assert device.name == "router1"
    assert device.device_type.model == "ISR4451"
    assert device.platform.name == "ios"
    assert device.serial == "123456789"
    assert device.site.name == "New York"
    assert device.comments == "testing"
    assert device.role.name == "undefined"
    assert device.location.name == "local"
    assert device.location.site.name == "New York"
    assert device.tenant.name == "test"
    assert len(device.tags) == 3


def test_translate_device_with_overrides(sample_device_info, sample_override_defaults):
    """Ensure device translation respects model overrides."""
    device = translate_device(sample_device_info, sample_override_defaults)
    assert device.device_type.model == "Catalyst"
    assert device.device_type.manufacturer.name == "Cisco"


def test_translate_interface(
    sample_device_info, sample_interface_info, sample_defaults
):
    """Ensure interface translation is correct."""
    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device,
        "GigabitEthernet0/0",
        sample_interface_info["GigabitEthernet0/0"],
        sample_defaults,
    )
    assert interface.device.name == "router1"
    assert interface.name == "GigabitEthernet0/0"
    assert interface.enabled is True
    assert interface.mtu == 1500
    assert interface.primary_mac_address.mac_address == "00:1C:58:29:4A:71"
    assert interface.speed == 1000000
    assert interface.description == "Uplink Interface"
    assert len(interface.tags) == 3


def test_translate_interface_with_overflow_data(
    sample_device_info, sample_interface_overflows_info, sample_defaults
):
    """Ensure interface translation is correct."""
    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device,
        "GigabitEthernet0/0",
        sample_interface_overflows_info["GigabitEthernet0/0"],
        sample_defaults,
    )
    assert interface.device.name == "router1"
    assert interface.name == "GigabitEthernet0/0"
    assert interface.enabled is True
    assert interface.mtu == 0
    assert interface.primary_mac_address.mac_address == "00:1C:58:29:4A:71"
    assert interface.speed == 0
    assert interface.description == "Uplink Interface"
    assert len(interface.tags) == 3


def test_translate_interface_ips(
    sample_device_info, sample_interface_info, sample_interfaces_ip, sample_defaults
):
    """Ensure interface IPs translation is correct."""
    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device,
        "GigabitEthernet0/0",
        sample_interface_info["GigabitEthernet0/0"],
        sample_defaults,
    )
    ip_entities = list(
        translate_interface_ips(interface, sample_interfaces_ip, sample_defaults)
    )

    assert len(ip_entities) == 0

    interface = translate_interface(
        device,
        "GigabitEthernet0/0/1",
        sample_interface_info["GigabitEthernet0/0/1"],
        sample_defaults,
    )
    ip_entities = list(
        translate_interface_ips(interface, sample_interfaces_ip, sample_defaults)
    )

    assert len(ip_entities) == 2
    assert ip_entities[0].prefix.prefix == "192.0.2.0/24"
    assert ip_entities[1].ip_address.address == "192.0.2.1/24"
    assert ip_entities[0].prefix.description == "prefix test"
    assert ip_entities[1].ip_address.description == "ip test"
    assert len(ip_entities[0].prefix.tags) == 3
    assert len(ip_entities[1].ip_address.tags) == 3


def test_translate_data(
    sample_device_info, sample_interface_info, sample_interfaces_ip, sample_defaults
):
    """Ensure data translation is correct."""
    data = {
        "device": sample_device_info,
        "interface": sample_interface_info,
        "interface_ip": sample_interfaces_ip,
        "driver": "ios",
    }
    entities = list(translate_data(data))
    assert len(entities) == 5
    assert entities[0].device.name == "router1"
    assert entities[0].device.site.name == "undefined"
    assert entities[0].device.platform.name == "IOS v15.2"
    assert entities[1].interface.name == "GigabitEthernet0/0"
    assert entities[2].interface.name == "GigabitEthernet0/0/1"
    assert entities[3].prefix.prefix == "192.0.2.0/24"
    assert entities[4].ip_address.address == "192.0.2.1/24"

    data["defaults"] = sample_defaults
    data["options"] = Options(platform_omit_version=True)

    entities = list(translate_data(data))
    assert entities[0].device.site.name == "New York"
    assert entities[0].device.platform.name == "ios"

    data["defaults"].role = "switch"
    data["defaults"].device.platform = "custom"
    data["options"].platform_omit_version = False

    entities = list(translate_data(data))
    assert entities[0].device.platform.name == "custom"
    assert entities[0].device.role.name == "switch"


def test_translate_vlan(sample_defaults):
    """Ensure VLAN translation is correct."""
    vid = "1"
    vlan_name = "Test  VLAN   "
    vlan = translate_vlan(vid, vlan_name, sample_defaults)

    assert vlan.vid == 1
    assert vlan.name == "Test VLAN"
    assert len(vlan.tags) == 2
    assert vlan.comments == "test"

    vid = "2"
    vlan_name = "Test - VLAN   "
    vlan = translate_vlan(vid, vlan_name, sample_defaults)
    assert vlan.vid == 2
    assert vlan.name == "Test - VLAN"

    vlan_name = "info-vlan "
    vlan = translate_vlan(vid, vlan_name, sample_defaults)
    assert vlan.vid == 2
    assert vlan.name == "info-vlan"

    vid = "NA"
    vlan = translate_vlan(vid, vlan_name, sample_defaults)
    assert vlan is None


def test_translate_vlan_with_defaults(sample_defaults):
    """Ensure VLAN translation includes default values."""
    sample_defaults.vlan = VlanParameters(
        tags=["vlantag"],
        comments="Default VLAN comment",
        description="Default VLAN description",
        group="Default Group",
        tenant="Default Tenant",
        role="Default Role",
    )
    vid = "200"
    vlan_name = "Default VLAN"
    vlan = translate_vlan(vid, vlan_name, sample_defaults)

    assert vlan.vid == 200
    assert vlan.name == "Default VLAN"
    assert vlan.comments == "Default VLAN comment"
    assert vlan.description == "Default VLAN description"
    assert vlan.group.name == "Default Group"
    assert vlan.tenant.name == "Default Tenant"
    assert vlan.role.name == "Default Role"
    assert len(vlan.tags) == 3
