#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""NetBox Labs - Translate Unit Tests."""

import pytest
from netboxlabs.diode.sdk.ingester import Tag

from device_discovery.policy.models import Defaults, ObjectParameters
from device_discovery.translate import (
    translate_data,
    translate_device,
    translate_interface,
    translate_interface_ips,
)


@pytest.fixture
def sample_device_info():
    """Sample device information for testing."""
    return {
        "hostname": "router1",
        "model": "ISR4451",
        "vendor": "Cisco",
        "serial_number": "123456789",
        "site": "New York",
        "driver": "ios",
        "interface_list": ["GigabitEthernet0/0"],
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
        }
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
    return {"GigabitEthernet0/0": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}}


@pytest.fixture
def sample_defaults():
    """Sample defaults for testing."""
    return Defaults(
        site="New York",
        tags=["tag1", "tag2"],
        device=ObjectParameters(comments="testing", tags=["devtag"]),
        interface=ObjectParameters(description="testing", tags=["inttag"]),
        ipaddress=ObjectParameters(description="ip test", tags=["iptag"]),
        prefix=ObjectParameters(description="prefix test",tags=["prefixtag"]),
        role="router",
    )


def test_translate_device(sample_device_info, sample_defaults):
    """Ensure device translation is correct."""
    device = translate_device(sample_device_info, sample_defaults)
    assert device.name == "router1"
    assert device.device_type.model == "ISR4451"
    assert device.platform.name == "ios"
    assert device.serial == "123456789"
    assert device.site.name == "New York"
    assert device.comments == "testing"
    assert device.tags == [Tag(name="tag1"), Tag(name="tag2"), Tag(name="devtag")]


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
    assert interface.mac_address == "00:1C:58:29:4A:71"
    assert interface.speed == 1000000
    assert interface.description == "Uplink Interface"
    assert interface.tags == [Tag(name="tag1"), Tag(name="tag2"), Tag(name="inttag")]


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
    assert interface.mac_address == "00:1C:58:29:4A:71"
    assert interface.speed == 0
    assert interface.description == "Uplink Interface"
    assert interface.tags == [Tag(name="tag1"), Tag(name="tag2"), Tag(name="inttag")]


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
    assert len(ip_entities) == 2
    assert ip_entities[0].prefix.prefix == "192.0.2.0/24"
    assert ip_entities[1].ip_address.address == "192.0.2.1/24"
    assert ip_entities[0].prefix.description == "prefix test"
    assert ip_entities[1].ip_address.description == "ip test"
    assert ip_entities[0].prefix.tags == [Tag(name="tag1"), Tag(name="tag2"), Tag(name="prefixtag")]
    assert ip_entities[1].ip_address.tags == [Tag(name="tag1"), Tag(name="tag2"), Tag(name="iptag")]


def test_translate_data(
    sample_device_info, sample_interface_info, sample_interfaces_ip
):
    """Ensure data translation is correct."""
    data = {
        "device": sample_device_info,
        "interface": sample_interface_info,
        "interface_ip": sample_interfaces_ip,
        "driver": "ios",
    }
    entities = list(translate_data(data))
    assert len(entities) == 4
    assert entities[0].device.name == "router1"
    assert entities[1].interface.name == "GigabitEthernet0/0"
    assert entities[2].prefix.prefix == "192.0.2.0/24"
    assert entities[3].ip_address.address == "192.0.2.1/24"
