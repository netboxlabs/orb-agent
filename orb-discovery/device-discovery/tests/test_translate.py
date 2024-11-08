#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""NetBox Labs - Translate Unit Tests."""

import pytest

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


def test_translate_device(sample_device_info):
    """Ensure device translation is correct."""
    device = translate_device(sample_device_info)
    assert device.name == "router1"
    assert device.device_type.model == "ISR4451"
    assert device.platform.name == "ios"
    assert device.serial == "123456789"
    assert device.site.name == "New York"


def test_translate_interface(sample_device_info, sample_interface_info):
    """Ensure interface translation is correct."""
    device = translate_device(sample_device_info)
    interface = translate_interface(
        device, "GigabitEthernet0/0", sample_interface_info["GigabitEthernet0/0"]
    )
    assert interface.device.name == "router1"
    assert interface.name == "GigabitEthernet0/0"
    assert interface.enabled is True
    assert interface.mtu == 1500
    assert interface.mac_address == "00:1C:58:29:4A:71"
    assert interface.speed == 1000000
    assert interface.description == "Uplink Interface"


def test_translate_interface_with_overflow_data(
    sample_device_info, sample_interface_overflows_info
):
    """Ensure interface translation is correct."""
    device = translate_device(sample_device_info)
    interface = translate_interface(
        device,
        "GigabitEthernet0/0",
        sample_interface_overflows_info["GigabitEthernet0/0"],
    )
    assert interface.device.name == "router1"
    assert interface.name == "GigabitEthernet0/0"
    assert interface.enabled is True
    assert interface.mtu == 0
    assert interface.mac_address == "00:1C:58:29:4A:71"
    assert interface.speed == 0
    assert interface.description == "Uplink Interface"


def test_translate_interface_ips(
    sample_device_info, sample_interface_info, sample_interfaces_ip
):
    """Ensure interface IPs translation is correct."""
    device = translate_device(sample_device_info)
    interface = translate_interface(
        device, "GigabitEthernet0/0", sample_interface_info["GigabitEthernet0/0"]
    )
    ip_entities = list(translate_interface_ips(interface, sample_interfaces_ip))
    assert len(ip_entities) == 2
    assert ip_entities[0].prefix.prefix == "192.0.2.0/24"
    assert ip_entities[1].ip_address.address == "192.0.2.1/24"


def test_translate_data(
    sample_device_info, sample_interface_info, sample_interfaces_ip
):
    """Ensure data translation is correct."""
    data = {
        "device": sample_device_info,
        "interface": sample_interface_info,
        "interface_ip": sample_interfaces_ip,
        "driver": "ios",
        "site": "New York",
    }
    entities = list(translate_data(data))
    assert len(entities) == 4
    assert entities[0].device.name == "router1"
    assert entities[1].interface.name == "GigabitEthernet0/0"
    assert entities[2].prefix.prefix == "192.0.2.0/24"
    assert entities[3].ip_address.address == "192.0.2.1/24"
