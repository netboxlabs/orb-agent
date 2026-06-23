#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Integration tests for discovered-VRF wiring through translate_data."""

import pytest

from device_discovery.policy.models import Defaults, IpamParameters, Options
from device_discovery.translate import translate_data


def _data(
    network_instances=None,
    defaults=None,
    interfaces=None,
    interfaces_ip=None,
    options=None,
):
    """Build a translate_data payload for a single-device discovery cycle."""
    return {
        "driver": "eos",
        "device": {
            "hostname": "router1",
            "model": "DCS-7050",
            "vendor": "Arista",
            "serial_number": "SN1",
            "os_version": "4.30",
        },
        "interface": interfaces
        or {
            "Ethernet1": {"is_enabled": True, "speed": 1000},
            "Management1": {"is_enabled": True, "speed": 1000},
        },
        "interface_ip": interfaces_ip
        or {
            "Ethernet1": {"ipv4": {"10.0.0.1": {"prefix_length": 24}}},
            "Management1": {"ipv4": {"192.168.0.1": {"prefix_length": 24}}},
        },
        "defaults": defaults or Defaults(),
        "options": options or Options(discover_vrfs=True),
        "network_instances": network_instances,
    }


_INSTANCES = {
    "default": {
        "name": "default",
        "type": "DEFAULT_INSTANCE",
        "state": {"route_distinguisher": ""},
        "interfaces": {"interface": {"Ethernet1": {}}},
    },
    "MGMT": {
        "name": "MGMT",
        "type": "L3VRF",
        "state": {"route_distinguisher": "123:456"},
        "interfaces": {"interface": {"Management1": {}}},
    },
}


def _by_kind(entities):
    """Index translated entities by oneof kind for assertions."""
    out = {"vrf": [], "ip_address": [], "prefix": []}
    for e in entities:
        for kind in out:
            if e.HasField(kind):
                out[kind].append(getattr(e, kind))
    return out


def test_discovered_vrf_emitted_and_attached():
    """A discovered VRF is emitted and attached to its interface's IP and prefix."""
    entities = list(translate_data(_data(network_instances=_INSTANCES)))
    kinds = _by_kind(entities)

    assert [v.name for v in kinds["vrf"]] == ["MGMT"]
    assert kinds["vrf"][0].rd == "123:456"

    mgmt_ips = [ip for ip in kinds["ip_address"] if ip.address == "192.168.0.1/24"]
    assert mgmt_ips and mgmt_ips[0].vrf.name == "MGMT"
    assert mgmt_ips[0].vrf.rd == "123:456"
    mgmt_prefixes = [p for p in kinds["prefix"] if p.prefix == "192.168.0.0/24"]
    assert mgmt_prefixes and mgmt_prefixes[0].vrf.name == "MGMT"


def test_default_instance_interface_gets_no_vrf():
    """Interfaces in the default routing table carry no VRF."""
    entities = list(translate_data(_data(network_instances=_INSTANCES)))
    kinds = _by_kind(entities)
    eth_ips = [ip for ip in kinds["ip_address"] if ip.address == "10.0.0.1/24"]
    assert eth_ips and not eth_ips[0].HasField("vrf")


def test_discovered_vrf_wins_over_defaults():
    """Discovered VRF takes precedence over defaults vrf, vrf_ipv4 and vrf_ipv6."""
    defaults = Defaults(
        ipaddress=IpamParameters(
            vrf="PolicyVRF", vrf_ipv4="PolicyVRF4", vrf_ipv6="PolicyVRF6"
        ),
        prefix=IpamParameters(vrf="PolicyVRF"),
    )
    interfaces_ip = {
        "Ethernet1": {"ipv4": {"10.0.0.1": {"prefix_length": 24}}},
        "Management1": {
            "ipv4": {"192.168.0.1": {"prefix_length": 24}},
            "ipv6": {"2001:db8::1": {"prefix_length": 64}},
        },
    }
    entities = list(
        translate_data(
            _data(
                network_instances=_INSTANCES,
                defaults=defaults,
                interfaces_ip=interfaces_ip,
            )
        )
    )
    kinds = _by_kind(entities)

    mgmt_ips = [ip for ip in kinds["ip_address"] if ip.address == "192.168.0.1/24"]
    assert mgmt_ips[0].vrf.name == "MGMT"
    mgmt_prefixes = [p for p in kinds["prefix"] if p.prefix == "192.168.0.0/24"]
    assert mgmt_prefixes[0].vrf.name == "MGMT"

    # The per-AF IPv6 override also loses to the discovered VRF.
    mgmt_v6_ips = [ip for ip in kinds["ip_address"] if ip.address == "2001:db8::1/64"]
    assert mgmt_v6_ips[0].vrf.name == "MGMT"

    # The unmapped (default-instance) interface keeps the configured defaults.
    eth_ips = [ip for ip in kinds["ip_address"] if ip.address == "10.0.0.1/24"]
    assert eth_ips[0].vrf.name == "PolicyVRF4"
    eth_prefixes = [p for p in kinds["prefix"] if p.prefix == "10.0.0.0/24"]
    assert eth_prefixes[0].vrf.name == "PolicyVRF"


def test_discovered_vrf_applies_to_ip_only_interface():
    """An interface present only in interface_ip data still gets the discovered VRF."""
    entities = list(
        translate_data(
            _data(
                network_instances=_INSTANCES,
                interfaces={"Ethernet1": {"is_enabled": True, "speed": 1000}},
                interfaces_ip={
                    "Management1": {"ipv4": {"192.168.0.1": {"prefix_length": 24}}},
                },
            )
        )
    )
    kinds = _by_kind(entities)
    mgmt_ips = [ip for ip in kinds["ip_address"] if ip.address == "192.168.0.1/24"]
    assert mgmt_ips and mgmt_ips[0].vrf.name == "MGMT"


def test_interface_less_vrf_still_emitted():
    """A VRF with no interfaces is still emitted as a standalone entity."""
    instances = {"LONELY": {"name": "LONELY", "type": "L3VRF"}}
    entities = list(translate_data(_data(network_instances=instances)))
    kinds = _by_kind(entities)
    assert [v.name for v in kinds["vrf"]] == ["LONELY"]


def test_no_network_instances_emits_no_vrfs():
    """Without network_instances data, no VRF entities are emitted."""
    entities = list(translate_data(_data(network_instances=None)))
    kinds = _by_kind(entities)
    assert kinds["vrf"] == []


def test_option_off_ignores_network_instances_payload():
    """With discover_vrfs off, a pre-populated payload emits no VRFs."""
    entities = list(
        translate_data(_data(network_instances=_INSTANCES, options=Options()))
    )
    kinds = _by_kind(entities)
    assert kinds["vrf"] == []
    assert all(not ip.HasField("vrf") for ip in kinds["ip_address"])
    assert all(not p.HasField("vrf") for p in kinds["prefix"])


@pytest.fixture
def stack_data():
    """Two-member stack payload with one VRF'd interface on member 2."""
    instances = {
        "MGMT": {
            "name": "MGMT",
            "type": "L3VRF",
            "state": {"route_distinguisher": ""},
            "interfaces": {"interface": {"GigabitEthernet2/0/1": {}}},
        },
    }
    data = _data(
        network_instances=instances,
        interfaces={
            "GigabitEthernet1/0/1": {"is_enabled": True, "speed": 1000},
            "GigabitEthernet2/0/1": {"is_enabled": True, "speed": 1000},
        },
        interfaces_ip={
            "GigabitEthernet2/0/1": {"ipv4": {"10.2.0.1": {"prefix_length": 24}}},
        },
    )
    data["chassis_members"] = {
        "members": [
            {"id": 1, "serial": "SN1"},
            {"id": 2, "serial": "SN2"},
        ],
        "domain": None,
    }
    return data


def test_stack_path_applies_discovered_vrf(stack_data):
    """The virtual-chassis path threads the discovered VRF onto member IPs."""
    entities = list(translate_data(stack_data))
    kinds = _by_kind(entities)

    assert [v.name for v in kinds["vrf"]] == ["MGMT"]
    assert not kinds["vrf"][0].HasField("rd")
    member_ips = [ip for ip in kinds["ip_address"] if ip.address == "10.2.0.1/24"]
    assert member_ips and member_ips[0].vrf.name == "MGMT"
