#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Tests for the SVI interface-name VLAN resolver."""

import pytest

from device_discovery.svi_vlan import svi_vlan_id

# The accept table is the SVI naming this resolver recognizes, drawn from a
# 1877-device corpus. It is not a claim that every entry was observed there:
# any form added without a device behind it belongs in the reject table until
# one turns up. The reject table is the set of look-alikes a trailing-integer
# parser gets wrong. Keep in sync with the Go twin's table in
# orb-discovery/snmp-discovery/mapping/svi_vlan_test.go.
ACCEPT = {
    "Vlan100": 100, "vlan100": 100, "VLAN100": 100, "vlan 600": 600,
    "vlan-249": 249, "vlan_7": 7, "Vlanif24": 24, "Vlan-interface12": 12,
    "VLAN ID 0051": 51, "Vl52": 52, "Interface vlan30": 30,
    "svi9": 9, "vlan1": 1, "vlan4094": 4094,
}

REJECT = [
    "Loopback0", "Tunnel10", "Port-channel20", "Serial0/0/0:1",
    "eth0", "GigabitEthernet1/0/1", "StackPort1", "Po1",
    "GigabitEthernet0/1.100", "port1.0.5", "lo0.100", "ge-0/0/0.0", "irb.100", "vlan.7",
    "vlan0", "vlan4095", "vlan99999",
    "ve55", "Bvi1", "br0", "v190", "vgi1", "rvi7",
    # A bridge-domain id is not a VLAN id: BDI100 can route a service
    # instance whose encapsulation is dot1q 10.
    "BDI100", "Bdi100", "bdi7",
    "vlan307-v0",
    # A leading "interface" needs a separator after it. No device has been seen
    # emitting the run-together form; add it with a capture behind it.
    "InterfaceVlan30", "interfacevlan30",
    "802.1Q VLAN", "L3IPVLAN Interface", "vlan", "vlanMgmt", "bridge",
    "", "   ",
]


@pytest.mark.parametrize(("name", "want"), sorted(ACCEPT.items()))
def test_accepts(name, want):
    """Each SVI-shaped name resolves to its documented VLAN ID."""
    assert svi_vlan_id(name) == want


@pytest.mark.parametrize("name", REJECT)
def test_rejects(name):
    """Each look-alike or out-of-range name resolves to None."""
    assert svi_vlan_id(name) is None
