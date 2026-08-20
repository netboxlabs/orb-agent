#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Built-in default patterns for interface type detection."""

from device_discovery.policy.models import InterfacePattern

# Built-in patterns covering 80-90% of deployments
# Ordered by specificity (most specific first within each vendor)
DEFAULT_INTERFACE_PATTERNS = [
    # Cisco IOS/IOS-XE - High-Speed Interfaces
    InterfacePattern(match=r"^(HundredGig|Hu)\S+", type="100gbase-x-qsfp28"),
    InterfacePattern(match=r"^(FortyGig|Fo)\S+", type="40gbase-x-qsfpp"),
    InterfacePattern(match=r"^(TwentyFiveGig|Twe)\S+", type="25gbase-x-sfp28"),
    InterfacePattern(match=r"^(TenGig|Te)\S+", type="10gbase-x-sfpp"),
    InterfacePattern(match=r"^(FiveGig|Fi)\S+", type="5gbase-t"),
    InterfacePattern(match=r"^(TwoGig|Tw)\S+", type="2.5gbase-t"),
    # Cisco IOS/IOS-XE - Standard Interfaces
    InterfacePattern(match=r"^(GigabitEthernet|Gi)\d+", type="1000base-t"),
    InterfacePattern(match=r"^(FastEthernet|Fa)\d+", type="100base-tx"),
    # Juniper JunOS - Physical Interfaces
    InterfacePattern(match=r"^et-\d+/\d+/\d+", type="40gbase-x-qsfpp"),
    InterfacePattern(match=r"^xe-\d+/\d+/\d+", type="10gbase-x-sfpp"),
    InterfacePattern(match=r"^ge-\d+/\d+/\d+", type="1000base-t"),
    # Nokia SR OS
    InterfacePattern(match=r"^ethernet-\d+/\d+", type="1000base-t"),
    # LAG/Port-Channel (Cross-vendor)
    InterfacePattern(match=r"^(Port-channel|port-channel|Po)\d+", type="lag"),
    InterfacePattern(match=r"^ae\d+", type="lag"),
    InterfacePattern(match=r"^Bundle-Ether\d+", type="lag"),
    # Loopback Interfaces (Virtual)
    InterfacePattern(match=r"^Loopback\d+", type="virtual"),
    InterfacePattern(match=r"^lo\d*$", type="virtual"),
    # VLAN/SVI Interfaces (Virtual)
    # Case-insensitive because the same interface is spelled differently across
    # platforms and releases (BDI100 / Bdi100, Vlanif100 / vlanif100). Every
    # entry below names an interface the device implements in software, so
    # without a pattern here it falls through to speed-based detection and is
    # emitted as an Ethernet type.
    InterfacePattern(match=r"^Vlan\d+", type="virtual"),
    InterfacePattern(match=r"^vlan\.\d+", type="virtual"),
    InterfacePattern(match=r"^irb$", type="virtual"),
    InterfacePattern(match=r"(?i)^vlanif\d+", type="virtual"),
    InterfacePattern(match=r"(?i)^vlan-interface\d+", type="virtual"),
    # Bridge-domain / bridge-group SVIs (Cisco IOS-XE BDI, IOS-XR BVI)
    InterfacePattern(match=r"(?i)^bdi\d+", type="virtual"),
    InterfacePattern(match=r"(?i)^bvi\d+", type="virtual"),
    # VXLAN overlay endpoints
    InterfacePattern(match=r"(?i)^nve\d+", type="virtual"),
    InterfacePattern(match=r"(?i)^vxlan\d+", type="virtual"),
    # Software-instantiated access interfaces (Cisco)
    InterfacePattern(match=r"(?i)^virtual-template\d+", type="virtual"),
    InterfacePattern(match=r"(?i)^virtual-access\d+", type="virtual"),
    InterfacePattern(match=r"(?i)^dialer\d+", type="virtual"),
    InterfacePattern(match=r"(?i)^null\d+", type="virtual"),
    # Tunnel Interfaces (Virtual)
    InterfacePattern(match=r"^Tunnel\d+", type="virtual"),
    InterfacePattern(match=r"(?i)^tunnel-(?:ip|te|mte)\d+", type="virtual"),
    # Management Interfaces
    InterfacePattern(match=r"^(Management|mgmt)\d+", type="1000base-t"),
    InterfacePattern(match=r"^management$", type="1000base-t"),
    InterfacePattern(match=r"^(fxp|em)\d+", type="1000base-t"),
    # Cumulus Linux Switch Ports
    InterfacePattern(match=r"^swp\d+", type="1000base-t"),
    # Generic Linux Ethernet
    InterfacePattern(match=r"^(eth|ens|enp)\d+", type="1000base-t"),
]
