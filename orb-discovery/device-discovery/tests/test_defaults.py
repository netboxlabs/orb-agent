#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Tests for built-in default patterns and speed-based detection."""

from device_discovery.defaults import DEFAULT_INTERFACE_PATTERNS
from device_discovery.interface import (
    detect_type_by_speed,
    match_interface_type,
    merge_interface_patterns,
)
from device_discovery.policy.models import InterfacePattern


def test_builtin_cisco_patterns():
    """Test built-in Cisco interface patterns."""
    assert match_interface_type("GigabitEthernet0/0", DEFAULT_INTERFACE_PATTERNS) == "1000base-t"
    assert match_interface_type("Gi0/0", DEFAULT_INTERFACE_PATTERNS) == "1000base-t"
    assert match_interface_type("TenGigabitEthernet1/0/1", DEFAULT_INTERFACE_PATTERNS) == "10gbase-x-sfpp"
    assert match_interface_type("Te1/0/1", DEFAULT_INTERFACE_PATTERNS) == "10gbase-x-sfpp"
    assert match_interface_type("FastEthernet0/1", DEFAULT_INTERFACE_PATTERNS) == "100base-tx"
    assert match_interface_type("Fa0/1", DEFAULT_INTERFACE_PATTERNS) == "100base-tx"
    assert match_interface_type("FortyGigE1/0/1", DEFAULT_INTERFACE_PATTERNS) == "40gbase-x-qsfpp"
    assert match_interface_type("HundredGigE1/0/1", DEFAULT_INTERFACE_PATTERNS) == "100gbase-x-qsfp28"


def test_builtin_juniper_patterns():
    """Test built-in Juniper interface patterns."""
    assert match_interface_type("ge-0/0/0", DEFAULT_INTERFACE_PATTERNS) == "1000base-t"
    assert match_interface_type("xe-0/0/0", DEFAULT_INTERFACE_PATTERNS) == "10gbase-x-sfpp"
    assert match_interface_type("et-0/0/0", DEFAULT_INTERFACE_PATTERNS) == "40gbase-x-qsfpp"
    assert match_interface_type("ae0", DEFAULT_INTERFACE_PATTERNS) == "lag"
    assert match_interface_type("ae123", DEFAULT_INTERFACE_PATTERNS) == "lag"
    assert match_interface_type("lo0", DEFAULT_INTERFACE_PATTERNS) == "virtual"
    assert match_interface_type("lo", DEFAULT_INTERFACE_PATTERNS) == "virtual"
    assert match_interface_type("irb", DEFAULT_INTERFACE_PATTERNS) == "virtual"
    assert match_interface_type("fxp0", DEFAULT_INTERFACE_PATTERNS) == "1000base-t"


def test_builtin_lag_patterns():
    """Test built-in LAG/Port-channel patterns."""
    assert match_interface_type("Port-channel1", DEFAULT_INTERFACE_PATTERNS) == "lag"
    assert match_interface_type("port-channel10", DEFAULT_INTERFACE_PATTERNS) == "lag"
    assert match_interface_type("Po1", DEFAULT_INTERFACE_PATTERNS) == "lag"
    assert match_interface_type("Bundle-Ether100", DEFAULT_INTERFACE_PATTERNS) == "lag"


def test_builtin_virtual_patterns():
    """Test built-in virtual interface patterns."""
    assert match_interface_type("Loopback0", DEFAULT_INTERFACE_PATTERNS) == "virtual"
    assert match_interface_type("Loopback100", DEFAULT_INTERFACE_PATTERNS) == "virtual"
    assert match_interface_type("Vlan1", DEFAULT_INTERFACE_PATTERNS) == "virtual"
    assert match_interface_type("Vlan100", DEFAULT_INTERFACE_PATTERNS) == "virtual"
    assert match_interface_type("vlan.100", DEFAULT_INTERFACE_PATTERNS) == "virtual"
    assert match_interface_type("Tunnel0", DEFAULT_INTERFACE_PATTERNS) == "virtual"


def test_builtin_nokia_patterns():
    """Test built-in Nokia interface patterns."""
    assert match_interface_type("ethernet-1/1", DEFAULT_INTERFACE_PATTERNS) == "1000base-t"
    assert match_interface_type("ethernet-1/2", DEFAULT_INTERFACE_PATTERNS) == "1000base-t"


def test_builtin_management_patterns():
    """Test built-in management interface patterns."""
    assert match_interface_type("Management1", DEFAULT_INTERFACE_PATTERNS) == "1000base-t"
    assert match_interface_type("mgmt0", DEFAULT_INTERFACE_PATTERNS) == "1000base-t"


def test_builtin_linux_patterns():
    """Test built-in Linux interface patterns."""
    assert match_interface_type("eth0", DEFAULT_INTERFACE_PATTERNS) == "1000base-t"
    assert match_interface_type("ens192", DEFAULT_INTERFACE_PATTERNS) == "1000base-t"
    assert match_interface_type("enp0s3", DEFAULT_INTERFACE_PATTERNS) == "1000base-t"
    assert match_interface_type("swp1", DEFAULT_INTERFACE_PATTERNS) == "1000base-t"


def test_speed_based_detection():
    """Test speed-based interface type detection."""
    assert detect_type_by_speed(100) == "100base-tx"
    assert detect_type_by_speed(1000) == "1000base-t"
    assert detect_type_by_speed(2500) == "2.5gbase-t"
    assert detect_type_by_speed(5000) == "5gbase-t"
    assert detect_type_by_speed(10000) == "10gbase-x-sfpp"
    assert detect_type_by_speed(25000) == "25gbase-x-sfp28"
    assert detect_type_by_speed(40000) == "40gbase-x-qsfpp"
    assert detect_type_by_speed(50000) == "50gbase-x-sfp56"
    assert detect_type_by_speed(100000) == "100gbase-x-qsfp28"
    assert detect_type_by_speed(200000) == "200gbase-x-qsfp56"
    assert detect_type_by_speed(400000) == "400gbase-x-qsfp112"
    assert detect_type_by_speed(800000) == "800gbase-x-qsfp-dd"


def test_speed_based_detection_boundaries():
    """Test speed-based detection at boundary values."""
    # Test boundary conditions
    assert detect_type_by_speed(99) == "100base-tx"
    assert detect_type_by_speed(101) == "1000base-t"
    assert detect_type_by_speed(999) == "1000base-t"
    assert detect_type_by_speed(1001) == "2.5gbase-t"
    assert detect_type_by_speed(9999) == "10gbase-x-sfpp"
    assert detect_type_by_speed(10001) == "25gbase-x-sfp28"


def test_pattern_merging_with_user_patterns():
    """Test user patterns override built-in patterns."""
    user_patterns = [
        InterfacePattern(match=r"^Gi.*", type="10gbase-t"),  # Override
    ]

    merged = merge_interface_patterns(user_patterns, include_defaults=True)

    # User pattern should come first
    assert merged[0].match == r"^Gi.*"
    assert merged[0].type == "10gbase-t"

    # Built-in patterns should follow
    assert len(merged) > 1
    # Verify a built-in pattern is present
    builtin_matches = [p for p in merged if p.match == r"^et-\d+/\d+/\d+"]
    assert len(builtin_matches) == 1


def test_pattern_merging_without_user_patterns():
    """Test merging with no user patterns returns only built-in."""
    merged = merge_interface_patterns(None, include_defaults=True)

    # Should return built-in patterns
    assert len(merged) == len(DEFAULT_INTERFACE_PATTERNS)
    assert merged[0].match == DEFAULT_INTERFACE_PATTERNS[0].match


def test_pattern_merging_exclude_defaults():
    """Test excluding built-in patterns."""
    user_patterns = [
        InterfacePattern(match=r"^Gi.*", type="10gbase-t"),
    ]

    merged = merge_interface_patterns(user_patterns, include_defaults=False)

    # Should only have user patterns
    assert len(merged) == 1
    assert merged[0].match == r"^Gi.*"


def test_pattern_merging_empty_user_exclude_defaults():
    """Test excluding defaults with no user patterns returns empty list."""
    merged = merge_interface_patterns(None, include_defaults=False)
    assert merged == []


def test_most_specific_match_wins_with_builtins():
    """Test that most specific pattern wins with built-in patterns."""
    # TenGigabitEthernet is more specific than GigabitEthernet
    # Both patterns exist in defaults, but TenGig should match first
    result = match_interface_type("TenGigabitEthernet1/0/1", DEFAULT_INTERFACE_PATTERNS)
    assert result == "10gbase-x-sfpp"

    # GigabitEthernet should match the Gig pattern
    result = match_interface_type("GigabitEthernet0/0", DEFAULT_INTERFACE_PATTERNS)
    assert result == "1000base-t"
