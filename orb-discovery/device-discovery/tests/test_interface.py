#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""NetBox Labs - Interface Unit Tests."""

import pytest

from device_discovery.interface import (
    match_interface_type,
    translate_interface,
)
from device_discovery.policy.models import (
    Defaults,
    DeviceParameters,
    InterfacePattern,
    IpamParameters,
    ObjectParameters,
    VlanParameters,
)
from device_discovery.translate import translate_device


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


# Unit Tests for Pattern Matching Function


def test_match_interface_type_no_patterns():
    """Test pattern matching with no patterns configured."""
    result = match_interface_type("GigabitEthernet0/0", None)
    assert result is None

    result = match_interface_type("GigabitEthernet0/0", [])
    assert result is None


def test_match_interface_type_single_match():
    """Test pattern matching with single pattern."""
    patterns = [InterfacePattern(match="Gi.*", type="1000base-t")]
    result = match_interface_type("GigabitEthernet0/0", patterns)
    assert result == "1000base-t"

    result = match_interface_type("Gi0/0/0", patterns)
    assert result == "1000base-t"


def test_match_interface_type_no_match():
    """Test pattern matching when no pattern matches."""
    patterns = [InterfacePattern(match="Te.*", type="10gbase-x-sfpp")]
    result = match_interface_type("GigabitEthernet0/0", patterns)
    assert result is None


def test_match_interface_type_most_specific_wins():
    """Test that most specific (longest) match wins."""
    patterns = [
        InterfacePattern(match="^Gi", type="short-match"),
        InterfacePattern(match="^GigabitEthernet", type="long-match"),
        InterfacePattern(match="^Ten", type="10gbase-x-sfpp"),
    ]
    # "GigabitEthernet" matches longer (15 chars) than "Gi" (2 chars)
    result = match_interface_type("GigabitEthernet0/0", patterns)
    assert result == "long-match"

    # Only "Ten" matches at the start
    result = match_interface_type("TenGigabitEthernet1/0/1", patterns)
    assert result == "10gbase-x-sfpp"


def test_match_interface_type_first_pattern_wins_on_tie():
    """Test that first pattern wins when match lengths are equal."""
    patterns = [
        InterfacePattern(match="Ethernet.*", type="first-type"),
        InterfacePattern(match="Eth.*", type="second-type"),
    ]
    # Both could match "Ethernet0/0" but with different lengths
    # "Ethernet.*" is more specific
    result = match_interface_type("Ethernet0/0", patterns)
    assert result == "first-type"


def test_match_interface_type_multiple_patterns():
    """Test pattern matching with multiple different patterns."""
    patterns = [
        InterfacePattern(match="Gi.*", type="1000base-t"),
        InterfacePattern(match="Te.*", type="10gbase-x-sfpp"),
        InterfacePattern(match="Fa.*", type="100base-tx"),
        InterfacePattern(match="ethernet-.*", type="1000base-t"),
    ]
    assert match_interface_type("GigabitEthernet0/0", patterns) == "1000base-t"
    assert match_interface_type("TenGigabitEthernet1/0/1", patterns) == "10gbase-x-sfpp"
    assert match_interface_type("FastEthernet0/0", patterns) == "100base-tx"
    assert match_interface_type("ethernet-1/1", patterns) == "1000base-t"
    assert match_interface_type("Loopback0", patterns) is None


def test_match_interface_type_case_sensitive():
    """Test that pattern matching is case-sensitive by default."""
    patterns = [InterfacePattern(match="gi.*", type="1000base-t")]
    result = match_interface_type("GigabitEthernet0/0", patterns)
    assert result is None

    result = match_interface_type("gigabit0/0", patterns)
    assert result == "1000base-t"


def test_match_interface_type_anchored_patterns():
    """Test patterns with anchors (^ and $)."""
    patterns = [
        InterfacePattern(match="^Gi0/0/0$", type="specific-interface"),
        InterfacePattern(match="Gi.*", type="generic-type"),
    ]
    # Exact match should win (it's more specific - matches entire string)
    result = match_interface_type("Gi0/0/0", patterns)
    assert result == "specific-interface"

    # Other interfaces match generic pattern
    result = match_interface_type("Gi0/0/1", patterns)
    assert result == "generic-type"


# Integration Tests for Interface Translation with Patterns


def test_translate_interface_with_pattern_matching(
    sample_device_info, sample_interface_info, sample_defaults
):
    """Test interface translation with pattern-based type assignment."""
    # Configure patterns
    sample_defaults.interface_patterns = [
        InterfacePattern(match="GigabitEthernet.*", type="1000base-t"),
        InterfacePattern(match="Te.*", type="10gbase-x-sfpp"),
    ]

    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device,
        "GigabitEthernet0/0",
        sample_interface_info["GigabitEthernet0/0"],
        sample_defaults,
    )

    assert interface.type == "1000base-t"
    assert interface.name == "GigabitEthernet0/0"


def test_translate_interface_pattern_no_match_uses_default(
    sample_device_info, sample_interface_info, sample_defaults
):
    """Test that default if_type is used when no user/built-in pattern matches and no speed."""
    # User pattern that won't match
    sample_defaults.interface_patterns = [
        InterfacePattern(match="Te.*", type="10gbase-x-sfpp"),
    ]
    sample_defaults.if_type = "other"

    device = translate_device(sample_device_info, sample_defaults)

    # Use an interface name that won't match user or built-in patterns and has no speed
    interface = translate_interface(
        device,
        "UnknownInterface0",
        {"is_enabled": True, "speed": 0},
        sample_defaults,
    )

    # No pattern matches and no speed, should use default
    assert interface.type == "other"


def test_translate_interface_subinterface_ignores_patterns(
    sample_device_info, sample_interface_info, sample_defaults
):
    """Test that subinterfaces always get 'virtual' type regardless of patterns."""
    sample_defaults.interface_patterns = [
        InterfacePattern(match=".*", type="should-not-match"),
    ]

    device = translate_device(sample_device_info, sample_defaults)

    # Create parent interface
    parent = translate_interface(
        device,
        "GigabitEthernet0/0",
        sample_interface_info["GigabitEthernet0/0"],
        sample_defaults,
    )

    # Create subinterface with parent
    subinterface = translate_interface(
        device,
        "GigabitEthernet0/0.100",
        {},
        sample_defaults,
        parent=parent,
    )

    # Subinterface should be "virtual" despite pattern matching everything
    assert subinterface.type == "virtual"
    assert parent.type == "should-not-match"  # Parent uses pattern


def test_translate_interface_most_specific_pattern_wins(
    sample_device_info, sample_interface_info, sample_defaults
):
    """Test that most specific pattern match wins across user and built-in patterns."""
    # Use very specific user pattern that will win over built-ins
    sample_defaults.interface_patterns = [
        InterfacePattern(match=r"^GigabitEthernet0/0/1$", type="specific-subinterface"),
        InterfacePattern(match=r"^TestInterface.*", type="user-test-type"),
    ]

    device = translate_device(sample_device_info, sample_defaults)

    # Should match the very specific user pattern (exact match)
    interface = translate_interface(
        device,
        "GigabitEthernet0/0/1",
        sample_interface_info["GigabitEthernet0/0/1"],
        sample_defaults,
    )
    assert interface.type == "specific-subinterface"

    # Should match built-in pattern since no user pattern matches
    interface2 = translate_interface(
        device,
        "GigabitEthernet1/0",
        sample_interface_info["GigabitEthernet0/0"],
        sample_defaults,
    )
    assert interface2.type == "1000base-t"  # From built-in Cisco pattern

    # Should match user pattern for test interfaces
    interface3 = translate_interface(
        device,
        "TestInterface1",
        {"is_enabled": True},
        sample_defaults,
    )
    assert interface3.type == "user-test-type"


def test_translate_interface_backward_compatible(
    sample_device_info, sample_interface_info, sample_defaults
):
    """Test that built-in patterns work automatically when no user patterns configured."""
    # No user patterns configured (None) - built-in patterns should apply
    sample_defaults.interface_patterns = None
    sample_defaults.if_type = "other"

    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device,
        "GigabitEthernet0/0",
        sample_interface_info["GigabitEthernet0/0"],
        sample_defaults,
    )

    # Should use built-in pattern (zero-configuration experience)
    assert interface.type == "1000base-t"


# Integration Tests for Built-in Patterns and Speed-Based Detection


def test_interface_with_builtin_pattern(sample_device_info, sample_defaults):
    """Test interface type detection using built-in patterns."""
    # No user patterns configured
    sample_defaults.interface_patterns = None
    sample_defaults.if_type = "other"

    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device,
        "GigabitEthernet0/0",
        {"is_enabled": True, "mac_address": "00:11:22:33:44:55", "speed": 1000},
        sample_defaults,
    )

    # Should match built-in Cisco pattern
    assert interface.type == "1000base-t"


def test_interface_with_builtin_juniper_pattern(sample_device_info, sample_defaults):
    """Test interface type detection using built-in Juniper patterns."""
    sample_defaults.interface_patterns = None
    sample_defaults.if_type = "other"

    device = translate_device(sample_device_info, sample_defaults)

    # Test Juniper GE interface
    interface = translate_interface(
        device,
        "ge-0/0/0",
        {"is_enabled": True, "speed": 1000},
        sample_defaults,
    )
    assert interface.type == "1000base-t"

    # Test Juniper XE interface
    interface = translate_interface(
        device,
        "xe-0/0/1",
        {"is_enabled": True, "speed": 10000},
        sample_defaults,
    )
    assert interface.type == "10gbase-x-sfpp"

    # Test Juniper LAG interface
    interface = translate_interface(
        device,
        "ae0",
        {"is_enabled": True},
        sample_defaults,
    )
    assert interface.type == "lag"


def test_interface_with_builtin_virtual_pattern(sample_device_info, sample_defaults):
    """Test interface type detection for virtual interfaces using built-in patterns."""
    sample_defaults.interface_patterns = None
    sample_defaults.if_type = "other"

    device = translate_device(sample_device_info, sample_defaults)

    # Test Loopback
    interface = translate_interface(
        device,
        "Loopback0",
        {"is_enabled": True},
        sample_defaults,
    )
    assert interface.type == "virtual"

    # Test VLAN interface
    interface = translate_interface(
        device,
        "Vlan100",
        {"is_enabled": True},
        sample_defaults,
    )
    assert interface.type == "virtual"


def test_interface_with_speed_detection(sample_device_info, sample_defaults):
    """Test interface type detection using speed fallback."""
    # No user patterns configured
    sample_defaults.interface_patterns = None
    sample_defaults.if_type = "other"

    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device,
        "Ethernet1",  # Generic name, no pattern match
        {"is_enabled": True, "speed": 10000},  # 10G speed
        sample_defaults,
    )

    # Should use speed-based detection
    assert interface.type == "10gbase-x-sfpp"


def test_interface_with_speed_detection_25g(sample_device_info, sample_defaults):
    """Test interface type detection using speed fallback for 25G."""
    sample_defaults.interface_patterns = None
    sample_defaults.if_type = "other"

    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device,
        "Ethernet2",  # Generic name
        {"is_enabled": True, "speed": 25000},  # 25G speed
        sample_defaults,
    )

    # Should use speed-based detection
    assert interface.type == "25gbase-x-sfp28"


def test_interface_with_speed_detection_100g(sample_device_info, sample_defaults):
    """Test interface type detection using speed fallback for 100G."""
    sample_defaults.interface_patterns = None
    sample_defaults.if_type = "other"

    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device,
        "Ethernet3",  # Generic name
        {"is_enabled": True, "speed": 100000},  # 100G speed
        sample_defaults,
    )

    # Should use speed-based detection
    assert interface.type == "100gbase-x-qsfp28"


def test_interface_speed_detection_not_used_when_pattern_matches(
    sample_device_info, sample_defaults
):
    """Test that speed detection is not used when pattern matches."""
    sample_defaults.interface_patterns = None
    sample_defaults.if_type = "other"

    device = translate_device(sample_device_info, sample_defaults)

    # GigabitEthernet has built-in pattern, should use that even with different speed
    interface = translate_interface(
        device,
        "GigabitEthernet0/0",
        {"is_enabled": True, "speed": 10000},  # Speed says 10G
        sample_defaults,
    )

    # Should use built-in pattern (1000base-t), not speed (would be 10gbase-x-sfpp)
    assert interface.type == "1000base-t"


def test_interface_user_pattern_overrides_builtin(sample_device_info, sample_defaults):
    """Test user patterns take priority over built-in patterns."""
    # User overrides GigabitEthernet to be 10G
    sample_defaults.interface_patterns = [
        InterfacePattern(match=r"^Gi.*", type="10gbase-x-sfpp"),
    ]

    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device,
        "GigabitEthernet0/0",
        {"is_enabled": True},
        sample_defaults,
    )

    # Should use user's override, not built-in
    assert interface.type == "10gbase-x-sfpp"


def test_interface_user_pattern_with_builtin_fallback(
    sample_device_info, sample_defaults
):
    """Test user patterns with built-in patterns as fallback."""
    # User only defines pattern for TenGig, built-ins handle the rest
    sample_defaults.interface_patterns = [
        InterfacePattern(match=r"^TenGig.*", type="custom-10g"),
    ]

    device = translate_device(sample_device_info, sample_defaults)

    # User pattern should match
    interface1 = translate_interface(
        device,
        "TenGigabitEthernet1/0/1",
        {"is_enabled": True},
        sample_defaults,
    )
    assert interface1.type == "custom-10g"

    # Built-in pattern should match
    interface2 = translate_interface(
        device,
        "GigabitEthernet0/0",
        {"is_enabled": True},
        sample_defaults,
    )
    assert interface2.type == "1000base-t"  # From built-in patterns


def test_interface_no_speed_no_pattern_uses_default(
    sample_device_info, sample_defaults
):
    """Test that default is used when no pattern matches and no speed."""
    sample_defaults.interface_patterns = None
    sample_defaults.if_type = "other"

    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device,
        "UnknownInterface0",  # No pattern match
        {"is_enabled": True, "speed": 0},  # No valid speed
        sample_defaults,
    )

    # Should fall back to defaults.if_type
    assert interface.type == "other"


# Model Validation Tests


def test_interface_pattern_valid_regex():
    """Test InterfacePattern accepts valid regex patterns."""
    valid_patterns = [
        "Gi.*",
        "Te.*",
        "^GigabitEthernet0/0$",
        "ethernet-[0-9]+/[0-9]+",
        ".*",
    ]

    for pattern_str in valid_patterns:
        pattern = InterfacePattern(match=pattern_str, type="test-type")
        assert pattern.match == pattern_str


def test_interface_pattern_invalid_regex():
    """Test InterfacePattern rejects invalid regex patterns."""
    invalid_patterns = [
        "Gi[.*",  # Unclosed bracket
        "(?P<incomplete",  # Incomplete group
        "(?P<>invalid)",  # Empty group name
    ]

    for pattern_str in invalid_patterns:
        with pytest.raises(ValueError, match="Invalid regex pattern"):
            InterfacePattern(match=pattern_str, type="test-type")


def test_defaults_with_interface_patterns():
    """Test Defaults model with interface_patterns field."""
    defaults = Defaults(
        site="Test Site",
        if_type="other",
        interface_patterns=[
            InterfacePattern(match="Gi.*", type="1000base-t"),
            InterfacePattern(match="Te.*", type="10gbase-x-sfpp"),
        ],
    )

    assert len(defaults.interface_patterns) == 2
    assert defaults.interface_patterns[0].match == "Gi.*"
    assert defaults.interface_patterns[1].type == "10gbase-x-sfpp"


def test_defaults_without_interface_patterns():
    """Test Defaults model works without interface_patterns (backward compatibility)."""
    defaults = Defaults(site="Test Site", if_type="other")
    assert defaults.interface_patterns is None
