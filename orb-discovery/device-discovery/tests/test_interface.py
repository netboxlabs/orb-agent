#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""NetBox Labs - Interface Unit Tests."""

import datetime

import pytest
from netboxlabs.diode.sdk.ingester import VLAN

from device_discovery.interface import (
    build_interface_entities,
    match_interface_type,
    translate_interface,
)
from device_discovery.policy.models import (
    Defaults,
    DeviceParameters,
    InterfacePattern,
    IpamParameters,
    ObjectParameters,
    Options,
    PrefixParameters,
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
        prefix=PrefixParameters(description="prefix test", tags=["prefixtag"]),
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


# Tests for build_interface_entities exclusion filtering


@pytest.fixture
def sample_diode_device(sample_device_info, sample_defaults):
    """A minimal DiodeDevice for use in interface tests."""
    return translate_device(sample_device_info, sample_defaults, config_info=None, options=None)


def test_build_interface_entities_excludes_matching_interfaces(sample_diode_device):
    """Interfaces matching exclude patterns and their IPs are not ingested."""
    interfaces = {
        "GigabitEthernet0/0": {
            "is_enabled": True, "mtu": 1500, "speed": 1000,
            "mac_address": "00:11:22:33:44:55", "description": "Uplink",
        },
        "tap103i0": {
            "is_enabled": True, "mtu": 1500, "speed": 10,
            "mac_address": "", "description": "",
        },
    }
    interfaces_ip = {
        "tap103i0": {"ipv4": {"10.0.0.1": {"prefix_length": 24}}, "ipv6": {}},
        "GigabitEthernet0/0": {"ipv4": {"192.168.1.1": {"prefix_length": 24}}, "ipv6": {}},
    }
    defaults = Defaults(interface_exclude_patterns=["^tap.*"])
    entities = build_interface_entities(sample_diode_device, interfaces, interfaces_ip, defaults)

    interface_names = [
        e.interface.name
        for e in entities
        if e.HasField("interface")
    ]
    ip_addresses = [
        e.ip_address.address
        for e in entities
        if e.HasField("ip_address")
    ]

    assert "GigabitEthernet0/0" in interface_names
    assert "tap103i0" not in interface_names
    assert not any("10.0.0.1" in addr for addr in ip_addresses)
    assert any("192.168.1.1" in addr for addr in ip_addresses)


def test_build_interface_entities_no_exclude_patterns(sample_diode_device):
    """All interfaces are ingested when no exclude patterns are configured."""
    interfaces = {
        "tap103i0": {"is_enabled": True, "mtu": 1500, "speed": 10, "mac_address": "", "description": ""},
    }
    interfaces_ip = {
        "tap103i0": {"ipv4": {"10.0.0.1": {"prefix_length": 24}}, "ipv6": {}},
    }
    defaults = Defaults()
    entities = build_interface_entities(sample_diode_device, interfaces, interfaces_ip, defaults)

    interface_names = [e.interface.name for e in entities if e.HasField("interface")]
    assert "tap103i0" in interface_names


def test_build_interface_entities_excludes_ip_only_interface(sample_diode_device):
    """Excluded interface absent from interfaces dict is also suppressed via ip-only fallback loop."""
    interfaces = {}
    interfaces_ip = {
        "tap103i0": {"ipv4": {"10.0.0.1": {"prefix_length": 24}}, "ipv6": {}},
    }
    defaults = Defaults(interface_exclude_patterns=["^tap"])
    entities = build_interface_entities(sample_diode_device, interfaces, interfaces_ip, defaults)
    assert not any(e.HasField("interface") for e in entities)
    assert not any(e.HasField("ip_address") for e in entities)


def test_build_interface_entities_invalid_exclude_pattern_skipped(sample_diode_device):
    """Invalid regex patterns are skipped with a warning; valid ones still apply."""
    interfaces = {
        "tap0": {"is_enabled": True, "mtu": 1500, "speed": 10, "mac_address": "", "description": ""},
        "eth0": {"is_enabled": True, "mtu": 1500, "speed": 1000, "mac_address": "", "description": ""},
    }
    defaults = Defaults(interface_exclude_patterns=["[invalid", "^tap"])
    entities = build_interface_entities(sample_diode_device, interfaces, {}, defaults)

    interface_names = [e.interface.name for e in entities if e.HasField("interface")]
    # invalid pattern "[invalid" is skipped; valid "^tap" still excludes tap0
    assert "tap0" not in interface_names
    assert "eth0" in interface_names


def _extract_prefix(entities):
    """Return the first Prefix entity from a list of Entity wrappers."""
    for entity in entities:
        if hasattr(entity, "prefix") and entity.prefix.prefix:
            return entity.prefix
    return None


def test_prefix_emission_no_defaults_scope_empty(sample_diode_device):
    """Baseline: no defaults.prefix → all four scope_* empty (orb-agent#100 guard)."""
    from device_discovery.interface import build_interface_entities
    from device_discovery.policy.models import Defaults, Options

    interfaces = {"Eth1/1": {"is_enabled": True, "speed": 10000, "mtu": 1500, "mac_address": "", "description": ""}}
    interfaces_ip = {"Eth1/1": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}}
    defaults = Defaults(site="DC-East")  # site set but propagate_* is False — NO cascade
    options = Options()  # propagate_defaults_to_prefix_scope defaults to False

    entities = build_interface_entities(
        sample_diode_device, interfaces, interfaces_ip, defaults, options=options,
    )
    prefix = _extract_prefix(entities)
    assert prefix is not None
    # scope_site / scope_location are Site / Location proto messages; empty
    # means their .name is "" (no scope attached).
    assert prefix.scope_site.name == ""
    assert prefix.scope_location.name == ""


def test_prefix_emission_explicit_scope_site(sample_diode_device):
    """Explicit defaults.prefix.scope_site → emitted scope_site, location empty."""
    from device_discovery.interface import build_interface_entities
    from device_discovery.policy.models import Defaults, Options, PrefixParameters

    interfaces = {"Eth1/1": {"is_enabled": True, "speed": 10000, "mtu": 1500, "mac_address": "", "description": ""}}
    interfaces_ip = {"Eth1/1": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}}
    defaults = Defaults(prefix=PrefixParameters(scope_site="DC-East"))
    options = Options()

    entities = build_interface_entities(
        sample_diode_device, interfaces, interfaces_ip, defaults, options=options,
    )
    prefix = _extract_prefix(entities)
    assert prefix is not None
    assert prefix.scope_site.name == "DC-East"
    assert prefix.scope_location.name == ""


def test_prefix_emission_both_scope_fields_explicit(sample_diode_device):
    """Both explicit scope_* set → most-specific wins (location > site)."""
    from device_discovery.interface import build_interface_entities
    from device_discovery.policy.models import Defaults, Options, PrefixParameters

    interfaces = {"Eth1/1": {"is_enabled": True, "speed": 10000, "mtu": 1500, "mac_address": "", "description": ""}}
    interfaces_ip = {"Eth1/1": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}}
    defaults = Defaults(
        prefix=PrefixParameters(
            scope_site="DC-East",
            scope_location="Floor-3",
        ),
    )
    options = Options()

    entities = build_interface_entities(
        sample_diode_device, interfaces, interfaces_ip, defaults, options=options,
    )
    prefix = _extract_prefix(entities)
    # Protobuf scope is a oneof — only the most-specific value is on the wire.
    assert prefix.scope_location.name == "Floor-3"
    # Site is embedded inside the Location for NetBox uniqueness (locations
    # are unique within site, not globally).
    assert prefix.scope_location.site.name == "DC-East"
    assert not prefix.scope_site.name


def test_prefix_emission_cascade_off_blocks_defaults_site(sample_diode_device):
    """Regression guard for orb-agent#100: cascade off → defaults.site does NOT touch Prefix scope."""
    from device_discovery.interface import build_interface_entities
    from device_discovery.policy.models import Defaults, Options

    interfaces = {"Eth1/1": {"is_enabled": True, "speed": 10000, "mtu": 1500, "mac_address": "", "description": ""}}
    interfaces_ip = {"Eth1/1": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}}
    defaults = Defaults(site="DC-East", location="Floor-3")
    options = Options(propagate_defaults_to_prefix_scope=False)  # explicit False

    entities = build_interface_entities(
        sample_diode_device, interfaces, interfaces_ip, defaults, options=options,
    )
    prefix = _extract_prefix(entities)
    assert prefix.scope_site.name == ""
    assert prefix.scope_location.name == ""


def test_prefix_emission_cascade_on_inherits_site_and_location(sample_diode_device):
    """Cascade on + no explicit scope_* → defaults.location wins over defaults.site by precedence."""
    from device_discovery.interface import build_interface_entities
    from device_discovery.policy.models import Defaults, Options

    interfaces = {"Eth1/1": {"is_enabled": True, "speed": 10000, "mtu": 1500, "mac_address": "", "description": ""}}
    interfaces_ip = {"Eth1/1": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}}
    defaults = Defaults(site="DC-East", location="Floor-3")
    options = Options(propagate_defaults_to_prefix_scope=True)

    entities = build_interface_entities(
        sample_diode_device, interfaces, interfaces_ip, defaults, options=options,
    )
    prefix = _extract_prefix(entities)
    # location is more specific than site → it wins under the oneof precedence rule.
    assert prefix.scope_location.name == "Floor-3"
    # Site is embedded so NetBox can disambiguate "Floor-3 in DC-East" from
    # any other site's "Floor-3" — locations are unique within site, not globally.
    assert prefix.scope_location.site.name == "DC-East"
    assert not prefix.scope_site.name


def test_prefix_emission_explicit_beats_cascade(sample_diode_device):
    """Explicit defaults.prefix.scope_site wins over cascade from defaults.site."""
    from device_discovery.interface import build_interface_entities
    from device_discovery.policy.models import Defaults, Options, PrefixParameters

    interfaces = {"Eth1/1": {"is_enabled": True, "speed": 10000, "mtu": 1500, "mac_address": "", "description": ""}}
    interfaces_ip = {"Eth1/1": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}}
    defaults = Defaults(
        site="DC-East",
        prefix=PrefixParameters(scope_site="DC-West"),  # explicit wins
    )
    options = Options(propagate_defaults_to_prefix_scope=True)

    entities = build_interface_entities(
        sample_diode_device, interfaces, interfaces_ip, defaults, options=options,
    )
    prefix = _extract_prefix(entities)
    assert prefix.scope_site.name == "DC-West"


def test_prefix_emission_explicit_scope_blocks_cross_field_cascade(sample_diode_device):
    """
    Cross-field regression: any explicit defaults.prefix.scope_* skips the entire cascade.

    Without this guard, an operator who explicitly sets scope_site would
    have it silently overridden by a cascaded scope_location (more
    specific → wins the oneof precedence). The cascade is skipped
    wholesale when any explicit prefix scope is set.
    """
    from device_discovery.interface import build_interface_entities
    from device_discovery.policy.models import Defaults, Options, PrefixParameters

    interfaces = {"Eth1/1": {"is_enabled": True, "speed": 10000, "mtu": 1500, "mac_address": "", "description": ""}}
    interfaces_ip = {"Eth1/1": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}}
    defaults = Defaults(
        site="DC-East",
        location="Floor-3",  # would cascade to scope_location and win precedence
        prefix=PrefixParameters(scope_site="DC-West"),  # explicit scope_site — operator's choice
    )
    options = Options(propagate_defaults_to_prefix_scope=True)

    entities = build_interface_entities(
        sample_diode_device, interfaces, interfaces_ip, defaults, options=options,
    )
    prefix = _extract_prefix(entities)
    # Explicit scope_site wins; scope_location is NOT cascaded because explicit mode.
    assert prefix.scope_site.name == "DC-West"
    assert not prefix.scope_location.name


def test_prefix_emission_cascade_skips_undefined_site_placeholder(sample_diode_device):
    """The literal 'undefined' default for defaults.site is not cascaded — it's a placeholder, not a real site."""
    from device_discovery.interface import build_interface_entities
    from device_discovery.policy.models import Defaults, Options

    interfaces = {"Eth1/1": {"is_enabled": True, "speed": 10000, "mtu": 1500, "mac_address": "", "description": ""}}
    interfaces_ip = {"Eth1/1": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}}
    defaults = Defaults()  # site defaults to "undefined"
    options = Options(propagate_defaults_to_prefix_scope=True)

    entities = build_interface_entities(
        sample_diode_device, interfaces, interfaces_ip, defaults, options=options,
    )
    prefix = _extract_prefix(entities)
    assert prefix.scope_site.name == ""  # not "undefined"


def test_prefix_emission_legacy_ipam_parameters_assignment_does_not_crash(sample_diode_device):
    """
    Back-compat regression for in-process callers assigning a bare IpamParameters.

    Pydantic does not validate field assignment after construction, so a
    library caller could do `defaults.prefix = IpamParameters(role="x")`
    without coercion to PrefixParameters. The scope reads in
    _resolve_prefix_scope_kwargs must tolerate the missing attributes
    rather than crashing the entire discovery cycle with AttributeError.
    """
    from device_discovery.interface import build_interface_entities
    from device_discovery.policy.models import Defaults, IpamParameters, Options

    interfaces = {"Eth1/1": {"is_enabled": True, "speed": 10000, "mtu": 1500, "mac_address": "", "description": ""}}
    interfaces_ip = {"Eth1/1": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}}
    defaults = Defaults()
    # Legacy in-process pattern: bypass Pydantic validation and assign a
    # plain IpamParameters. Missing scope_site / scope_location attributes
    # must not raise.
    defaults.prefix = IpamParameters(role="customer-edge")
    options = Options()

    # Must not raise AttributeError on the scope reads.
    entities = build_interface_entities(
        sample_diode_device, interfaces, interfaces_ip, defaults, options=options,
    )
    prefix = _extract_prefix(entities)
    assert prefix is not None
    assert prefix.scope_site.name == ""
    assert prefix.scope_location.name == ""
    # Non-scope IpamParameters fields still flow through (role inherited).
    assert prefix.role.name == "customer-edge"


def test_prefix_emission_scope_location_alone_emits_without_site(sample_diode_device):
    """
    Explicit scope_location alone (no scope_site) emits bare Location.

    When the operator only sets scope_location and we have no site context
    (neither explicit scope_site nor a cascade site to embed), we pass a
    bare Location(name=...) — the operator owns the ambiguity. We do NOT
    fabricate a site or fall back to defaults.site without the cascade
    flag.
    """
    from device_discovery.interface import build_interface_entities
    from device_discovery.policy.models import Defaults, Options, PrefixParameters

    interfaces = {"Eth1/1": {"is_enabled": True, "speed": 10000, "mtu": 1500, "mac_address": "", "description": ""}}
    interfaces_ip = {"Eth1/1": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}}
    defaults = Defaults(
        site="DC-East",  # set but cascade is off — must NOT leak into Location
        prefix=PrefixParameters(scope_location="Floor-3"),  # explicit, no scope_site
    )
    options = Options()  # cascade off

    entities = build_interface_entities(
        sample_diode_device, interfaces, interfaces_ip, defaults, options=options,
    )
    prefix = _extract_prefix(entities)
    assert prefix.scope_location.name == "Floor-3"
    # No site embedded — operator didn't provide one and cascade is off.
    assert prefix.scope_location.site.name == ""


def test_driver_type_honored_when_valid(
    sample_device_info, sample_defaults
):
    """A valid driver-provided type is used (tier 3)."""
    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device, "UnknownInterface0", {"is_enabled": True, "type": "lag"}, sample_defaults
    )
    assert interface.type == "lag"


def test_driver_type_below_user_patterns(
    sample_device_info, sample_defaults
):
    """A user interface_pattern (tier 2) overrides the driver-provided type (tier 3)."""
    sample_defaults.interface_patterns = [
        InterfacePattern(match="^UnknownInterface0$", type="1000base-t"),
    ]
    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device, "UnknownInterface0", {"is_enabled": True, "type": "lag"}, sample_defaults
    )
    assert interface.type == "1000base-t"


def test_driver_type_beats_speed_and_builtin(
    sample_device_info, sample_defaults
):
    """A valid driver type wins over speed-based detection (tier 5)."""
    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device,
        "UnknownInterface0",
        {"is_enabled": True, "type": "lag", "speed": 10000},
        sample_defaults,
    )
    assert interface.type == "lag"


def test_invalid_driver_type_falls_through_and_warns(
    sample_device_info, sample_defaults, caplog
):
    """An invalid driver type is ignored (with a warning) and resolution falls through."""
    sample_defaults.if_type = "other"
    device = translate_device(sample_device_info, sample_defaults)
    with caplog.at_level("WARNING"):
        interface = translate_interface(
            device,
            "UnknownInterface0",
            {"is_enabled": True, "type": "G/10Gig", "speed": 0},
            sample_defaults,
        )
    assert interface.type == "other"
    assert any("not a valid netbox" in r.message.lower() for r in caplog.records)


def test_detect_type_by_speed_only_emits_valid_netbox_types():
    """Every speed-based type (incl. the >400G fallback) is a valid NetBox type."""
    from device_discovery.interface import detect_type_by_speed
    from device_discovery.interface_types import VALID_INTERFACE_TYPES

    for mbps in (100, 1000, 2500, 5000, 10000, 25000, 40000, 50000,
                 100000, 200000, 400000, 800000, 1600000):
        t = detect_type_by_speed(mbps)
        assert t in VALID_INTERFACE_TYPES, f"{mbps} Mbps -> {t!r} not a valid NetBox type"
    assert detect_type_by_speed(800000) == "800gbase-x-qsfpdd"


def test_builtin_patterns_only_emit_valid_netbox_types():
    """Every built-in interface pattern maps to a valid NetBox type."""
    from device_discovery.defaults import DEFAULT_INTERFACE_PATTERNS
    from device_discovery.interface_types import VALID_INTERFACE_TYPES

    for p in DEFAULT_INTERFACE_PATTERNS:
        assert p.type in VALID_INTERFACE_TYPES, f"pattern {p.match!r} -> {p.type!r} invalid"


# Unit Tests for emit_prefix_vlan (SVI VLAN attachment on derived prefixes)


def _named_vlan(vid, name):
    """Build a pb.VLAN with both fields set, mirroring _build_vlan_cache's output."""
    return VLAN(vid=vid, name=name)


def _prefixes(entities):
    return [e.prefix for e in entities if e.HasField("prefix")]


TWO_SVIS = {
    "Vlan10": {"is_up": True, "is_enabled": True, "mtu": 1500, "speed": 1000},
    "Vlan20": {"is_up": True, "is_enabled": True, "mtu": 1500, "speed": 1000},
}
TWO_SVIS_IP = {
    "Vlan10": {"ipv4": {"10.0.0.1": {"prefix_length": 24}}},
    "Vlan20": {"ipv4": {"10.0.0.2": {"prefix_length": 24}}},
}


def test_prefix_vlan_attaches_when_unanimous():
    """A prefix derived from a single agreed-upon VLAN carries that VLAN."""
    # Both addresses reach 10.0.0.0/24 through VLAN 10, so nothing is contested.
    ents = build_interface_entities(
        device="sw1",
        interfaces={"Vlan10": TWO_SVIS["Vlan10"]},
        interfaces_ip={
            "Vlan10": {
                "ipv4": {
                    "10.0.0.1": {"prefix_length": 24},
                    "10.0.0.2": {"prefix_length": 24},
                }
            }
        },
        defaults=Defaults(site="dc1"),
        options=Options(emit_prefix_vlan="svi-name"),
        vlan_cache={10: _named_vlan(10, "office")},
    )
    got = [p for p in _prefixes(ents) if p.prefix == "10.0.0.0/24"]
    assert got, "a prefix must still be derived"
    assert all(p.vlan.vid == 10 for p in got)


def test_prefix_vlan_withheld_when_contested():
    """A prefix reached through two disagreeing VLANs carries neither."""
    # One network reached through two different VLANs. Emitting both would put
    # conflicting values on one object and fail the whole changeset.
    ents = build_interface_entities(
        device="sw1", interfaces=TWO_SVIS, interfaces_ip=TWO_SVIS_IP,
        defaults=Defaults(site="dc1"),
        options=Options(emit_prefix_vlan="svi-name"),
        vlan_cache={10: _named_vlan(10, "office"), 20: _named_vlan(20, "voice")},
    )
    for p in _prefixes(ents):
        if p.prefix == "10.0.0.0/24":
            assert not p.HasField("vlan"), "a contested VLAN must not be written"


def test_prefix_vlan_withheld_when_partially_resolved():
    """A prefix with one unresolved contributor carries no VLAN."""
    # VLAN 20 is absent from the device database, so one contributor resolves
    # and the other does not. Silence beats a half-attributed prefix.
    ents = build_interface_entities(
        device="sw1", interfaces=TWO_SVIS, interfaces_ip=TWO_SVIS_IP,
        defaults=Defaults(site="dc1"),
        options=Options(emit_prefix_vlan="svi-name"),
        vlan_cache={10: _named_vlan(10, "office")},
    )
    for p in _prefixes(ents):
        if p.prefix == "10.0.0.0/24":
            assert not p.HasField("vlan")


def test_prefix_vlan_off_by_default():
    """With emit_prefix_vlan left at its default, no prefix carries a VLAN."""
    ents = build_interface_entities(
        device="sw1", interfaces=TWO_SVIS, interfaces_ip=TWO_SVIS_IP,
        defaults=Defaults(site="dc1"), options=Options(),
        vlan_cache={10: _named_vlan(10, "office")},
    )
    assert all(not p.HasField("vlan") for p in _prefixes(ents))


def test_prefix_vlan_skips_stub_named_vlan():
    """A nameless VLAN cache entry is never used as a prefix's VLAN candidate."""
    # A VLAN with no name is a stub; referencing it would rename the
    # operator's VLAN, because a matched reference is applied as an update.
    ents = build_interface_entities(
        device="sw1",
        interfaces={"Vlan10": TWO_SVIS["Vlan10"]},
        interfaces_ip={"Vlan10": {"ipv4": {"10.0.0.1": {"prefix_length": 24}}}},
        defaults=Defaults(site="dc1"),
        options=Options(emit_prefix_vlan="svi-name"),
        vlan_cache={10: _named_vlan(10, "")},
    )
    assert all(not p.HasField("vlan") for p in _prefixes(ents))


@pytest.mark.parametrize(
    "if_name",
    [
        "BDI100",
        "Bdi100",
        "BVI10",
        "Vlanif100",
        "vlanif100",
        "Vlan-interface100",
        "nve1",
        "Nve1",
        "Vxlan1",
        "Virtual-Template1",
        "Virtual-Access2",
        "Dialer1",
        "Null0",
        "tunnel-ip1",
        "tunnel-te200",
        "tunnel-mte5",
    ],
)
def test_translate_interface_software_interface_is_virtual_despite_speed(
    if_name, sample_device_info, sample_defaults
):
    """
    A software-implemented interface is virtual even when the device reports a speed.

    Speed-based detection sits below the built-in patterns, so a missing pattern
    silently turns one of these into an Ethernet type: a BDI reporting 1000 Mbps
    was emitted as 1000base-t, which is what netboxlabs/orb-agent#522 reported.
    Each name is passed with a speed to keep that ordering pinned.
    """
    device = translate_device(sample_device_info, sample_defaults)

    interface = translate_interface(
        device,
        if_name,
        {"is_enabled": True, "speed": 1000},
        sample_defaults,
    )

    assert interface.type == "virtual", f"{if_name} must not be typed from its speed"


def test_translate_interface_physical_still_typed_from_its_name(
    sample_device_info, sample_defaults
):
    """The added virtual patterns must not capture physical interfaces."""
    device = translate_device(sample_device_info, sample_defaults)

    for if_name, expected in (
        ("GigabitEthernet0/1", "1000base-t"),
        ("TenGigabitEthernet1/0/1", "10gbase-x-sfpp"),
        ("Port-channel1", "lag"),
    ):
        interface = translate_interface(
            device, if_name, {"is_enabled": True, "speed": 1000}, sample_defaults
        )
        assert interface.type == expected, if_name


def test_prefix_vlan_withheld_when_vrfs_differ_only_outside_the_matcher():
    """
    Contributors whose VRFs resolve to one NetBox record are reconciled together.

    The ipam.vrf matchers key on name and rd, so two VRF messages differing only
    in a description denote the same record. Grouping on the serialized message
    put them in separate groups, each unanimous by itself, and the SVI kept a
    VLAN the abstaining contributor should have taken from it, while Diode still
    resolved both prefixes to one object.
    """
    from netboxlabs.diode.sdk.ingester import VRF, Entity, Prefix

    from device_discovery.interface import _reconcile_prefix_vlans

    # A discovered VRF carries a description; the other contributor fell back to
    # defaults.prefix.vrf under the same name.
    svi = Prefix(prefix="10.0.0.0/24", vrf=VRF(name="CUST", description="from device"))
    svi.vlan.CopyFrom(VLAN(vid=10, name="office"))
    routed = Prefix(prefix="10.0.0.0/24", vrf=VRF(name="CUST"))

    entities = [Entity(prefix=svi), Entity(prefix=routed)]
    _reconcile_prefix_vlans(entities)

    assert not entities[0].prefix.HasField("vlan"), (
        "an abstaining contributor to the same NetBox prefix must strip the VLAN"
    )


def test_prefix_vlan_kept_when_vrfs_are_genuinely_different_records():
    """A different rd is a different NetBox VRF, so those prefixes do not reconcile."""
    from netboxlabs.diode.sdk.ingester import VRF, Entity, Prefix

    from device_discovery.interface import _reconcile_prefix_vlans

    svi = Prefix(prefix="10.0.0.0/24", vrf=VRF(name="CUST", rd="65000:1"))
    svi.vlan.CopyFrom(VLAN(vid=10, name="office"))
    other = Prefix(prefix="10.0.0.0/24", vrf=VRF(name="CUST", rd="65000:2"))

    entities = [Entity(prefix=svi), Entity(prefix=other)]
    _reconcile_prefix_vlans(entities)

    assert entities[0].prefix.vlan.vid == 10, "a separate VRF record must not reconcile"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("svi-name", "svi-name"),
        ("SVI-Name ", "svi-name"),          # case and whitespace normalised
        ("off", "off"),
        (False, "off"),      # YAML 1.1 reads a bare `off` as this
        (True, "off"),       # and a bare `on` / `yes` as this
        (None, "off"),
        ("typo", "off"),
        (1, "off"),          # yaml.v3 coerces an int scalar into the Go string field
        (1.5, "off"),
        # A YAML timestamp. safe_load produces date / datetime; the Go decoder
        # hands its string field the raw text, and resolves it to off.
        (datetime.date(2026, 8, 20), "off"),
        (datetime.datetime(2026, 8, 20, 10, 0, tzinfo=datetime.timezone.utc), "off"),
        # A !!binary scalar. yaml.v3 gives the Go string field the decoded
        # bytes, so its text is what decides the mode there too.
        (b"svi-name", "svi-name"),
        (b"nonsense", "off"),
        (b"\xff\xfe", "off"),   # not decodable text at all
    ],
)
def test_emit_prefix_vlan_scalars_never_reject_a_policy(value, expected):
    """
    Every scalar resolves to a mode, matching what the snmp-discovery twin does.

    The Go option is a *string field decoded by gopkg.in/yaml.v3, which coerces
    an int or float scalar into it and then resolves anything unrecognized to
    'off'. Raising here for those would make one policy text valid for
    snmp-discovery and fatal for device-discovery.
    """
    from device_discovery.policy.models import Config

    assert Config(options={"emit_prefix_vlan": value}).options.emit_prefix_vlan == expected


@pytest.mark.parametrize("value", [["svi-name"], {"mode": "svi-name"}])
def test_emit_prefix_vlan_collections_are_a_policy_error(value):
    """
    A sequence or mapping is rejected, which is also what the Go decoder does.

    yaml.v3 refuses to decode either into a string field, so the policy fails on
    the snmp side too. Accepting it here would be the same cross-backend
    divergence in the other direction.
    """
    from pydantic import ValidationError

    from device_discovery.policy.models import Config

    with pytest.raises(ValidationError):
        Config(options={"emit_prefix_vlan": value})
