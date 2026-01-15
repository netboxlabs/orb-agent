// Copyright 2024 NetBox Labs Inc
package mapping

import (
	"log/slog"
	"testing"

	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/stretchr/testify/assert"
)

// TestResolveInterfaceType_Priority tests the 5-tier priority system
func TestResolveInterfaceType_Priority(t *testing.T) {
	logger := slog.Default()

	t.Run("Tier 1: User pattern overrides all", func(t *testing.T) {
		// User says all GigabitEthernet should be 100gbase-x (unusual but valid)
		userPatterns := []config.InterfacePattern{
			{Match: `^GigabitEthernet\d+`, Type: "100gbase-x-qsfp28"},
		}
		merged := MergePatterns(userPatterns, true)
		matcher, err := NewPatternMatcher(merged, logger)
		assert.NoError(t, err)

		speed := int64(1000000) // 1 Gbps in Kbps
		// ifType "117" = gigabitEthernet, speed says 1Gbps, built-in pattern says 1000base-t
		// But user pattern should override all
		result := ResolveInterfaceType(
			"GigabitEthernet0/1",
			"117", // SNMP ifType for gigabitEthernet
			&speed,
			"other", // Default
			matcher,
			1, // 1 user pattern
		)
		assert.Equal(t, "100gbase-x-qsfp28", result, "User pattern should override SNMP ifType, speed, and built-in")
	})

	t.Run("Tier 2: SNMP ifType beats built-in pattern", func(t *testing.T) {
		// No user patterns, only built-ins
		merged := MergePatterns(nil, true)
		matcher, err := NewPatternMatcher(merged, logger)
		assert.NoError(t, err)

		// Interface name matches built-in pattern for "lag"
		// But SNMP ifType says it's virtual
		result := ResolveInterfaceType(
			"Port-channel1",
			"24", // SNMP ifType for softwareLoopback (virtual)
			nil,
			"other",
			matcher,
			0,
		)
		assert.Equal(t, "virtual", result, "SNMP ifType should beat built-in pattern")
	})

	t.Run("Tier 2: Speed-based detection for Ethernet", func(t *testing.T) {
		merged := MergePatterns(nil, true)
		matcher, err := NewPatternMatcher(merged, logger)
		assert.NoError(t, err)

		speed := int64(10000000) // 10 Gbps in Kbps
		// ifType is ethernet, speed indicates 10G
		result := ResolveInterfaceType(
			"UnknownEthernetInterface",
			"6", // SNMP ifType for ethernetCsmacd
			&speed,
			"other",
			matcher,
			0,
		)
		assert.Equal(t, "10gbase-t", result, "Speed-based detection should work for Ethernet")
	})

	t.Run("Tier 3: Built-in pattern fallback", func(t *testing.T) {
		// No user patterns, only built-ins
		merged := MergePatterns(nil, true)
		matcher, err := NewPatternMatcher(merged, logger)
		assert.NoError(t, err)

		// Interface name matches built-in, SNMP ifType unknown
		result := ResolveInterfaceType(
			"TenGigabitEthernet0/1",
			"999", // Unknown SNMP ifType
			nil,
			"other",
			matcher,
			0,
		)
		assert.Equal(t, "10gbase-x-sfpp", result, "Built-in pattern should be used as fallback")
	})

	t.Run("Tier 5: Default fallback", func(t *testing.T) {
		// No matches anywhere, should use default
		result := ResolveInterfaceType(
			"CompletelyUnknownInterface",
			"9999", // Unknown SNMP ifType
			nil,
			"custom-default",
			nil, // No pattern matcher
			0,
		)
		assert.Equal(t, "custom-default", result, "Should use default when nothing matches")
	})

	t.Run("Tier 5: Final fallback to 'other'", func(t *testing.T) {
		// No matches anywhere, no default specified
		result := ResolveInterfaceType(
			"CompletelyUnknownInterface",
			"9999",
			nil,
			"", // No default
			nil,
			0,
		)
		assert.Equal(t, "other", result, "Should fallback to 'other' when no default")
	})
}

func TestResolveInterfaceType_EdgeCases(t *testing.T) {
	logger := slog.Default()

	t.Run("Empty interface name skips pattern matching", func(t *testing.T) {
		userPatterns := []config.InterfacePattern{
			{Match: `.*`, Type: "should-not-match"},
		}
		merged := MergePatterns(userPatterns, true)
		matcher, err := NewPatternMatcher(merged, logger)
		assert.NoError(t, err)

		// Empty name with known SNMP ifType
		result := ResolveInterfaceType(
			"",
			"161", // ieee8023adLag
			nil,
			"other",
			matcher,
			1,
		)
		assert.Equal(t, "lag", result, "Should use SNMP ifType when name is empty")
	})

	t.Run("Nil pattern matcher", func(t *testing.T) {
		// No pattern matcher, should skip to SNMP ifType
		result := ResolveInterfaceType(
			"GigabitEthernet0/1",
			"117", // gigabitEthernet
			nil,
			"other",
			nil, // No matcher
			0,
		)
		// No speed, so InterfaceTypeMap lookup happens but gigabitEthernet (117) is not in the map
		// So it should fall through to default
		assert.Equal(t, "other", result, "Should fallback when no pattern matcher")
	})

	t.Run("Zero speed value", func(t *testing.T) {
		merged := MergePatterns(nil, true)
		matcher, err := NewPatternMatcher(merged, logger)
		assert.NoError(t, err)

		speed := int64(0)
		result := ResolveInterfaceType(
			"eth0",
			"6", // ethernetCsmacd
			&speed,
			"other",
			matcher,
			0,
		)
		// Zero speed shouldn't trigger speed-based detection
		// Should use built-in pattern for eth0
		assert.Equal(t, "1000base-t", result, "Should use built-in pattern when speed is 0")
	})

	t.Run("Nil speed pointer", func(t *testing.T) {
		merged := MergePatterns(nil, true)
		matcher, err := NewPatternMatcher(merged, logger)
		assert.NoError(t, err)

		result := ResolveInterfaceType(
			"TenGigabitEthernet0/1",
			"6", // ethernetCsmacd
			nil, // No speed
			"other",
			matcher,
			0,
		)
		// No speed-based detection, but built-in pattern should match
		assert.Equal(t, "10gbase-x-sfpp", result, "Should use built-in pattern when speed is nil")
	})
}

func TestResolveInterfaceType_RealWorldScenarios(t *testing.T) {
	logger := slog.Default()

	t.Run("Cisco switch with custom mgmt pattern", func(t *testing.T) {
		// User wants to override management interface detection
		userPatterns := []config.InterfacePattern{
			{Match: `^mgmt-`, Type: "1000base-t"},
		}
		merged := MergePatterns(userPatterns, true)
		matcher, err := NewPatternMatcher(merged, logger)
		assert.NoError(t, err)

		result := ResolveInterfaceType(
			"mgmt-eth0",
			"6",
			nil,
			"other",
			matcher,
			1,
		)
		assert.Equal(t, "1000base-t", result)
	})

	t.Run("Juniper interface with SNMP speed", func(t *testing.T) {
		merged := MergePatterns(nil, true)
		matcher, err := NewPatternMatcher(merged, logger)
		assert.NoError(t, err)

		speed := int64(10000000) // 10G
		result := ResolveInterfaceType(
			"xe-0/0/0",
			"6", // ethernetCsmacd
			&speed,
			"other",
			matcher,
			0,
		)
		// Speed-based detection (Tier 2) beats built-in pattern (Tier 3)
		assert.Equal(t, "10gbase-t", result)
	})

	t.Run("LAG interface from SNMP ifType", func(t *testing.T) {
		merged := MergePatterns(nil, true)
		matcher, err := NewPatternMatcher(merged, logger)
		assert.NoError(t, err)

		result := ResolveInterfaceType(
			"Bundle-Ether100",
			"161", // ieee8023adLag
			nil,
			"other",
			matcher,
			0,
		)
		// SNMP ifType (Tier 2) should match before built-in pattern (Tier 3)
		assert.Equal(t, "lag", result)
	})
}

func TestGetNetboxType_BackwardCompatibility(t *testing.T) {
	t.Run("GetNetboxType wraps ResolveInterfaceType", func(t *testing.T) {
		speed := int64(1000000) // 1G
		result := GetNetboxType("6", "other", &speed)
		// Should use speed-based detection
		assert.Equal(t, "1000base-t", result)
	})

	t.Run("GetNetboxType with SNMP ifType map", func(t *testing.T) {
		result := GetNetboxType("161", "other", nil) // ieee8023adLag
		assert.Equal(t, "lag", result)
	})

	t.Run("GetNetboxType with default fallback", func(t *testing.T) {
		result := GetNetboxType("9999", "custom-default", nil)
		assert.Equal(t, "custom-default", result)
	})
}
