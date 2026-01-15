// Copyright 2024 NetBox Labs Inc
package mapping

import (
	"log/slog"
	"testing"

	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/stretchr/testify/assert"
)

func TestNewPatternMatcher(t *testing.T) {
	logger := slog.Default()

	t.Run("Valid patterns compile successfully", func(t *testing.T) {
		patterns := []config.InterfacePattern{
			{Match: `^Gi\d+`, Type: "1000base-t"},
			{Match: `^Te\d+`, Type: "10gbase-x-sfpp"},
		}
		matcher, err := NewPatternMatcher(patterns, logger)
		assert.NoError(t, err)
		assert.NotNil(t, matcher)
		assert.Equal(t, 2, len(matcher.compiledPatterns))
	})

	t.Run("Invalid regex returns error", func(t *testing.T) {
		patterns := []config.InterfacePattern{
			{Match: `^Gi\d+`, Type: "1000base-t"},
			{Match: `[invalid(`, Type: "10gbase-x-sfpp"}, // Invalid regex
		}
		matcher, err := NewPatternMatcher(patterns, logger)
		assert.Error(t, err)
		assert.Nil(t, matcher)
		assert.Contains(t, err.Error(), "failed to compile pattern 1")
	})

	t.Run("Empty patterns creates empty matcher", func(t *testing.T) {
		patterns := []config.InterfacePattern{}
		matcher, err := NewPatternMatcher(patterns, logger)
		assert.NoError(t, err)
		assert.NotNil(t, matcher)
		assert.Equal(t, 0, len(matcher.compiledPatterns))
	})
}

func TestPatternMatcher_MatchInterfaceType(t *testing.T) {
	logger := slog.Default()

	t.Run("User pattern overrides built-in pattern", func(t *testing.T) {
		// User wants all GigabitEthernet to be 10gbase-t instead of default 1000base-t
		userPatterns := []config.InterfacePattern{
			{Match: `^GigabitEthernet\d+`, Type: "10gbase-t"},
		}
		merged := MergePatterns(userPatterns, true)
		matcher, err := NewPatternMatcher(merged, logger)
		assert.NoError(t, err)

		matchedType := matcher.MatchInterfaceType("GigabitEthernet0/1", 1)
		assert.Equal(t, "10gbase-t", matchedType, "User pattern should override built-in")
	})

	t.Run("Built-in pattern matches when no user pattern", func(t *testing.T) {
		merged := MergePatterns(nil, true)
		matcher, err := NewPatternMatcher(merged, logger)
		assert.NoError(t, err)

		matchedType := matcher.MatchInterfaceType("GigabitEthernet0/1", 0)
		assert.Equal(t, "1000base-t", matchedType, "Built-in pattern should match")
	})

	t.Run("Most specific match wins within user patterns", func(t *testing.T) {
		userPatterns := []config.InterfacePattern{
			{Match: `^Gi`, Type: "1000base-t"},                    // Less specific
			{Match: `^GigabitEthernet\d+/\d+`, Type: "10gbase-t"}, // More specific
		}
		merged := MergePatterns(userPatterns, true)
		matcher, err := NewPatternMatcher(merged, logger)
		assert.NoError(t, err)

		matchedType := matcher.MatchInterfaceType("GigabitEthernet0/1", 2)
		assert.Equal(t, "10gbase-t", matchedType, "More specific pattern should win")
	})

	t.Run("Most specific match wins within built-in patterns", func(t *testing.T) {
		merged := MergePatterns(nil, true)
		matcher, err := NewPatternMatcher(merged, logger)
		assert.NoError(t, err)

		// TenGig pattern is more specific than Te pattern in built-ins
		matchedType := matcher.MatchInterfaceType("TenGigabitEthernet0/1", 0)
		assert.Equal(t, "10gbase-x-sfpp", matchedType, "Built-in most specific should win")
	})

	t.Run("No match returns empty string", func(t *testing.T) {
		userPatterns := []config.InterfacePattern{
			{Match: `^Gi\d+`, Type: "1000base-t"},
		}
		merged := MergePatterns(userPatterns, true)
		matcher, err := NewPatternMatcher(merged, logger)
		assert.NoError(t, err)

		matchedType := matcher.MatchInterfaceType("UnknownInterface", 1)
		assert.Equal(t, "", matchedType, "No match should return empty string")
	})

	t.Run("Empty interface name returns empty string", func(t *testing.T) {
		merged := MergePatterns(nil, true)
		matcher, err := NewPatternMatcher(merged, logger)
		assert.NoError(t, err)

		matchedType := matcher.MatchInterfaceType("", 0)
		assert.Equal(t, "", matchedType)
	})

	t.Run("Case sensitive matching", func(t *testing.T) {
		userPatterns := []config.InterfacePattern{
			{Match: `^Gi\d+`, Type: "1000base-t"},
		}
		merged := MergePatterns(userPatterns, true)
		matcher, err := NewPatternMatcher(merged, logger)
		assert.NoError(t, err)

		// Should not match lowercase
		matchedType := matcher.MatchInterfaceType("gi0/1", 1)
		assert.Equal(t, "", matchedType, "Pattern matching should be case sensitive")

		// Should match uppercase
		matchedType = matcher.MatchInterfaceType("Gi0/1", 1)
		assert.Equal(t, "1000base-t", matchedType)
	})
}

func TestPatternMatcher_findBestMatch(t *testing.T) {
	logger := slog.Default()

	t.Run("Longer match wins", func(t *testing.T) {
		patterns := []config.InterfacePattern{
			{Match: `^Gi`, Type: "type1"},
			{Match: `^GigabitEthernet`, Type: "type2"},
		}
		matcher, err := NewPatternMatcher(patterns, logger)
		assert.NoError(t, err)

		matchedType := matcher.findBestMatch("GigabitEthernet0/1", matcher.compiledPatterns)
		assert.Equal(t, "type2", matchedType, "Longer match should win")
	})

	t.Run("Empty patterns returns empty string", func(t *testing.T) {
		patterns := []config.InterfacePattern{}
		matcher, err := NewPatternMatcher(patterns, logger)
		assert.NoError(t, err)

		matchedType := matcher.findBestMatch("GigabitEthernet0/1", matcher.compiledPatterns)
		assert.Equal(t, "", matchedType)
	})
}

func TestMergePatterns(t *testing.T) {
	t.Run("Merge user patterns with defaults", func(t *testing.T) {
		userPatterns := []config.InterfacePattern{
			{Match: `^custom-`, Type: "custom-type"},
		}
		merged := MergePatterns(userPatterns, true)

		// User patterns should come first
		assert.Greater(t, len(merged), 1, "Should have user + built-in patterns")
		assert.Equal(t, "^custom-", merged[0].Match, "User pattern should be first")

		// Built-in patterns should follow
		hasBuiltin := false
		for i := 1; i < len(merged); i++ {
			if merged[i].Match == `^(HundredGig|Hu)\S+` {
				hasBuiltin = true
				break
			}
		}
		assert.True(t, hasBuiltin, "Built-in patterns should be included")
	})

	t.Run("User patterns only when includeDefaults is false", func(t *testing.T) {
		userPatterns := []config.InterfacePattern{
			{Match: `^custom-`, Type: "custom-type"},
		}
		merged := MergePatterns(userPatterns, false)

		assert.Equal(t, 1, len(merged), "Should only have user patterns")
		assert.Equal(t, "^custom-", merged[0].Match)
	})

	t.Run("Empty user patterns with defaults", func(t *testing.T) {
		merged := MergePatterns(nil, true)

		assert.Greater(t, len(merged), 0, "Should have built-in patterns")
		// First pattern should be a built-in
		assert.Equal(t, `^(HundredGig|Hu)\S+`, merged[0].Match)
	})

	t.Run("Empty user patterns without defaults", func(t *testing.T) {
		merged := MergePatterns(nil, false)

		assert.Equal(t, 0, len(merged), "Should have no patterns")
	})
}

func TestBuiltInPatterns(t *testing.T) {
	logger := slog.Default()

	// Create matcher with only built-in patterns
	matcher, err := NewPatternMatcher(DefaultInterfacePatterns, logger)
	assert.NoError(t, err)

	tests := []struct {
		name          string
		interfaceName string
		expectedType  string
	}{
		// Cisco IOS/IOS-XE
		{"Cisco HundredGig", "HundredGigE0/1/0", "100gbase-x-qsfp28"},
		{"Cisco FortyGig", "FortyGigabitEthernet0/1", "40gbase-x-qsfpp"},
		{"Cisco TenGig", "TenGigabitEthernet0/1", "10gbase-x-sfpp"},
		{"Cisco GigabitEthernet", "GigabitEthernet0/1", "1000base-t"},
		{"Cisco FastEthernet", "FastEthernet0/1", "100base-tx"},

		// Juniper
		{"Juniper et", "et-0/0/0", "40gbase-x-qsfpp"},
		{"Juniper xe", "xe-0/0/0", "10gbase-x-sfpp"},
		{"Juniper ge", "ge-0/0/0", "1000base-t"},

		// LAG
		{"Cisco Port-channel", "Port-channel1", "lag"},
		{"Juniper ae", "ae0", "lag"},
		{"Cisco IOS-XR Bundle", "Bundle-Ether100", "lag"},

		// Virtual
		{"Loopback", "Loopback0", "virtual"},
		{"VLAN", "Vlan100", "virtual"},
		{"Tunnel", "Tunnel0", "virtual"},

		// Management
		{"Management", "Management0", "1000base-t"},
		{"Juniper fxp", "fxp0", "1000base-t"},

		// Linux
		{"Linux eth", "eth0", "1000base-t"},
		{"Linux ens", "ens33", "1000base-t"},
		{"Cumulus swp", "swp1", "1000base-t"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matchedType := matcher.findBestMatch(tt.interfaceName, matcher.compiledPatterns)
			assert.Equal(t, tt.expectedType, matchedType,
				"Pattern should match %s to %s", tt.interfaceName, tt.expectedType)
		})
	}
}
