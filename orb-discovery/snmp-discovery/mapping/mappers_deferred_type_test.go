package mapping

import (
	"log/slog"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/stretchr/testify/assert"
)

func TestInterfaceMapper_DeferredTypeResolution(t *testing.T) {
	logger := slog.Default()

	t.Run("Pattern matching with name processed after type", func(t *testing.T) {
		// Create mapper with user patterns
		userPatterns := []config.InterfacePattern{
			{Match: `^GigabitEthernet\d+`, Type: "custom-gigabit"},
		}
		mapper, err := NewInterfaceMapper(logger, userPatterns)
		assert.NoError(t, err)

		// Simulate SNMP data where type OID comes before name OID
		// This is common in real SNMP walks due to numeric OID ordering
		values := map[ObjectIDIndex]*ObjectIDValue{
			"1.3.6.1.2.1.2.2.1.2.1": { // name (processed later due to reverse sort)
				OID:    "1.3.6.1.2.1.2.2.1.2.1",
				Index:  "1",
				Parent: "1.3.6.1.2.1.2.2.1.2",
				Value:  "GigabitEthernet0/1",
				Type:   OctetString,
			},
			"1.3.6.1.2.1.2.2.1.3.1": { // type (processed first due to reverse sort)
				OID:    "1.3.6.1.2.1.2.2.1.3.1",
				Index:  "1",
				Parent: "1.3.6.1.2.1.2.2.1.3",
				Value:  "6", // ethernetCsmacd
				Type:   Integer,
			},
		}

		mappingEntry := &Entry{
			OID:    "1.3.6.1.2.1.2.2.1",
			Entity: "interface",
			Field:  "_id",
			MappingEntries: []Entry{
				{
					OID:    "1.3.6.1.2.1.2.2.1.2",
					Entity: "interface",
					Field:  "name",
				},
				{
					OID:    "1.3.6.1.2.1.2.2.1.3",
					Entity: "interface",
					Field:  "type",
				},
			},
		}

		registry := NewEntityRegistry(logger)
		defaults := &config.Defaults{
			Interface: config.InterfaceDefaults{
				Type: "other",
			},
		}

		result := mapper.Map(values, mappingEntry, registry, defaults)
		iface, ok := result.(*diode.Interface)
		assert.True(t, ok)
		assert.NotNil(t, iface)
		assert.NotNil(t, iface.Name)
		assert.Equal(t, "GigabitEthernet0/1", *iface.Name)
		assert.NotNil(t, iface.Type)
		// Should use user pattern match via deferred type resolution
		assert.Equal(t, "custom-gigabit", *iface.Type, "Should use user pattern with deferred type resolution")
	})

	t.Run("Pattern matching with name processed before type", func(t *testing.T) {
		// Create mapper with user patterns
		userPatterns := []config.InterfacePattern{
			{Match: `^TenGigabitEthernet\d+`, Type: "custom-tengig"},
		}
		mapper, err := NewInterfaceMapper(logger, userPatterns)
		assert.NoError(t, err)

		// Simulate SNMP data where name OID comes before type OID
		values := map[ObjectIDIndex]*ObjectIDValue{
			"1.3.6.1.2.1.2.2.1.1.1": { // some field before name
				OID:    "1.3.6.1.2.1.2.2.1.1.1",
				Index:  "1",
				Parent: "1.3.6.1.2.1.2.2.1.1",
				Value:  "1",
				Type:   Integer,
			},
			"1.3.6.1.2.1.2.2.1.2.1": { // name
				OID:    "1.3.6.1.2.1.2.2.1.2.1",
				Index:  "1",
				Parent: "1.3.6.1.2.1.2.2.1.2",
				Value:  "TenGigabitEthernet0/1",
				Type:   OctetString,
			},
			"1.3.6.1.2.1.2.2.1.3.1": { // type
				OID:    "1.3.6.1.2.1.2.2.1.3.1",
				Index:  "1",
				Parent: "1.3.6.1.2.1.2.2.1.3",
				Value:  "6", // ethernetCsmacd
				Type:   Integer,
			},
		}

		mappingEntry := &Entry{
			OID:    "1.3.6.1.2.1.2.2.1",
			Entity: "interface",
			Field:  "_id",
			MappingEntries: []Entry{
				{
					OID:    "1.3.6.1.2.1.2.2.1.2",
					Entity: "interface",
					Field:  "name",
				},
				{
					OID:    "1.3.6.1.2.1.2.2.1.3",
					Entity: "interface",
					Field:  "type",
				},
			},
		}

		registry := NewEntityRegistry(logger)
		defaults := &config.Defaults{
			Interface: config.InterfaceDefaults{
				Type: "other",
			},
		}

		result := mapper.Map(values, mappingEntry, registry, defaults)
		iface, ok := result.(*diode.Interface)
		assert.True(t, ok)
		assert.NotNil(t, iface)
		assert.NotNil(t, iface.Name)
		assert.Equal(t, "TenGigabitEthernet0/1", *iface.Name)
		assert.NotNil(t, iface.Type)
		// Should use user pattern match via deferred type resolution
		assert.Equal(t, "custom-tengig", *iface.Type, "Should use user pattern with deferred type resolution")
	})

	t.Run("Built-in pattern matching with deferred resolution", func(t *testing.T) {
		// Create mapper with no user patterns, only built-ins
		mapper, err := NewInterfaceMapper(logger, nil)
		assert.NoError(t, err)

		values := map[ObjectIDIndex]*ObjectIDValue{
			"1.3.6.1.2.1.2.2.1.2.1": { // name
				OID:    "1.3.6.1.2.1.2.2.1.2.1",
				Index:  "1",
				Parent: "1.3.6.1.2.1.2.2.1.2",
				Value:  "Port-channel1",
				Type:   OctetString,
			},
			"1.3.6.1.2.1.2.2.1.3.1": { // type
				OID:    "1.3.6.1.2.1.2.2.1.3.1",
				Index:  "1",
				Parent: "1.3.6.1.2.1.2.2.1.3",
				Value:  "999", // Unknown ifType
				Type:   Integer,
			},
		}

		mappingEntry := &Entry{
			OID:    "1.3.6.1.2.1.2.2.1",
			Entity: "interface",
			Field:  "_id",
			MappingEntries: []Entry{
				{
					OID:    "1.3.6.1.2.1.2.2.1.2",
					Entity: "interface",
					Field:  "name",
				},
				{
					OID:    "1.3.6.1.2.1.2.2.1.3",
					Entity: "interface",
					Field:  "type",
				},
			},
		}

		registry := NewEntityRegistry(logger)
		defaults := &config.Defaults{
			Interface: config.InterfaceDefaults{
				Type: "other",
			},
		}

		result := mapper.Map(values, mappingEntry, registry, defaults)
		iface, ok := result.(*diode.Interface)
		assert.True(t, ok)
		assert.NotNil(t, iface)
		assert.NotNil(t, iface.Type)
		// Should use built-in pattern for Port-channel
		assert.Equal(t, "lag", *iface.Type, "Should use built-in pattern match via deferred type resolution")
	})

	t.Run("Deferred resolution with no pattern matcher", func(t *testing.T) {
		// Create mapper without patterns
		mapper, err := NewInterfaceMapper(logger, nil)
		assert.NoError(t, err)
		// Clear pattern matcher to simulate old behavior
		mapper.patternMatcher = nil

		values := map[ObjectIDIndex]*ObjectIDValue{
			"1.3.6.1.2.1.2.2.1.2.1": { // name
				OID:    "1.3.6.1.2.1.2.2.1.2.1",
				Index:  "1",
				Parent: "1.3.6.1.2.1.2.2.1.2",
				Value:  "GigabitEthernet0/1",
				Type:   OctetString,
			},
			"1.3.6.1.2.1.2.2.1.3.1": { // type
				OID:    "1.3.6.1.2.1.2.2.1.3.1",
				Index:  "1",
				Parent: "1.3.6.1.2.1.2.2.1.3",
				Value:  "161", // ieee8023adLag
				Type:   Integer,
			},
		}

		mappingEntry := &Entry{
			OID:    "1.3.6.1.2.1.2.2.1",
			Entity: "interface",
			Field:  "_id",
			MappingEntries: []Entry{
				{
					OID:    "1.3.6.1.2.1.2.2.1.2",
					Entity: "interface",
					Field:  "name",
				},
				{
					OID:    "1.3.6.1.2.1.2.2.1.3",
					Entity: "interface",
					Field:  "type",
				},
			},
		}

		registry := NewEntityRegistry(logger)
		defaults := &config.Defaults{
			Interface: config.InterfaceDefaults{
				Type: "other",
			},
		}

		result := mapper.Map(values, mappingEntry, registry, defaults)
		iface, ok := result.(*diode.Interface)
		assert.True(t, ok)
		assert.NotNil(t, iface)
		assert.NotNil(t, iface.Type)
		// Should use SNMP ifType mapping with deferred resolution
		assert.Equal(t, "lag", *iface.Type, "Should use SNMP ifType when no pattern matcher")
	})
}
