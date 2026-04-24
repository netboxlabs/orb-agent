package mapping_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/mapping"
	"github.com/stretchr/testify/assert"
)

type FakeManufacturers struct{}

func (f *FakeManufacturers) GetManufacturer(_ string) (string, error) {
	return "Cisco", nil
}

type FakeDeviceLookup struct{}

func (f *FakeDeviceLookup) GetDevice(_ string) (string, error) {
	return "cisco4000", nil
}

func TestMapObjectIDsToEntity(t *testing.T) {
	tests := []struct {
		name      string
		mapping   []config.MappingEntry
		objectIDs mapping.ObjectIDValueMap
		defaults  *config.Defaults
		expected  []diode.Entity
	}{
		{
			name: "Valid Mapping for multiple entities of same type",
			mapping: []config.MappingEntry{
				{
					OID:            ".1.3.6.1.2.1.2.2.1",
					Entity:         "interface",
					Field:          "_id",
					IdentifierSize: 1,
					MappingEntries: []config.MappingEntry{
						{
							OID:    ".1.3.6.1.2.1.2.2.1.2",
							Entity: "interface",
							Field:  "name",
						},
						{
							OID:    ".1.3.6.1.2.1.2.2.1.5",
							Entity: "interface",
							Field:  "speed",
						},
						{
							OID:    ".1.3.6.1.2.1.2.2.1.6",
							Entity: "interface",
							Field:  "macAddress",
						},
						{
							OID:    ".1.3.6.1.2.1.2.2.1.7",
							Entity: "interface",
							Field:  "adminStatus",
						},
					},
				},
			},
			objectIDs: mapping.ObjectIDValueMap{
				".1.3.6.1.2.1.2.2.1.2.999": mapping.Value{Value: "GigabitEthernet1/0/1", Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1},
				".1.3.6.1.2.1.2.2.1.5.999": mapping.Value{Value: "1000000000", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 1},
				".1.3.6.1.2.1.2.2.1.6.999": mapping.Value{Value: "\x00\x00\x00\x00\x00\x00", Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1},
				".1.3.6.1.2.1.2.2.1.7.999": mapping.Value{Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 1},
				".1.3.6.1.2.1.2.2.1.2.555": mapping.Value{Value: "GigabitEthernet1/0/1", Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1},
				".1.3.6.1.2.1.2.2.1.5.555": mapping.Value{Value: "1000000000", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 1},
				".1.3.6.1.2.1.2.2.1.6.555": mapping.Value{Value: "\x00\x00\x00\x00\x00\x11", Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1},
				".1.3.6.1.2.1.2.2.1.7.555": mapping.Value{Value: "0", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 1},
			},
			expected: []diode.Entity{
				&diode.Interface{
					Speed:             &[]int64{1000000}[0],
					Name:              diode.String("GigabitEthernet1/0/1"),
					PrimaryMacAddress: nil, // all-zeros MAC address should be ignored
					Enabled:           &[]bool{true}[0],
					Type:              diode.String("other"),
					Device:            &diode.Device{},
				},
				&diode.Interface{
					Speed: &[]int64{1000000}[0],
					Name:  diode.String("GigabitEthernet1/0/1"),
					PrimaryMacAddress: &diode.MACAddress{
						MacAddress: &[]string{"00:00:00:00:00:11"}[0],
					},
					Enabled: &[]bool{false}[0],
					Type:    diode.String("other"),
					Device:  &diode.Device{},
				},
			},
		},
		{
			name: "Valid Mapping for multiple entities of different types",
			mapping: []config.MappingEntry{
				{
					OID:            ".1.3.6.1.2.1.2.2.1",
					Entity:         "interface",
					Field:          "_id",
					IdentifierSize: 1,
					MappingEntries: []config.MappingEntry{
						{
							OID:    ".1.3.6.1.2.1.2.2.1.2",
							Entity: "interface",
							Field:  "name",
						},
						{
							OID:    ".1.3.6.1.2.1.2.2.1.5",
							Entity: "interface",
							Field:  "speed",
						},
						{
							OID:    ".1.3.6.1.2.1.2.2.1.6",
							Entity: "interface",
							Field:  "macAddress",
						},
						{
							OID:    ".1.3.6.1.2.1.2.2.1.7",
							Entity: "interface",
							Field:  "adminStatus",
						},
					},
				},
				{
					OID:            ".1.3.6.1.2.1.4.20.1",
					Entity:         "ipAddress",
					IdentifierSize: 4,
					MappingEntries: []config.MappingEntry{
						{
							OID:    ".1.3.6.1.2.1.4.20.1.1",
							Entity: "ipAddress",
							Field:  "address",
						},
						{
							OID:    ".1.3.6.1.2.1.4.20.1.2",
							Entity: "ipAddress",
							Field:  "_id",
						},
					},
				},
			},
			objectIDs: mapping.ObjectIDValueMap{
				".1.3.6.1.2.1.2.2.1.2.999":          mapping.Value{Value: "GigabitEthernet1/0/1", Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1},
				".1.3.6.1.2.1.2.2.1.5.999":          mapping.Value{Value: "1000000000", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 1},
				".1.3.6.1.2.1.2.2.1.6.999":          mapping.Value{Value: "\x00\x00\x00\x00\x00\x00", Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1},
				".1.3.6.1.2.1.2.2.1.7.999":          mapping.Value{Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 1},
				".1.3.6.1.2.1.4.20.1.1.192.168.1.2": mapping.Value{Value: "192.168.1.2", Type: mapping.Asn1BER(mapping.IPAddress), IdentifierSize: 4},
			},
			expected: []diode.Entity{
				&diode.Interface{
					Speed:             &[]int64{1000000}[0],
					Name:              diode.String("GigabitEthernet1/0/1"),
					PrimaryMacAddress: nil, // all-zeros MAC address should be ignored
					Enabled:           &[]bool{true}[0],
					Type:              diode.String("other"),
					Device:            &diode.Device{},
				},
				&diode.IPAddress{
					Address: diode.String("192.168.1.2/32"),
				},
			},
		},
		{
			name: "Valid Mapping for IPAdress",
			mapping: []config.MappingEntry{
				{
					OID:            ".1.3.6.1.2.1.4.20.1",
					Entity:         "ipAddress",
					Field:          "_id",
					IdentifierSize: 4,
					MappingEntries: []config.MappingEntry{
						{
							OID:    ".1.3.6.1.2.1.4.20.1.1",
							Entity: "ipAddress",
							Field:  "address",
						},
					},
				},
			},
			objectIDs: mapping.ObjectIDValueMap{
				".1.3.6.1.2.1.4.20.1.1.192.168.1.2": mapping.Value{Value: "192.168.1.2", Type: mapping.Asn1BER(mapping.IPAddress), IdentifierSize: 4},
			},
			expected: []diode.Entity{
				&diode.IPAddress{
					Address: diode.String("192.168.1.2/32"),
				},
			},
		},
		{
			name: "Not In Mapping",
			mapping: []config.MappingEntry{
				{
					OID:    "1.3.6.1.2.1.4.20.1.1",
					Entity: "ipAddress",
					Field:  "address",
				},
			},
			objectIDs: mapping.ObjectIDValueMap{
				"1.3.6.1.2.1.4.20.1.2.192.168.1.2": mapping.Value{Value: "192.168.1.2", Type: mapping.Asn1BER(mapping.IPAddress)},
			},
			expected: []diode.Entity{},
		},
		{
			name: "Invalid ObjectID length for type",
			mapping: []config.MappingEntry{
				{
					OID:            "1.3.6.1.2.1.4.20.1.1",
					Entity:         "ipAddress",
					Field:          "address",
					IdentifierSize: 4,
				},
			},
			objectIDs: mapping.ObjectIDValueMap{
				"168.1.2": mapping.Value{Value: "192.168.1.2", Type: mapping.Asn1BER(mapping.IPAddress)},
			},
			expected: []diode.Entity{},
		},
		{
			name: "IPAddress with assigned interface",
			mapping: []config.MappingEntry{
				{
					OID:            ".1.3.6.1.2.1.2.2.1",
					Entity:         "interface",
					Field:          "_id",
					IdentifierSize: 1,
					MappingEntries: []config.MappingEntry{
						{
							OID:    ".1.3.6.1.2.1.2.2.1.2",
							Entity: "interface",
							Field:  "name",
						},
					},
				},
				{
					OID:            ".1.3.6.1.2.1.4.20.1",
					Entity:         "ipAddress",
					Field:          "_id",
					IdentifierSize: 4,
					MappingEntries: []config.MappingEntry{
						{
							OID:    ".1.3.6.1.2.1.4.20.1.1",
							Entity: "ipAddress",
							Field:  "address",
						},
						{
							OID:    ".1.3.6.1.2.1.4.20.1.2",
							Entity: "ipAddress",
							Field:  "assignedObject",
							Relationship: config.Relationship{
								Type:  "interface",
								Field: "_id",
							},
						},
					},
				},
			},
			objectIDs: mapping.ObjectIDValueMap{
				".1.3.6.1.2.1.2.2.1.2.999":          mapping.Value{Value: "GigabitEthernet1/0/1", Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1},
				".1.3.6.1.2.1.4.20.1.1.192.168.1.2": mapping.Value{Value: "192.168.1.2", Type: mapping.Asn1BER(mapping.IPAddress), IdentifierSize: 4},
				".1.3.6.1.2.1.4.20.1.2.192.168.1.2": mapping.Value{Value: "999", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 4},
			},
			expected: []diode.Entity{
				&diode.IPAddress{
					Address: diode.String("192.168.1.2/32"),
					AssignedObject: &diode.Interface{
						Name:   diode.String("GigabitEthernet1/0/1"),
						Type:   diode.String("other"),
						Device: &diode.Device{},
					},
				},
			},
		},
		{
			name: "Device with name",
			mapping: []config.MappingEntry{
				{
					OID:    ".1.3.6.1.2.1.1",
					Entity: "device",
					Field:  "_id",
					MappingEntries: []config.MappingEntry{
						{
							OID:    ".1.3.6.1.2.1.1.5.0",
							Entity: "device",
							Field:  "name",
						},
					},
				},
			},
			objectIDs: mapping.ObjectIDValueMap{
				".1.3.6.1.2.1.1.5.0": mapping.Value{Value: "test", Type: mapping.Asn1BER(mapping.OctetString)},
			},
			expected: []diode.Entity{
				&diode.Device{Name: diode.String("test")},
			},
		},
		{
			name: "Excluded interface and its IP are not ingested",
			mapping: []config.MappingEntry{
				{
					OID:            ".1.3.6.1.2.1.2.2.1",
					Entity:         "interface",
					Field:          "_id",
					IdentifierSize: 1,
					MappingEntries: []config.MappingEntry{
						{OID: ".1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
					},
				},
				{
					OID:            ".1.3.6.1.2.1.4.20.1",
					Entity:         "ipAddress",
					Field:          "_id",
					IdentifierSize: 4,
					MappingEntries: []config.MappingEntry{
						{OID: ".1.3.6.1.2.1.4.20.1.1", Entity: "ipAddress", Field: "address"},
						{
							OID:          ".1.3.6.1.2.1.4.20.1.2",
							Entity:       "ipAddress",
							Field:        "assignedObject",
							Relationship: config.Relationship{Type: "interface", Field: "_id"},
						},
					},
				},
			},
			objectIDs: mapping.ObjectIDValueMap{
				".1.3.6.1.2.1.2.2.1.2.1":         mapping.Value{Value: "eth0", Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1},
				".1.3.6.1.2.1.2.2.1.2.2":         mapping.Value{Value: "tap0", Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1},
				".1.3.6.1.2.1.4.20.1.1.10.0.0.1": mapping.Value{Value: "10.0.0.1", Type: mapping.Asn1BER(mapping.IPAddress), IdentifierSize: 4},
				".1.3.6.1.2.1.4.20.1.2.10.0.0.1": mapping.Value{Value: "2", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 4},
			},
			defaults: &config.Defaults{
				Interface:                config.InterfaceDefaults{Type: "other"},
				InterfaceExcludePatterns: []string{"^tap.*"},
			},
			expected: []diode.Entity{
				&diode.Interface{
					Name:   diode.String("eth0"),
					Type:   diode.String("other"),
					Device: &diode.Device{},
				},
			},
		},
		{
			name: "Device with platform from sysObjectID",
			mapping: []config.MappingEntry{
				{
					OID:    ".1.3.6.1.2.1.1",
					Entity: "device",
					Field:  "_id",
					MappingEntries: []config.MappingEntry{
						{
							OID:    ".1.3.6.1.2.1.1.2.0",
							Entity: "device",
							Field:  "platform",
						},
					},
				},
			},
			objectIDs: mapping.ObjectIDValueMap{
				".1.3.6.1.2.1.1.2.0": mapping.Value{Value: "1.3.6.1.4.1.9.1.1234", Type: mapping.Asn1BER(mapping.ObjectIdentifier)},
			},
			expected: []diode.Entity{
				&diode.Device{
					DeviceType: &diode.DeviceType{
						Manufacturer: &diode.Manufacturer{
							Name: diode.String("Cisco"),
						},
						Model: diode.String("cisco4000"),
					},
					Platform: &diode.Platform{
						Name: diode.String("Cisco"),
						Slug: diode.String("cisco"),
						Manufacturer: &diode.Manufacturer{
							Name: diode.String("Cisco"),
						},
					},
				},
			},
		},
		{
			name: "Invalid exclude pattern is skipped, valid pattern still applies",
			mapping: []config.MappingEntry{
				{
					OID:            ".1.3.6.1.2.1.2.2.1",
					Entity:         "interface",
					Field:          "_id",
					IdentifierSize: 1,
					MappingEntries: []config.MappingEntry{
						{OID: ".1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
					},
				},
			},
			objectIDs: mapping.ObjectIDValueMap{
				".1.3.6.1.2.1.2.2.1.2.1": mapping.Value{Value: "tap0", Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1},
				".1.3.6.1.2.1.2.2.1.2.2": mapping.Value{Value: "eth0", Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1},
			},
			defaults: &config.Defaults{
				Interface:                config.InterfaceDefaults{Type: "other"},
				InterfaceExcludePatterns: []string{"[invalid", "^tap.*"},
			},
			expected: []diode.Entity{
				&diode.Interface{
					Name:   diode.String("eth0"),
					Type:   diode.String("other"),
					Device: &diode.Device{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mappingConfig, err := mapping.NewConfig(tt.mapping, slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false})), &FakeManufacturers{}, &FakeDeviceLookup{}, nil)
			assert.NoError(t, err)
			defaults := tt.defaults
			if defaults == nil {
				defaults = &config.Defaults{
					Interface: config.InterfaceDefaults{
						Type: "other",
					},
				}
			}
			mapper := mapping.NewObjectIDMapper(mappingConfig, slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false})), defaults, "")
			entities := mapper.MapObjectIDsToEntity(tt.objectIDs)

			assert.ElementsMatch(t, tt.expected, entities)
		})
	}
}

func TestObjectIDs(t *testing.T) {
	tests := []struct {
		name         string
		mapping      []config.MappingEntry
		expectedOIDs map[string]int
	}{
		{
			name: "Single OID",
			mapping: []config.MappingEntry{
				{
					OID:            "1.3.6.1.2.1.4.20.1.1",
					Entity:         "ipAddress",
					Field:          "address",
					IdentifierSize: 4,
				},
			},
			expectedOIDs: map[string]int{
				"1.3.6.1.2.1.4.20.1.1": 4,
			},
		},
		{
			name: "Child OIDs from parent mapping",
			mapping: []config.MappingEntry{
				{
					OID:    ".1.3.6.1.2.1.2.2.1",
					Entity: "interface",
					Field:  "_id",
					MappingEntries: []config.MappingEntry{
						{
							OID:    ".1.3.6.1.2.1.2.2.1.2",
							Entity: "interface",
							Field:  "name",
						},
						{
							OID:    ".1.3.6.1.2.1.2.2.1.5",
							Entity: "interface",
							Field:  "speed",
						},
					},
				},
			},
			expectedOIDs: map[string]int{
				".1.3.6.1.2.1.2.2.1.2": 1,
				".1.3.6.1.2.1.2.2.1.5": 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mappingConfig, err := mapping.NewConfig(tt.mapping, slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false})), &FakeManufacturers{}, &FakeDeviceLookup{}, nil)
			assert.NoError(t, err)
			objectIDs := mappingConfig.ObjectIDs()

			assert.Equal(t, tt.expectedOIDs, objectIDs)
		})
	}
}

func TestObjectIDIndex_HasParent(t *testing.T) {
	tests := []struct {
		name     string
		index    mapping.ObjectIDIndex
		parent   string
		expected bool
	}{
		{
			name:     "exact match",
			index:    "1.2.3.4",
			parent:   "1.2.3.4",
			expected: true,
		},
		{
			name:     "valid parent",
			index:    "1.2.3.4.5.6",
			parent:   "1.2.3.4",
			expected: true,
		},
		{
			name:     "invalid parent",
			index:    "1.2.3.4.5.6",
			parent:   "1.2.3.5",
			expected: false,
		},
		{
			name:     "empty parent",
			index:    "1.2.3.4",
			parent:   "",
			expected: false,
		},
		{
			name:     "empty index",
			index:    "",
			parent:   "1.2.3.4",
			expected: false,
		},
		{
			name:     "parent longer than index",
			index:    "1.2.3",
			parent:   "1.2.3.4",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.index.HasParent(tt.parent)
			if result != tt.expected {
				t.Errorf("HasParent() = %v, want %v for index %q and parent %q",
					result, tt.expected, tt.index, tt.parent)
			}
		})
	}
}

func extractIdentifierSize(mappingEntry config.MappingEntry) int {
	if mappingEntry.MappingEntries[0].IdentifierSize != 0 {
		return mappingEntry.MappingEntries[0].IdentifierSize
	}
	if mappingEntry.IdentifierSize == 0 {
		return 1 // Default value when parent is 0
	}
	return mappingEntry.IdentifierSize
}

func TestIPAddressIdentifierSizeInheritance(t *testing.T) {
	tests := []struct {
		name        string
		mapping     []config.MappingEntry
		objectIDs   mapping.ObjectIDValueMap
		expected    []diode.Entity
		description string
	}{
		{
			name: "IP address child mappings inherit identifier size from parent (replicates log scenario)",
			mapping: []config.MappingEntry{
				{
					OID:            ".1.3.6.1.2.1.4.20.1",
					Entity:         "ipAddress",
					Field:          "_id",
					IdentifierSize: 4, // Parent has identifier size 4 for IPv4 addresses
					MappingEntries: []config.MappingEntry{
						{
							OID:    ".1.3.6.1.2.1.4.20.1.1",
							Entity: "ipAddress",
							Field:  "address",
							// No IdentifierSize specified - should inherit from parent
						},
						{
							OID:    ".1.3.6.1.2.1.4.20.1.3",
							Entity: "ipAddress",
							Field:  "addressPrefixSize",
							// No IdentifierSize specified - should inherit from parent
						},
					},
				},
			},
			objectIDs: mapping.ObjectIDValueMap{
				// This simulates the scenario from the logs where we have a full IP address in the OID
				".1.3.6.1.2.1.4.20.1.1.192.168.1.100": mapping.Value{
					Value:          "192.168.1.100",
					Type:           mapping.Asn1BER(mapping.IPAddress),
					IdentifierSize: 4, // This should be inherited by child mappings
				},
				".1.3.6.1.2.1.4.20.1.3.192.168.1.100": mapping.Value{
					Value:          "255.255.255.0", // Netmask
					Type:           mapping.Asn1BER(mapping.IPAddress),
					IdentifierSize: 4,
				},
			},
			expected: []diode.Entity{
				&diode.IPAddress{
					Address: diode.String("192.168.1.100/24"), // Should get full IP with correct prefix
				},
			},
			description: "This test verifies that IP addresses are parsed correctly with all 4 octets instead of just the last octet",
		},
		{
			name: "Child mapping with explicit identifier size overrides parent",
			mapping: []config.MappingEntry{
				{
					OID:            ".1.3.6.1.2.1.4.20.1",
					Entity:         "ipAddress",
					Field:          "_id",
					IdentifierSize: 4, // Parent has identifier size 4
					MappingEntries: []config.MappingEntry{
						{
							OID:            ".1.3.6.1.2.1.4.20.1.1",
							Entity:         "ipAddress",
							Field:          "address",
							IdentifierSize: 2, // Child explicitly sets different size
						},
					},
				},
			},
			objectIDs: mapping.ObjectIDValueMap{
				".1.3.6.1.2.1.4.20.1.1.1.2": mapping.Value{
					Value:          "1.2",
					Type:           mapping.Asn1BER(mapping.IPAddress),
					IdentifierSize: 2, // Should use child's explicit size
				},
			},
			expected: []diode.Entity{
				&diode.IPAddress{
					Address: nil, // Invalid IP format "1.2" is rejected by validation
				},
			},
			description: "This test verifies that child mappings can override parent identifier size, but invalid IPs are still rejected",
		},
		{
			name: "Zero identifier size on parent defaults correctly",
			mapping: []config.MappingEntry{
				{
					OID:            ".1.3.6.1.2.1.4.20.1",
					Entity:         "ipAddress",
					Field:          "_id",
					IdentifierSize: 0, // Parent has zero identifier size
					MappingEntries: []config.MappingEntry{
						{
							OID:    ".1.3.6.1.2.1.4.20.1.1",
							Entity: "ipAddress",
							Field:  "address",
							// Should inherit 0 from parent
						},
					},
				},
			},
			objectIDs: mapping.ObjectIDValueMap{
				".1.3.6.1.2.1.4.20.1.1.192": mapping.Value{
					Value:          "192",
					Type:           mapping.Asn1BER(mapping.IPAddress),
					IdentifierSize: 0, // This would default to 1 in ObjectIDs() function
				},
			},
			expected: []diode.Entity{
				&diode.IPAddress{
					Address: nil, // Invalid IP format (incomplete) is rejected by validation
				},
			},
			description: "This test verifies behavior when parent has zero identifier size - invalid IPs are rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
			mappingConfig, err := mapping.NewConfig(tt.mapping, logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil)
			assert.NoError(t, err)
			objectIDMapper := mapping.NewObjectIDMapper(mappingConfig, logger, &config.Defaults{}, "")

			entities := objectIDMapper.MapObjectIDsToEntity(tt.objectIDs)

			// Sort both slices for consistent comparison
			assert.ElementsMatch(t, tt.expected, entities, tt.description)

			// Additional verification: check that ObjectIDs() returns correct identifier sizes
			objectIDs := mappingConfig.ObjectIDs()
			for oid, expectedSize := range map[string]int{
				".1.3.6.1.2.1.4.20.1.1": extractIdentifierSize(tt.mapping[0]),
			} {
				if actualSize, exists := objectIDs[oid]; exists {
					assert.Equal(t, expectedSize, actualSize,
						"OID %s should have identifier size %d but got %d", oid, expectedSize, actualSize)
				}
			}
		})
	}
}

func TestObjectIDsMethodWithIdentifierSizeInheritance(t *testing.T) {
	tests := []struct {
		name         string
		mapping      []config.MappingEntry
		expectedOIDs map[string]int
		description  string
	}{
		{
			name: "IP address mappings with inherited identifier sizes",
			mapping: []config.MappingEntry{
				{
					OID:            ".1.3.6.1.2.1.4.20.1",
					Entity:         "ipAddress",
					Field:          "_id",
					IdentifierSize: 4,
					MappingEntries: []config.MappingEntry{
						{
							OID:    ".1.3.6.1.2.1.4.20.1.1",
							Entity: "ipAddress",
							Field:  "address",
							// Should inherit IdentifierSize 4 from parent
						},
						{
							OID:    ".1.3.6.1.2.1.4.20.1.3",
							Entity: "ipAddress",
							Field:  "addressPrefixSize",
							// Should inherit IdentifierSize 4 from parent
						},
					},
				},
			},
			expectedOIDs: map[string]int{
				".1.3.6.1.2.1.4.20.1.1": 4, // Should inherit from parent
				".1.3.6.1.2.1.4.20.1.3": 4, // Should inherit from parent
			},
			description: "Child OIDs should inherit identifier size 4 from parent for IP address parsing",
		},
		{
			name: "Mixed inheritance and explicit identifier sizes",
			mapping: []config.MappingEntry{
				{
					OID:            ".1.3.6.1.2.1.2.2.1",
					Entity:         "interface",
					Field:          "_id",
					IdentifierSize: 1,
					MappingEntries: []config.MappingEntry{
						{
							OID:    ".1.3.6.1.2.1.2.2.1.2",
							Entity: "interface",
							Field:  "name",
							// Should inherit IdentifierSize 1 from parent
						},
						{
							OID:            ".1.3.6.1.2.1.2.2.1.5",
							Entity:         "interface",
							Field:          "speed",
							IdentifierSize: 2, // Explicit override
						},
					},
				},
			},
			expectedOIDs: map[string]int{
				".1.3.6.1.2.1.2.2.1.2": 1, // Inherited from parent
				".1.3.6.1.2.1.2.2.1.5": 2, // Explicit override
			},
			description: "Mix of inherited and explicit identifier sizes should work correctly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
			mappingConfig, err := mapping.NewConfig(tt.mapping, logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil)
			assert.NoError(t, err)
			objectIDs := mappingConfig.ObjectIDs()

			for expectedOID, expectedSize := range tt.expectedOIDs {
				actualSize, exists := objectIDs[expectedOID]
				assert.True(t, exists, "OID %s should exist in ObjectIDs() output", expectedOID)
				assert.Equal(t, expectedSize, actualSize,
					"OID %s should have identifier size %d but got %d. %s",
					expectedOID, expectedSize, actualSize, tt.description)
			}
		})
	}
}

// --- OBS-1896: primary IP assignment tests ---

// primaryIPFixture is the minimal mapping config the primary-IP tests reuse:
// one interface entry + one ipAddress entry that assigns itself to the
// interface. The ipAddress index carries the full IPv4 address (IdentifierSize
// = 4) so different discovered IPs live under different ObjectIDIndex keys.
func primaryIPFixture() []config.MappingEntry {
	return []config.MappingEntry{
		{
			OID:            ".1.3.6.1.2.1.2.2.1",
			Entity:         "interface",
			Field:          "_id",
			IdentifierSize: 1,
			MappingEntries: []config.MappingEntry{
				{OID: ".1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
			},
		},
		{
			OID:            ".1.3.6.1.2.1.4.20.1",
			Entity:         "ipAddress",
			Field:          "_id",
			IdentifierSize: 4,
			MappingEntries: []config.MappingEntry{
				{OID: ".1.3.6.1.2.1.4.20.1.1", Entity: "ipAddress", Field: "address"},
				{
					OID:          ".1.3.6.1.2.1.4.20.1.2",
					Entity:       "ipAddress",
					Field:        "assignedObject",
					Relationship: config.Relationship{Type: "interface"},
				},
			},
		},
	}
}

// primaryIPOneInterfaceOIDs seeds one interface named "Gi0" (ifIndex 1) and
// one IP address at the given literal address, assigned to that interface.
func primaryIPOneInterfaceOIDs(address, ifName string) mapping.ObjectIDValueMap {
	return mapping.ObjectIDValueMap{
		".1.3.6.1.2.1.2.2.1.2.1": mapping.Value{
			Value: ifName, Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1,
		},
		".1.3.6.1.2.1.4.20.1.1." + address: mapping.Value{
			Value: address, Type: mapping.Asn1BER(mapping.IPAddress), IdentifierSize: 4,
		},
		".1.3.6.1.2.1.4.20.1.2." + address: mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 4,
		},
	}
}

// findDevice returns the first non-nil device pointer reachable through the
// emitted entities. It prefers a standalone diode.Device entity but falls
// back to an Interface's Device reference (the same currentDevice pointer).
func findDevice(entities []diode.Entity) *diode.Device {
	for _, e := range entities {
		if d, ok := e.(*diode.Device); ok {
			return d
		}
	}
	for _, e := range entities {
		if iface, ok := e.(*diode.Interface); ok && iface.Device != nil {
			return iface.Device
		}
		if ip, ok := e.(*diode.IPAddress); ok {
			if iface, ok := ip.AssignedObject.(*diode.Interface); ok && iface.Device != nil {
				return iface.Device
			}
		}
	}
	return nil
}

func TestAssignPrimaryIP_DirectIPv4Match(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil)
	assert.NoError(t, err)

	m := mapping.NewObjectIDMapper(mappingConfig, logger, &config.Defaults{}, "10.0.0.1")
	entities := m.MapObjectIDsToEntity(primaryIPOneInterfaceOIDs("10.0.0.1", "Gi0"))

	device := findDevice(entities)
	assert.NotNil(t, device, "device reference must be reachable")
	assert.NotNil(t, device.PrimaryIp4, "primary IP must be assigned")
	if device.PrimaryIp4 != nil {
		assert.Equal(t, "10.0.0.1/32", *device.PrimaryIp4.Address)
	}
}

// TestAssignPrimaryIP_DeviceIsProtoSerializable is the regression test for
// the reference-cycle bug that caused a stack overflow during ingestion
// against a real diode target. Before the fix, device.PrimaryIp4 shared a
// pointer with an IPAddress whose assigned Interface pointed back at the
// same Device -- the diode SDK's proto serializer recursed forever.
func TestAssignPrimaryIP_DeviceIsProtoSerializable(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil)
	assert.NoError(t, err)

	m := mapping.NewObjectIDMapper(mappingConfig, logger, &config.Defaults{}, "10.0.0.1")
	entities := m.MapObjectIDsToEntity(primaryIPOneInterfaceOIDs("10.0.0.1", "Gi0"))

	device := m.CurrentDevice()
	assert.NotNil(t, device.PrimaryIp4)

	// Converting every emitted entity to its proto form must complete
	// without recursing into the primary_ip4 -> interface -> device cycle.
	for _, e := range entities {
		proto := e.ConvertToProtoEntity()
		assert.NotNil(t, proto)
	}
	// The device itself is constructed on the fly by the caller; exercise
	// the path that crashed in the lab (marshal a live Device entity).
	proto := device.ConvertToProtoEntity()
	assert.NotNil(t, proto)

	// The snapshot must keep the nested Device reference (Diode requires
	// Interface.device to be set) but that nested Device must have
	// PrimaryIp4 cleared so the graph is a tree, not a cycle.
	if iface, ok := device.PrimaryIp4.AssignedObject.(*diode.Interface); ok && iface != nil {
		assert.NotNil(t, iface.Device, "PrimaryIp4 snapshot must keep a Device on the assigned interface")
		if iface.Device != nil {
			assert.Nil(t, iface.Device.PrimaryIp4, "nested Device must have PrimaryIp4 cleared to break the cycle")
		}
	}
}

// TestAssignPrimaryIP_DeviceIsProtoSerializable_WithSubinterfaceParent
// covers the specific regression flagged by the PR #368 review: if the
// matched IPAddress is assigned to a subinterface (which has a Parent
// pointer back into the interface graph), a shallow-only copy still
// serializes into a cycle unless the relationship pointers are cleared.
// We seed the scenario directly via the test helper.
func TestAssignPrimaryIP_DeviceIsProtoSerializable_WithSubinterfaceParent(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil)
	assert.NoError(t, err)

	m := mapping.NewObjectIDMapper(mappingConfig, logger, &config.Defaults{}, "10.0.0.1")
	device := m.CurrentDevice()

	// Build: subinterface "Gi0.10" with back-references on every cycle-prone
	// field -- Parent, Bridge, Lag, and Module all point at entities whose
	// Device is the owning `device` (which carries PrimaryIp4 once
	// assignPrimaryIP runs). Without the relationship-pointer prune in
	// detachForPrimaryIP, ConvertToProtoEntity would recurse forever via
	// PrimaryIp4 -> subinterface copy -> (any of those pointers) ->
	// Device (same) -> PrimaryIp4 -> ...
	parentName := "Gi0"
	parent := &diode.Interface{Name: &parentName, Device: device}
	bridgeName := "br0"
	bridge := &diode.Interface{Name: &bridgeName, Device: device}
	lagName := "Port-Channel1"
	lag := &diode.Interface{Name: &lagName, Device: device}
	module := &diode.Module{Device: device}
	subName := "Gi0.10"
	sub := &diode.Interface{
		Name:   &subName,
		Device: device,
		Parent: parent,
		Bridge: bridge,
		Lag:    lag,
		Module: module,
	}
	addr := "10.0.0.1/32"
	ip := &diode.IPAddress{Address: &addr, AssignedObject: sub}

	entities := map[diode.Entity]bool{ip: true}
	m.AssignPrimaryIPForTest(device, entities)

	assert.NotNil(t, device.PrimaryIp4)
	// Serialization must terminate.
	proto := device.ConvertToProtoEntity()
	assert.NotNil(t, proto)

	// Snapshot must not retain the Parent / Bridge / Lag / Module
	// back-references.
	snap, ok := device.PrimaryIp4.AssignedObject.(*diode.Interface)
	assert.True(t, ok)
	assert.Nil(t, snap.Parent, "snapshot interface must not retain Parent back-edge")
	assert.Nil(t, snap.Bridge, "snapshot interface must not retain Bridge back-edge")
	assert.Nil(t, snap.Lag, "snapshot interface must not retain Lag back-edge")
	assert.Nil(t, snap.Module, "snapshot interface must not retain Module back-edge")
}

func TestAssignPrimaryIP_NoMatch(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil)
	assert.NoError(t, err)

	// Target 10.0.0.1, discovered only 10.0.0.2.
	m := mapping.NewObjectIDMapper(mappingConfig, logger, &config.Defaults{}, "10.0.0.1")
	entities := m.MapObjectIDsToEntity(primaryIPOneInterfaceOIDs("10.0.0.2", "Gi0"))

	device := findDevice(entities)
	assert.NotNil(t, device)
	assert.Nil(t, device.PrimaryIp4, "primary IP must not be set when no match")
}

// bufferHandler captures slog records for assertion.
type bufferHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *bufferHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *bufferHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	// r.Clone() is required per slog docs: the Record's contents may be
	// reused by the caller after Handle returns.
	h.records = append(h.records, r.Clone())
	return nil
}
func (h *bufferHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *bufferHandler) WithGroup(_ string) slog.Handler      { return h }

func (h *bufferHandler) find(level slog.Level, msg string) *slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.records {
		if h.records[i].Level == level && h.records[i].Message == msg {
			return &h.records[i]
		}
	}
	return nil
}

type fakeResolver struct {
	addrs []string
	err   error
}

func (f *fakeResolver) LookupHost(_ context.Context, _ string) ([]string, error) {
	return f.addrs, f.err
}

func TestAssignPrimaryIP_HostnameResolvesToIPv4(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil)
	assert.NoError(t, err)

	resolver := &fakeResolver{addrs: []string{"10.0.0.1"}}
	m := mapping.NewObjectIDMapperForTest(mappingConfig, logger, &config.Defaults{}, "router.example", resolver)

	entities := m.MapObjectIDsToEntity(primaryIPOneInterfaceOIDs("10.0.0.1", "Gi0"))
	device := findDevice(entities)
	assert.NotNil(t, device.PrimaryIp4)
	assert.Equal(t, "10.0.0.1/32", *device.PrimaryIp4.Address)
}

func TestAssignPrimaryIP_HostnameResolvesToIPv6Only(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil)
	assert.NoError(t, err)

	resolver := &fakeResolver{addrs: []string{"2001:db8::1"}}
	m := mapping.NewObjectIDMapperForTest(mappingConfig, logger, &config.Defaults{}, "router.example", resolver)

	entities := m.MapObjectIDsToEntity(primaryIPOneInterfaceOIDs("10.0.0.1", "Gi0"))
	device := findDevice(entities)
	assert.NotNil(t, device)
	assert.Nil(t, device.PrimaryIp4, "IPv6-only DNS result must not yield a PrimaryIp4")
}

func TestAssignPrimaryIP_InvalidHost(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil)
	assert.NoError(t, err)

	resolver := &fakeResolver{err: errors.New("nxdomain")}
	m := mapping.NewObjectIDMapperForTest(mappingConfig, logger, &config.Defaults{}, "nope.invalid", resolver)

	entities := m.MapObjectIDsToEntity(primaryIPOneInterfaceOIDs("10.0.0.1", "Gi0"))
	device := findDevice(entities)
	assert.NotNil(t, device)
	assert.Nil(t, device.PrimaryIp4)
}

func TestAssignPrimaryIP_MultipleMatches(t *testing.T) {
	handler := &bufferHandler{}
	logger := slog.New(handler)

	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil)
	assert.NoError(t, err)

	m := mapping.NewObjectIDMapper(mappingConfig, logger, &config.Defaults{}, "10.0.0.1")

	// Build two IPAddress entities sharing the same stripped address but
	// assigned to two distinct interfaces, so primaryIPSortKey differs.
	ip1Name := "Loopback0"
	ip2Name := "GigabitEthernet0/1"
	addr := "10.0.0.1/32"
	ip1 := &diode.IPAddress{
		Address:        &addr,
		AssignedObject: &diode.Interface{Name: &ip1Name},
	}
	ip2 := &diode.IPAddress{
		Address:        &addr,
		AssignedObject: &diode.Interface{Name: &ip2Name},
	}

	entities := map[diode.Entity]bool{ip1: true, ip2: true}
	device := m.CurrentDevice()

	m.AssignPrimaryIPForTest(device, entities)

	if assert.NotNil(t, device.PrimaryIp4) && assert.NotNil(t, device.PrimaryIp4.Address) {
		// Lexicographically smaller key wins:
		//   "10.0.0.1/32|GigabitEthernet0/1" < "10.0.0.1/32|Loopback0"
		assert.Equal(t, "10.0.0.1/32", *device.PrimaryIp4.Address)
		if snapshotIface, ok := device.PrimaryIp4.AssignedObject.(*diode.Interface); assert.True(t, ok) && assert.NotNil(t, snapshotIface.Name) {
			assert.Equal(t, ip2Name, *snapshotIface.Name,
				"deterministic selection must prefer the smaller sort key")
		}
	}

	rec := handler.find(slog.LevelWarn, "multiple IP candidates for primary IP assignment; picking deterministic first")
	assert.NotNil(t, rec, "expected Warn log for multi-match")
}

// TestAssignPrimaryIP_MultipleMatches_EqualCompositeKey exercises the
// content-based tiebreaker when two entries have the same primaryIPSortKey
// (same address, same assigned interface name). Deterministic selection
// must still hold via primaryIPContentKey.
func TestAssignPrimaryIP_MultipleMatches_EqualCompositeKey(t *testing.T) {
	handler := &bufferHandler{}
	logger := slog.New(handler)

	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil)
	assert.NoError(t, err)

	m := mapping.NewObjectIDMapper(mappingConfig, logger, &config.Defaults{}, "10.0.0.1")

	// Identical address and interface name: composite sort key collides.
	// The entities differ by Description so the content-based tiebreaker
	// picks the lexicographically-smaller JSON serialization.
	ifName := "Loopback0"
	addr := "10.0.0.1/32"
	descA := "alpha"
	descB := "bravo"
	ipA := &diode.IPAddress{
		Address:        &addr,
		AssignedObject: &diode.Interface{Name: &ifName},
		Description:    &descA,
	}
	ipB := &diode.IPAddress{
		Address:        &addr,
		AssignedObject: &diode.Interface{Name: &ifName},
		Description:    &descB,
	}
	entities := map[diode.Entity]bool{ipA: true, ipB: true}
	device := m.CurrentDevice()

	m.AssignPrimaryIPForTest(device, entities)

	if assert.NotNil(t, device.PrimaryIp4) && assert.NotNil(t, device.PrimaryIp4.Description) {
		// JSON of ipA contains "alpha" which is < "bravo"; deterministic pick: ipA.
		assert.Equal(t, "alpha", *device.PrimaryIp4.Description)
	}

	rec := handler.find(slog.LevelWarn, "multiple IP candidates for primary IP assignment; picking deterministic first")
	assert.NotNil(t, rec, "expected Warn log for multi-match")
}

// TestAssignPrimaryIP_UnassignedIPIgnored verifies the "verified interface
// IP" guarantee: a discovered IPAddress whose AssignedObject is not an
// Interface is not a valid primary-IP candidate even if its address matches
// the target.
func TestAssignPrimaryIP_UnassignedIPIgnored(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil)
	assert.NoError(t, err)

	m := mapping.NewObjectIDMapper(mappingConfig, logger, &config.Defaults{}, "10.0.0.1")

	addr := "10.0.0.1/32"
	unassigned := &diode.IPAddress{Address: &addr} // AssignedObject is nil
	entities := map[diode.Entity]bool{unassigned: true}
	device := m.CurrentDevice()

	m.AssignPrimaryIPForTest(device, entities)

	assert.Nil(t, device.PrimaryIp4, "primary IP must not be set from an IPAddress without an Interface assignment")
}

func TestAssignPrimaryIP_ExcludedInterfaceIP(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// The IP is assigned to an interface whose name matches the exclusion
	// pattern; filterExcludedEntities drops the IPAddress, so primary-IP
	// must remain nil.
	defaults := &config.Defaults{
		InterfaceExcludePatterns: []string{"^Null.*"},
	}
	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, defaults)
	assert.NoError(t, err)

	m := mapping.NewObjectIDMapper(mappingConfig, logger, defaults, "10.0.0.1")
	_ = m.MapObjectIDsToEntity(primaryIPOneInterfaceOIDs("10.0.0.1", "Null0"))

	// Interface+IP are both excluded from the output, so reach the device
	// directly via the test helper.
	device := m.CurrentDevice()
	assert.NotNil(t, device)
	assert.Nil(t, device.PrimaryIp4, "primary IP must not point to an IPAddress on an excluded interface")
}

func TestAssignPrimaryIP_PrefixStripping(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Reuses the default /32 emission: verifies stripPrefix drops "/32"
	// before comparing to the bare target literal.
	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil)
	assert.NoError(t, err)

	m := mapping.NewObjectIDMapper(mappingConfig, logger, &config.Defaults{}, "10.0.0.1")
	entities := m.MapObjectIDsToEntity(primaryIPOneInterfaceOIDs("10.0.0.1", "Gi0"))

	device := findDevice(entities)
	assert.NotNil(t, device.PrimaryIp4)
	assert.Equal(t, "10.0.0.1/32", *device.PrimaryIp4.Address)
}

// TestAssignPrimaryIP_NonDefaultPrefix exercises the stripPrefix path with a
// real subnet-mask-derived prefix (/24) rather than the default /32.
func TestAssignPrimaryIP_NonDefaultPrefix(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Extend the default fixture with addressPrefixSize so the emitted
	// IPAddress carries /24.
	entries := []config.MappingEntry{
		{
			OID:            ".1.3.6.1.2.1.2.2.1",
			Entity:         "interface",
			Field:          "_id",
			IdentifierSize: 1,
			MappingEntries: []config.MappingEntry{
				{OID: ".1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
			},
		},
		{
			OID:            ".1.3.6.1.2.1.4.20.1",
			Entity:         "ipAddress",
			Field:          "_id",
			IdentifierSize: 4,
			MappingEntries: []config.MappingEntry{
				{OID: ".1.3.6.1.2.1.4.20.1.1", Entity: "ipAddress", Field: "address"},
				{OID: ".1.3.6.1.2.1.4.20.1.3", Entity: "ipAddress", Field: "addressPrefixSize"},
				{
					OID:          ".1.3.6.1.2.1.4.20.1.2",
					Entity:       "ipAddress",
					Field:        "assignedObject",
					Relationship: config.Relationship{Type: "interface"},
				},
			},
		},
	}
	mappingConfig, err := mapping.NewConfig(entries, logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil)
	assert.NoError(t, err)

	oids := mapping.ObjectIDValueMap{
		".1.3.6.1.2.1.2.2.1.2.1": mapping.Value{
			Value: "Gi0", Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1,
		},
		".1.3.6.1.2.1.4.20.1.1.10.0.0.1": mapping.Value{
			Value: "10.0.0.1", Type: mapping.Asn1BER(mapping.IPAddress), IdentifierSize: 4,
		},
		".1.3.6.1.2.1.4.20.1.3.10.0.0.1": mapping.Value{
			Value: "255.255.255.0", Type: mapping.Asn1BER(mapping.IPAddress), IdentifierSize: 4,
		},
		".1.3.6.1.2.1.4.20.1.2.10.0.0.1": mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 4,
		},
	}

	m := mapping.NewObjectIDMapper(mappingConfig, logger, &config.Defaults{}, "10.0.0.1")
	entities := m.MapObjectIDsToEntity(oids)

	device := findDevice(entities)
	assert.NotNil(t, device.PrimaryIp4)
	assert.Equal(t, "10.0.0.1/24", *device.PrimaryIp4.Address,
		"primary IP must carry the discovered /24 prefix, and stripPrefix must still match against the bare target")
}
