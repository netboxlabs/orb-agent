package mapping_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/mapping"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

type FakeManufacturers struct{}

func (f *FakeManufacturers) GetManufacturer(_ string) (string, error) {
	return "Cisco", nil
}

type FakeDeviceLookup struct{}

func (f *FakeDeviceLookup) GetDevice(_ string) (string, error) {
	return "cisco4000", nil
}

func (f *FakeDeviceLookup) GetDeviceModel(_ string, _ map[string]string) (string, error) {
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
			mappingConfig, err := mapping.NewConfig(tt.mapping, slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false})), &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
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
			mappingConfig, err := mapping.NewConfig(tt.mapping, slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false})), &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
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
			// IPAddressMapper now drops invalid/empty rows by returning
			// nil rather than emitting an IPAddress with no Address.
			// MapObjectIDsToEntity therefore yields no IPAddress
			// entities for this row.
			expected:    []diode.Entity{},
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
			// Same drop semantics as above: invalid/empty rows are no
			// longer emitted as nil-Address entities.
			expected:    []diode.Entity{},
			description: "This test verifies behavior when parent has zero identifier size - invalid IPs are rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
			mappingConfig, err := mapping.NewConfig(tt.mapping, logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
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
			mappingConfig, err := mapping.NewConfig(tt.mapping, logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
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

	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
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

	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
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

// TestAssignPrimaryIP_DeviceIsProtoSerializable_IPv6 mirrors
// TestAssignPrimaryIP_DeviceIsProtoSerializable for the v6 path. The
// detachForPrimaryIP6 helper is duplicated from its v4 sibling and
// could drift independently, reintroducing the cycle bug for
// PrimaryIp6 without tripping any existing PrimaryIp4 coverage.
func TestAssignPrimaryIP_DeviceIsProtoSerializable_IPv6(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mappingConfig, err := mapping.NewConfig(primaryIPFixtureBothTables(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
	assert.NoError(t, err)

	m := mapping.NewObjectIDMapper(mappingConfig, logger, &config.Defaults{}, "2001:db8::1")
	entities := m.MapObjectIDsToEntity(primaryIPModernIPv6OIDs("2001:db8::1", "Gi0", 64))

	device := m.CurrentDevice()
	assert.NotNil(t, device.PrimaryIp6, "v6 literal target must yield PrimaryIp6")

	// Every emitted entity must serialize without recursing into the
	// primary_ip6 -> interface -> device cycle.
	for _, e := range entities {
		proto := e.ConvertToProtoEntity()
		assert.NotNil(t, proto)
	}
	proto := device.ConvertToProtoEntity()
	assert.NotNil(t, proto)

	// The snapshot keeps the nested Device reference but that nested
	// Device must have BOTH primary IPs cleared so the graph is a
	// tree, not a cycle (regardless of evaluation order between v4
	// and v6 passes).
	if iface, ok := device.PrimaryIp6.AssignedObject.(*diode.Interface); ok && iface != nil {
		assert.NotNil(t, iface.Device, "PrimaryIp6 snapshot must keep a Device on the assigned interface")
		if iface.Device != nil {
			assert.Nil(t, iface.Device.PrimaryIp4, "nested Device must have PrimaryIp4 cleared to break the cycle")
			assert.Nil(t, iface.Device.PrimaryIp6, "nested Device must have PrimaryIp6 cleared to break the cycle")
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

	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
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

	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
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

	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
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

	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
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

	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
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

	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
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

	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
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

	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
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
	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, defaults, config.Options{})
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
	mappingConfig, err := mapping.NewConfig(primaryIPFixture(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
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
	mappingConfig, err := mapping.NewConfig(entries, logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
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

// --- RFC 4293 ipAddressTable + dedup integration (OBS-2798) ---

// primaryIPFixtureBothTables returns a mapping config with both the legacy
// ipAddrTable and the modern ipAddressTable wired up against the shared
// interface entry. Used by dedup and primary-IP integration tests.
func primaryIPFixtureBothTables() []config.MappingEntry {
	entries := primaryIPFixture()
	entries = append(entries, config.MappingEntry{
		OID:       ".1.3.6.1.2.1.4.34.1",
		Entity:    "ipAddress",
		Field:     "_id",
		IndexKind: "inet_address",
		MappingEntries: []config.MappingEntry{
			{
				OID: ".1.3.6.1.2.1.4.34.1.3", Entity: "ipAddress", Field: "assignedObject",
				Relationship: config.Relationship{Type: "interface"},
			},
			{OID: ".1.3.6.1.2.1.4.34.1.4", Entity: "ipAddress", Field: "addressType"},
			{OID: ".1.3.6.1.2.1.4.34.1.5", Entity: "ipAddress", Field: "addressPrefix"},
			{OID: ".1.3.6.1.2.1.4.34.1.7", Entity: "ipAddress", Field: "addressStatus"},
			{OID: ".1.3.6.1.2.1.4.34.1.10", Entity: "ipAddress", Field: "addressRowStatus"},
		},
	})
	return entries
}

// ipv4NetworkOctets returns the dotted network address (host bits
// zeroed) for an IPv4 address + prefix length, formatted as decimal
// octets joined by dots. Used to build RFC 4293-compliant test
// RowPointers into ipAddressPrefixTable.
func ipv4NetworkOctets(addr string, plen int) string {
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		panic("ipv4NetworkOctets requires an IPv4 literal: " + addr)
	}
	mask := net.CIDRMask(plen, 32)
	network := ip.Mask(mask)
	return fmt.Sprintf("%d.%d.%d.%d", network[0], network[1], network[2], network[3])
}

// ipv6NetworkBytes returns the 16-byte network address (host bits
// zeroed) for an IPv6 address + prefix length, formatted as decimal
// octets joined by dots. IPv4-mapped IPv6 inputs (e.g. ::ffff:10.0.0.1)
// are accepted — they're encoded as addrType=2/addrLen=16 in
// ipAddressTable, so callers building RowPointers for them still need
// 16-byte network output.
func ipv6NetworkBytes(addr string, plen int) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		panic("ipv6NetworkBytes requires a parseable IP literal: " + addr)
	}
	ip = ip.To16()
	if ip == nil {
		panic("ipv6NetworkBytes requires a 16-byte address: " + addr)
	}
	mask := net.CIDRMask(plen, 128)
	network := ip.Mask(mask)
	parts := make([]string, 16)
	for i, b := range network {
		parts[i] = fmt.Sprintf("%d", b)
	}
	return strings.Join(parts, ".")
}

// modernIPv4PDUs adds RFC 4293 ipAddressTable PDUs for the given IPv4
// address assigned to ifIndex 1, with the given prefix length. The
// RowPointer encodes ipAddressPrefixEntry's index per RFC 4293:
// <ifIndex=1>.<addrType=1>.<addrLen=4>.<prefixBytes>.<prefixLen>,
// where prefixBytes is the network address (host bits zeroed).
func modernIPv4PDUs(addr string, plen int) mapping.ObjectIDValueMap {
	octets := strings.Split(addr, ".")
	rowSuffix := "1.4." + strings.Join(octets, ".")
	prefixOctets := ipv4NetworkOctets(addr, plen)
	rowPtr := fmt.Sprintf(".1.3.6.1.2.1.4.32.1.5.1.1.4.%s.%d", prefixOctets, plen)
	return mapping.ObjectIDValueMap{
		".1.3.6.1.2.1.4.34.1.3." + rowSuffix: mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.4." + rowSuffix: mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.5." + rowSuffix: mapping.Value{
			Value: rowPtr, Type: mapping.Asn1BER(mapping.ObjectIdentifier), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.7." + rowSuffix: mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.10." + rowSuffix: mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
	}
}

// modernIPv6PDUs is the IPv6 sibling of modernIPv4PDUs. Encodes addrType=2
// addrLen=16 followed by 16 decimal bytes. The RowPointer's prefix
// portion uses the network bytes (host bits zeroed) per RFC 4293.
func modernIPv6PDUs(addr string, plen int) mapping.ObjectIDValueMap {
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() != nil {
		panic("modernIPv6PDUs requires an IPv6 literal: " + addr)
	}
	ip = ip.To16()
	bytes := make([]string, 16)
	for i, b := range ip {
		bytes[i] = fmt.Sprintf("%d", b)
	}
	rowSuffix := "2.16." + strings.Join(bytes, ".")
	rowPtr := fmt.Sprintf(".1.3.6.1.2.1.4.32.1.5.1.2.16.%s.%d", ipv6NetworkBytes(addr, plen), plen)
	return mapping.ObjectIDValueMap{
		".1.3.6.1.2.1.4.34.1.3." + rowSuffix: mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.4." + rowSuffix: mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.5." + rowSuffix: mapping.Value{
			Value: rowPtr, Type: mapping.Asn1BER(mapping.ObjectIdentifier), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.7." + rowSuffix: mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.10." + rowSuffix: mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
	}
}

// mergeOIDs combines several ObjectIDValueMaps into one. Later entries
// overwrite earlier ones on key collision (intentional for tests that
// want to override a default).
func mergeOIDs(maps ...mapping.ObjectIDValueMap) mapping.ObjectIDValueMap {
	out := mapping.ObjectIDValueMap{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// primaryIPModernOIDs seeds one interface "Gi0" (ifIndex 1) plus an
// inet_address-indexed ipAddressTable row at the given v4 address with
// the chosen prefix length. Used to exercise the new IPv4 primary-IP
// path through ipAddressTable.
func primaryIPModernOIDs(addr, ifName string, plen int) mapping.ObjectIDValueMap {
	out := mapping.ObjectIDValueMap{
		".1.3.6.1.2.1.2.2.1.2.1": mapping.Value{
			Value: ifName, Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1,
		},
	}
	for k, v := range modernIPv4PDUs(addr, plen) {
		out[k] = v
	}
	return out
}

// primaryIPModernIPv6OIDs is the v6 sibling of primaryIPModernOIDs.
func primaryIPModernIPv6OIDs(addr, ifName string, plen int) mapping.ObjectIDValueMap {
	out := mapping.ObjectIDValueMap{
		".1.3.6.1.2.1.2.2.1.2.1": mapping.Value{
			Value: ifName, Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1,
		},
	}
	for k, v := range modernIPv6PDUs(addr, plen) {
		out[k] = v
	}
	return out
}

// primaryIPModernDualStackOIDs combines modern v4 + v6 rows on ifIndex 1.
func primaryIPModernDualStackOIDs(v4, v6, ifName string, v4Plen, v6Plen int) mapping.ObjectIDValueMap {
	out := primaryIPModernOIDs(v4, ifName, v4Plen)
	for k, v := range modernIPv6PDUs(v6, v6Plen) {
		out[k] = v
	}
	return out
}

func TestAssignPrimaryIP_IPv6Literal_FromIpAddressTable(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg, err := mapping.NewConfig(primaryIPFixtureBothTables(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
	assert.NoError(t, err)

	m := mapping.NewObjectIDMapperForTest(cfg, logger, &config.Defaults{}, "2001:db8::1", &fakeResolver{})
	entities := m.MapObjectIDsToEntity(primaryIPModernIPv6OIDs("2001:db8::1", "Gi0", 64))
	device := findDevice(entities)
	assert.NotNil(t, device.PrimaryIp6, "v6 literal target must yield PrimaryIp6")
	if device.PrimaryIp6 != nil {
		assert.Equal(t, "2001:db8::1/64", *device.PrimaryIp6.Address)
	}
	assert.Nil(t, device.PrimaryIp4, "no v4 candidates → PrimaryIp4 stays nil")
}

func TestAssignPrimaryIP_HostnameResolvesToIPv6_AssignsPrimaryIp6(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg, err := mapping.NewConfig(primaryIPFixtureBothTables(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
	assert.NoError(t, err)

	resolver := &fakeResolver{addrs: []string{"2001:db8::1"}}
	m := mapping.NewObjectIDMapperForTest(cfg, logger, &config.Defaults{}, "router.example", resolver)
	entities := m.MapObjectIDsToEntity(primaryIPModernIPv6OIDs("2001:db8::1", "Gi0", 64))
	device := findDevice(entities)
	assert.NotNil(t, device.PrimaryIp6, "v6 DNS-only target must yield PrimaryIp6")
	assert.Nil(t, device.PrimaryIp4)
}

func TestAssignPrimaryIP_DualStackHostname_AssignsBoth(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg, err := mapping.NewConfig(primaryIPFixtureBothTables(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
	assert.NoError(t, err)

	resolver := &fakeResolver{addrs: []string{"10.0.0.1", "2001:db8::1"}}
	m := mapping.NewObjectIDMapperForTest(cfg, logger, &config.Defaults{}, "router.example", resolver)
	entities := m.MapObjectIDsToEntity(primaryIPModernDualStackOIDs("10.0.0.1", "2001:db8::1", "Gi0", 24, 64))
	device := findDevice(entities)
	assert.NotNil(t, device.PrimaryIp4, "dual-stack target must yield PrimaryIp4")
	assert.NotNil(t, device.PrimaryIp6, "dual-stack target must yield PrimaryIp6")
}

// TestAssignPrimaryIP_IPv4MappedIPv6Target_AssignsPrimaryIp6 covers
// the candidate side of the mapped-IPv6 family-detection bug: when the
// SNMP target is given as `::ffff:10.0.0.1`, resolveTargetIPs must put
// it in the v6 candidate list (not collapse to v4) so a discovered
// v6 entity emitted as `::ffff:10.0.0.1/N` matches and PrimaryIp6 is
// set.
func TestAssignPrimaryIP_IPv4MappedIPv6Target_AssignsPrimaryIp6(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg, err := mapping.NewConfig(primaryIPFixtureBothTables(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
	assert.NoError(t, err)

	// Build a single ipAddressTable row for ::ffff:10.0.0.1. The row's
	// suffix uses the host bytes; the RowPointer to ipAddressPrefixTable
	// uses the prefix's network bytes (host bits zeroed) per RFC 4293.
	v6Bytes := []string{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "255", "255", "10", "0", "0", "1"}
	rowSuffix := "2.16." + strings.Join(v6Bytes, ".")
	rowPtr := fmt.Sprintf(".1.3.6.1.2.1.4.32.1.5.1.2.16.%s.%d", ipv6NetworkBytes("::ffff:10.0.0.1", 96), 96)
	pdus := mapping.ObjectIDValueMap{
		".1.3.6.1.2.1.2.2.1.2.1": mapping.Value{
			Value: "Gi0", Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1,
		},
		".1.3.6.1.2.1.4.34.1.3." + rowSuffix: mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.4." + rowSuffix: mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.5." + rowSuffix: mapping.Value{
			Value: rowPtr, Type: mapping.Asn1BER(mapping.ObjectIdentifier), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.7." + rowSuffix: mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.10." + rowSuffix: mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
	}

	m := mapping.NewObjectIDMapper(cfg, logger, &config.Defaults{}, "::ffff:10.0.0.1")
	entities := m.MapObjectIDsToEntity(pdus)
	device := findDevice(entities)
	assert.NotNil(t, device.PrimaryIp6, "mapped-IPv6 literal target must yield PrimaryIp6")
	assert.Nil(t, device.PrimaryIp4, "mapped-IPv6 literal target must not be collapsed to PrimaryIp4")
}

// TestAssignPrimaryIP_IPv4MappedIPv6_NotMisclassifiedAsIPv4 is the
// regression test for the family-detection bug Codex flagged: a row
// decoded as ipv6:::ffff:10.0.0.1 had `parsed.To4() != nil`, so
// pickPrimaryIPHit treated it as IPv4 and could match a v4 candidate
// (or skip a legitimate v6 hit). Family detection now reads the
// textual address.
func TestAssignPrimaryIP_IPv4MappedIPv6_NotMisclassifiedAsIPv4(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg, err := mapping.NewConfig(primaryIPFixtureBothTables(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
	assert.NoError(t, err)

	// Build an ipAddressTable row for ::ffff:10.0.0.1 with addrType=2,
	// addrLen=16. The row's suffix uses the host bytes; the RowPointer
	// uses the prefix's network bytes (host bits zeroed) per RFC 4293.
	v6Bytes := []string{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "255", "255", "10", "0", "0", "1"}
	rowSuffix := "2.16." + strings.Join(v6Bytes, ".")
	rowPtr := fmt.Sprintf(".1.3.6.1.2.1.4.32.1.5.1.2.16.%s.%d", ipv6NetworkBytes("::ffff:10.0.0.1", 96), 96)
	pdus := mapping.ObjectIDValueMap{
		".1.3.6.1.2.1.2.2.1.2.1": mapping.Value{
			Value: "Gi0", Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1,
		},
		".1.3.6.1.2.1.4.34.1.3." + rowSuffix: mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.4." + rowSuffix: mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.5." + rowSuffix: mapping.Value{
			Value: rowPtr, Type: mapping.Asn1BER(mapping.ObjectIdentifier), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.7." + rowSuffix: mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.10." + rowSuffix: mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
	}

	// SNMP target is an IPv4 literal (10.0.0.1). The ONLY discovered IP
	// is the IPv4-mapped IPv6 entity ::ffff:10.0.0.1 (modern table,
	// addrType=2). Pre-fix: pickPrimaryIPHit's parsed.To4() != nil
	// marked this as v4 and the v4 candidate would match. Post-fix:
	// the textual ":" classifies the row as v6, so the v4 pass skips
	// it entirely and PrimaryIp4 stays nil.
	m := mapping.NewObjectIDMapper(cfg, logger, &config.Defaults{}, "10.0.0.1")
	entities := m.MapObjectIDsToEntity(pdus)
	device := findDevice(entities)
	assert.Nil(t, device.PrimaryIp4,
		"IPv4-mapped IPv6 row must not be assigned to PrimaryIp4")
}

func TestAssignPrimaryIP_ModernIPv4_FromIpAddressTable(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg, err := mapping.NewConfig(primaryIPFixtureBothTables(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
	assert.NoError(t, err)

	m := mapping.NewObjectIDMapper(cfg, logger, &config.Defaults{}, "10.0.0.1")
	entities := m.MapObjectIDsToEntity(primaryIPModernOIDs("10.0.0.1", "Gi0", 24))
	device := findDevice(entities)
	assert.NotNil(t, device.PrimaryIp4)
	if device.PrimaryIp4 != nil {
		assert.Equal(t, "10.0.0.1/24", *device.PrimaryIp4.Address)
	}
}

// TestOBS2798_ModernOnlyDevice_PopulatesPrimaryIPs reproduces the bug
// described in https://linear.app/netboxlabs/issue/OBS-2798. A device
// that does not respond to ipAddrTable but does populate ipAddressTable
// must still yield IP entities and have its PrimaryIp4 (and PrimaryIp6
// where applicable) set when the SNMP target host matches.
func TestOBS2798_ModernOnlyDevice_PopulatesPrimaryIPs(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg, err := mapping.NewConfig(primaryIPFixtureBothTables(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
	assert.NoError(t, err)

	m := mapping.NewObjectIDMapper(cfg, logger, &config.Defaults{}, "10.0.0.1")
	// Deliberately ipAddressTable PDUs only — no ipAddrTable rows.
	entities := m.MapObjectIDsToEntity(primaryIPModernDualStackOIDs("10.0.0.1", "2001:db8::1", "Gi0", 24, 64))

	device := findDevice(entities)
	assert.NotNil(t, device, "device entity must be reachable")
	assert.NotNil(t, device.PrimaryIp4, "PrimaryIp4 must be set from ipAddressTable")
	if device.PrimaryIp4 != nil {
		assert.Equal(t, "10.0.0.1/24", *device.PrimaryIp4.Address)
	}

	v4Count, v6Count := 0, 0
	for _, e := range entities {
		ip, ok := e.(*diode.IPAddress)
		if !ok || ip.Address == nil {
			continue
		}
		if strings.HasPrefix(*ip.Address, "10.0.0.1") {
			v4Count++
		}
		if strings.HasPrefix(*ip.Address, "2001:db8::1") {
			v6Count++
		}
	}
	assert.Equal(t, 1, v4Count, "exactly one IPv4 entity must be emitted from ipAddressTable")
	assert.Equal(t, 1, v6Count, "exactly one IPv6 entity must be emitted from ipAddressTable")
}

func TestMapObjectIDsToEntity_LegacyAndModernSameAddress_Deduplicates(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mappingConfig, err := mapping.NewConfig(primaryIPFixtureBothTables(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
	assert.NoError(t, err)

	m := mapping.NewObjectIDMapper(mappingConfig, logger, &config.Defaults{}, "")
	pdus := mergeOIDs(
		primaryIPOneInterfaceOIDs("10.0.0.1", "Gi0"),
		modernIPv4PDUs("10.0.0.1", 24),
	)
	entities := m.MapObjectIDsToEntity(pdus)

	count := 0
	var survivingIP *diode.IPAddress
	for _, e := range entities {
		if ip, ok := e.(*diode.IPAddress); ok && ip.Address != nil &&
			strings.HasPrefix(*ip.Address, "10.0.0.1") {
			count++
			survivingIP = ip
		}
	}
	assert.Equal(t, 1, count, "duplicate IP entities must be deduped to one")
	// The legacy fixture emits 10.0.0.1/32 (host-route default from
	// address-only PDU); the modern fixture emits 10.0.0.1/24 (RowPointer
	// prefix). Asserting /24 proves the modern row won the dedup.
	if assert.NotNil(t, survivingIP, "deduped IP entity must be present") {
		assert.Equal(t, "10.0.0.1/24", *survivingIP.Address,
			"modern ipAddressTable row must win over legacy ipAddrTable row")
	}
}

// TestAssignPrimaryIP_RejectsPlaceholderInterface verifies the
// "verified interface IP" guarantee tightening Copilot flagged: a
// modern row whose ipAddressIfIndex column referenced an ifIndex that
// never had a corresponding ifTable row walked produces a placeholder
// Interface with Name=DefaultInterfaceName ("unknown"). That
// placeholder must NOT count as a verified interface for primary-IP
// selection — otherwise device.PrimaryIp4 would point at an
// interface that wasn't actually discovered.
func TestAssignPrimaryIP_RejectsPlaceholderInterface(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg, err := mapping.NewConfig(primaryIPFixtureBothTables(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
	assert.NoError(t, err)

	// Modern row references ifIndex=99 but no ifTable PDU is included,
	// so GetOrCreateEntity fabricates an Interface with Name="unknown".
	pdus := mapping.ObjectIDValueMap{
		".1.3.6.1.2.1.4.34.1.3.1.4.10.0.0.1": mapping.Value{
			Value: "99", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.4.1.4.10.0.0.1": mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.5.1.4.10.0.0.1": mapping.Value{
			Value: ".1.3.6.1.2.1.4.32.1.5.1.1.4." + ipv4NetworkOctets("10.0.0.1", 24) + ".24",
			Type:  mapping.Asn1BER(mapping.ObjectIdentifier), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.7.1.4.10.0.0.1": mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.10.1.4.10.0.0.1": mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
	}

	m := mapping.NewObjectIDMapper(cfg, logger, &config.Defaults{}, "10.0.0.1")
	entities := m.MapObjectIDsToEntity(pdus)
	// Use CurrentDevice so we observe the device pointer even when no
	// emitted entity carries it back to findDevice.
	device := m.CurrentDevice()
	if assert.NotNil(t, device) {
		assert.Nil(t, device.PrimaryIp4,
			"placeholder Interface (Name=DefaultInterfaceName) must not satisfy the verified-interface check")
	}
	_ = entities
}

// TestMapObjectIDsToEntity_DedupTreatsPlaceholderAsUnassigned ensures
// the same hardening applies in dedup: a modern row whose Interface
// is the placeholder "unknown" must not displace a legacy row that
// has a real ifDescr-named interface binding.
func TestMapObjectIDsToEntity_DedupTreatsPlaceholderAsUnassigned(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg, err := mapping.NewConfig(primaryIPFixtureBothTables(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
	assert.NoError(t, err)

	// Legacy row provides interface "Gi0" (real, named). Modern row
	// references ifIndex=99 (placeholder, no ifTable PDU). Without
	// the verified-interface check, modern would win dedup; with it,
	// the legacy real-interface row wins.
	modernPlaceholder := mapping.ObjectIDValueMap{
		".1.3.6.1.2.1.4.34.1.3.1.4.10.0.0.1": mapping.Value{
			Value: "99", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.4.1.4.10.0.0.1": mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.5.1.4.10.0.0.1": mapping.Value{
			Value: ".1.3.6.1.2.1.4.32.1.5.1.1.4." + ipv4NetworkOctets("10.0.0.1", 24) + ".24",
			Type:  mapping.Asn1BER(mapping.ObjectIdentifier), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.7.1.4.10.0.0.1": mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.10.1.4.10.0.0.1": mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
	}
	pdus := mergeOIDs(
		primaryIPOneInterfaceOIDs("10.0.0.1", "Gi0"),
		modernPlaceholder,
	)

	m := mapping.NewObjectIDMapper(cfg, logger, &config.Defaults{}, "10.0.0.1")
	entities := m.MapObjectIDsToEntity(pdus)

	count := 0
	var survivingIP *diode.IPAddress
	for _, e := range entities {
		if ip, ok := e.(*diode.IPAddress); ok && ip.Address != nil &&
			strings.HasPrefix(*ip.Address, "10.0.0.1") {
			count++
			survivingIP = ip
		}
	}
	assert.Equal(t, 1, count)
	if assert.NotNil(t, survivingIP) {
		// Legacy row wins because its "Gi0" interface is real, while
		// the modern row's "99" is just a placeholder.
		iface, ok := survivingIP.AssignedObject.(*diode.Interface)
		if assert.True(t, ok) && assert.NotNil(t, iface.Name) {
			assert.Equal(t, "Gi0", *iface.Name,
				"legacy entry with real interface must win when modern has only a placeholder")
		}
	}
	device := findDevice(entities)
	assert.NotNil(t, device.PrimaryIp4,
		"PrimaryIp4 must be assigned via the legacy row's real interface")
}

// TestMapObjectIDsToEntity_ExcludedInterfaceDropsBothLegacyAndModern
// verifies the dedup-before-exclude ordering: when the legacy row is
// bound to an excluded interface and the modern row is missing
// AssignedObject, an exclude-then-dedup order would have removed the
// legacy row first and left the unassigned modern duplicate behind,
// emitting an IP that should have been suppressed. With dedup first,
// assigned-wins consolidates to the legacy row, then the exclusion
// sweep drops both copies.
func TestMapObjectIDsToEntity_ExcludedInterfaceDropsBothLegacyAndModern(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	defaults := &config.Defaults{
		InterfaceExcludePatterns: []string{"^Gi0$"},
	}
	mappingConfig, err := mapping.NewConfig(primaryIPFixtureBothTables(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, defaults, config.Options{})
	assert.NoError(t, err)

	// Legacy row binds to "Gi0" (will be excluded). Modern row carries
	// the same IP but no ipAddressIfIndex (so AssignedObject stays
	// nil).
	modernNoIfIndex := mapping.ObjectIDValueMap{
		".1.3.6.1.2.1.4.34.1.4.1.4.10.0.0.1": mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.5.1.4.10.0.0.1": mapping.Value{
			Value: ".1.3.6.1.2.1.4.32.1.5.1.1.4." + ipv4NetworkOctets("10.0.0.1", 24) + ".24",
			Type:  mapping.Asn1BER(mapping.ObjectIdentifier), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.7.1.4.10.0.0.1": mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.10.1.4.10.0.0.1": mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
	}
	pdus := mergeOIDs(
		primaryIPOneInterfaceOIDs("10.0.0.1", "Gi0"),
		modernNoIfIndex,
	)

	m := mapping.NewObjectIDMapper(mappingConfig, logger, defaults, "10.0.0.1")
	entities := m.MapObjectIDsToEntity(pdus)

	for _, e := range entities {
		ip, ok := e.(*diode.IPAddress)
		if !ok || ip.Address == nil {
			continue
		}
		assert.NotContains(t, *ip.Address, "10.0.0.1",
			"IP from excluded interface must not survive via the unassigned modern duplicate")
	}
}

// TestMapObjectIDsToEntity_LegacyKeptWhenModernLacksInterface verifies
// that the dedup pass keeps the legacy row when the modern row is
// missing AssignedObject (e.g. partial walk where ipAddressIfIndex was
// not returned). Without this priority, the legacy row would be
// dropped, both candidates leaving pickPrimaryIPHit empty-handed and
// primary-IP selection regressing for the device.
func TestMapObjectIDsToEntity_LegacyKeptWhenModernLacksInterface(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mappingConfig, err := mapping.NewConfig(primaryIPFixtureBothTables(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
	assert.NoError(t, err)

	// Build a modern row WITHOUT the .3 (ipAddressIfIndex) PDU, so
	// AssignedObject stays nil for that entity. Filter columns are
	// still present so the row isn't dropped.
	modernNoIfIndex := mapping.ObjectIDValueMap{
		".1.3.6.1.2.1.4.34.1.4.1.4.10.0.0.1": mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.5.1.4.10.0.0.1": mapping.Value{
			Value: ".1.3.6.1.2.1.4.32.1.5.1.1.4." + ipv4NetworkOctets("10.0.0.1", 24) + ".24",
			Type:  mapping.Asn1BER(mapping.ObjectIdentifier), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.7.1.4.10.0.0.1": mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
		".1.3.6.1.2.1.4.34.1.10.1.4.10.0.0.1": mapping.Value{
			Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 0,
		},
	}
	pdus := mergeOIDs(
		primaryIPOneInterfaceOIDs("10.0.0.1", "Gi0"),
		modernNoIfIndex,
	)

	m := mapping.NewObjectIDMapper(mappingConfig, logger, &config.Defaults{}, "10.0.0.1")
	entities := m.MapObjectIDsToEntity(pdus)

	count := 0
	var survivingIP *diode.IPAddress
	for _, e := range entities {
		if ip, ok := e.(*diode.IPAddress); ok && ip.Address != nil &&
			strings.HasPrefix(*ip.Address, "10.0.0.1") {
			count++
			survivingIP = ip
		}
	}
	assert.Equal(t, 1, count, "exactly one IP entity must survive dedup")
	if assert.NotNil(t, survivingIP) {
		// The legacy row carries the interface binding (host-route /32);
		// the modern row would be /24 but has no AssignedObject.
		assert.Equal(t, "10.0.0.1/32", *survivingIP.Address,
			"legacy entry with interface binding must win when modern lacks one")
		_, assigned := survivingIP.AssignedObject.(*diode.Interface)
		assert.True(t, assigned, "surviving entity must keep its interface assignment")
	}

	// Sanity: pickPrimaryIPHit can now find the surviving entity, so
	// PrimaryIp4 is set despite the modern row's missing ifIndex.
	device := findDevice(entities)
	assert.NotNil(t, device.PrimaryIp4,
		"PrimaryIp4 must still be assigned via the legacy row")
}

func TestEntry_VendorPropagated(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mappers := map[string]mapping.OrbToEntityMapper{
		"interface_vlan": &noopMapper{},
	}
	entry := mapping.NewMappingEntry(config.MappingEntry{
		OID:    ".1.3.6.1.4.1.9.9.68.1.2.2.1",
		Entity: "interface_vlan",
		Vendor: "cisco",
	}, logger, mappers)
	if entry == nil {
		t.Fatal("entry is nil")
	}
	if entry.Vendor != "cisco" {
		t.Errorf("Vendor: got %q, want %q", entry.Vendor, "cisco")
	}
}

type noopMapper struct{}

func (n *noopMapper) Map(map[mapping.ObjectIDIndex]*mapping.ObjectIDValue, *mapping.Entry, *mapping.EntityRegistry, *config.Defaults) diode.Entity {
	return nil
}

func TestCreateEntity_VLAN(t *testing.T) {
	e, err := mapping.CreateEntity(mapping.VLANEntityType)
	if err != nil {
		t.Fatalf("createEntity(VLANEntityType): %v", err)
	}
	if _, ok := e.(*diode.VLAN); !ok {
		t.Errorf("got %T, want *diode.VLAN", e)
	}
}

func TestCreateEntity_InterfaceVLAN(t *testing.T) {
	// interface_vlan is consumed by VlanMapper.PostMap; createEntity
	// should not produce a row-scoped entity for it.
	if _, err := mapping.CreateEntity(mapping.InterfaceVLANEntityType); err == nil {
		t.Error("expected error for interface_vlan, got nil")
	}
}

func TestNewConfig_RegistersVlanMapper(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mappings := []config.MappingEntry{
		{OID: ".1.3.6.1.2.1.17.7.1.4.3.1", Entity: "vlan", Field: "_id"},
		{OID: ".1.3.6.1.4.1.9.9.68.1.5.1.1", Entity: "interface_vlan", Vendor: "cisco"},
	}
	cfg, err := mapping.NewConfig(mappings, logger, nil, nil, &config.Defaults{}, config.Options{})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("cfg is nil")
	}
	entries := mapping.ConfigEntries(cfg)
	for _, oid := range []string{".1.3.6.1.2.1.17.7.1.4.3.1", ".1.3.6.1.4.1.9.9.68.1.5.1.1"} {
		entry, ok := entries[oid]
		if !ok {
			t.Errorf("entry not registered: %s", oid)
			continue
		}
		if entry.Mapper == nil {
			t.Errorf("entry %s has nil Mapper", oid)
		}
	}
}

func TestConfig_VendorPartitioning(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mappings := []config.MappingEntry{
		{OID: ".1.3.6.1.2.1.2.2.1", Entity: "interface", Field: "_id"},
		{OID: ".1.3.6.1.2.1.17.7.1.4.3.1", Entity: "vlan", Field: "_id"},
		{OID: ".1.3.6.1.4.1.9.9.68.1.2.2.1", Entity: "interface_vlan", Field: "_id", Vendor: "cisco"},
	}
	cfg, err := mapping.NewConfig(mappings, logger, nil, nil, &config.Defaults{}, config.Options{})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	gen := cfg.GenericObjectIDs()
	if _, hasCisco := gen[".1.3.6.1.4.1.9.9.68.1.2.2.1"]; hasCisco {
		t.Error("generic set must not include vendor=cisco entry")
	}
	if _, hasIface := gen[".1.3.6.1.2.1.2.2.1"]; !hasIface {
		t.Error("generic set must include unscoped entry")
	}
	cisco := cfg.VendorObjectIDs("cisco")
	if _, ok := cisco[".1.3.6.1.4.1.9.9.68.1.2.2.1"]; !ok {
		t.Error("cisco set missing the cisco-scoped entry")
	}
	if len(cfg.VendorObjectIDs("juniper")) != 0 {
		t.Error("juniper set must be empty (no juniper-scoped entries)")
	}
}

// TestGenericObjectIDs_ChassisModuleColumnsGatedByDiscoverModules asserts that
// the two ENTITY-MIB columns consumed exclusively by module / module bay
// discovery (entPhysicalDescr and entPhysicalVendorType, child entries with
// entity "chassis_module") are skipped from the generic walk OID set when
// options.discover_modules is off (the default). They must be present when
// the mode is "linecards" or "full". Pure walk-optimization gating: the
// downstream TranslateModulesWithAlias path already short-circuits on
// mode=off, so this purely removes unnecessary SNMP traffic on large
// modular chassis.
func TestGenericObjectIDs_ChassisModuleColumnsGatedByDiscoverModules(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	const (
		descrOID      = ".1.3.6.1.2.1.47.1.1.1.1.2"
		vendorTypeOID = ".1.3.6.1.2.1.47.1.1.1.1.3"
		parentOID     = ".1.3.6.1.2.1.47.1.1.1"
	)

	// Mirror the chassis_inventory parent + chassis_module children block
	// in policy/mapping.yaml.
	mappings := []config.MappingEntry{
		{
			OID: parentOID, Entity: "chassis_inventory", Field: "_id", IdentifierSize: 2,
			MappingEntries: []config.MappingEntry{
				{OID: descrOID, Entity: "chassis_module", Field: "descr"},
				{OID: vendorTypeOID, Entity: "chassis_module", Field: "vendor_type"},
				{OID: ".1.3.6.1.2.1.47.1.1.1.1.5", Entity: "chassis_inventory", Field: "class"},
				{OID: ".1.3.6.1.2.1.47.1.1.1.1.11", Entity: "chassis_inventory", Field: "serialNumber"},
			},
		},
	}

	cases := []struct {
		name         string
		opts         config.Options
		wantIncluded bool
	}{
		{
			name:         "default (unset) -> off, columns absent",
			opts:         config.Options{},
			wantIncluded: false,
		},
		{
			name: "explicit off, columns absent",
			opts: func() config.Options {
				v := config.DiscoverModulesOff
				return config.Options{DiscoverModules: &v}
			}(),
			wantIncluded: false,
		},
		{
			name: "linecards, columns present",
			opts: func() config.Options {
				v := config.DiscoverModulesLinecards
				return config.Options{DiscoverModules: &v}
			}(),
			wantIncluded: true,
		},
		{
			name: "full, columns present",
			opts: func() config.Options {
				v := config.DiscoverModulesFull
				return config.Options{DiscoverModules: &v}
			}(),
			wantIncluded: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := mapping.NewConfig(mappings, logger, nil, nil, &config.Defaults{}, tc.opts)
			if err != nil {
				t.Fatalf("NewConfig: %v", err)
			}
			gen := cfg.GenericObjectIDs()
			_, hasDescr := gen[descrOID]
			_, hasVendorType := gen[vendorTypeOID]
			if tc.wantIncluded {
				if !hasDescr {
					t.Errorf("expected %s in generic OIDs", descrOID)
				}
				if !hasVendorType {
					t.Errorf("expected %s in generic OIDs", vendorTypeOID)
				}
			} else {
				if hasDescr {
					t.Errorf("unexpected %s in generic OIDs (mode=off should skip)", descrOID)
				}
				if hasVendorType {
					t.Errorf("unexpected %s in generic OIDs (mode=off should skip)", vendorTypeOID)
				}
			}
			// Sibling chassis_inventory columns must remain regardless of mode.
			if _, ok := gen[".1.3.6.1.2.1.47.1.1.1.1.5"]; !ok {
				t.Error("chassis_inventory column .1.3.6.1.2.1.47.1.1.1.1.5 must be present in all modes")
			}
			if _, ok := gen[".1.3.6.1.2.1.47.1.1.1.1.11"]; !ok {
				t.Error("chassis_inventory column .1.3.6.1.2.1.47.1.1.1.1.11 must be present in all modes")
			}
		})
	}
}

func TestMappingYAML_QBridgeEntriesPresent(t *testing.T) {
	body, err := os.ReadFile("../policy/mapping.yaml")
	if err != nil {
		t.Fatalf("read mapping.yaml: %v", err)
	}
	var doc config.Mapping
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	wanted := map[string]bool{
		".1.3.6.1.2.1.17.1.4.1":   false, // dot1dBasePortTable
		".1.3.6.1.2.1.17.7.1.4.3": false, // dot1qVlanStaticTable
		".1.3.6.1.2.1.17.7.1.4.5": false, // dot1qPortVlanTable
	}
	for _, e := range doc.Entries {
		if _, want := wanted[e.OID]; want {
			wanted[e.OID] = true
		}
	}
	for oid, found := range wanted {
		if !found {
			t.Errorf("mapping.yaml missing OID %s", oid)
		}
	}
}

func TestMappingYAML_CiscoOverlayEntriesPresent(t *testing.T) {
	body, err := os.ReadFile("../policy/mapping.yaml")
	if err != nil {
		t.Fatalf("read mapping.yaml: %v", err)
	}
	var doc config.Mapping
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	wanted := map[string]bool{
		".1.3.6.1.4.1.9.9.68.1.2.2.1": false, // vmMembershipTable
		".1.3.6.1.4.1.9.9.68.1.5.1":   false, // vmVoiceVlanTable
	}
	for _, e := range doc.Entries {
		if e.Vendor != "cisco" {
			continue
		}
		if _, want := wanted[e.OID]; want {
			wanted[e.OID] = true
		}
	}
	for oid, found := range wanted {
		if !found {
			t.Errorf("mapping.yaml missing cisco-scoped OID %s", oid)
		}
	}
}

// TestMapObjectIDsToEntity_VLANIndexCollision is a regression test for the
// case where an ifIndex value and a VLAN VID share the same numeric form
// (e.g., ifIndex=10 + dot1qVlanStaticName.10). The pre-fix
// groupByObjectIDIndex bucketed by bare index, which let the two tables
// collide and silently drop one of them depending on Go map iteration
// order. The fix skips post-pass-only OIDs (vlan / interface_vlan) from
// the bucketing so VlanMapper.PostMap can consume them via the full
// ObjectIDValueMap while InterfaceMapper still sees the ifTable bucket
// for the same numeric index.
func TestMapObjectIDsToEntity_VLANIndexCollision(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	mappings := []config.MappingEntry{
		{
			OID: ".1.3.6.1.2.1.2.2.1", Entity: "interface", Field: "_id", IdentifierSize: 1,
			MappingEntries: []config.MappingEntry{
				{OID: ".1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
				{OID: ".1.3.6.1.2.1.2.2.1.7", Entity: "interface", Field: "adminStatus"},
				{OID: ".1.3.6.1.2.1.2.2.1.3", Entity: "interface", Field: "type"},
			},
		},
		{
			OID: ".1.3.6.1.2.1.17.7.1.4.3", Entity: "vlan", Field: "_id", IdentifierSize: 1,
			MappingEntries: []config.MappingEntry{
				{OID: ".1.3.6.1.2.1.17.7.1.4.3.1.1", Entity: "vlan", Field: "name"},
				{OID: ".1.3.6.1.2.1.17.7.1.4.3.1.5", Entity: "vlan", Field: "rowStatus"},
			},
		},
	}
	cfg, err := mapping.NewConfig(mappings, logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
	assert.NoError(t, err)
	mapper := mapping.NewObjectIDMapper(cfg, logger, &config.Defaults{Interface: config.InterfaceDefaults{Type: "other"}}, "")
	// Both ifIndex=10 (in ifTable) AND vid=10 (in dot1qVlanStaticTable)
	// — same numeric index in two different tables.
	oids := mapping.ObjectIDValueMap{
		// ifTable row for ifIndex 10
		".1.3.6.1.2.1.2.2.1.2.10": mapping.Value{Value: "GigabitEthernet1/0/10", Type: mapping.OctetString, IdentifierSize: 1},
		".1.3.6.1.2.1.2.2.1.7.10": mapping.Value{Value: "1", Type: mapping.Integer, IdentifierSize: 1},
		".1.3.6.1.2.1.2.2.1.3.10": mapping.Value{Value: "6", Type: mapping.Integer, IdentifierSize: 1},
		// dot1qVlanStaticTable row for vid 10 (collision)
		".1.3.6.1.2.1.17.7.1.4.3.1.1.10": mapping.Value{Value: "Engineering", Type: mapping.OctetString, IdentifierSize: 1},
		".1.3.6.1.2.1.17.7.1.4.3.1.5.10": mapping.Value{Value: "1", Type: mapping.Integer, IdentifierSize: 1},
	}
	entities := mapper.MapObjectIDsToEntity(oids)
	var sawIface, sawVLAN bool
	for _, e := range entities {
		if iface, ok := e.(*diode.Interface); ok && iface.Name != nil && *iface.Name == "GigabitEthernet1/0/10" {
			sawIface = true
		}
		if v, ok := e.(*diode.VLAN); ok && v.Vid != nil && *v.Vid == 10 && v.Name != nil && *v.Name == "Engineering" {
			sawVLAN = true
		}
	}
	if !sawIface {
		t.Errorf("expected Interface entity for ifIndex 10 (GigabitEthernet1/0/10); got entities=%+v", entities)
	}
	if !sawVLAN {
		t.Errorf("expected VLAN entity for vid 10 (Engineering); got entities=%+v", entities)
	}
}
