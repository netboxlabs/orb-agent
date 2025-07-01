package mapping_test

import (
	"log/slog"
	"os"
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
					Speed: &[]int64{1000000}[0],
					Name:  diode.String("GigabitEthernet1/0/1"),
					PrimaryMacAddress: &diode.MACAddress{
						MacAddress: &[]string{"00:00:00:00:00:00"}[0],
					},
					Enabled: &[]bool{true}[0],
					Type:    diode.String("other"),
					Device:  &diode.Device{},
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
					Speed: &[]int64{1000000}[0],
					Name:  diode.String("GigabitEthernet1/0/1"),
					PrimaryMacAddress: &diode.MACAddress{
						MacAddress: diode.String("00:00:00:00:00:00"),
					},
					Enabled: &[]bool{true}[0],
					Type:    diode.String("other"),
					Device:  &diode.Device{},
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
							Field:  "assigned_object",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapper := mapping.NewObjectIDMapper(
				tt.mapping,
				slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false})),
				&FakeManufacturers{},
				&FakeDeviceLookup{},
				&config.Defaults{
					Interface: config.InterfaceDefaults{
						Type: "other",
					},
				},
			)
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
			mapper := mapping.NewObjectIDMapper(
				tt.mapping,
				slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false})),
				&FakeManufacturers{},
				&FakeDeviceLookup{},
				&config.Defaults{},
			)
			objectIDs := mapper.ObjectIDs()

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
