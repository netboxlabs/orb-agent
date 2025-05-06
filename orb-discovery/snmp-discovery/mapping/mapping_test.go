package mapping_test

import (
	"log/slog"
	"os"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"

	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/mapping"
)

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
				".1.3.6.1.2.1.2.2.1.2.999": mapping.Value{Value: "GigabitEthernet1/0/1", Type: mapping.Asn1BER(mapping.OctetString)},
				".1.3.6.1.2.1.2.2.1.5.999": mapping.Value{Value: "1000000000", Type: mapping.Asn1BER(mapping.Integer)},
				".1.3.6.1.2.1.2.2.1.6.999": mapping.Value{Value: "00:00:00:00:00:00", Type: mapping.Asn1BER(mapping.OctetString)},
				".1.3.6.1.2.1.2.2.1.7.999": mapping.Value{Value: "1", Type: mapping.Asn1BER(mapping.Integer)},
				".1.3.6.1.2.1.2.2.1.2.555": mapping.Value{Value: "GigabitEthernet1/0/1", Type: mapping.Asn1BER(mapping.OctetString)},
				".1.3.6.1.2.1.2.2.1.5.555": mapping.Value{Value: "1000000000", Type: mapping.Asn1BER(mapping.Integer)},
				".1.3.6.1.2.1.2.2.1.6.555": mapping.Value{Value: "00:00:00:00:00:11", Type: mapping.Asn1BER(mapping.OctetString)},
				".1.3.6.1.2.1.2.2.1.7.555": mapping.Value{Value: "0", Type: mapping.Asn1BER(mapping.Integer)},
			},
			expected: []diode.Entity{
				&diode.Interface{
					Speed: &[]int64{1000000000}[0],
					Name:  diode.String("GigabitEthernet1/0/1"),
					PrimaryMacAddress: &diode.MACAddress{
						MacAddress: &[]string{"00:00:00:00:00:00"}[0],
					},
					Enabled: &[]bool{true}[0],
				},
				&diode.Interface{
					Speed: &[]int64{1000000000}[0],
					Name:  diode.String("GigabitEthernet1/0/1"),
					PrimaryMacAddress: &diode.MACAddress{
						MacAddress: &[]string{"00:00:00:00:00:11"}[0],
					},
					Enabled: &[]bool{false}[0],
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
				".1.3.6.1.2.1.2.2.1.2.999":          mapping.Value{Value: "GigabitEthernet1/0/1", Type: mapping.Asn1BER(mapping.OctetString)},
				".1.3.6.1.2.1.2.2.1.5.999":          mapping.Value{Value: "1000000000", Type: mapping.Asn1BER(mapping.Integer)},
				".1.3.6.1.2.1.2.2.1.6.999":          mapping.Value{Value: "00:00:00:00:00:00", Type: mapping.Asn1BER(mapping.OctetString)},
				".1.3.6.1.2.1.2.2.1.7.999":          mapping.Value{Value: "1", Type: mapping.Asn1BER(mapping.Integer)},
				".1.3.6.1.2.1.4.20.1.1.192.168.1.2": mapping.Value{Value: "192.168.1.2", Type: mapping.Asn1BER(mapping.IPAddress)},
			},
			expected: []diode.Entity{
				&diode.Interface{
					Speed: &[]int64{1000000000}[0],
					Name:  diode.String("GigabitEthernet1/0/1"),
					PrimaryMacAddress: &diode.MACAddress{
						MacAddress: &[]string{"00:00:00:00:00:00"}[0],
					},
					Enabled: &[]bool{true}[0],
				},
				&diode.IPAddress{
					Address: diode.String("192.168.1.2"),
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
				".1.3.6.1.2.1.4.20.1.1.192.168.1.2": mapping.Value{Value: "192.168.1.2", Type: mapping.Asn1BER(mapping.IPAddress)},
			},
			expected: []diode.Entity{
				&diode.IPAddress{
					Address: diode.String("192.168.1.2"),
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapper := mapping.NewObjectIDMapper(tt.mapping, slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false})))
			entities := mapper.MapObjectIDsToEntity(tt.objectIDs)

			assert.ElementsMatch(t, tt.expected, entities)
		})
	}
}

func TestObjectIDs(t *testing.T) {
	tests := []struct {
		name         string
		mapping      []config.MappingEntry
		expectedOIDs []string
	}{
		{
			name: "Single OID",
			mapping: []config.MappingEntry{
				{
					OID:    "1.3.6.1.2.1.4.20.1.1",
					Entity: "ipAddress",
					Field:  "address",
				},
			},
			expectedOIDs: []string{
				"1.3.6.1.2.1.4.20.1.1",
			},
		},
		{
			name: "Duplicate OID",
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
			expectedOIDs: []string{
				".1.3.6.1.2.1.2.2.1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapper := mapping.NewObjectIDMapper(tt.mapping, slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false})))
			objectIDs := mapper.ObjectIDs()

			assert.ElementsMatch(t, tt.expectedOIDs, objectIDs)
		})
	}
}
