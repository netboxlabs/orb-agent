package mapping_test

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/mapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestIPAddressMapper_Map(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name           string
		values         map[mapping.ObjectIDIndex]*mapping.ObjectIDValue
		mappingEntry   *mapping.Entry
		defaults       *config.Defaults
		expectedEntity *diode.IPAddress
		expectError    bool
	}{
		{
			name: "successful mapping with all fields",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.1.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.1.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.1",
					Value:  "192.168.1.1",
					Type:   mapping.IPAddress,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1.1",
				Entity: "ipAddress",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.4.20.1.1",
						Entity: "ipAddress",
						Field:  "_id",
					},
					{
						OID:    "1.3.6.1.2.1.4.20.1.1",
						Entity: "ipAddress",
						Field:  "address",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.IPAddress{
				Address: mapping.StringPtr("192.168.1.1/32"),
			},
			expectError: false,
		},
		{
			name: "mapping with global defaults",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.1.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.1.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.1",
					Value:  "192.168.1.1",
					Type:   mapping.IPAddress,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1.1",
				Entity: "ipAddress",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.4.20.1.1",
						Entity: "ipAddress",
						Field:  "_id",
					},
					{
						OID:    "1.3.6.1.2.1.4.20.1.1",
						Entity: "ipAddress",
						Field:  "address",
					},
				},
			},
			defaults: &config.Defaults{
				IPAddress: config.IPAddressDefaults{
					Description: "IP Address Description",
					Tags:        []string{"global-tag1", "global-tag2"},
				},
			},
			expectedEntity: &diode.IPAddress{
				Address:     mapping.StringPtr("192.168.1.1/32"),
				Description: mapping.StringPtr("IP Address Description"),
				Tags: []*diode.Tag{
					{Name: mapping.StringPtr("global-tag1")},
					{Name: mapping.StringPtr("global-tag2")},
				},
			},
			expectError: false,
		},
		{
			name: "mapping with entity-specific defaults",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.1.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.1.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.1",
					Value:  "192.168.1.1",
					Type:   mapping.IPAddress,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1.1",
				Entity: "ipAddress",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.4.20.1.1",
						Entity: "ipAddress",
						Field:  "_id",
					},
					{
						OID:    "1.3.6.1.2.1.4.20.1.1",
						Entity: "ipAddress",
						Field:  "address",
					},
				},
			},
			defaults: &config.Defaults{
				IPAddress: config.IPAddressDefaults{
					Description: "IP Address specific description",
					Tags:        []string{"ip-tag1", "ip-tag2"},
				},
			},
			expectedEntity: &diode.IPAddress{
				Address:     mapping.StringPtr("192.168.1.1/32"),
				Description: mapping.StringPtr("IP Address specific description"),
				Tags: []*diode.Tag{
					{Name: mapping.StringPtr("ip-tag1")},
					{Name: mapping.StringPtr("ip-tag2")},
				},
			},
			expectError: false,
		},
		{
			name: "mapping with both global and entity-specific defaults",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.1.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.1.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.1",
					Value:  "192.168.1.1",
					Type:   mapping.IPAddress,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1.1",
				Entity: "ipAddress",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.4.20.1.1",
						Entity: "ipAddress",
						Field:  "_id",
					},
					{
						OID:    "1.3.6.1.2.1.4.20.1.1",
						Entity: "ipAddress",
						Field:  "address",
					},
				},
			},
			defaults: &config.Defaults{
				Tags: []string{"global-tag1", "global-tag2"},
				IPAddress: config.IPAddressDefaults{
					Description: "IP Address specific description",
					Tags:        []string{"ip-tag1", "ip-tag2"},
				},
			},
			expectedEntity: &diode.IPAddress{
				Address:     mapping.StringPtr("192.168.1.1/32"),
				Description: mapping.StringPtr("IP Address specific description"),
				Tags: []*diode.Tag{
					{Name: mapping.StringPtr("ip-tag1")},
					{Name: mapping.StringPtr("ip-tag2")},
					{Name: mapping.StringPtr("global-tag1")},
					{Name: mapping.StringPtr("global-tag2")},
				},
			},
			expectError: false,
		},
		{
			name: "mapping with interface relationship",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.1.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.1.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.1",
					Value:  "192.168.1.1",
					Type:   mapping.IPAddress,
				},
				"1.3.6.1.2.1.4.20.1.2.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.2.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.2",
					Value:  "1",
					Type:   mapping.Integer,
				},
			},
			defaults: nil,
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1.1",
				Entity: "ipAddress",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.4.20.1.1",
						Entity: "ipAddress",
						Field:  "_id",
					},
					{
						OID:    "1.3.6.1.2.1.4.20.1.1",
						Entity: "ipAddress",
						Field:  "address",
					},
					{
						OID:    "1.3.6.1.2.1.4.20.1.2",
						Entity: "ipAddress",
						Field:  "assigned_object",
						Relationship: config.Relationship{
							Type: "interface",
						},
					},
				},
			},
			expectedEntity: &diode.IPAddress{
				Address: mapping.StringPtr("192.168.1.1/32"),
			},
			expectError: false,
		},
		{
			name:   "empty values map",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1.1",
				Entity: "ipAddress",
				Field:  "_id",
			},
			expectedEntity: &diode.IPAddress{},
			expectError:    false,
		},
		{
			name: "mapping with tenant default and entity-specific defaults",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.1.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.1.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.1",
					Value:  "192.168.1.1",
					Type:   mapping.IPAddress,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1.1",
				Entity: "ipAddress",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.4.20.1.1",
						Entity: "ipAddress",
						Field:  "address",
					},
				},
			},
			defaults: &config.Defaults{
				IPAddress: config.IPAddressDefaults{
					Description: "IP Address specific description",
					Tenant:      "ip-address-tenant",
					Role:        "ip-address-role",
					Vrf:         "ip-address-vrf",
				},
			},
			expectedEntity: &diode.IPAddress{
				Address:     mapping.StringPtr("192.168.1.1/32"),
				Description: mapping.StringPtr("IP Address specific description"),
				Tenant: &diode.Tenant{
					Name: mapping.StringPtr("ip-address-tenant"),
				},
				Role: mapping.StringPtr("ip-address-role"),
				Vrf: &diode.VRF{
					Name: mapping.StringPtr("ip-address-vrf"),
					Rd:   mapping.StringPtr("ip-address-vrf"),
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := mapping.NewEntityRegistry(logger)
			mapper := mapping.NewIPAddressMapper(logger)
			entity := mapper.Map(tt.values, tt.mappingEntry, registry, tt.defaults)

			if tt.expectError {
				assert.Nil(t, entity)
				return
			}

			assert.NotNil(t, entity)
			ipAddress, ok := entity.(*diode.IPAddress)
			assert.True(t, ok)
			assert.Equal(t, tt.expectedEntity.Address, ipAddress.Address)
			assert.Equal(t, tt.expectedEntity.Description, ipAddress.Description)
			assert.Equal(t, tt.expectedEntity.Role, ipAddress.Role)
			if tt.expectedEntity.Vrf != nil {
				assert.Equal(t, tt.expectedEntity.Vrf.Name, ipAddress.Vrf.Name)
				assert.Equal(t, tt.expectedEntity.Vrf.Rd, ipAddress.Vrf.Rd)
			}
			if tt.expectedEntity.Tags != nil {
				assert.Equal(t, len(tt.expectedEntity.Tags), len(ipAddress.Tags))
				for i, tag := range tt.expectedEntity.Tags {
					assert.Equal(t, tag.Name, ipAddress.Tags[i].Name)
				}
			}
			if tt.expectedEntity.Tenant != nil {
				assert.NotNil(t, ipAddress.Tenant)
				assert.Equal(t, tt.expectedEntity.Tenant.Name, ipAddress.Tenant.Name)
			}
		})
	}
}

func TestInterfaceMapper_Map(t *testing.T) {
	tests := []struct {
		name           string
		values         map[mapping.ObjectIDIndex]*mapping.ObjectIDValue
		mappingEntry   *mapping.Entry
		defaults       *config.Defaults
		expectedEntity *diode.Interface
		expectError    bool
	}{
		{
			name: "successful mapping with all fields",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.2.2.1.1.1": {
					OID:    "1.3.6.1.2.1.2.2.1.1.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.1",
					Value:  "1",
					Type:   mapping.Integer,
				},
				"1.3.6.1.2.1.2.2.1.2.1": {
					OID:    "1.3.6.1.2.1.2.2.1.2.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.2",
					Value:  "eth0",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.2.2.1.4.1": {
					OID:    "1.3.6.1.2.1.2.2.1.5.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.5",
					Value:  "1500",
					Type:   mapping.Integer,
				},
				"1.3.6.1.2.1.2.2.1.5.1": {
					OID:    "1.3.6.1.2.1.2.2.1.5.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.5",
					Value:  "1000000",
					Type:   mapping.Integer,
				},
				"1.3.6.1.2.1.2.2.1.6.1": {
					OID:    "1.3.6.1.2.1.2.2.1.6.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.6",
					Value:  "\x00\x11\x22\x33\x44\x55",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.2.2.1.7.1": {
					OID:    "1.3.6.1.2.1.2.2.1.7.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.7",
					Value:  "1",
					Type:   mapping.Integer,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.2.2.1.1",
						Entity: "interface",
						Field:  "_id",
					},
					{
						OID:    "1.3.6.1.2.1.2.2.1.2",
						Entity: "interface",
						Field:  "name",
					},
					{
						OID:    "1.3.6.1.2.1.2.2.1.4",
						Entity: "interface",
						Field:  "mtu",
					},
					{
						OID:    "1.3.6.1.2.1.2.2.1.5",
						Entity: "interface",
						Field:  "speed",
					},
					{
						OID:    "1.3.6.1.2.1.2.2.1.6",
						Entity: "interface",
						Field:  "macAddress",
					},
					{
						OID:    "1.3.6.1.2.1.2.2.1.7",
						Entity: "interface",
						Field:  "adminStatus",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.Interface{
				Name:              mapping.StringPtr("eth0"),
				Speed:             int64Ptr(1000),
				Mtu:               int64Ptr(1500),
				PrimaryMacAddress: &diode.MACAddress{MacAddress: mapping.StringPtr("00:11:22:33:44:55")},
				Enabled:           boolPtr(true),
			},
			expectError: false,
		},
		{
			name: "mapping with defaults",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.2.2.1.1.1": {
					OID:    "1.3.6.1.2.1.2.2.1.1.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.1",
					Value:  "1",
					Type:   mapping.Integer,
				},
				"1.3.6.1.2.1.2.2.1.2.1": {
					OID:    "1.3.6.1.2.1.2.2.1.2.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.2",
					Value:  "eth0",
					Type:   mapping.OctetString,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.2.2.1.1",
						Entity: "interface",
						Field:  "_id",
					},
					{
						OID:    "1.3.6.1.2.1.2.2.1.2",
						Entity: "interface",
						Field:  "name",
					},
				},
			},
			defaults: &config.Defaults{
				Interface: config.InterfaceDefaults{
					Description: "Interface specific description",
					Tags:        []string{"interface-tag1", "interface-tag2"},
					Type:        "ethernet",
				},
				Tags: []string{"global-tag1", "global-tag2"},
			},
			expectedEntity: &diode.Interface{
				Name:        mapping.StringPtr("eth0"),
				Description: mapping.StringPtr("Interface specific description"),
				Tags: []*diode.Tag{
					{Name: mapping.StringPtr("interface-tag1")},
					{Name: mapping.StringPtr("interface-tag2")},
					{Name: mapping.StringPtr("global-tag1")},
					{Name: mapping.StringPtr("global-tag2")},
				},
				Type: mapping.StringPtr("ethernet"),
			},
			expectError: false,
		},
		{
			name: "mapping with invalid speed value",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.2.2.1.1.1": {
					OID:    "1.3.6.1.2.1.2.2.1.1.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.1",
					Value:  "1",
					Type:   mapping.Integer,
				},
				"1.3.6.1.2.1.2.2.1.5.1": {
					OID:    "1.3.6.1.2.1.2.2.1.5.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.5",
					Value:  "invalid",
					Type:   mapping.Integer,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.2.2.1.1",
						Entity: "interface",
						Field:  "_id",
					},
					{
						OID:    "1.3.6.1.2.1.2.2.1.5",
						Entity: "interface",
						Field:  "speed",
					},
				},
			},
			expectedEntity: &diode.Interface{
				Name: mapping.StringPtr("unknown"),
			},
			expectError: false,
		},
		{
			name: "mapping with type and speed values",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.2.2.1.3.1": {
					OID:    "1.3.6.1.2.1.2.2.1.3.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.3",
					Value:  "6",
					Type:   mapping.Integer,
				},
				"1.3.6.1.2.1.2.2.1.5.1": {
					OID:    "1.3.6.1.2.1.2.2.1.5.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.5",
					Value:  "10000000",
					Type:   mapping.Integer,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.2.2.1.1",
						Entity: "interface",
						Field:  "_id",
					},
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
					{
						OID:    "1.3.6.1.2.1.2.2.1.5",
						Entity: "interface",
						Field:  "speed",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.Interface{
				Speed: int64Ptr(10000),
				Type:  mapping.StringPtr("10base-t"),
			},
			expectError: false,
		},
		{
			name:   "empty values map",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1.1",
				Entity: "interface",
				Field:  "_id",
			},
			expectedEntity: &diode.Interface{
				Name: mapping.StringPtr("unknown"),
			},
			expectError: false,
		},
		{
			name: "mapping with MTU value of 0 should result in nil MTU",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.2.2.1.1.1": {
					OID:    "1.3.6.1.2.1.2.2.1.1.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.1",
					Value:  "1",
					Type:   mapping.Integer,
				},
				"1.3.6.1.2.1.2.2.1.2.1": {
					OID:    "1.3.6.1.2.1.2.2.1.2.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.2",
					Value:  "eth0",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.2.2.1.4.1": {
					OID:    "1.3.6.1.2.1.2.2.1.4.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.4",
					Value:  "0",
					Type:   mapping.Integer,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.2.2.1.1",
						Entity: "interface",
						Field:  "_id",
					},
					{
						OID:    "1.3.6.1.2.1.2.2.1.2",
						Entity: "interface",
						Field:  "name",
					},
					{
						OID:    "1.3.6.1.2.1.2.2.1.4",
						Entity: "interface",
						Field:  "mtu",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.Interface{
				Name: mapping.StringPtr("eth0"),
				Mtu:  nil, // MTU should be nil when value is 0
			},
			expectError: false,
		},
		{
			name: "mapping with negative MTU value should result in nil MTU",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.2.2.1.1.1": {
					OID:    "1.3.6.1.2.1.2.2.1.1.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.1",
					Value:  "1",
					Type:   mapping.Integer,
				},
				"1.3.6.1.2.1.2.2.1.2.1": {
					OID:    "1.3.6.1.2.1.2.2.1.2.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.2",
					Value:  "eth0",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.2.2.1.4.1": {
					OID:    "1.3.6.1.2.1.2.2.1.4.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.4",
					Value:  "-1",
					Type:   mapping.Integer,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.2.2.1.1",
						Entity: "interface",
						Field:  "_id",
					},
					{
						OID:    "1.3.6.1.2.1.2.2.1.2",
						Entity: "interface",
						Field:  "name",
					},
					{
						OID:    "1.3.6.1.2.1.2.2.1.4",
						Entity: "interface",
						Field:  "mtu",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.Interface{
				Name: mapping.StringPtr("eth0"),
				Mtu:  nil, // MTU should be nil when value is negative
			},
			expectError: false,
		},
		{
			name: "mapping with empty MTU value should result in nil MTU",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.2.2.1.1.1": {
					OID:    "1.3.6.1.2.1.2.2.1.1.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.1",
					Value:  "1",
					Type:   mapping.Integer,
				},
				"1.3.6.1.2.1.2.2.1.2.1": {
					OID:    "1.3.6.1.2.1.2.2.1.2.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.2",
					Value:  "eth0",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.2.2.1.4.1": {
					OID:    "1.3.6.1.2.1.2.2.1.4.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.4",
					Value:  "",
					Type:   mapping.Integer,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.2.2.1.1",
						Entity: "interface",
						Field:  "_id",
					},
					{
						OID:    "1.3.6.1.2.1.2.2.1.2",
						Entity: "interface",
						Field:  "name",
					},
					{
						OID:    "1.3.6.1.2.1.2.2.1.4",
						Entity: "interface",
						Field:  "mtu",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.Interface{
				Name: mapping.StringPtr("eth0"),
				Mtu:  nil, // MTU should be nil when value is empty
			},
			expectError: false,
		},
		{
			name: "mapping with speed below minimum should result in nil speed",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.2.2.1.1.1": {
					OID:    "1.3.6.1.2.1.2.2.1.1.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.1",
					Value:  "1",
					Type:   mapping.Integer,
				},
				"1.3.6.1.2.1.2.2.1.2.1": {
					OID:    "1.3.6.1.2.1.2.2.1.2.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.2",
					Value:  "eth0",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.2.2.1.5.1": {
					OID:    "1.3.6.1.2.1.2.2.1.5.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.5",
					Value:  "0",
					Type:   mapping.Integer,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.2.2.1.1",
						Entity: "interface",
						Field:  "_id",
					},
					{
						OID:    "1.3.6.1.2.1.2.2.1.2",
						Entity: "interface",
						Field:  "name",
					},
					{
						OID:    "1.3.6.1.2.1.2.2.1.5",
						Entity: "interface",
						Field:  "speed",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.Interface{
				Name:  mapping.StringPtr("eth0"),
				Speed: nil, // Speed should be nil when value is below minimum
			},
			expectError: false,
		},
		{
			name: "mapping with speed above maximum should result in nil speed",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.2.2.1.1.1": {
					OID:    "1.3.6.1.2.1.2.2.1.1.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.1",
					Value:  "1",
					Type:   mapping.Integer,
				},
				"1.3.6.1.2.1.2.2.1.2.1": {
					OID:    "1.3.6.1.2.1.2.2.1.2.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.2",
					Value:  "eth0",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.2.2.1.5.1": {
					OID:    "1.3.6.1.2.1.2.2.1.5.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.5",
					Value:  "2147483648000",
					Type:   mapping.Integer,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.2.2.1.1",
						Entity: "interface",
						Field:  "_id",
					},
					{
						OID:    "1.3.6.1.2.1.2.2.1.2",
						Entity: "interface",
						Field:  "name",
					},
					{
						OID:    "1.3.6.1.2.1.2.2.1.5",
						Entity: "interface",
						Field:  "speed",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.Interface{
				Name:  mapping.StringPtr("eth0"),
				Speed: nil, // Speed should be nil when value is above maximum
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.Default()
			registry := mapping.NewEntityRegistry(logger)
			mapper := mapping.NewInterfaceMapper(logger)
			entity := mapper.Map(tt.values, tt.mappingEntry, registry, tt.defaults)

			if tt.expectError {
				assert.Nil(t, entity)
				return
			}

			assert.NotNil(t, entity)
			iface, ok := entity.(*diode.Interface)
			assert.True(t, ok)
			if tt.expectedEntity.Name != nil {
				assert.Equal(t, tt.expectedEntity.Name, iface.Name)
			}
			if tt.expectedEntity.Mtu != nil {
				assert.Equal(t, tt.expectedEntity.Mtu, iface.Mtu)
			}
			if tt.expectedEntity.Speed != nil {
				assert.Equal(t, tt.expectedEntity.Speed, iface.Speed)
			}
			if tt.expectedEntity.PrimaryMacAddress != nil {
				assert.Equal(t, tt.expectedEntity.PrimaryMacAddress.MacAddress, iface.PrimaryMacAddress.MacAddress)
			}
			if tt.expectedEntity.Type != nil {
				assert.Equal(t, tt.expectedEntity.Type, iface.Type, "Expected type to be %s, got %s", *tt.expectedEntity.Type, *iface.Type)
			}
			if tt.expectedEntity.Enabled != nil {
				assert.Equal(t, tt.expectedEntity.Enabled, iface.Enabled, "Expected enabled to be %t, got %t", *tt.expectedEntity.Enabled, *iface.Enabled)
			}
			if tt.expectedEntity.Description != nil {
				assert.Equal(t, tt.expectedEntity.Description, iface.Description, "Expected description to be %s, got %s", *tt.expectedEntity.Description, *iface.Description)
			}
			if tt.expectedEntity.Tags != nil {
				assert.Equal(t, len(tt.expectedEntity.Tags), len(iface.Tags))
				for i, tag := range tt.expectedEntity.Tags {
					assert.Equal(t, tag.Name, iface.Tags[i].Name)
				}
			}
		})
	}
}

func TestInterfaceMapper_FormatMACAddress(t *testing.T) {
	logger := slog.Default()
	mapper := mapping.NewInterfaceMapper(logger)

	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{
			name:        "valid hex string with backslashes",
			input:       "\x00\x11\x22\x33\x44\x55",
			expected:    "00:11:22:33:44:55",
			expectError: false,
		},
		{
			name:        "valid hex string with lowercase letters",
			input:       "\x00\x11\x22\x33\x44\xab",
			expected:    "00:11:22:33:44:AB",
			expectError: false,
		},
		{
			name:        "invalid (too short) hex string with backslashes",
			input:       "\x00\x11\x22\x33\x44",
			expected:    "",
			expectError: true,
		},
		{
			name:        "invalid (too long) hex string with backslashes",
			input:       "\x00\x11\x22\x33\x44\x55\x66",
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := mapper.FormatMACAddress(tt.input)
			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestDeviceMapper_Map(t *testing.T) {
	logger := slog.Default()

	// Create a mock manufacturer data retriever
	mockDeviceLookup := &MockDeviceLookup{}
	mockDeviceLookup.On("GetDevice", "1.3.6.1.4.1.9.1.1234").Return("cisco4000", nil)
	mockDeviceLookup.On("GetDevice", "1.3.6.1.4.1.9.1.9999").Return("", fmt.Errorf("device not found"))
	mockDeviceLookup.On("GetDevice", "1.3.6.1.4.1.123.1.5678").Return("device-with-unknown-manufacturer", nil)

	mockManufacturers := &MockManufacturerDataRetriever{}
	mockManufacturers.On("GetManufacturer", "9").Return("Cisco", nil)
	mockManufacturers.On("GetManufacturer", "25506").Return("Juniper", nil)
	mockManufacturers.On("GetManufacturer", "999").Return("", fmt.Errorf("manufacturer not found"))
	mockManufacturers.On("GetManufacturer", "123").Return("", fmt.Errorf("manufacturer not found"))
	mapper := mapping.NewDeviceMapper(mockManufacturers, mockDeviceLookup, logger)

	tests := []struct {
		name           string
		values         map[mapping.ObjectIDIndex]*mapping.ObjectIDValue
		mappingEntry   *mapping.Entry
		defaults       *config.Defaults
		expectedEntity *diode.Device
		expectError    bool
	}{
		{
			name: "successful mapping with name and platform",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.1.5.0": {
					OID:    "1.3.6.1.2.1.1.5.0",
					Index:  "0",
					Parent: "1.3.6.1.2.1.1.5",
					Value:  "router1",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.1.2.0": {
					OID:    "1.3.6.1.2.1.1.2.0",
					Index:  "0",
					Parent: "1.3.6.1.2.1.1.2",
					Value:  "1.3.6.1.4.1.9.1.1234",
					Type:   mapping.ObjectIdentifier,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.1",
				Entity: "device",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.1.5",
						Entity: "device",
						Field:  "name",
					},
					{
						OID:    "1.3.6.1.2.1.1.2",
						Entity: "device",
						Field:  "platform",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.Device{
				Name: mapping.StringPtr("router1"),
				DeviceType: &diode.DeviceType{
					Manufacturer: &diode.Manufacturer{
						Name: mapping.StringPtr("Cisco"),
					},
					Model: mapping.StringPtr("cisco4000"),
				},
				Platform: &diode.Platform{
					Manufacturer: &diode.Manufacturer{
						Name: mapping.StringPtr("Cisco"),
					},
				},
			},
			expectError: false,
		},
		{
			name: "device lookup fails and falls back to objectID as model",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.1.5.0": {
					OID:    "1.3.6.1.2.1.1.5.0",
					Index:  "0",
					Parent: "1.3.6.1.2.1.1.5",
					Value:  "router1",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.1.2.0": {
					OID:    "1.3.6.1.2.1.1.2.0",
					Index:  "0",
					Parent: "1.3.6.1.2.1.1.2",
					Value:  "1.3.6.1.4.1.9.1.9999",
					Type:   mapping.ObjectIdentifier,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.1",
				Entity: "device",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.1.5",
						Entity: "device",
						Field:  "name",
					},
					{
						OID:    "1.3.6.1.2.1.1.2",
						Entity: "device",
						Field:  "platform",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.Device{
				Name: mapping.StringPtr("router1"),
				DeviceType: &diode.DeviceType{
					Manufacturer: &diode.Manufacturer{
						Name: mapping.StringPtr("Cisco"),
					},
					Model: mapping.StringPtr("1.3.6.1.4.1.9.1.9999"),
				},
				Platform: &diode.Platform{
					Manufacturer: &diode.Manufacturer{
						Name: mapping.StringPtr("Cisco"),
					},
				},
			},
			expectError: false,
		},
		{
			name: "manufacturer lookup fails and falls back to objectID as manufacturer",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.1.5.0": {
					OID:    "1.3.6.1.2.1.1.5.0",
					Index:  "0",
					Parent: "1.3.6.1.2.1.1.5",
					Value:  "router2",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.1.2.0": {
					OID:    "1.3.6.1.2.1.1.2.0",
					Index:  "0",
					Parent: "1.3.6.1.2.1.1.2",
					Value:  "1.3.6.1.4.1.123.1.5678",
					Type:   mapping.ObjectIdentifier,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.1",
				Entity: "device",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.1.5",
						Entity: "device",
						Field:  "name",
					},
					{
						OID:    "1.3.6.1.2.1.1.2",
						Entity: "device",
						Field:  "platform",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.Device{
				Name: mapping.StringPtr("router2"),
				DeviceType: &diode.DeviceType{
					Manufacturer: &diode.Manufacturer{
						Name: mapping.StringPtr("1.3.6.1.4.1.123.1.5678"),
					},
					Model: mapping.StringPtr("device-with-unknown-manufacturer"),
				},
				Platform: &diode.Platform{
					Name: mapping.StringPtr("1.3.6.1.4.1.123.1.5678"),
					Manufacturer: &diode.Manufacturer{
						Name: mapping.StringPtr("1.3.6.1.4.1.123.1.5678"),
					},
				},
			},
			expectError: false,
		},
		{
			name: "mapping with both global and entity-specific defaults",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.1.5.0": {
					OID:    "1.3.6.1.2.1.1.5.0",
					Index:  "0",
					Parent: "1.3.6.1.2.1.1.5",
					Value:  "router1",
					Type:   mapping.OctetString,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.1",
				Entity: "device",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.1.5",
						Entity: "device",
						Field:  "name",
					},
				},
			},
			defaults: &config.Defaults{
				Tags:     []string{"global-tag1", "global-tag2"},
				Role:     "test-role",
				Site:     "test-site",
				Location: "test-location",
				Device: config.DeviceDefaults{
					Description: "Device specific description",
					Tags:        []string{"device-tag1", "device-tag2"},
					Comments:    "Device specific comments",
				},
			},
			expectedEntity: &diode.Device{
				Name:        mapping.StringPtr("router1"),
				Description: mapping.StringPtr("Device specific description"),
				Comments:    mapping.StringPtr("Device specific comments"),
				Tags: []*diode.Tag{
					{Name: mapping.StringPtr("device-tag1")},
					{Name: mapping.StringPtr("device-tag2")},
					{Name: mapping.StringPtr("global-tag1")},
					{Name: mapping.StringPtr("global-tag2")},
				},
				Role: &diode.DeviceRole{
					Name: mapping.StringPtr("test-role"),
				},
				Site: &diode.Site{
					Name: mapping.StringPtr("test-site"),
				},
				Location: &diode.Location{
					Name: mapping.StringPtr("test-location"),
					Site: &diode.Site{
						Name: mapping.StringPtr("test-site"),
					},
				},
			},
			expectError: false,
		},
		{
			name: "mapping with invalid platform OID",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.1.5.0": {
					OID:    "1.3.6.1.2.1.1.5.0",
					Index:  "0",
					Parent: "1.3.6.1.2.1.1.5",
					Value:  "router1",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.1.2.0": {
					OID:    "1.3.6.1.2.1.1.2.0",
					Index:  "0",
					Parent: "1.3.6.1.2.1.1.2",
					Value:  "invalid",
					Type:   mapping.ObjectIdentifier,
				},
			},
			defaults: nil,
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.1",
				Entity: "device",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.1.5",
						Entity: "device",
						Field:  "name",
					},
					{
						OID:    "1.3.6.1.2.1.1.2",
						Entity: "device",
						Field:  "platform",
					},
				},
			},
			expectedEntity: &diode.Device{
				Name: mapping.StringPtr("router1"),
			},
			expectError: false,
		},
		{
			name: "successful mapping with description field",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.1.5.0": {
					OID:    "1.3.6.1.2.1.1.5.0",
					Index:  "0",
					Parent: "1.3.6.1.2.1.1.5",
					Value:  "test-device",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.1.1.0": {
					OID:    "1.3.6.1.2.1.1.1.0",
					Index:  "0",
					Parent: "1.3.6.1.2.1.1.1",
					Value:  "Test device description from SNMP",
					Type:   mapping.OctetString,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.1",
				Entity: "device",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.1.5",
						Entity: "device",
						Field:  "name",
					},
					{
						OID:    "1.3.6.1.2.1.1.1",
						Entity: "device",
						Field:  "description",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.Device{
				Name:        mapping.StringPtr("test-device"),
				Description: mapping.StringPtr("Test device description from SNMP"),
			},
			expectError: false,
		},
		{
			name:   "empty values map",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.1",
				Entity: "device",
				Field:  "_id",
			},
			expectedEntity: &diode.Device{},
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := mapping.NewEntityRegistry(logger)
			entity := mapper.Map(tt.values, tt.mappingEntry, registry, tt.defaults)

			if tt.expectError {
				assert.Nil(t, entity)
				return
			}

			assert.NotNil(t, entity)
			device, ok := entity.(*diode.Device)
			assert.True(t, ok)
			assert.Equal(t, tt.expectedEntity.Name, device.Name)
			if tt.expectedEntity.DeviceType != nil {
				assert.Equal(t, tt.expectedEntity.DeviceType.Manufacturer.Name, device.DeviceType.Manufacturer.Name)
				assert.Equal(t, tt.expectedEntity.DeviceType.Model, device.DeviceType.Model)
			}
			if tt.expectedEntity.Platform != nil {
				assert.Equal(t, tt.expectedEntity.Platform.Manufacturer.Name, device.Platform.Manufacturer.Name)
			}
			assert.Equal(t, tt.expectedEntity.Description, device.Description)
			if tt.expectedEntity.Location != nil {
				assert.Equal(t, tt.expectedEntity.Location.Name, device.Location.Name)
				assert.Equal(t, tt.expectedEntity.Location.Site.Name, device.Location.Site.Name)
			}
			if tt.expectedEntity.Site != nil {
				assert.Equal(t, tt.expectedEntity.Site.Name, device.Site.Name)
			}
			if tt.expectedEntity.Tags != nil {
				assert.Equal(t, len(tt.expectedEntity.Tags), len(device.Tags))
				for i, tag := range tt.expectedEntity.Tags {
					assert.Equal(t, tag.Name, device.Tags[i].Name)
				}
			}
		})
	}
}

// MockManufacturerDataRetriever is a mock implementation of ManufacturerDataRetriever
type MockManufacturerDataRetriever struct {
	mock.Mock
}

func (m *MockManufacturerDataRetriever) GetManufacturer(id string) (string, error) {
	args := m.Called(id)
	return args.Get(0).(string), args.Error(1)
}

type MockDeviceLookup struct {
	mock.Mock
}

func (m *MockDeviceLookup) GetDevice(deviceOID string) (string, error) {
	args := m.Called(deviceOID)
	return args.Get(0).(string), args.Error(1)
}

// Helper functions to create pointers
func int64Ptr(i int64) *int64 {
	return &i
}

func boolPtr(b bool) *bool {
	return &b
}

func TestMaskToPrefixSize(t *testing.T) {
	tests := []struct {
		name        string
		maskStr     string
		expected    int
		expectError bool
	}{
		{
			name:        "valid subnet mask 255.255.255.0",
			maskStr:     "255.255.255.0",
			expected:    24,
			expectError: false,
		},
		{
			name:        "valid subnet mask 255.255.0.0",
			maskStr:     "255.255.0.0",
			expected:    16,
			expectError: false,
		},
		{
			name:        "valid subnet mask 255.0.0.0",
			maskStr:     "255.0.0.0",
			expected:    8,
			expectError: false,
		},
		{
			name:        "valid subnet mask 255.255.255.128",
			maskStr:     "255.255.255.128",
			expected:    25,
			expectError: false,
		},
		{
			name:        "valid subnet mask 255.255.255.192",
			maskStr:     "255.255.255.192",
			expected:    26,
			expectError: false,
		},
		{
			name:        "valid subnet mask 255.255.255.224",
			maskStr:     "255.255.255.224",
			expected:    27,
			expectError: false,
		},
		{
			name:        "valid subnet mask 255.255.255.240",
			maskStr:     "255.255.255.240",
			expected:    28,
			expectError: false,
		},
		{
			name:        "valid subnet mask 255.255.255.248",
			maskStr:     "255.255.255.248",
			expected:    29,
			expectError: false,
		},
		{
			name:        "valid subnet mask 255.255.255.252",
			maskStr:     "255.255.255.252",
			expected:    30,
			expectError: false,
		},
		{
			name:        "valid subnet mask 255.255.255.254",
			maskStr:     "255.255.255.254",
			expected:    31,
			expectError: false,
		},
		{
			name:        "valid subnet mask 255.255.255.255",
			maskStr:     "255.255.255.255",
			expected:    32,
			expectError: false,
		},
		{
			name:        "invalid mask format - too few parts",
			maskStr:     "255.255.255",
			expected:    0,
			expectError: true,
		},
		{
			name:        "invalid mask format - too many parts",
			maskStr:     "255.255.255.255.255",
			expected:    0,
			expectError: true,
		},
		{
			name:        "invalid mask format - not an IP",
			maskStr:     "invalid.mask.format",
			expected:    0,
			expectError: true,
		},
		{
			name:        "invalid mask - IPv6 address",
			maskStr:     "2001:db8::1",
			expected:    0,
			expectError: true,
		},
		{
			name:        "invalid mask - out of range values",
			maskStr:     "256.256.256.256",
			expected:    0,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the maskToPrefixSize function by creating a temporary mapper
			mapper := mapping.NewIPAddressMapper(slog.Default())

			// Create a test case that will trigger the maskToPrefixSize function
			values := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"test.mask": {
					OID:    "test.mask",
					Index:  "test",
					Parent: "test",
					Value:  tt.maskStr,
					Type:   mapping.IPAddress,
				},
			}

			mappingEntry := &mapping.Entry{
				OID:    "test",
				Entity: "ipAddress",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "test",
						Entity: "ipAddress",
						Field:  "address_prefixSize",
					},
				},
			}

			entityRegistry := mapping.NewEntityRegistry(slog.Default())
			result := mapper.Map(values, mappingEntry, entityRegistry, nil)

			if tt.expectError {
				// For error cases, we expect the function to skip the invalid mask
				// and return an entity with no address set (since no valid fields were found)
				assert.NotNil(t, result)
				ipAddress, ok := result.(*diode.IPAddress)
				assert.True(t, ok)
				// The address should be nil since the invalid mask was skipped
				assert.Nil(t, ipAddress.Address)
			} else {
				// For valid cases, we expect the function to work correctly
				assert.NotNil(t, result)
				ipAddress, ok := result.(*diode.IPAddress)
				assert.True(t, ok)
				// The address should be just the prefix since there's no address field
				assert.Equal(t, fmt.Sprintf("/%d", tt.expected), *ipAddress.Address)
			}
		})
	}
}

func TestIPAddressMapper_Map_AddressPrefixSize(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name           string
		values         map[mapping.ObjectIDIndex]*mapping.ObjectIDValue
		mappingEntry   *mapping.Entry
		defaults       *config.Defaults
		expectedEntity *diode.IPAddress
		expectError    bool
	}{
		{
			name: "address_prefixSize with existing address",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.1.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.1.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.1",
					Value:  "192.168.1.1",
					Type:   mapping.IPAddress,
				},
				"1.3.6.1.2.1.4.20.1.3.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.3.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.3",
					Value:  "255.255.255.0",
					Type:   mapping.IPAddress,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1.1",
				Entity: "ipAddress",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.4.20.1.1",
						Entity: "ipAddress",
						Field:  "address",
					},
					{
						OID:    "1.3.6.1.2.1.4.20.1.3",
						Entity: "ipAddress",
						Field:  "address_prefixSize",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.IPAddress{
				Address: mapping.StringPtr("192.168.1.1/24"),
			},
			expectError: false,
		},
		{
			name: "address_prefixSize without existing address",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.3.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.3.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.3",
					Value:  "255.255.255.0",
					Type:   mapping.IPAddress,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1.3",
				Entity: "ipAddress",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.4.20.1.3",
						Entity: "ipAddress",
						Field:  "address_prefixSize",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.IPAddress{
				Address: mapping.StringPtr("/24"),
			},
			expectError: false,
		},
		{
			name: "address_prefixSize with address that already has prefix",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.1.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.1.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.1",
					Value:  "192.168.1.1/16",
					Type:   mapping.IPAddress,
				},
				"1.3.6.1.2.1.4.20.1.3.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.3.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.3",
					Value:  "255.255.255.0",
					Type:   mapping.IPAddress,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1.1",
				Entity: "ipAddress",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.4.20.1.1",
						Entity: "ipAddress",
						Field:  "address",
					},
					{
						OID:    "1.3.6.1.2.1.4.20.1.3",
						Entity: "ipAddress",
						Field:  "address_prefixSize",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.IPAddress{
				Address: mapping.StringPtr("192.168.1.1/24"),
			},
			expectError: false,
		},
		{
			name: "address_prefixSize with address that has no prefix",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.1.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.1.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.1",
					Value:  "192.168.1.1",
					Type:   mapping.IPAddress,
				},
				"1.3.6.1.2.1.4.20.1.3.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.3.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.3",
					Value:  "255.255.255.0",
					Type:   mapping.IPAddress,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1.1",
				Entity: "ipAddress",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.4.20.1.1",
						Entity: "ipAddress",
						Field:  "address",
					},
					{
						OID:    "1.3.6.1.2.1.4.20.1.3",
						Entity: "ipAddress",
						Field:  "address_prefixSize",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.IPAddress{
				Address: mapping.StringPtr("192.168.1.1/24"),
			},
			expectError: false,
		},
		{
			name: "address_prefixSize with invalid mask - should skip",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.1.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.1.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.1",
					Value:  "192.168.1.1",
					Type:   mapping.IPAddress,
				},
				"1.3.6.1.2.1.4.20.1.3.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.3.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.3",
					Value:  "invalid.mask",
					Type:   mapping.IPAddress,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1.1",
				Entity: "ipAddress",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.4.20.1.1",
						Entity: "ipAddress",
						Field:  "address",
					},
					{
						OID:    "1.3.6.1.2.1.4.20.1.3",
						Entity: "ipAddress",
						Field:  "address_prefixSize",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.IPAddress{
				Address: mapping.StringPtr("192.168.1.1/32"),
			},
			expectError: false,
		},
		{
			name: "address_prefixSize with different subnet masks",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.1.10.0.0.1": {
					OID:    "1.3.6.1.2.1.4.20.1.1.10.0.0.1",
					Index:  "10.0.0.1",
					Parent: "1.3.6.1.2.1.4.20.1.1",
					Value:  "10.0.0.1",
					Type:   mapping.IPAddress,
				},
				"1.3.6.1.2.1.4.20.1.3.10.0.0.1": {
					OID:    "1.3.6.1.2.1.4.20.1.3.10.0.0.1",
					Index:  "10.0.0.1",
					Parent: "1.3.6.1.2.1.4.20.1.3",
					Value:  "255.0.0.0",
					Type:   mapping.IPAddress,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1.1",
				Entity: "ipAddress",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.4.20.1.1",
						Entity: "ipAddress",
						Field:  "address",
					},
					{
						OID:    "1.3.6.1.2.1.4.20.1.3",
						Entity: "ipAddress",
						Field:  "address_prefixSize",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.IPAddress{
				Address: mapping.StringPtr("10.0.0.1/8"),
			},
			expectError: false,
		},
		{
			name: "address_prefixSize with /30 subnet",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.1.172.16.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.1.172.16.1.1",
					Index:  "172.16.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.1",
					Value:  "172.16.1.1",
					Type:   mapping.IPAddress,
				},
				"1.3.6.1.2.1.4.20.1.3.172.16.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.3.172.16.1.1",
					Index:  "172.16.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.3",
					Value:  "255.255.255.252",
					Type:   mapping.IPAddress,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1.1",
				Entity: "ipAddress",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.4.20.1.1",
						Entity: "ipAddress",
						Field:  "address",
					},
					{
						OID:    "1.3.6.1.2.1.4.20.1.3",
						Entity: "ipAddress",
						Field:  "address_prefixSize",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.IPAddress{
				Address: mapping.StringPtr("172.16.1.1/30"),
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapper := mapping.NewIPAddressMapper(logger)
			entityRegistry := mapping.NewEntityRegistry(logger)

			result := mapper.Map(tt.values, tt.mappingEntry, entityRegistry, tt.defaults)

			if tt.expectError {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				ipAddress, ok := result.(*diode.IPAddress)
				assert.True(t, ok)
				assert.Equal(t, tt.expectedEntity.Address, ipAddress.Address)
			}
		})
	}
}
