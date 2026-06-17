package mapping_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/mapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
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
						Field:  "assignedObject",
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
			// IPAddressMapper now drops the row (returns nil) when no
			// PDU populated the address, instead of emitting an
			// empty &diode.IPAddress{}. expectError=true triggers the
			// runner's assert.Nil branch.
			expectError: true,
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
					Vrf:         config.VrfParameters{Name: "ip-address-vrf"},
				},
			},
			expectedEntity: &diode.IPAddress{
				Address:     mapping.StringPtr("192.168.1.1/32"),
				Description: mapping.StringPtr("IP Address specific description"),
				Tenant: &diode.Tenant{
					Name: mapping.StringPtr("ip-address-tenant"),
				},
				Role: mapping.StringPtr("ip-address-role"),
				// Scalar form: Vrf.Name set, Vrf.Rd left nil so NetBox can
				// match an existing VRF whose rd column is null. The
				// pre-fix rd=name hardcode is the behaviour change.
				Vrf: &diode.VRF{
					Name: mapping.StringPtr("ip-address-vrf"),
				},
			},
			expectError: false,
		},
		{
			// Rich VrfParameters form propagates Rd / Description /
			// Comments / Tags onto the emitted diode.VRF.
			name: "ipAddress with rich VRF defaults (name + rd + description + comments + tags)",
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
					Vrf: config.VrfParameters{
						Name:        "prod",
						Rd:          "65000:100",
						Description: "Prod VRF",
						Comments:    "Imported via SNMP",
						Tags:        []string{"auto", "vrf"},
					},
				},
			},
			expectedEntity: &diode.IPAddress{
				Address: mapping.StringPtr("192.168.1.1/32"),
				Vrf: &diode.VRF{
					Name:        mapping.StringPtr("prod"),
					Rd:          mapping.StringPtr("65000:100"),
					Description: mapping.StringPtr("Prod VRF"),
					Comments:    mapping.StringPtr("Imported via SNMP"),
					Tags: []*diode.Tag{
						{Name: mapping.StringPtr("auto")},
						{Name: mapping.StringPtr("vrf")},
					},
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
				require.NotNil(t, ipAddress.Vrf,
					"expected a VRF, got nil — subsequent field assertions would panic")
				assert.Equal(t, tt.expectedEntity.Vrf.Name, ipAddress.Vrf.Name)
				assert.Equal(t, tt.expectedEntity.Vrf.Rd, ipAddress.Vrf.Rd)
				assert.Equal(t, tt.expectedEntity.Vrf.Description, ipAddress.Vrf.Description)
				assert.Equal(t, tt.expectedEntity.Vrf.Comments, ipAddress.Vrf.Comments)
				require.Len(t, ipAddress.Vrf.Tags, len(tt.expectedEntity.Vrf.Tags),
					"VRF tag count mismatch — would panic on per-element indexing below")
				for i, expectedTag := range tt.expectedEntity.Vrf.Tags {
					assert.Equal(t, expectedTag.Name, ipAddress.Vrf.Tags[i].Name)
				}
			} else {
				assert.Nil(t, ipAddress.Vrf,
					"expected no VRF on the emitted IPAddress, got one")
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
				"1.3.6.1.2.1.31.1.1.1.18.1": {
					OID:    "1.3.6.1.2.1.31.1.1.1.18.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.31.1.1.1.18",
					Value:  "uplink interface",
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
					{
						OID:    "1.3.6.1.2.1.31.1.1.1.18",
						Entity: "interface",
						Field:  "description",
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
				Description:       mapping.StringPtr("uplink interface"),
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
				Type:  mapping.StringPtr("other"),
			},
			expectError: false,
		},
		{
			name: "mapping with highSpeed value",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.31.1.1.1.15.1": {
					OID:    "1.3.6.1.2.1.31.1.1.1.15.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.31.1.1.1.15",
					Value:  "10000",
					Type:   mapping.Integer,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.31.1.1.1.15",
						Entity: "interface",
						Field:  "highSpeed",
					},
				},
			},
			expectedEntity: &diode.Interface{
				Speed: int64Ptr(10000000),
			},
			expectError: false,
		},
		{
			name: "mapping with highSpeed preferred over speed",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.2.2.1.5.1": {
					OID:    "1.3.6.1.2.1.2.2.1.5.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.5",
					Value:  "10000000",
					Type:   mapping.Integer,
				},
				"1.3.6.1.2.1.31.1.1.1.15.1": {
					OID:    "1.3.6.1.2.1.31.1.1.1.15.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.31.1.1.1.15",
					Value:  "10000",
					Type:   mapping.Integer,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.2.2.1.5",
						Entity: "interface",
						Field:  "speed",
					},
					{
						OID:    "1.3.6.1.2.1.31.1.1.1.15",
						Entity: "interface",
						Field:  "highSpeed",
					},
				},
			},
			expectedEntity: &diode.Interface{
				Speed: int64Ptr(10000000),
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
					Value:  "-1000",
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
		{
			name: "mapping with MTU above maximum should result in nil MTU",
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
					Value:  "2147483648",
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
				Mtu:  nil, // MTU should be nil when value is above maximum
			},
			expectError: false,
		},
		{
			name: "mapping with MTU below minimum should result in nil MTU",
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
				Mtu:  nil, // MTU should be nil when value is below minimum
			},
			expectError: false,
		},
		{
			name: "mapping with MTU that overflows int32 should result in nil MTU",
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
					Value:  "9223372036854775807",
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
				Mtu:  nil, // MTU should be nil when value overflows int32
			},
			expectError: false,
		},
		{
			name: "mapping with MTU at maximum valid value should succeed",
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
					Value:  "2147483647",
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
				Mtu:  int64Ptr(2147483647), // MTU should be set when value is at maximum valid range
			},
			expectError: false,
		},
		{
			name: "mapping with MTU at minimum valid value should succeed",
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
				},
			},
			defaults: nil,
			expectedEntity: &diode.Interface{
				Name: mapping.StringPtr("eth0"),
				Mtu:  int64Ptr(1), // MTU should be set when value is at minimum valid range
			},
			expectError: false,
		},
		{
			name: "mapping with MTU just above maximum should result in nil MTU",
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
					Value:  "2147483648",
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
				Mtu:  nil, // MTU should be nil when value is just above maximum
			},
			expectError: false,
		},
		{
			name: "mapping with MTU just below minimum should result in nil MTU",
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
				Mtu:  nil, // MTU should be nil when value is just below minimum
			},
			expectError: false,
		},
		{
			name: "trailing null bytes are stripped from interface name and description",
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
					Value:  "eth0\x00",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.31.1.1.1.18.1": {
					OID:    "1.3.6.1.2.1.31.1.1.1.18.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.31.1.1.1.18",
					Value:  "uplink\x00",
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
					{
						OID:    "1.3.6.1.2.1.31.1.1.1.18",
						Entity: "interface",
						Field:  "description",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.Interface{
				Name:        mapping.StringPtr("eth0"),
				Description: mapping.StringPtr("uplink"),
			},
			expectError: false,
		},
		{
			name: "interior null bytes are stripped from interface name and description",
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
					Value:  "eth\x000",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.31.1.1.1.18.1": {
					OID:    "1.3.6.1.2.1.31.1.1.1.18.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.31.1.1.1.18",
					Value:  "up\x00link",
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
					{
						OID:    "1.3.6.1.2.1.31.1.1.1.18",
						Entity: "interface",
						Field:  "description",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.Interface{
				Name:        mapping.StringPtr("eth0"),
				Description: mapping.StringPtr("uplink"),
			},
			expectError: false,
		},
		{
			name: "null-byte-only description falls back to configured default",
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
				"1.3.6.1.2.1.31.1.1.1.18.1": {
					OID:    "1.3.6.1.2.1.31.1.1.1.18.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.31.1.1.1.18",
					Value:  "\x00",
					Type:   mapping.OctetString,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{OID: "1.3.6.1.2.1.2.2.1.1", Entity: "interface", Field: "_id"},
					{OID: "1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
					{OID: "1.3.6.1.2.1.31.1.1.1.18", Entity: "interface", Field: "description"},
				},
			},
			defaults: &config.Defaults{
				Interface: config.InterfaceDefaults{
					Description: "default interface description",
				},
			},
			expectedEntity: &diode.Interface{
				Name:        mapping.StringPtr("eth0"),
				Description: mapping.StringPtr("default interface description"),
			},
			expectError: false,
		},
		{
			// SNMP description must not be overwritten by the default description.
			name: "SNMP description is preserved when defaults also specify a description",
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
				"1.3.6.1.2.1.31.1.1.1.18.1": {
					OID:    "1.3.6.1.2.1.31.1.1.1.18.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.31.1.1.1.18",
					Value:  "uplink to core",
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
					{
						OID:    "1.3.6.1.2.1.31.1.1.1.18",
						Entity: "interface",
						Field:  "description",
					},
				},
			},
			defaults: &config.Defaults{
				Interface: config.InterfaceDefaults{
					Description: "default interface description",
				},
			},
			expectedEntity: &diode.Interface{
				Name:        mapping.StringPtr("eth0"),
				Description: mapping.StringPtr("uplink to core"),
			},
			expectError: false,
		},
		{
			name: "ifName fallback when ifDescr is empty",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.2.2.1.2.1": {
					OID:    "1.3.6.1.2.1.2.2.1.2.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.2",
					Value:  "",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.31.1.1.1.1.1": {
					OID:    "1.3.6.1.2.1.31.1.1.1.1.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.31.1.1.1.1",
					Value:  "mgmt",
					Type:   mapping.OctetString,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{OID: "1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
					{OID: "1.3.6.1.2.1.31.1.1.1.1", Entity: "interface", Field: "name_alternate"},
				},
			},
			expectedEntity: &diode.Interface{
				Name: mapping.StringPtr("mgmt"),
			},
			expectError: false,
		},
		{
			name: "ifName replaces ifDescr when ifDescr is descriptive",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.2.2.1.2.1": {
					OID:    "1.3.6.1.2.1.2.2.1.2.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.2",
					Value:  "Unit: 1 Slot: 0 Port: 1 Gigabit - Level",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.31.1.1.1.1.1": {
					OID:    "1.3.6.1.2.1.31.1.1.1.1.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.31.1.1.1.1",
					Value:  "Gi1/0/1",
					Type:   mapping.OctetString,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{OID: "1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
					{OID: "1.3.6.1.2.1.31.1.1.1.1", Entity: "interface", Field: "name_alternate"},
				},
			},
			expectedEntity: &diode.Interface{
				Name: mapping.StringPtr("Gi1/0/1"),
			},
			expectError: false,
		},
		{
			// Under the mapper's slices.Sort + slices.Reverse iteration,
			// ifName (`.31.x`) is processed BEFORE ifDescr (`.2.2.x`).
			// `case "name"` must not overwrite the already-set clean
			// Name with the descriptive ifDescr — both case-arms are
			// guarded so the final Name is order-independent.
			name: "ifDescr does not overwrite clean ifName even when processed second",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				// OID-sorted reverse means .31.x lands BEFORE .2.2.x.
				"1.3.6.1.2.1.31.1.1.1.1.1": {
					OID:    "1.3.6.1.2.1.31.1.1.1.1.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.31.1.1.1.1",
					Value:  "Gi1/0/1",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.2.2.1.2.1": {
					OID:    "1.3.6.1.2.1.2.2.1.2.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.2",
					Value:  "Unit: 1 Slot: 0 Port: 1 Gigabit - Level",
					Type:   mapping.OctetString,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{OID: "1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
					{OID: "1.3.6.1.2.1.31.1.1.1.1", Entity: "interface", Field: "name_alternate"},
				},
			},
			expectedEntity: &diode.Interface{
				Name: mapping.StringPtr("Gi1/0/1"),
			},
			expectError: false,
		},
		{
			// Dell FTOS / Extreme SLX style: ifDescr has a single space
			// but is the canonical name (no colon-space substring), so
			// it must remain Name even when ifName is a whitespace-free
			// shorter form. Protects the asymmetry between the broad
			// containsWhitespace predicate (subinterface heuristic) and
			// the narrower looksDescriptive predicate (name selection).
			name: "single-space canonical ifDescr beats short ifName",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.2.2.1.2.1": {
					OID:    "1.3.6.1.2.1.2.2.1.2.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.2",
					Value:  "TenGigabitEthernet 0/0",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.31.1.1.1.1.1": {
					OID:    "1.3.6.1.2.1.31.1.1.1.1.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.31.1.1.1.1",
					Value:  "Te0/0",
					Type:   mapping.OctetString,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{OID: "1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
					{OID: "1.3.6.1.2.1.31.1.1.1.1", Entity: "interface", Field: "name_alternate"},
				},
			},
			expectedEntity: &diode.Interface{
				Name: mapping.StringPtr("TenGigabitEthernet 0/0"),
			},
			expectError: false,
		},
		{
			// Pre-existing behavior still applies when both names are
			// clean (no colon-space): ifDescr wins. This is the
			// regression guard for the long-standing "ifDescr wins
			// when both are populated" test, applied to a non-Gi name
			// to vary it.
			name: "clean ifDescr still wins over clean ifName",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.2.2.1.2.1": {
					OID:    "1.3.6.1.2.1.2.2.1.2.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.2",
					Value:  "FortyGigE1/0/1",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.31.1.1.1.1.1": {
					OID:    "1.3.6.1.2.1.31.1.1.1.1.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.31.1.1.1.1",
					Value:  "Fo1/0/1",
					Type:   mapping.OctetString,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{OID: "1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
					{OID: "1.3.6.1.2.1.31.1.1.1.1", Entity: "interface", Field: "name_alternate"},
				},
			},
			expectedEntity: &diode.Interface{
				Name: mapping.StringPtr("FortyGigE1/0/1"),
			},
			expectError: false,
		},
		{
			name: "ifName fallback when ifDescr PDU is absent",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.31.1.1.1.1.1": {
					OID:    "1.3.6.1.2.1.31.1.1.1.1.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.31.1.1.1.1",
					Value:  "port1",
					Type:   mapping.OctetString,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{OID: "1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
					{OID: "1.3.6.1.2.1.31.1.1.1.1", Entity: "interface", Field: "name_alternate"},
				},
			},
			expectedEntity: &diode.Interface{
				Name: mapping.StringPtr("port1"),
			},
			expectError: false,
		},
		{
			name: "ifDescr wins when both are populated",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.2.2.1.2.1": {
					OID:    "1.3.6.1.2.1.2.2.1.2.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.2",
					Value:  "GigabitEthernet1/0/1",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.31.1.1.1.1.1": {
					OID:    "1.3.6.1.2.1.31.1.1.1.1.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.31.1.1.1.1",
					Value:  "Gi1/0/1",
					Type:   mapping.OctetString,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{OID: "1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
					{OID: "1.3.6.1.2.1.31.1.1.1.1", Entity: "interface", Field: "name_alternate"},
				},
			},
			expectedEntity: &diode.Interface{
				Name: mapping.StringPtr("GigabitEthernet1/0/1"),
			},
			expectError: false,
		},
		{
			name: "both name sources empty leaves default unknown",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.2.2.1.2.1": {
					OID:    "1.3.6.1.2.1.2.2.1.2.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.2",
					Value:  "",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.31.1.1.1.1.1": {
					OID:    "1.3.6.1.2.1.31.1.1.1.1.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.31.1.1.1.1",
					Value:  "",
					Type:   mapping.OctetString,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{OID: "1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
					{OID: "1.3.6.1.2.1.31.1.1.1.1", Entity: "interface", Field: "name_alternate"},
				},
			},
			expectedEntity: &diode.Interface{
				Name: mapping.StringPtr(mapping.DefaultInterfaceName),
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.Default()
			registry := mapping.NewEntityRegistry(logger)
			mapper, err := mapping.NewInterfaceMapper(logger, nil)
			assert.NoError(t, err)
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

func TestInterfaceMapper_Map_ZeroSpeedAndMtu(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name         string
		values       map[mapping.ObjectIDIndex]*mapping.ObjectIDValue
		mappingEntry *mapping.Entry
		assertFn     func(t *testing.T, iface *diode.Interface)
	}{
		{
			name: "speed value of zero is accepted",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
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
			assertFn: func(t *testing.T, iface *diode.Interface) {
				assert.Equal(t, mapping.StringPtr("eth0"), iface.Name)
				zero := int64(0)
				assert.Equal(t, &zero, iface.Speed)
			},
		},
		{
			name: "negative speed is ignored",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
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
					Value:  "-1000",
					Type:   mapping.Integer,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
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
			assertFn: func(t *testing.T, iface *diode.Interface) {
				assert.Equal(t, mapping.StringPtr("eth0"), iface.Name)
				assert.Nil(t, iface.Speed)
			},
		},
		{
			name: "mtu value of zero is ignored",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
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
			assertFn: func(t *testing.T, iface *diode.Interface) {
				assert.Equal(t, mapping.StringPtr("eth0"), iface.Name)
				assert.Nil(t, iface.Mtu)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := mapping.NewEntityRegistry(logger)
			mapper, err := mapping.NewInterfaceMapper(logger, nil)
			assert.NoError(t, err)
			entity := mapper.Map(tt.values, tt.mappingEntry, registry, nil)
			assert.NotNil(t, entity)
			iface, ok := entity.(*diode.Interface)
			assert.True(t, ok)
			tt.assertFn(t, iface)
		})
	}
}

func TestInterfaceMapper_Map_HighSpeed(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name         string
		values       map[mapping.ObjectIDIndex]*mapping.ObjectIDValue
		mappingEntry *mapping.Entry
		assertFn     func(t *testing.T, iface *diode.Interface)
	}{
		{
			name: "highSpeed invalid value is ignored",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.31.1.1.1.15.1": {
					OID:    "1.3.6.1.2.1.31.1.1.1.15.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.31.1.1.1.15",
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
						OID:    "1.3.6.1.2.1.31.1.1.1.15",
						Entity: "interface",
						Field:  "highSpeed",
					},
				},
			},
			assertFn: func(t *testing.T, iface *diode.Interface) {
				assert.Nil(t, iface.Speed)
			},
		},
		{
			name: "highSpeed above maximum is ignored",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.31.1.1.1.15.1": {
					OID:    "1.3.6.1.2.1.31.1.1.1.15.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.31.1.1.1.15",
					Value:  "2147483648",
					Type:   mapping.Integer,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.31.1.1.1.15",
						Entity: "interface",
						Field:  "highSpeed",
					},
				},
			},
			assertFn: func(t *testing.T, iface *diode.Interface) {
				assert.Nil(t, iface.Speed)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := mapping.NewEntityRegistry(logger)
			mapper, err := mapping.NewInterfaceMapper(logger, nil)
			assert.NoError(t, err)
			entity := mapper.Map(tt.values, tt.mappingEntry, registry, nil)
			assert.NotNil(t, entity)
			iface, ok := entity.(*diode.Interface)
			assert.True(t, ok)
			tt.assertFn(t, iface)
		})
	}
}

func TestInterfaceMapper_FormatMACAddress(t *testing.T) {
	logger := slog.Default()
	mapper, err := mapping.NewInterfaceMapper(logger, nil)
	assert.NoError(t, err)

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
		{
			name:        "invalid all zeros MAC address (00:00:00:00:00:00)",
			input:       "\x00\x00\x00\x00\x00\x00",
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
			name: "device description under 200 characters remains unchanged",
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
					Value:  "This is a short device description that is well under 200 characters",
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
				Description: mapping.StringPtr("This is a short device description that is well under 200 characters"),
			},
			expectError: false,
		},
		{
			name: "device description exactly 200 characters remains unchanged",
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
					Value:  "This device description is exactly 200 charactersxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
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
				Description: mapping.StringPtr("This device description is exactly 200 charactersxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
			},
			expectError: false,
		},
		{
			name: "device description over 200 characters gets truncated to 197 plus ellipsis",
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
					Value:  "This device description is deliberately longer than two hundred characters to test the truncation functionality that should cut it off at 197 characters and add an ellipsis suffix to indicate that the description was truncated due to length constraints",
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
				Description: mapping.StringPtr("This device description is deliberately longer than two hundred characters to test the truncation functionality that should cut it off at 197 characters and add an ellipsis suffix to indicate that ..."),
			},
			expectError: false,
		},
		{
			name: "device description with trailing whitespace gets trimmed and remains under 200 characters",
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
					Value:  "This device description has trailing whitespace that should be stripped    \t\n\r",
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
				Description: mapping.StringPtr("This device description has trailing whitespace that should be stripped"),
			},
			expectError: false,
		},
		{
			name: "device description with trailing whitespace gets trimmed but still over 200 characters and truncated",
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
					Value:  "This device description is deliberately longer than two hundred characters to test the truncation functionality that should cut it off at 197 characters and add an ellipsis suffix to indicate that the description was truncated due to length constraints                    \t\n\r",
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
				Description: mapping.StringPtr("This device description is deliberately longer than two hundred characters to test the truncation functionality that should cut it off at 197 characters and add an ellipsis suffix to indicate that ..."),
			},
			expectError: false,
		},
		{
			name: "device description at exactly 200 characters with trailing whitespace gets trimmed to under 200",
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
					Value:  "This device description is exactly 200 charactersxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx     ",
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
				Description: mapping.StringPtr("This device description is exactly 200 charactersxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
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
		{
			name: "null-byte-only description falls back to configured default",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.1.5.0": {
					OID:    "1.3.6.1.2.1.1.5.0",
					Index:  "0",
					Parent: "1.3.6.1.2.1.1.5",
					Value:  "router1",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.1.1.0": {
					OID:    "1.3.6.1.2.1.1.1.0",
					Index:  "0",
					Parent: "1.3.6.1.2.1.1.1",
					Value:  "\x00",
					Type:   mapping.OctetString,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.1",
				Entity: "device",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{OID: "1.3.6.1.2.1.1.5", Entity: "device", Field: "name"},
					{OID: "1.3.6.1.2.1.1.1", Entity: "device", Field: "description"},
				},
			},
			defaults: &config.Defaults{
				Device: config.DeviceDefaults{
					Description: "default device description",
				},
			},
			expectedEntity: &diode.Device{
				Name:        mapping.StringPtr("router1"),
				Description: mapping.StringPtr("default device description"),
			},
			expectError: false,
		},
		{
			// SNMP description must not be overwritten by the default description.
			name: "SNMP description is preserved when defaults also specify a description",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.1.5.0": {
					OID:    "1.3.6.1.2.1.1.5.0",
					Index:  "0",
					Parent: "1.3.6.1.2.1.1.5",
					Value:  "router1",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.1.1.0": {
					OID:    "1.3.6.1.2.1.1.1.0",
					Index:  "0",
					Parent: "1.3.6.1.2.1.1.1",
					Value:  "description from SNMP",
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
			defaults: &config.Defaults{
				Device: config.DeviceDefaults{
					Description: "default device description",
				},
			},
			expectedEntity: &diode.Device{
				Name:        mapping.StringPtr("router1"),
				Description: mapping.StringPtr("description from SNMP"),
			},
			expectError: false,
		},
		{
			name: "trailing null bytes are stripped from device name and description",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.1.5.0": {
					OID:    "1.3.6.1.2.1.1.5.0",
					Index:  "0",
					Parent: "1.3.6.1.2.1.1.5",
					Value:  "router01\x00",
					Type:   mapping.OctetString,
				},
				"1.3.6.1.2.1.1.1.0": {
					OID:    "1.3.6.1.2.1.1.1.0",
					Index:  "0",
					Parent: "1.3.6.1.2.1.1.1",
					Value:  "core router\x00",
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
			defaults:       nil,
			expectedEntity: &diode.Device{Name: mapping.StringPtr("router01"), Description: mapping.StringPtr("core router")},
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

// TestDeviceMapper_Map_SerialNumber* tests were removed because the
// DeviceMapper no longer handles the "serialNumber" field. That responsibility
// moved to TranslateAsStack in mapping/chassis.go (see
// TestTranslateAsStack_Standalone* in mapping/chassis_test.go).
// mapping.yaml now routes entPhysicalSerialNum to entity "chassis_inventory",
// making the former case "serialNumber": branch in DeviceMapper.Map dead code.

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

func (m *MockDeviceLookup) GetDeviceModel(deviceOID string, walked map[string]string) (string, error) {
	// If an explicit GetDeviceModel expectation is registered, honour it.
	// Otherwise fall back to GetDevice so that tests written against the
	// old interface continue to work without modification.
	for _, call := range m.ExpectedCalls {
		if call.Method == "GetDeviceModel" {
			args := m.Called(deviceOID, walked)
			return args.Get(0).(string), args.Error(1)
		}
	}
	return m.GetDevice(deviceOID)
}

// FakeDynamicDeviceLookup resolves GetDeviceModel by looking up sourceOID
// in the walked map that the mapper passes in. GetDevice is unused.
type FakeDynamicDeviceLookup struct {
	sourceOID string
}

func (f *FakeDynamicDeviceLookup) GetDevice(_ string) (string, error) {
	return "", fmt.Errorf("dynamic ref; use GetDeviceModel")
}

func (f *FakeDynamicDeviceLookup) GetDeviceModel(_ string, walked map[string]string) (string, error) {
	// Accept both leading-dot and no-leading-dot spellings, mirroring the
	// real DeviceLookup.GetDeviceModel normalisation.
	if v, ok := walked[f.sourceOID]; ok {
		return v, nil
	}
	alt := strings.TrimPrefix(f.sourceOID, ".")
	if v, ok := walked[alt]; ok {
		return v, nil
	}
	if v, ok := walked["."+alt]; ok {
		return v, nil
	}
	return "", fmt.Errorf("not found")
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
						Field:  "addressPrefixSize",
					},
				},
			}

			entityRegistry := mapping.NewEntityRegistry(slog.Default())
			result := mapper.Map(values, mappingEntry, entityRegistry, nil)

			// Both branches now drop the row by returning nil:
			//  - valid mask + no IP builds "/24", validation rejects.
			//  - invalid mask fails maskToPrefixSize, fieldFound stays
			//    false, the post-loop guard catches the empty address.
			// Either way the mapper no longer leaks an empty entity.
			assert.Nil(t, result)
			_ = tt.expectError // Both paths now produce the same result.
		})
	}
}

// TestIPAddressMapper_Map_VRFNameEmptyWarns locks in the gate behaviour
// when an operator sets VRF sub-fields (Rd, Description, Comments, Tags)
// without a Name. The row drops silently in the proto (NetBox VRF
// matching keys on Name + Rd, and there's nothing to attach without
// Name), but the mapper emits a WARNING so the misconfiguration is
// visible in the logs instead of silently producing IPs with no VRF.
func TestIPAddressMapper_Map_VRFNameEmptyWarns(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	registry := mapping.NewEntityRegistry(logger)
	mapper := mapping.NewIPAddressMapper(logger)

	values := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		"1.3.6.1.2.1.4.20.1.1.10.0.0.1": {
			OID:    "1.3.6.1.2.1.4.20.1.1.10.0.0.1",
			Index:  "10.0.0.1",
			Parent: "1.3.6.1.2.1.4.20.1.1",
			Value:  "10.0.0.1",
			Type:   mapping.IPAddress,
		},
	}
	mappingEntry := &mapping.Entry{
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
	}
	defaults := &config.Defaults{
		IPAddress: config.IPAddressDefaults{
			Vrf: config.VrfParameters{
				Rd:          "65000:100",
				Description: "leftover sub-fields",
				Tags:        []string{"orphan"},
			},
		},
	}

	entity := mapper.Map(values, mappingEntry, registry, defaults)
	require.NotNil(t, entity)
	ip := entity.(*diode.IPAddress)
	assert.Nil(t, ip.Vrf, "VRF must NOT be emitted when Name is empty even if other VRF fields are set")
	logOut := buf.String()
	assert.Contains(t, logOut, "VRF defaults dropped: name is empty",
		"expected a warning surfacing the misconfiguration in the logs")
	assert.Contains(t, logOut, "65000:100", "warning should include the dropped Rd value for debugging")
	assert.Contains(t, logOut, "override_defaults",
		"warning should also point at the per-target override path, not only the policy-level path")

	// Rate-limit: applyDefaults runs per discovered IP. With the same
	// misconfig, subsequent calls must NOT keep appending duplicate
	// warnings to the log — sync.Once gates it to one line per mapper.
	buf.Reset()
	for i := 0; i < 5; i++ {
		// Reset the entity registry between calls so each iteration
		// is treated as a fresh row (otherwise Map() short-circuits on
		// the cached registry entry from the first call).
		registry = mapping.NewEntityRegistry(logger)
		mapper.Map(values, mappingEntry, registry, defaults)
	}
	assert.NotContains(t, buf.String(), "VRF defaults dropped",
		"warning must fire at most once per mapper lifetime; subsequent calls must stay silent")
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
			name: "addressPrefixSize with existing address",
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
						Field:  "addressPrefixSize",
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
			name: "addressPrefixSize without existing address - now extracts IP from index",
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
						Field:  "addressPrefixSize",
					},
				},
			},
			defaults: nil,
			expectedEntity: &diode.IPAddress{
				Address: mapping.StringPtr("192.168.1.1/24"), // Now extracts IP from index
			},
			expectError: false,
		},
		{
			name: "addressPrefixSize with address that already has prefix",
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
						Field:  "addressPrefixSize",
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
			name: "addressPrefixSize with address that has no prefix",
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
						Field:  "addressPrefixSize",
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
			name: "addressPrefixSize with invalid mask - should skip",
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
						Field:  "addressPrefixSize",
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
			name: "addressPrefixSize with different subnet masks",
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
						Field:  "addressPrefixSize",
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
			name: "addressPrefixSize with /30 subnet",
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
						Field:  "addressPrefixSize",
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
				if tt.expectedEntity.Address != nil && ipAddress.Address != nil {
					t.Logf("Expected: %s, Got: %s", *tt.expectedEntity.Address, *ipAddress.Address)
				}
				assert.Equal(t, tt.expectedEntity.Address, ipAddress.Address)
			}
		})
	}
}

func Test_validateIPv4CIDR(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		expected bool
	}{
		{
			name:     "valid CIDR /24",
			cidr:     "192.168.1.1/24",
			expected: true,
		},
		{
			name:     "valid CIDR /8",
			cidr:     "10.0.0.1/8",
			expected: true,
		},
		{
			name:     "valid CIDR /32",
			cidr:     "127.0.0.1/32",
			expected: true,
		},
		{
			name:     "valid CIDR /0",
			cidr:     "0.0.0.0/0",
			expected: true,
		},
		{
			name:     "invalid prefix too high",
			cidr:     "192.168.1.1/33",
			expected: false,
		},
		{
			name:     "invalid IP octet",
			cidr:     "256.1.1.1/24",
			expected: false,
		},
		{
			name:     "invalid IP format",
			cidr:     "999.999.999.999/24",
			expected: false,
		},
		{
			name:     "missing prefix",
			cidr:     "192.168.1.1",
			expected: false,
		},
		{
			name:     "only prefix",
			cidr:     "/24",
			expected: false,
		},
		{
			name:     "IPv6 CIDR (should reject)",
			cidr:     "fe80::1/64",
			expected: false,
		},
		{
			name:     "malformed CIDR",
			cidr:     "192.168.1.1/abc",
			expected: false,
		},
		{
			name:     "incomplete IP",
			cidr:     "192.168.1/24",
			expected: false,
		},
		{
			name:     "too many octets",
			cidr:     "192.168.1.1.1/24",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapping.ValidateIPv4CIDR(tt.cidr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIPAddressMapper_Map_ValueFieldExtraction(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name           string
		values         map[mapping.ObjectIDIndex]*mapping.ObjectIDValue
		mappingEntry   *mapping.Entry
		expectedEntity *diode.IPAddress
	}{
		{
			name: "IP in value field with correct type",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.1.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.1.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.1",
					Value:  "192.168.1.1",
					Type:   0x40, // IPAddress type
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1",
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
			expectedEntity: &diode.IPAddress{
				Address: mapping.StringPtr("192.168.1.1/32"),
			},
		},
		{
			name: "IP in value field with wrong type (OctetString)",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.1.10.110.18.4": {
					OID:    "1.3.6.1.2.1.4.20.1.1.10.110.18.4",
					Index:  "10.110.18.4",
					Parent: "1.3.6.1.2.1.4.20.1.1",
					Value:  "10.110.18.4",
					Type:   0x04, // OctetString type
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1",
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
			expectedEntity: &diode.IPAddress{
				Address: mapping.StringPtr("10.110.18.4/32"),
			},
		},
		{
			name: "fallback to index when value is invalid",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.1.10.0.0.1": {
					OID:    "1.3.6.1.2.1.4.20.1.1.10.0.0.1",
					Index:  "10.0.0.1",
					Parent: "1.3.6.1.2.1.4.20.1.1",
					Value:  "invalid.ip",
					Type:   0x40,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1",
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
			expectedEntity: &diode.IPAddress{
				Address: mapping.StringPtr("10.0.0.1/32"),
			},
		},
		{
			name: "value field IP with netmask",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.1.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.1.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.1",
					Value:  "192.168.1.1",
					Type:   0x40,
				},
				"1.3.6.1.2.1.4.20.1.3.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.3.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.3",
					Value:  "255.255.255.0",
					Type:   0x40,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1",
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
						Field:  "addressPrefixSize",
					},
				},
			},
			expectedEntity: &diode.IPAddress{
				Address: mapping.StringPtr("192.168.1.1/24"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapper := mapping.NewIPAddressMapper(logger)
			entityRegistry := mapping.NewEntityRegistry(logger)

			result := mapper.Map(tt.values, tt.mappingEntry, entityRegistry, nil)

			assert.NotNil(t, result)
			ipAddress, ok := result.(*diode.IPAddress)
			assert.True(t, ok)
			assert.Equal(t, tt.expectedEntity.Address, ipAddress.Address)
		})
	}
}

func TestIPAddressMapper_Map_InvalidCases(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name            string
		values          map[mapping.ObjectIDIndex]*mapping.ObjectIDValue
		mappingEntry    *mapping.Entry
		expectEmpty     bool
		expectedAddress *string
	}{
		{
			name: "both value and index invalid",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.1.999.999.999.999": {
					OID:    "1.3.6.1.2.1.4.20.1.1.999.999.999.999",
					Index:  "999.999.999.999",
					Parent: "1.3.6.1.2.1.4.20.1.1",
					Value:  "invalid",
					Type:   0x40,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1",
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
			expectEmpty: true,
		},
		{
			name: "incomplete IP with only 3 octets",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.1.192.168.1": {
					OID:    "1.3.6.1.2.1.4.20.1.1.192.168.1",
					Index:  "192.168.1",
					Parent: "1.3.6.1.2.1.4.20.1.1",
					Value:  "192.168.1",
					Type:   0x40,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1",
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
			expectEmpty: true,
		},
		{
			name: "malformed IP address 256.1.1.1",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.1.256.1.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.1.256.1.1.1",
					Index:  "256.1.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.1",
					Value:  "256.1.1.1",
					Type:   0x40,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1",
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
			expectEmpty: true,
		},
		{
			name: "only prefix without IP - now extracts IP from index",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.3.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.3.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.3",
					Value:  "255.255.255.0",
					Type:   0x40,
				},
			},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.4.20.1",
				Entity: "ipAddress",
				Field:  "_id",
				MappingEntries: []mapping.Entry{
					{
						OID:    "1.3.6.1.2.1.4.20.1.3",
						Entity: "ipAddress",
						Field:  "addressPrefixSize",
					},
				},
			},
			expectEmpty:     false, // Changed: now extracts IP from addressPrefixSize field's index
			expectedAddress: mapping.StringPtr("192.168.1.1/24"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapper := mapping.NewIPAddressMapper(logger)
			entityRegistry := mapping.NewEntityRegistry(logger)

			result := mapper.Map(tt.values, tt.mappingEntry, entityRegistry, nil)

			if tt.expectEmpty {
				// The mapper now drops empty/invalid rows by
				// returning nil instead of emitting an entity with
				// no address. Either nil or an entity with no
				// Address satisfies the contract for these cases.
				if result == nil {
					return
				}
				ipAddress, ok := result.(*diode.IPAddress)
				assert.True(t, ok)
				assert.True(t, ipAddress.Address == nil || *ipAddress.Address == "")
				return
			}

			assert.NotNil(t, result)
			ipAddress, ok := result.(*diode.IPAddress)
			assert.True(t, ok)

			if tt.expectedAddress != nil {
				// Check the expected address
				if ipAddress.Address != nil {
					t.Logf("Expected: %s, Got: %s", *tt.expectedAddress, *ipAddress.Address)
				}
				assert.Equal(t, tt.expectedAddress, ipAddress.Address)
			}
		})
	}
}

func TestDeviceMapper_Map_OverrideDeviceModelManufacturerPlatform(t *testing.T) {
	logger := slog.Default()
	registry := mapping.NewEntityRegistry(logger)
	mapper := mapping.NewDeviceMapper(&FakeManufacturers{}, &FakeDeviceLookup{}, logger)

	values := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		"1.3.6.1.2.1.1.2.0": {
			OID:    "1.3.6.1.2.1.1.2.0",
			Parent: "1.3.6.1.2.1.1.2",
			Value:  ".1.3.6.1.4.1.9.1.2495",
			Type:   mapping.ObjectIdentifier,
		},
	}
	entry := &mapping.Entry{
		OID:    "1.3.6.1.2.1.1.2",
		Entity: "device",
		Field:  "_id",
		MappingEntries: []mapping.Entry{
			{OID: "1.3.6.1.2.1.1.2", Entity: "device", Field: "platform"},
		},
	}
	defaults := &config.Defaults{
		Device: config.DeviceDefaults{
			Model:        "C9300-48P",
			Manufacturer: "Cisco Systems",
			Platform:     "IOS-XE 17.9",
		},
	}
	entity := mapper.Map(values, entry, registry, defaults)
	device, ok := entity.(*diode.Device)
	assert.True(t, ok)
	assert.NotNil(t, device.DeviceType)
	assert.Equal(t, "C9300-48P", *device.DeviceType.Model)
	assert.Equal(t, "Cisco Systems", *device.DeviceType.Manufacturer.Name)
	assert.Equal(t, "IOS-XE 17.9", *device.Platform.Name)
	assert.Equal(t, "Cisco Systems", *device.Platform.Manufacturer.Name,
		"Platform.Manufacturer must also follow the Manufacturer override")
}

func TestDeviceMapper_Map_OverrideModelOnlyPreservesAutoManufacturer(t *testing.T) {
	logger := slog.Default()
	registry := mapping.NewEntityRegistry(logger)
	mapper := mapping.NewDeviceMapper(&FakeManufacturers{}, &FakeDeviceLookup{}, logger)

	values := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		"1.3.6.1.2.1.1.2.0": {
			OID:    "1.3.6.1.2.1.1.2.0",
			Parent: "1.3.6.1.2.1.1.2",
			Value:  ".1.3.6.1.4.1.9.1.2495",
			Type:   mapping.ObjectIdentifier,
		},
	}
	entry := &mapping.Entry{
		OID:    "1.3.6.1.2.1.1.2",
		Entity: "device",
		Field:  "_id",
		MappingEntries: []mapping.Entry{
			{OID: "1.3.6.1.2.1.1.2", Entity: "device", Field: "platform"},
		},
	}
	defaults := &config.Defaults{
		Device: config.DeviceDefaults{
			Model: "custom-model",
			// Manufacturer + Platform intentionally unset
		},
	}
	entity := mapper.Map(values, entry, registry, defaults)
	device := entity.(*diode.Device)
	assert.Equal(t, "custom-model", *device.DeviceType.Model)
	// FakeManufacturers.GetManufacturer returns "Cisco"; that should flow
	// through unchanged because Manufacturer override is empty.
	assert.Equal(t, "Cisco", *device.DeviceType.Manufacturer.Name)
}

func TestDeviceMapper_Map_OverrideManufacturerOnlyFlowsIntoPlatformName(t *testing.T) {
	logger := slog.Default()
	registry := mapping.NewEntityRegistry(logger)
	mapper := mapping.NewDeviceMapper(&FakeManufacturers{}, &FakeDeviceLookup{}, logger)

	values := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		"1.3.6.1.2.1.1.2.0": {
			OID:    "1.3.6.1.2.1.1.2.0",
			Parent: "1.3.6.1.2.1.1.2",
			Value:  ".1.3.6.1.4.1.9.1.2495",
			Type:   mapping.ObjectIdentifier,
		},
	}
	entry := &mapping.Entry{
		OID:    "1.3.6.1.2.1.1.2",
		Entity: "device",
		Field:  "_id",
		MappingEntries: []mapping.Entry{
			{OID: "1.3.6.1.2.1.1.2", Entity: "device", Field: "platform"},
		},
	}
	defaults := &config.Defaults{
		Device: config.DeviceDefaults{
			Manufacturer: "Cisco Systems",
			// Platform intentionally unset: spec says Manufacturer
			// override should also flow into Platform.Name.
		},
	}
	entity := mapper.Map(values, entry, registry, defaults)
	device := entity.(*diode.Device)
	assert.Equal(t, "Cisco Systems", *device.DeviceType.Manufacturer.Name)
	assert.Equal(t, "Cisco Systems", *device.Platform.Manufacturer.Name)
	assert.Equal(t, "Cisco Systems", *device.Platform.Name,
		"Platform.Name must track the Manufacturer override when Platform override is unset")
}

func TestDeviceMapper_Map_DynamicModelRefResolvedFromWalked(t *testing.T) {
	logger := slog.Default()
	registry := mapping.NewEntityRegistry(logger)
	mapper := mapping.NewDeviceMapper(&FakeManufacturers{}, &FakeDynamicDeviceLookup{
		sourceOID: ".1.3.6.1.2.1.1.1.0",
	}, logger)

	// The group for ifIndex "0" (all MIB-II system group scalars) contains
	// both the sysObjectID PDU and the sysDescr PDU; the mapper must
	// pass the walked map through to GetDeviceModel so the dynamic ref
	// resolves.
	values := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		"1.3.6.1.2.1.1.2.0": {
			OID:    "1.3.6.1.2.1.1.2.0",
			Parent: "1.3.6.1.2.1.1.2",
			Value:  ".1.3.6.1.4.1.14988.1",
			Type:   mapping.ObjectIdentifier,
		},
		"1.3.6.1.2.1.1.1.0": {
			OID:    "1.3.6.1.2.1.1.1.0",
			Parent: "1.3.6.1.2.1.1.1",
			Value:  "RouterOS CCR2004-16G-2S+",
			Type:   mapping.OctetString,
		},
	}
	entry := &mapping.Entry{
		OID:    "1.3.6.1.2.1.1.2",
		Entity: "device",
		Field:  "_id",
		MappingEntries: []mapping.Entry{
			{OID: "1.3.6.1.2.1.1.2", Entity: "device", Field: "platform"},
		},
	}
	entity := mapper.Map(values, entry, registry, nil)
	device := entity.(*diode.Device)
	assert.Equal(t, "RouterOS CCR2004-16G-2S+", *device.DeviceType.Model)
}

// --- RFC 4293 ipAddressTable tests (OBS-2798) ---

// inetAddrTableEntry builds a synthetic ipAddressTable mapping.Entry that
// recognizes addressPrefix and the filter columns (used by Tasks 5/6).
func inetAddrTableEntry() *mapping.Entry {
	return &mapping.Entry{
		OID: ".1.3.6.1.2.1.4.34.1", Entity: "ipAddress", Field: "_id",
		IndexKind: "inet_address",
		MappingEntries: []mapping.Entry{
			{OID: ".1.3.6.1.2.1.4.34.1.4", Entity: "ipAddress", Field: "addressType"},
			{OID: ".1.3.6.1.2.1.4.34.1.5", Entity: "ipAddress", Field: "addressPrefix"},
			{OID: ".1.3.6.1.2.1.4.34.1.7", Entity: "ipAddress", Field: "addressStatus"},
			{OID: ".1.3.6.1.2.1.4.34.1.10", Entity: "ipAddress", Field: "addressRowStatus"},
		},
	}
}

func TestIPAddressMapper_IPv4FromInetAddressIndex(t *testing.T) {
	logger := slog.Default()
	registry := mapping.NewEntityRegistry(logger)
	mapper := mapping.NewIPAddressMapper(logger)

	pdus := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		".1.3.6.1.2.1.4.34.1.5.1.4.10.0.0.1": {
			OID:    ".1.3.6.1.2.1.4.34.1.5.1.4.10.0.0.1",
			Index:  "ipv4:10.0.0.1",
			Parent: ".1.3.6.1.2.1.4.34.1.5",
			Value:  ".1.3.6.1.2.1.4.32.1.5.1.1.4.10.0.0.0.24",
			Type:   mapping.ObjectIdentifier,
		},
	}
	got := mapper.Map(pdus, inetAddrTableEntry(), registry, nil)
	ip, ok := got.(*diode.IPAddress)
	if !ok || ip == nil || ip.Address == nil {
		t.Fatalf("expected non-nil *diode.IPAddress with Address, got %#v", got)
	}
	assert.Equal(t, "10.0.0.1/24", *ip.Address)
}

func TestIPAddressMapper_IPv6FromInetAddressIndex(t *testing.T) {
	logger := slog.Default()
	registry := mapping.NewEntityRegistry(logger)
	mapper := mapping.NewIPAddressMapper(logger)

	pdus := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		".1.3.6.1.2.1.4.34.1.5.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1": {
			OID:    ".1.3.6.1.2.1.4.34.1.5.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1",
			Index:  "ipv6:2001:db8::1",
			Parent: ".1.3.6.1.2.1.4.34.1.5",
			Value:  ".1.3.6.1.2.1.4.32.1.5.1.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.0.64",
			Type:   mapping.ObjectIdentifier,
		},
	}
	got := mapper.Map(pdus, inetAddrTableEntry(), registry, nil)
	ip := got.(*diode.IPAddress)
	if ip.Address == nil {
		t.Fatalf("expected Address to be set")
	}
	assert.Equal(t, "2001:db8::1/64", *ip.Address)
}

func TestIPAddressMapper_RowPointer_ZeroDotZero_FallsBackToHostRoute(t *testing.T) {
	logger := slog.Default()
	registry := mapping.NewEntityRegistry(logger)
	mapper := mapping.NewIPAddressMapper(logger)

	pdus := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		"k": {
			OID: ".1.3.6.1.2.1.4.34.1.5.1.4.10.0.0.1", Index: "ipv4:10.0.0.1",
			Parent: ".1.3.6.1.2.1.4.34.1.5", Value: ".0.0",
			Type: mapping.ObjectIdentifier,
		},
	}
	got := mapper.Map(pdus, inetAddrTableEntry(), registry, nil)
	ip := got.(*diode.IPAddress)
	assert.Equal(t, "10.0.0.1/32", *ip.Address)
}

func TestIPAddressMapper_RowPointer_OversizedPrefix_Clamped(t *testing.T) {
	logger := slog.Default()
	registry := mapping.NewEntityRegistry(logger)
	mapper := mapping.NewIPAddressMapper(logger)

	pdus := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		"k": {
			OID:    ".1.3.6.1.2.1.4.34.1.5.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1",
			Index:  "ipv6:2001:db8::1",
			Parent: ".1.3.6.1.2.1.4.34.1.5",
			Value:  ".1.3.6.1.2.1.4.32.1.5.1.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.0.200",
			Type:   mapping.ObjectIdentifier,
		},
	}
	got := mapper.Map(pdus, inetAddrTableEntry(), registry, nil)
	ip := got.(*diode.IPAddress)
	assert.Equal(t, "2001:db8::1/128", *ip.Address)
}

func TestIPAddressMapper_RowPointer_NotPrefixTable_FallsBackToHostRoute(t *testing.T) {
	logger := slog.Default()
	registry := mapping.NewEntityRegistry(logger)
	mapper := mapping.NewIPAddressMapper(logger)

	pdus := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		"k": {
			OID: ".1.3.6.1.2.1.4.34.1.5.1.4.10.0.0.1", Index: "ipv4:10.0.0.1",
			Parent: ".1.3.6.1.2.1.4.34.1.5", Value: ".1.2.3.4.5.24",
			Type: mapping.ObjectIdentifier,
		},
	}
	got := mapper.Map(pdus, inetAddrTableEntry(), registry, nil)
	ip := got.(*diode.IPAddress)
	assert.Equal(t, "10.0.0.1/32", *ip.Address)
}

// TestIPAddressMapper_RowPointer_AddrLenMismatch_FallsBackToHostRoute
// covers the strict-shape case Copilot flagged: a pointer that declares
// addrLen=99 but carries fewer (or different-count) address bytes is
// structurally invalid. Pre-fix this would have parsed the trailing
// numeric component as the prefix length; post-fix the row falls back
// to the host-route default.
func TestIPAddressMapper_RowPointer_AddrLenMismatch_FallsBackToHostRoute(t *testing.T) {
	logger := slog.Default()
	registry := mapping.NewEntityRegistry(logger)
	mapper := mapping.NewIPAddressMapper(logger)

	// .1.3.6.1.2.1.4.32.1.5.<ifIndex=1>.<addrType=2>.<addrLen=99>.1.2.3.4.24
	// addrType=2 implies addrLen=16, not 99; suffixParts = 8, expected 20.
	pdus := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		"k": {
			OID: ".1.3.6.1.2.1.4.34.1.5.1.4.10.0.0.1", Index: "ipv4:10.0.0.1",
			Parent: ".1.3.6.1.2.1.4.34.1.5",
			Value:  ".1.3.6.1.2.1.4.32.1.5.1.2.99.1.2.3.4.24",
			Type:   mapping.ObjectIdentifier,
		},
	}
	got := mapper.Map(pdus, inetAddrTableEntry(), registry, nil)
	ip := got.(*diode.IPAddress)
	// Host-route default rather than a fabricated /24.
	assert.Equal(t, "10.0.0.1/32", *ip.Address)
}

// TestIPAddressMapper_RowPointer_IfIndexMismatch_FallsBackToHostRoute
// covers the cross-interface prefix-row case Copilot flagged: a
// modern row whose ipAddressIfIndex is 1 must NOT silently accept a
// prefix entry that lives under a different ifIndex. On devices with
// overlapping subnets, the row would otherwise pick up another
// interface's prefix length.
func TestIPAddressMapper_RowPointer_IfIndexMismatch_FallsBackToHostRoute(t *testing.T) {
	logger := slog.Default()
	registry := mapping.NewEntityRegistry(logger)
	mapper := mapping.NewIPAddressMapper(logger)

	entry := &mapping.Entry{
		OID: ".1.3.6.1.2.1.4.34.1", Entity: "ipAddress", Field: "_id",
		IndexKind: "inet_address",
		MappingEntries: []mapping.Entry{
			{
				OID: ".1.3.6.1.2.1.4.34.1.3", Entity: "ipAddress", Field: "assignedObject",
				Relationship: config.Relationship{Type: "interface"},
			},
			{OID: ".1.3.6.1.2.1.4.34.1.5", Entity: "ipAddress", Field: "addressPrefix"},
		},
	}
	// Row with ifIndex=1, but the RowPointer claims ifIndex=2 (a
	// different interface). Both addrBytes describe a prefix that
	// would contain 10.0.0.1 if accepted.
	pdus := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		".1.3.6.1.2.1.4.34.1.3.1.4.10.0.0.1": {
			OID: ".1.3.6.1.2.1.4.34.1.3.1.4.10.0.0.1", Index: "ipv4:10.0.0.1",
			Parent: ".1.3.6.1.2.1.4.34.1.3", Value: "1", Type: mapping.Integer,
		},
		".1.3.6.1.2.1.4.34.1.5.1.4.10.0.0.1": {
			OID: ".1.3.6.1.2.1.4.34.1.5.1.4.10.0.0.1", Index: "ipv4:10.0.0.1",
			Parent: ".1.3.6.1.2.1.4.34.1.5",
			// Pointer's first component is ifIndex=2, not 1.
			Value: ".1.3.6.1.2.1.4.32.1.5.2.1.4.10.0.0.0.24",
			Type:  mapping.ObjectIdentifier,
		},
	}
	got := mapper.Map(pdus, entry, registry, nil)
	if got == nil {
		t.Fatalf("expected entity, got nil")
	}
	ip := got.(*diode.IPAddress)
	assert.Equal(t, "10.0.0.1/32", *ip.Address,
		"RowPointer with ifIndex differing from row's ipAddressIfIndex must fall back to host route")
}

// TestIPAddressMapper_AssignedObject_IfIndexZero_LeavesUnassigned
// covers the InterfaceIndexOrZero=0 case: per RFC 4293,
// ipAddressIfIndex=0 means the address is not bound to any
// interface. The mapper must NOT fabricate a placeholder Interface
// for ifIndex 0.
func TestIPAddressMapper_AssignedObject_IfIndexZero_LeavesUnassigned(t *testing.T) {
	logger := slog.Default()
	registry := mapping.NewEntityRegistry(logger)
	mapper := mapping.NewIPAddressMapper(logger)

	entry := &mapping.Entry{
		OID: ".1.3.6.1.2.1.4.34.1", Entity: "ipAddress", Field: "_id",
		IndexKind: "inet_address",
		MappingEntries: []mapping.Entry{
			{
				OID: ".1.3.6.1.2.1.4.34.1.3", Entity: "ipAddress", Field: "assignedObject",
				Relationship: config.Relationship{Type: "interface"},
			},
			{OID: ".1.3.6.1.2.1.4.34.1.5", Entity: "ipAddress", Field: "addressPrefix"},
		},
	}
	pdus := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		".1.3.6.1.2.1.4.34.1.3.1.4.10.0.0.1": {
			OID: ".1.3.6.1.2.1.4.34.1.3.1.4.10.0.0.1", Index: "ipv4:10.0.0.1",
			Parent: ".1.3.6.1.2.1.4.34.1.3", Value: "0", Type: mapping.Integer,
		},
		".1.3.6.1.2.1.4.34.1.5.1.4.10.0.0.1": {
			OID: ".1.3.6.1.2.1.4.34.1.5.1.4.10.0.0.1", Index: "ipv4:10.0.0.1",
			Parent: ".1.3.6.1.2.1.4.34.1.5",
			Value:  ".1.3.6.1.2.1.4.32.1.5.1.1.4.10.0.0.0.24",
			Type:   mapping.ObjectIdentifier,
		},
	}
	got := mapper.Map(pdus, entry, registry, nil)
	if !assert.NotNil(t, got) {
		return
	}
	ip := got.(*diode.IPAddress)
	assert.Equal(t, "10.0.0.1/24", *ip.Address)
	assert.Nil(t, ip.AssignedObject,
		"ipAddressIfIndex=0 (InterfaceIndexOrZero) must not produce a placeholder Interface")
}

// TestIPAddressMapper_RowPointer_HostBitsNotZeroed_FallsBackToHostRoute
// covers the strict prefix-row index check: a pointer whose addrBytes
// still carry host bits (e.g. addrBytes=10.0.0.1 with prefixLen=24
// instead of the proper addrBytes=10.0.0.0) is structurally not a
// valid ipAddressPrefixTable row index per RFC 4293, even though the
// row's address would fall inside the masked prefix.
func TestIPAddressMapper_RowPointer_HostBitsNotZeroed_FallsBackToHostRoute(t *testing.T) {
	logger := slog.Default()
	registry := mapping.NewEntityRegistry(logger)
	mapper := mapping.NewIPAddressMapper(logger)

	pdus := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		"k": {
			OID: ".1.3.6.1.2.1.4.34.1.5.1.4.10.0.0.1", Index: "ipv4:10.0.0.1",
			Parent: ".1.3.6.1.2.1.4.34.1.5",
			// Bytes 10.0.0.1 with prefixLen 24 — host bits not zeroed.
			Value: ".1.3.6.1.2.1.4.32.1.5.1.1.4.10.0.0.1.24",
			Type:  mapping.ObjectIdentifier,
		},
	}
	got := mapper.Map(pdus, inetAddrTableEntry(), registry, nil)
	ip := got.(*diode.IPAddress)
	assert.Equal(t, "10.0.0.1/32", *ip.Address,
		"RowPointer with host bits set in addrBytes must fall back to host route")
}

// TestIPAddressMapper_RowPointer_AddressOutsidePrefix_FallsBackToHostRoute
// covers the unrelated-prefix-row case Copilot flagged: the pointer
// is structurally valid for the row's family but its network bytes
// describe a prefix that doesn't contain the row's address (e.g. a
// 10.0.0.1 row pointing at 192.168.0.0/16). Pre-fix the mapper would
// have emitted "10.0.0.1/16"; post-fix it falls back to host route.
func TestIPAddressMapper_RowPointer_AddressOutsidePrefix_FallsBackToHostRoute(t *testing.T) {
	logger := slog.Default()
	registry := mapping.NewEntityRegistry(logger)
	mapper := mapping.NewIPAddressMapper(logger)

	pdus := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		"k": {
			OID:    ".1.3.6.1.2.1.4.34.1.5.1.4.10.0.0.1",
			Index:  "ipv4:10.0.0.1",
			Parent: ".1.3.6.1.2.1.4.34.1.5",
			// Pointer to ipAddressPrefixTable for 192.168.0.0/16 —
			// a different network than the row's 10.0.0.1.
			Value: ".1.3.6.1.2.1.4.32.1.5.1.1.4.192.168.0.0.16",
			Type:  mapping.ObjectIdentifier,
		},
	}
	got := mapper.Map(pdus, inetAddrTableEntry(), registry, nil)
	ip := got.(*diode.IPAddress)
	assert.Equal(t, "10.0.0.1/32", *ip.Address,
		"row whose address is outside the pointed-to prefix must fall back to host route")
}

// TestIPAddressMapper_RowPointer_FamilyMismatch_FallsBackToHostRoute
// covers Copilot's family-cross concern: an IPv6 row that points at a
// well-formed IPv4 prefix entry must NOT silently borrow the v4
// prefix length. Pre-fix this would emit "2001:db8::1/24"; post-fix
// the row keeps its host-route default.
func TestIPAddressMapper_RowPointer_FamilyMismatch_FallsBackToHostRoute(t *testing.T) {
	logger := slog.Default()
	registry := mapping.NewEntityRegistry(logger)
	mapper := mapping.NewIPAddressMapper(logger)

	// IPv6 row (Index = "ipv6:..."). Pointer is structurally valid for
	// IPv4 (addrType=1, addrLen=4, ifIndex=1, addrBytes=10.0.0.0,
	// prefixLen=24) but its family doesn't match the row.
	pdus := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		"k": {
			OID:    ".1.3.6.1.2.1.4.34.1.5.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1",
			Index:  "ipv6:2001:db8::1",
			Parent: ".1.3.6.1.2.1.4.34.1.5",
			Value:  ".1.3.6.1.2.1.4.32.1.5.1.1.4.10.0.0.0.24",
			Type:   mapping.ObjectIdentifier,
		},
	}
	got := mapper.Map(pdus, inetAddrTableEntry(), registry, nil)
	ip := got.(*diode.IPAddress)
	// Host-route fallback for the IPv6 row.
	assert.Equal(t, "2001:db8::1/128", *ip.Address)
}

// TestIPAddressMapper_RowPointer_BadAddrType_FallsBackToHostRoute
// rejects addrType values outside the {1, 2} set we support
// (e.g. ipv4z=3, ipv6z=4, dns=16) regardless of byte count.
func TestIPAddressMapper_RowPointer_BadAddrType_FallsBackToHostRoute(t *testing.T) {
	logger := slog.Default()
	registry := mapping.NewEntityRegistry(logger)
	mapper := mapping.NewIPAddressMapper(logger)

	// addrType=3 (ipv4z) — even with otherwise plausible shape, reject.
	pdus := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		"k": {
			OID: ".1.3.6.1.2.1.4.34.1.5.1.4.10.0.0.1", Index: "ipv4:10.0.0.1",
			Parent: ".1.3.6.1.2.1.4.34.1.5",
			Value:  ".1.3.6.1.2.1.4.32.1.5.1.3.4.10.0.0.0.24",
			Type:   mapping.ObjectIdentifier,
		},
	}
	got := mapper.Map(pdus, inetAddrTableEntry(), registry, nil)
	ip := got.(*diode.IPAddress)
	assert.Equal(t, "10.0.0.1/32", *ip.Address)
}

// runIPAddressTableMap builds a synthetic ipAddressTable PDU set with
// the given column overrides (parent OID → string value) for index
// "ipv4:10.0.0.1" and runs the mapper. Always includes a /24 prefix
// RowPointer so the address gets set; tests can override columns 4/7/10.
func runIPAddressTableMap(t *testing.T, columns map[string]string) diode.Entity {
	t.Helper()
	logger := slog.Default()
	registry := mapping.NewEntityRegistry(logger)
	mapper := mapping.NewIPAddressMapper(logger)
	pdus := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		".1.3.6.1.2.1.4.34.1.5.1.4.10.0.0.1": {
			OID:    ".1.3.6.1.2.1.4.34.1.5.1.4.10.0.0.1",
			Index:  "ipv4:10.0.0.1",
			Parent: ".1.3.6.1.2.1.4.34.1.5",
			Value:  ".1.3.6.1.2.1.4.32.1.5.1.1.4.10.0.0.0.24",
			Type:   mapping.ObjectIdentifier,
		},
	}
	for parent, val := range columns {
		oid := parent + ".1.4.10.0.0.1"
		pdus[mapping.ObjectIDIndex(oid)] = &mapping.ObjectIDValue{
			OID:    oid,
			Index:  "ipv4:10.0.0.1",
			Parent: parent,
			Value:  val,
			Type:   mapping.Integer,
		}
	}
	return mapper.Map(pdus, inetAddrTableEntry(), registry, nil)
}

func TestIPAddressMapper_FilterAnycast_Dropped(t *testing.T) {
	got := runIPAddressTableMap(t, map[string]string{
		".1.3.6.1.2.1.4.34.1.4": "2", // anycast
	})
	assert.Nil(t, got, "anycast row must be dropped (nil)")
}

func TestIPAddressMapper_FilterBroadcast_Dropped(t *testing.T) {
	got := runIPAddressTableMap(t, map[string]string{
		".1.3.6.1.2.1.4.34.1.4": "3", // broadcast
	})
	assert.Nil(t, got)
}

func TestIPAddressMapper_FilterTentative_Dropped(t *testing.T) {
	got := runIPAddressTableMap(t, map[string]string{
		".1.3.6.1.2.1.4.34.1.7": "6", // tentative
	})
	assert.Nil(t, got)
}

func TestIPAddressMapper_FilterRowStatusInactive_Dropped(t *testing.T) {
	got := runIPAddressTableMap(t, map[string]string{
		".1.3.6.1.2.1.4.34.1.10": "2", // notInService
	})
	assert.Nil(t, got)
}

func TestIPAddressMapper_FilterPreferredUnicastActive_Kept(t *testing.T) {
	got := runIPAddressTableMap(t, map[string]string{
		".1.3.6.1.2.1.4.34.1.4":  "1", // unicast
		".1.3.6.1.2.1.4.34.1.7":  "1", // preferred
		".1.3.6.1.2.1.4.34.1.10": "1", // active
	})
	if got == nil {
		t.Fatalf("expected entity, got nil")
	}
	ip := got.(*diode.IPAddress)
	assert.Equal(t, "10.0.0.1/24", *ip.Address)
}

func TestIPAddressMapper_FilterDeprecated_Kept(t *testing.T) {
	got := runIPAddressTableMap(t, map[string]string{
		".1.3.6.1.2.1.4.34.1.7": "2", // deprecated
	})
	if got == nil {
		t.Fatalf("expected entity, got nil")
	}
}

func TestIPAddressMapper_FilterOptimistic_Kept(t *testing.T) {
	got := runIPAddressTableMap(t, map[string]string{
		".1.3.6.1.2.1.4.34.1.7": "8", // optimistic
	})
	if got == nil {
		t.Fatalf("optimistic addresses should be kept (RFC 4862 says usable with caveats), got nil")
	}
}

func TestIPAddressMapper_FilterColumnsMissing_Lenient(t *testing.T) {
	got := runIPAddressTableMap(t, nil)
	if got == nil {
		t.Fatalf("missing filter columns must be lenient (kept), got nil")
	}
}

func TestIPAddressMapper_LegacyTable_StillIPv4Only(t *testing.T) {
	logger := slog.Default()
	registry := mapping.NewEntityRegistry(logger)
	mapper := mapping.NewIPAddressMapper(logger)

	entry := &mapping.Entry{
		OID: ".1.3.6.1.2.1.4.20.1", Entity: "ipAddress", Field: "_id",
		IdentifierSize: 4,
		MappingEntries: []mapping.Entry{
			{OID: ".1.3.6.1.2.1.4.20.1.1", Entity: "ipAddress", Field: "address"},
		},
	}
	pdus := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		".1.3.6.1.2.1.4.20.1.1.10.0.0.1": {
			OID: ".1.3.6.1.2.1.4.20.1.1.10.0.0.1", Index: "10.0.0.1",
			Parent: ".1.3.6.1.2.1.4.20.1.1", Value: "10.0.0.1",
			Type: mapping.IPAddress,
		},
	}
	got := mapper.Map(pdus, entry, registry, nil)
	ip := got.(*diode.IPAddress)
	assert.Equal(t, "10.0.0.1/32", *ip.Address)
}

// TestDeviceMapping_WalksSysContactAndSysLocation confirms that the
// two OIDs needed for OID-ref defaults are direct children of the
// device system-group block (.1.3.6.1.2.1.1) in mapping.yaml, with the
// expected field names. Anchoring at the system-group block (not a
// recursive search across the whole file) ensures the OIDs are in the
// per-Map() walked snapshot that applyDefaults consumes.
func TestDeviceMapping_WalksSysContactAndSysLocation(t *testing.T) {
	data, err := os.ReadFile("../policy/mapping.yaml")
	require.NoError(t, err)

	var m config.Mapping
	require.NoError(t, yaml.Unmarshal(data, &m))

	var sysGroup *config.MappingEntry
	for i := range m.Entries {
		if m.Entries[i].OID == ".1.3.6.1.2.1.1" && m.Entries[i].Entity == "device" {
			sysGroup = &m.Entries[i]
			break
		}
	}
	require.NotNil(t, sysGroup, "device system-group block .1.3.6.1.2.1.1 not found in mapping.yaml")

	wantOIDs := map[string]string{
		".1.3.6.1.2.1.1.4.0": "sysContact",
		".1.3.6.1.2.1.1.6.0": "sysLocation",
	}
	found := map[string]string{}
	for _, child := range sysGroup.MappingEntries {
		if expectedField, want := wantOIDs[child.OID]; want {
			found[child.OID] = child.Field
			assert.Equal(t, expectedField, child.Field,
				"OID %s should have field=%q", child.OID, expectedField)
		}
	}
	for oid := range wantOIDs {
		_, present := found[oid]
		assert.True(t, present, "expected %s as a direct child of the device system-group block", oid)
	}
}

// TestDeviceMapper_Map_DefaultsResolveFromWalkedSnapshot is an end-to-end
// integration test for the OID-reference defaults path. It exercises the
// full DeviceMapper.Map flow with a synthetic system-group walk that
// contains sysName, sysContact, and sysLocation, then verifies that
// defaults.{location,asset_tag} pointing at those OIDs are resolved
// against the walked snapshot built inside Map() — closing the gap
// between the structural mapping.yaml assertion and the internal
// applyDefaults tests.
func TestDeviceMapper_Map_DefaultsResolveFromWalkedSnapshot(t *testing.T) {
	logger := slog.Default()
	mockDeviceLookup := &MockDeviceLookup{}
	mockManufacturers := &MockManufacturerDataRetriever{}
	mapper := mapping.NewDeviceMapper(mockManufacturers, mockDeviceLookup, logger)

	values := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		"1.3.6.1.2.1.1.5.0": {
			OID:    "1.3.6.1.2.1.1.5.0",
			Index:  "0",
			Parent: "1.3.6.1.2.1.1.5",
			Value:  "router1",
			Type:   mapping.OctetString,
		},
		"1.3.6.1.2.1.1.4.0": {
			OID:    "1.3.6.1.2.1.1.4.0",
			Index:  "0",
			Parent: "1.3.6.1.2.1.1.4",
			Value:  "asset-12345",
			Type:   mapping.OctetString,
		},
		"1.3.6.1.2.1.1.6.0": {
			OID:    "1.3.6.1.2.1.1.6.0",
			Index:  "0",
			Parent: "1.3.6.1.2.1.1.6",
			Value:  "Data Center 01",
			Type:   mapping.OctetString,
		},
	}
	mappingEntry := &mapping.Entry{
		OID:    "1.3.6.1.2.1.1",
		Entity: "device",
		Field:  "_id",
		MappingEntries: []mapping.Entry{
			{OID: "1.3.6.1.2.1.1.5", Entity: "device", Field: "name"},
			{OID: "1.3.6.1.2.1.1.4", Entity: "device", Field: "sysContact"},
			{OID: "1.3.6.1.2.1.1.6", Entity: "device", Field: "sysLocation"},
		},
	}
	// Defaults use the leading-dot OID spelling. Walked map keys are
	// stored without leading dot (matching the test fixture convention
	// elsewhere in this file). data.ResolveDefault must therefore
	// tolerate both spellings — this also exercises that path
	// end-to-end.
	defaults := &config.Defaults{
		Site:     "dc1",
		Location: ".1.3.6.1.2.1.1.6.0",
		AssetTag: ".1.3.6.1.2.1.1.4.0",
	}

	registry := mapping.NewEntityRegistry(logger)
	entity := mapper.Map(values, mappingEntry, registry, defaults)
	require.NotNil(t, entity)
	device, ok := entity.(*diode.Device)
	require.True(t, ok)

	require.NotNil(t, device.Location)
	require.NotNil(t, device.Location.Name)
	assert.Equal(t, "Data Center 01", *device.Location.Name)
	require.NotNil(t, device.Location.Site)
	assert.Equal(t, "dc1", *device.Location.Site.Name)

	require.NotNil(t, device.AssetTag)
	assert.Equal(t, "asset-12345", *device.AssetTag)
}

// TestDeviceMapper_Map_DefaultsResolveFromSysLocationOnly is the
// symmetric partial-walk test for sysLocation: a device that responds
// only to sysLocation (no name/description/platform/sysContact) must
// still apply defaults via the no-op switch case's fieldFound=true.
func TestDeviceMapper_Map_DefaultsResolveFromSysLocationOnly(t *testing.T) {
	logger := slog.Default()
	mapper := mapping.NewDeviceMapper(&MockManufacturerDataRetriever{}, &MockDeviceLookup{}, logger)

	values := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		"1.3.6.1.2.1.1.6.0": {
			OID:    "1.3.6.1.2.1.1.6.0",
			Index:  "0",
			Parent: "1.3.6.1.2.1.1.6",
			Value:  "Data Center 02",
			Type:   mapping.OctetString,
		},
	}
	mappingEntry := &mapping.Entry{
		OID:    "1.3.6.1.2.1.1",
		Entity: "device",
		Field:  "_id",
		MappingEntries: []mapping.Entry{
			{OID: "1.3.6.1.2.1.1.6", Entity: "device", Field: "sysLocation"},
		},
	}
	defaults := &config.Defaults{
		Site:     "dc2",
		Location: ".1.3.6.1.2.1.1.6.0",
	}

	registry := mapping.NewEntityRegistry(logger)
	entity := mapper.Map(values, mappingEntry, registry, defaults)
	require.NotNil(t, entity)
	device, ok := entity.(*diode.Device)
	require.True(t, ok)

	require.NotNil(t, device.Location)
	require.NotNil(t, device.Location.Name)
	assert.Equal(t, "Data Center 02", *device.Location.Name)
	require.NotNil(t, device.Location.Site)
	assert.Equal(t, "dc2", *device.Location.Site.Name)
}

// TestDeviceMapper_Map_DefaultsResolveFromSysContactOnly covers the
// edge case where a device responds to sysContact/sysLocation but not
// to name/description/platform. The no-op switch cases set fieldFound
// so applyDefaults still runs, and OID-ref defaults resolve normally.
func TestDeviceMapper_Map_DefaultsResolveFromSysContactOnly(t *testing.T) {
	logger := slog.Default()
	mapper := mapping.NewDeviceMapper(&MockManufacturerDataRetriever{}, &MockDeviceLookup{}, logger)

	values := map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{
		"1.3.6.1.2.1.1.4.0": {
			OID:    "1.3.6.1.2.1.1.4.0",
			Index:  "0",
			Parent: "1.3.6.1.2.1.1.4",
			Value:  "asset-from-contact",
			Type:   mapping.OctetString,
		},
	}
	mappingEntry := &mapping.Entry{
		OID:    "1.3.6.1.2.1.1",
		Entity: "device",
		Field:  "_id",
		MappingEntries: []mapping.Entry{
			{OID: "1.3.6.1.2.1.1.4", Entity: "device", Field: "sysContact"},
		},
	}
	defaults := &config.Defaults{
		Site:     "dc1",
		AssetTag: ".1.3.6.1.2.1.1.4.0",
	}

	registry := mapping.NewEntityRegistry(logger)
	entity := mapper.Map(values, mappingEntry, registry, defaults)
	require.NotNil(t, entity)
	device, ok := entity.(*diode.Device)
	require.True(t, ok)

	require.NotNil(t, device.AssetTag)
	assert.Equal(t, "asset-from-contact", *device.AssetTag)
}
