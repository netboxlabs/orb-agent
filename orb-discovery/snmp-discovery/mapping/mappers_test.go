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
				Address: stringPtr("192.168.1.1/32"),
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
				Address:     stringPtr("192.168.1.1/32"),
				Description: stringPtr("IP Address Description"),
				Tags: []*diode.Tag{
					{Name: stringPtr("global-tag1")},
					{Name: stringPtr("global-tag2")},
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
				Address:     stringPtr("192.168.1.1/32"),
				Description: stringPtr("IP Address specific description"),
				Tags: []*diode.Tag{
					{Name: stringPtr("ip-tag1")},
					{Name: stringPtr("ip-tag2")},
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
				Address:     stringPtr("192.168.1.1/32"),
				Description: stringPtr("IP Address specific description"),
				Tags: []*diode.Tag{
					{Name: stringPtr("ip-tag1")},
					{Name: stringPtr("ip-tag2")},
					{Name: stringPtr("global-tag1")},
					{Name: stringPtr("global-tag2")},
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
				Address: stringPtr("192.168.1.1/32"),
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
				Address:     stringPtr("192.168.1.1/32"),
				Description: stringPtr("IP Address specific description"),
				Tenant: &diode.Tenant{
					Name: stringPtr("ip-address-tenant"),
				},
				Role: stringPtr("ip-address-role"),
				Vrf: &diode.VRF{
					Name: stringPtr("ip-address-vrf"),
					Rd:   stringPtr("ip-address-vrf"),
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := mapping.NewEntityRegistry(logger)
			mapper := &mapping.IPAddressMapper{}
			registry.SetDefaults(tt.defaults)
			entity := mapper.Map(tt.values, tt.mappingEntry, registry, logger)

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
					Value:  "\\x00\\x11\\x22\\x33\\x44\\x55",
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
				Name:              stringPtr("eth0"),
				Speed:             int64Ptr(1000000),
				PrimaryMacAddress: &diode.MACAddress{MacAddress: stringPtr("00:11:22:33:44:55")},
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
				Name:        stringPtr("eth0"),
				Description: stringPtr("Interface specific description"),
				Tags: []*diode.Tag{
					{Name: stringPtr("interface-tag1")},
					{Name: stringPtr("interface-tag2")},
					{Name: stringPtr("global-tag1")},
					{Name: stringPtr("global-tag2")},
				},
				Type: stringPtr("ethernet"),
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
			expectedEntity: &diode.Interface{},
			expectError:    false,
		},
		{
			name:   "empty values map",
			values: map[mapping.ObjectIDIndex]*mapping.ObjectIDValue{},
			mappingEntry: &mapping.Entry{
				OID:    "1.3.6.1.2.1.2.2.1.1",
				Entity: "interface",
				Field:  "_id",
			},
			expectedEntity: &diode.Interface{},
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.Default()
			registry := mapping.NewEntityRegistry(logger)
			if tt.defaults != nil {
				registry.SetDefaults(tt.defaults)
			}
			mapper := &mapping.InterfaceMapper{}
			entity := mapper.Map(tt.values, tt.mappingEntry, registry, logger)

			if tt.expectError {
				assert.Nil(t, entity)
				return
			}

			assert.NotNil(t, entity)
			iface, ok := entity.(*diode.Interface)
			assert.True(t, ok)
			assert.Equal(t, tt.expectedEntity.Name, iface.Name)
			assert.Equal(t, tt.expectedEntity.Speed, iface.Speed)
			if tt.expectedEntity.PrimaryMacAddress != nil {
				assert.Equal(t, tt.expectedEntity.PrimaryMacAddress.MacAddress, iface.PrimaryMacAddress.MacAddress)
			}
			assert.Equal(t, tt.expectedEntity.Type, iface.Type)
			assert.Equal(t, tt.expectedEntity.Enabled, iface.Enabled)
			assert.Equal(t, tt.expectedEntity.Description, iface.Description)
			if tt.expectedEntity.Tags != nil {
				assert.Equal(t, len(tt.expectedEntity.Tags), len(iface.Tags))
				for i, tag := range tt.expectedEntity.Tags {
					assert.Equal(t, tag.Name, iface.Tags[i].Name)
				}
			}
		})
	}
}

func TestDeviceMapper_Map(t *testing.T) {
	logger := slog.Default()

	// Create a mock manufacturer data retriever
	mockManufacturers := &MockManufacturerDataRetriever{}
	mockManufacturers.On("GetManufacturer", 9).Return("Cisco", nil)
	mockManufacturers.On("GetManufacturer", 25506).Return("Juniper", nil)
	mockManufacturers.On("GetManufacturer", 999).Return("", fmt.Errorf("manufacturer not found"))
	mockManufacturers.On("GetDeviceModel", 1234).Return("cisco4000", nil)
	mockManufacturers.On("GetDeviceModel", 999).Return("", fmt.Errorf("device model not found"))

	mapper := mapping.NewDeviceMapper(mockManufacturers)

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
				Name: stringPtr("router1"),
				DeviceType: &diode.DeviceType{
					Manufacturer: &diode.Manufacturer{
						Name: stringPtr("Cisco"),
					},
					Model: stringPtr("cisco4000"),
				},
				Platform: &diode.Platform{
					Manufacturer: &diode.Manufacturer{
						Name: stringPtr("Cisco"),
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
				Name:        stringPtr("router1"),
				Description: stringPtr("Device specific description"),
				Comments:    stringPtr("Device specific comments"),
				Tags: []*diode.Tag{
					{Name: stringPtr("device-tag1")},
					{Name: stringPtr("device-tag2")},
					{Name: stringPtr("global-tag1")},
					{Name: stringPtr("global-tag2")},
				},
				Role: &diode.DeviceRole{
					Name: stringPtr("test-role"),
				},
				Site: &diode.Site{
					Name: stringPtr("test-site"),
				},
				Location: &diode.Location{
					Name: stringPtr("test-location"),
					Site: &diode.Site{
						Name: stringPtr("test-site"),
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
				Name: stringPtr("router1"),
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
			registry.SetDefaults(tt.defaults)
			entity := mapper.Map(tt.values, tt.mappingEntry, registry, logger)

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

func (m *MockManufacturerDataRetriever) GetManufacturer(id int) (string, error) {
	args := m.Called(id)
	return args.Get(0).(string), args.Error(1)
}

func (m *MockManufacturerDataRetriever) GetDeviceModel(id int) (string, error) {
	args := m.Called(id)
	return args.Get(0).(string), args.Error(1)
}

// Helper functions to create pointers
func stringPtr(s string) *string {
	return &s
}

func int64Ptr(i int64) *int64 {
	return &i
}

func boolPtr(b bool) *bool {
	return &b
}
