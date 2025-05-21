package mapping

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
)

func TestIPAddressMapper_Map(t *testing.T) {
	logger := slog.Default()
	registry := NewEntityRegistry(logger)
	mapper := &IPAddressMapper{}

	tests := []struct {
		name           string
		values         map[ObjectIDIndex]*ObjectIDValue
		mappingEntry   *mappingEntry
		expectedEntity *diode.IPAddress
		expectError    bool
	}{
		{
			name: "successful mapping with all fields",
			values: map[ObjectIDIndex]*ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.1.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.1.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.1",
					Value:  "192.168.1.1",
					Type:   IPAddress,
				},
			},
			mappingEntry: &mappingEntry{
				OID:    "1.3.6.1.2.1.4.20.1.1",
				Entity: "ipAddress",
				Field:  "_id",
				MappingEntries: []mappingEntry{
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
			expectedEntity: &diode.IPAddress{
				Address: stringPtr("192.168.1.1/32"),
			},
			expectError: false,
		},
		{
			name: "mapping with interface relationship",
			values: map[ObjectIDIndex]*ObjectIDValue{
				"1.3.6.1.2.1.4.20.1.1.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.1.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.1",
					Value:  "192.168.1.1",
					Type:   IPAddress,
				},
				"1.3.6.1.2.1.4.20.1.2.192.168.1.1": {
					OID:    "1.3.6.1.2.1.4.20.1.2.192.168.1.1",
					Index:  "192.168.1.1",
					Parent: "1.3.6.1.2.1.4.20.1.2",
					Value:  "1",
					Type:   Integer,
				},
			},
			mappingEntry: &mappingEntry{
				OID:    "1.3.6.1.2.1.4.20.1.1",
				Entity: "ipAddress",
				Field:  "_id",
				MappingEntries: []mappingEntry{
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
			values: map[ObjectIDIndex]*ObjectIDValue{},
			mappingEntry: &mappingEntry{
				OID:    "1.3.6.1.2.1.4.20.1.1",
				Entity: "ipAddress",
				Field:  "_id",
			},
			expectedEntity: &diode.IPAddress{},
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entity := mapper.Map(tt.values, tt.mappingEntry, registry, logger)

			if tt.expectError {
				assert.Nil(t, entity)
				return
			}

			assert.NotNil(t, entity)
			ipAddress, ok := entity.(*diode.IPAddress)
			assert.True(t, ok)
			assert.Equal(t, tt.expectedEntity.Address, ipAddress.Address)
		})
	}
}

func TestInterfaceMapper_Map(t *testing.T) {
	tests := []struct {
		name           string
		values         map[ObjectIDIndex]*ObjectIDValue
		mappingEntry   *mappingEntry
		expectedEntity *diode.Interface
		expectError    bool
	}{
		{
			name: "successful mapping with all fields",
			values: map[ObjectIDIndex]*ObjectIDValue{
				"1.3.6.1.2.1.2.2.1.1.1": {
					OID:    "1.3.6.1.2.1.2.2.1.1.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.1",
					Value:  "1",
					Type:   Integer,
				},
				"1.3.6.1.2.1.2.2.1.2.1": {
					OID:    "1.3.6.1.2.1.2.2.1.2.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.2",
					Value:  "eth0",
					Type:   OctetString,
				},
				"1.3.6.1.2.1.2.2.1.5.1": {
					OID:    "1.3.6.1.2.1.2.2.1.5.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.5",
					Value:  "1000000",
					Type:   Integer,
				},
				"1.3.6.1.2.1.2.2.1.6.1": {
					OID:    "1.3.6.1.2.1.2.2.1.6.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.6",
					Value:  "00:11:22:33:44:55",
					Type:   OctetString,
				},
				"1.3.6.1.2.1.2.2.1.7.1": {
					OID:    "1.3.6.1.2.1.2.2.1.7.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.7",
					Value:  "1",
					Type:   Integer,
				},
			},
			mappingEntry: &mappingEntry{
				OID:    "1.3.6.1.2.1.2.2.1.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mappingEntry{
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
			expectedEntity: &diode.Interface{
				Name:              stringPtr("eth0"),
				Speed:             int64Ptr(1000000),
				PrimaryMacAddress: &diode.MACAddress{MacAddress: stringPtr("00:11:22:33:44:55")},
				Enabled:           boolPtr(true),
			},
			expectError: false,
		},
		{
			name: "mapping with invalid speed value",
			values: map[ObjectIDIndex]*ObjectIDValue{
				"1.3.6.1.2.1.2.2.1.1.1": {
					OID:    "1.3.6.1.2.1.2.2.1.1.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.1",
					Value:  "1",
					Type:   Integer,
				},
				"1.3.6.1.2.1.2.2.1.5.1": {
					OID:    "1.3.6.1.2.1.2.2.1.5.1",
					Index:  "1",
					Parent: "1.3.6.1.2.1.2.2.1.5",
					Value:  "invalid",
					Type:   Integer,
				},
			},
			mappingEntry: &mappingEntry{
				OID:    "1.3.6.1.2.1.2.2.1.1",
				Entity: "interface",
				Field:  "_id",
				MappingEntries: []mappingEntry{
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
			values: map[ObjectIDIndex]*ObjectIDValue{},
			mappingEntry: &mappingEntry{
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
			registry := NewEntityRegistry(logger)
			mapper := &InterfaceMapper{}
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
			assert.Equal(t, tt.expectedEntity.Enabled, iface.Enabled)
		})
	}
}

func TestDeviceMapper_Map(t *testing.T) {
	logger := slog.Default()
	registry := NewEntityRegistry(logger)

	// Create a mock manufacturer data retriever
	mockManufacturers := &MockManufacturerDataRetriever{}
	mockManufacturers.On("GetManufacturer", 9).Return("Cisco", nil)
	mockManufacturers.On("GetManufacturer", 25506).Return("Juniper", nil)
	mockManufacturers.On("GetManufacturer", 999).Return("", fmt.Errorf("manufacturer not found"))
	mockManufacturers.On("GetDeviceModel", 1234).Return("cisco4000", nil)
	mockManufacturers.On("GetDeviceModel", 999).Return("", fmt.Errorf("device model not found"))

	mapper := &DeviceMapper{
		devices: mockManufacturers,
	}

	tests := []struct {
		name           string
		values         map[ObjectIDIndex]*ObjectIDValue
		mappingEntry   *mappingEntry
		expectedEntity *diode.Device
		expectError    bool
	}{
		{
			name: "successful mapping with name and platform",
			values: map[ObjectIDIndex]*ObjectIDValue{
				"1.3.6.1.2.1.1.5.0": {
					OID:    "1.3.6.1.2.1.1.5.0",
					Index:  "0",
					Parent: "1.3.6.1.2.1.1.5",
					Value:  "router1",
					Type:   OctetString,
				},
				"1.3.6.1.2.1.1.2.0": {
					OID:    "1.3.6.1.2.1.1.2.0",
					Index:  "0",
					Parent: "1.3.6.1.2.1.1.2",
					Value:  "1.3.6.1.4.1.9.1.1234",
					Type:   ObjectIdentifier,
				},
			},
			mappingEntry: &mappingEntry{
				OID:    "1.3.6.1.2.1.1",
				Entity: "device",
				Field:  "_id",
				MappingEntries: []mappingEntry{
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
				DeviceType: &diode.DeviceType{
					Manufacturer: &diode.Manufacturer{
						Name: diode.String("Cisco"),
					},
					Model: diode.String("cisco4000"),
				},
				Platform: &diode.Platform{
					Manufacturer: &diode.Manufacturer{
						Name: diode.String("Cisco"),
					},
				},
			},
			expectError: false,
		},
		{
			name: "mapping with unknown manufacturer",
			values: map[ObjectIDIndex]*ObjectIDValue{
				"1.3.6.1.2.1.1.2.0": {
					OID:    "1.3.6.1.2.1.1.2.0",
					Index:  "0",
					Parent: "1.3.6.1.2.1.1.2",
					Value:  "1.3.6.1.4.1.999.1.1234",
					Type:   ObjectIdentifier,
				},
			},
			mappingEntry: &mappingEntry{
				OID:    "1.3.6.1.2.1.1",
				Entity: "device",
				Field:  "_id",
				MappingEntries: []mappingEntry{
					{
						OID:    "1.3.6.1.2.1.1.2",
						Entity: "device",
						Field:  "platform",
					},
				},
			},
			expectedEntity: &diode.Device{
				Platform: &diode.Platform{
					Manufacturer: &diode.Manufacturer{
						Name: diode.String("unknown"),
					},
				},
			},
			expectError: false,
		},
		{
			name:   "empty values map",
			values: map[ObjectIDIndex]*ObjectIDValue{},
			mappingEntry: &mappingEntry{
				OID:    "1.3.6.1.2.1.1",
				Entity: "device",
				Field:  "_id",
			},
			expectedEntity: &diode.Device{},
			expectError:    false,
		},
		{
			name: "invalid OID format",
			values: map[ObjectIDIndex]*ObjectIDValue{
				"1.3.6.1.2.1.1.2.0": {
					OID:    "1.3.6.1.2.1.1.2.0",
					Index:  "0",
					Parent: "1.3.6.1.2.1.1.2",
					Value:  "invalid.oid",
					Type:   ObjectIdentifier,
				},
			},
			mappingEntry: &mappingEntry{
				OID:    "1.3.6.1.2.1.1",
				Entity: "device",
				Field:  "_id",
				MappingEntries: []mappingEntry{
					{
						OID:    "1.3.6.1.2.1.1.2",
						Entity: "device",
						Field:  "platform",
					},
				},
			},
			expectedEntity: &diode.Device{
				DeviceType: &diode.DeviceType{
					Manufacturer: &diode.Manufacturer{
						Name: diode.String("unknown"),
					},
					Model: diode.String("unknown"),
				},
				Platform: &diode.Platform{
					Manufacturer: &diode.Manufacturer{
						Name: diode.String("unknown"),
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entity := mapper.Map(tt.values, tt.mappingEntry, registry, logger)

			if tt.expectError {
				assert.Nil(t, entity)
				return
			}

			assert.NotNil(t, entity)
			device, ok := entity.(*diode.Device)
			assert.True(t, ok)
			assert.Equal(t, tt.expectedEntity.Name, device.Name)
			if tt.expectedEntity.Platform != nil && device.Platform != nil {
				assert.Equal(t, tt.expectedEntity.Platform.Manufacturer.Name, device.Platform.Manufacturer.Name)
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
