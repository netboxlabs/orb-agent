package mapping

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/data"
)

// IPAddressMapper is a struct that maps IP addresses to entities
type IPAddressMapper struct{}

// Map maps IP addresses to entities
func (m *IPAddressMapper) Map(values map[ObjectIDIndex]*ObjectIDValue, mappingEntry *Entry, entityRegistry *EntityRegistry, logger *slog.Logger) diode.Entity {
	logger.Debug("Mapping values to ipAddress entity", "values", values, "mappingEntry", mappingEntry)
	ipAddress := diode.IPAddress{}

	fieldFound := false
	// for each value in the map, map it to the ip address entity
	for objectID, value := range values {
		logger.Debug("Mapping value to ipAddress entity", "objectID", objectID, "value", value)
		for _, propertyMappingEntry := range mappingEntry.MappingEntries {
			if objectID.HasParent(mappingEntry.OID) {
				switch propertyMappingEntry.Field {
				case "address":
					x := fmt.Sprintf("%s/32", string(value.Index))
					ipAddress.Address = &x
					fieldFound = true
				case "assigned_object":
					if propertyMappingEntry.Relationship != (config.Relationship{}) {
						linkedEntity := entityRegistry.GetOrCreateEntity(EntityType(propertyMappingEntry.Relationship.Type), ObjectIDIndex(value.Value))
						if linkedEntity == nil {
							logger.Warn("No linked entity found while mapping assigned object", "relationship", propertyMappingEntry.Relationship)
							continue
						}
						// Handle relationship mapping
						if propertyMappingEntry.Relationship.Type == "interface" {
							ipAddress.AssignedObject = linkedEntity.(*diode.Interface)
							fieldFound = true
						}
					}
				default:
					logger.Warn("Unknown field", "field", mappingEntry.Field)
				}
			}
		}
	}

	// Apply defaults if available
	if defaults := entityRegistry.GetDefaults(); defaults != nil && fieldFound {
		// Apply IP address specific defaults
		if defaults.IPAddress.Description != "" {
			ipAddress.Description = &defaults.IPAddress.Description
		}
		if defaults.IPAddress.Comments != "" {
			ipAddress.Comments = &defaults.IPAddress.Comments
		}
		var tags []*diode.Tag
		// Add entity-specific tags
		if len(defaults.IPAddress.Tags) > 0 {
			for _, tag := range defaults.IPAddress.Tags {
				tags = append(tags, &diode.Tag{Name: &tag})
			}
		}
		// Add global tags
		if len(defaults.Tags) > 0 {
			for _, tag := range defaults.Tags {
				tags = append(tags, &diode.Tag{Name: &tag})
			}
		}
		if len(tags) > 0 {
			ipAddress.Tags = tags
		}

		// Apply global defaults if not overridden by entity-specific defaults
		if ipAddress.Description == nil && defaults.Description != "" {
			ipAddress.Description = &defaults.Description
		}
		if ipAddress.Comments == nil && defaults.Comments != "" {
			ipAddress.Comments = &defaults.Comments
		}
	}

	return &ipAddress
}

// InterfaceMapper is a struct that maps interfaces to entities
type InterfaceMapper struct{}

// Map maps interfaces to entities
func (m *InterfaceMapper) Map(values map[ObjectIDIndex]*ObjectIDValue, mappingEntry *Entry, entityRegistry *EntityRegistry, logger *slog.Logger) diode.Entity {
	logger.Debug("Mapping values to interface entity", "values", values, "mappingEntry", mappingEntry)
	interfaceEntity := entityRegistry.GetOrCreateEntity(EntityType(mappingEntry.Entity), getIndex(values)).(*diode.Interface)

	fieldFound := false
	for objectID, value := range values {
		for _, propertyMappingEntry := range mappingEntry.MappingEntries {
			if objectID.HasParent(propertyMappingEntry.OID) {
				logger.Debug("Mapping value to interface entity with mapper", "objectID", objectID, "value", value, "mappingEntry", propertyMappingEntry)
				switch propertyMappingEntry.Field {
				case "name":
					interfaceEntity.Name = &value.Value
					fieldFound = true
				case "speed":
					speed, err := strconv.Atoi(value.Value)
					if err != nil {
						logger.Warn("Error converting speed to int", "error", err, "value", value.Value)
						continue
					}
					speed64 := int64(speed)
					interfaceEntity.Speed = &speed64
					fieldFound = true
				case "macAddress":
					interfaceEntity.PrimaryMacAddress = &diode.MACAddress{
						MacAddress: &value.Value,
					}
					fieldFound = true
				case "adminStatus":
					enabled := value.Value == "1"
					interfaceEntity.Enabled = &enabled
					fieldFound = true
				default:
					logger.Warn("Unknown field", "field", propertyMappingEntry.Field)
				}
			}
		}
	}

	// Apply defaults if available
	if defaults := entityRegistry.GetDefaults(); defaults != nil && fieldFound {
		// Apply interface specific defaults
		if defaults.Interface.Description != "" {
			interfaceEntity.Description = &defaults.Interface.Description
		}
		var tags []*diode.Tag
		// Add entity-specific tags
		if len(defaults.Interface.Tags) > 0 {
			for _, tag := range defaults.Interface.Tags {
				tags = append(tags, &diode.Tag{Name: &tag})
			}
		}
		// Add global tags
		if len(defaults.Tags) > 0 {
			for _, tag := range defaults.Tags {
				tags = append(tags, &diode.Tag{Name: &tag})
			}
		}
		if len(tags) > 0 {
			interfaceEntity.Tags = tags
		}

		// Apply global defaults if not overridden by entity-specific defaults
		if interfaceEntity.Description == nil && defaults.Description != "" {
			interfaceEntity.Description = &defaults.Description
		}
	}

	return interfaceEntity
}

// DeviceMapper is a struct that maps devices to entities
type DeviceMapper struct {
	devices data.DeviceDataRetreiver
}

// NewDeviceMapper creates a new DeviceMapper
func NewDeviceMapper(devices data.DeviceDataRetreiver) *DeviceMapper {
	return &DeviceMapper{
		devices: devices,
	}
}

// Map maps devices to entities
func (m *DeviceMapper) Map(values map[ObjectIDIndex]*ObjectIDValue, mappingEntry *Entry, entityRegistry *EntityRegistry, logger *slog.Logger) diode.Entity {
	logger.Debug("Mapping values to device entity", "values", values, "mappingEntry", mappingEntry)
	deviceEntity := entityRegistry.GetOrCreateEntity(EntityType(mappingEntry.Entity), getIndex(values)).(*diode.Device)

	fieldFound := false
	for objectID, value := range values {
		for _, propertyMappingEntry := range mappingEntry.MappingEntries {
			if objectID.HasParent(propertyMappingEntry.OID) {
				logger.Debug("Mapping value to device entity with mapper", "objectID", objectID, "value", value, "mappingEntry", propertyMappingEntry)
				switch propertyMappingEntry.Field {
				case "name":
					deviceEntity.Name = &value.Value
					fieldFound = true
				case "platform":
					// Use getDeviceIDs to get the manufacturer and model
					manufacturerID, modelID, err := m.getDeviceIDs(value.Value)
					if err != nil {
						logger.Warn("Error getting device IDs", "error", err, "value", value.Value)
						continue
					}
					manufacturer, err := m.devices.GetManufacturer(manufacturerID)
					if err != nil {
						logger.Warn("Error getting manufacturer", "error", err, "manufacturerID", manufacturerID)
						continue
					}

					manufacturerEntity := diode.Manufacturer{
						Name: &manufacturer,
					}

					deviceEntity.Platform = &diode.Platform{
						Manufacturer: &manufacturerEntity,
					}

					deviceModel, err := m.devices.GetDeviceModel(modelID)
					if err != nil {
						logger.Warn("Error getting device model", "error", err, "modelID", modelID)
					}
					deviceEntity.DeviceType = &diode.DeviceType{
						Model:        &deviceModel,
						Manufacturer: &manufacturerEntity,
					}
					fieldFound = true
				default:
					logger.Warn("Unknown field", "field", propertyMappingEntry.Field)
				}
			}
		}
	}

	// Apply defaults if available
	if defaults := entityRegistry.GetDefaults(); fieldFound && defaults != nil {
		// Apply device specific defaults
		if defaults.Device.Description != "" {
			deviceEntity.Description = &defaults.Device.Description
		}
		var tags []*diode.Tag
		// Add entity-specific tags
		if len(defaults.Device.Tags) > 0 {
			for _, tag := range defaults.Device.Tags {
				tags = append(tags, &diode.Tag{Name: &tag})
			}
		}
		// Add global tags
		if len(defaults.Tags) > 0 {
			for _, tag := range defaults.Tags {
				tags = append(tags, &diode.Tag{Name: &tag})
			}
		}
		if len(tags) > 0 {
			deviceEntity.Tags = tags
		}

		// Apply global defaults if not overridden by entity-specific defaults
		if deviceEntity.Description == nil && defaults.Description != "" {
			deviceEntity.Description = &defaults.Description
		}
	}

	return deviceEntity
}

func (m *DeviceMapper) getDeviceIDs(objectID string) (int, int, error) {
	parts := strings.Split(objectID, ".")
	if len(parts) > 0 && parts[0] == "" {
		parts = parts[1:]
	}

	const ManufacturerIDIndex = 6
	// Check if we have enough parts to extract manufacturer and model IDs
	if len(parts) > ManufacturerIDIndex {
		manID, err := strconv.Atoi(parts[ManufacturerIDIndex])
		if err != nil {
			return 0, 0, err
		}

		modelID, err := strconv.Atoi(parts[len(parts)-1])
		if err != nil {
			return 0, 0, err
		}

		return manID, modelID, nil
	}

	return 0, 0, fmt.Errorf("invalid objectID: %s", objectID)
}
