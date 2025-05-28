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

// applyDefaults applies default values to an IP address entity
func (m *IPAddressMapper) applyDefaults(entity *diode.IPAddress, defaults *config.Defaults) {
	if defaults == nil {
		return
	}
	entityDefaults := defaults.IPAddress

	// Apply entity-specific defaults
	if entityDefaults.Description != "" {
		entity.Description = &entityDefaults.Description
	}
	if entityDefaults.Comments != "" {
		entity.Comments = &entityDefaults.Comments
	}

	// Collect tags from both entity-specific and global defaults
	var tags []*diode.Tag
	if len(entityDefaults.Tags) > 0 {
		for _, tag := range entityDefaults.Tags {
			tags = append(tags, &diode.Tag{Name: &tag})
		}
	}
	if len(defaults.Tags) > 0 {
		for _, tag := range defaults.Tags {
			tags = append(tags, &diode.Tag{Name: &tag})
		}
	}

	// Apply tags if any exist
	if len(tags) > 0 {
		entity.Tags = tags
	}

	// Apply global defaults if not overridden by entity-specific defaults
	if entity.Description == nil && entityDefaults.Description != "" {
		entity.Description = &entityDefaults.Description
	}
	if entity.Comments == nil && entityDefaults.Comments != "" {
		entity.Comments = &entityDefaults.Comments
	}
	if entity.Tenant == nil && entityDefaults.Tenant != "" {
		entity.Tenant = &diode.Tenant{
			Name: &entityDefaults.Tenant,
		}
	}
	if entity.Role == nil && entityDefaults.Role != "" {
		entity.Role = &entityDefaults.Role
	}
	if entity.Vrf == nil && entityDefaults.Vrf != "" {
		entity.Vrf = &diode.VRF{
			Name: &entityDefaults.Vrf,
			Rd:   &entityDefaults.Vrf,
		}
	}
}

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

	if fieldFound {
		m.applyDefaults(&ipAddress, entityRegistry.GetDefaults())
	}

	return &ipAddress
}

// InterfaceMapper is a struct that maps interfaces to entities
type InterfaceMapper struct{}

// applyDefaults applies default values to an interface entity
func (m *InterfaceMapper) applyDefaults(entity *diode.Interface, defaults *config.Defaults) {
	if defaults == nil {
		return
	}
	entityDefaults := defaults.Interface

	// Apply entity-specific defaults
	if entityDefaults.Description != "" {
		entity.Description = &entityDefaults.Description
	}

	// Collect tags from both entity-specific and global defaults
	var tags []*diode.Tag
	if len(entityDefaults.Tags) > 0 {
		for _, tag := range entityDefaults.Tags {
			tags = append(tags, &diode.Tag{Name: &tag})
		}
	}
	if len(defaults.Tags) > 0 {
		for _, tag := range defaults.Tags {
			tags = append(tags, &diode.Tag{Name: &tag})
		}
	}

	// Apply tags if any exist
	if len(tags) > 0 {
		entity.Tags = tags
	}

	// Apply global defaults if not overridden by entity-specific defaults
	if entity.Description == nil && entityDefaults.Description != "" {
		entity.Description = &entityDefaults.Description
	}

	if entity.Type == nil && entityDefaults.Type != "" {
		entity.Type = &entityDefaults.Type
	}
}

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
					if value.Value == "" {
						logger.Debug("Speed is empty", "value", value.Value)
						continue
					}
					speed, err := strconv.Atoi(value.Value)
					if err != nil {
						logger.Warn("Error converting speed to int", "error", err, "value", value.Value)
						continue
					}
					speed64 := int64(speed)
					interfaceEntity.Speed = &speed64
					fieldFound = true
				case "macAddress":
					macAddress, err := formatMACAddress(value.Value)
					if err != nil {
						logger.Warn("Error formatting mac address", "error", err, "value", value.Value)
						continue
					}
					interfaceEntity.PrimaryMacAddress = &diode.MACAddress{
						MacAddress: &macAddress,
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
	if fieldFound {
		m.applyDefaults(interfaceEntity, entityRegistry.GetDefaults())
	}

	return interfaceEntity
}

func formatMACAddress(rawStr string) (string, error) {
	// Decode escaped characters into actual bytes
	unquoted, err := strconv.Unquote(`"` + rawStr + `"`)
	if err != nil {
		return "", fmt.Errorf("failed to unquote string: %v", err)
	}

	macParts := make([]string, len(unquoted))
	for i := 0; i < len(unquoted); i++ {
		macParts[i] = fmt.Sprintf("%02x", unquoted[i])
	}
	return strings.Join(macParts, ":"), nil
}

// DeviceMapper is a struct that maps devices to entities
type DeviceMapper struct {
	devices data.DeviceDataRetreiver
}

// applyDefaults applies default values to a device entity
func (m *DeviceMapper) applyDefaults(entity *diode.Device, defaults *config.Defaults) {
	if defaults == nil {
		return
	}
	entityDefaults := defaults.Device

	// Apply entity-specific defaults
	if entityDefaults.Description != "" {
		entity.Description = &entityDefaults.Description
	}
	if entityDefaults.Comments != "" {
		entity.Comments = &entityDefaults.Comments
	}

	// Collect tags from both entity-specific and global defaults
	var tags []*diode.Tag
	if len(entityDefaults.Tags) > 0 {
		for _, tag := range entityDefaults.Tags {
			tags = append(tags, &diode.Tag{Name: &tag})
		}
	}
	if len(defaults.Tags) > 0 {
		for _, tag := range defaults.Tags {
			tags = append(tags, &diode.Tag{Name: &tag})
		}
	}

	// Apply tags if any exist
	if len(tags) > 0 {
		entity.Tags = tags
	}

	// Apply global defaults if not overridden by entity-specific defaults
	if entity.Description == nil && entityDefaults.Description != "" {
		entity.Description = &entityDefaults.Description
	}
	if entity.Comments == nil && entityDefaults.Comments != "" {
		entity.Comments = &entityDefaults.Comments
	}

	if entity.Role == nil && defaults.Role != "" {
		entity.Role = &diode.DeviceRole{
			Name: &defaults.Role,
		}
	}

	if entity.Site == nil && defaults.Site != "" {
		entity.Site = &diode.Site{
			Name: &defaults.Site,
		}
	}

	if entity.Location == nil && defaults.Location != "" {
		entity.Location = &diode.Location{
			Name: &defaults.Location,
		}
		if entity.Location.Site == nil && defaults.Site != "" {
			entity.Location.Site = &diode.Site{
				Name: &defaults.Site,
			}
		}
	}
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
	if fieldFound {
		m.applyDefaults(deviceEntity, entityRegistry.GetDefaults())
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
