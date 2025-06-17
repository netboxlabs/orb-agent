package mapping

import (
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/data"
)

// IPAddressMapper is a struct that maps IP addresses to entities
type IPAddressMapper struct {
	logger *slog.Logger
}

// NewIPAddressMapper creates a new IPAddressMapper
func NewIPAddressMapper(logger *slog.Logger) *IPAddressMapper {
	return &IPAddressMapper{
		logger: logger,
	}
}

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
func (m *IPAddressMapper) Map(values map[ObjectIDIndex]*ObjectIDValue, mappingEntry *Entry, entityRegistry *EntityRegistry, defaults *config.Defaults) diode.Entity {
	m.logger.Debug("Mapping values to ipAddress entity", "values", values, "mappingEntry", mappingEntry)
	ipAddress := diode.IPAddress{}

	fieldFound := false
	// for each value in the map, map it to the ip address entity
	for objectID, value := range values {
		m.logger.Debug("Mapping value to ipAddress entity", "objectID", objectID, "value", value)
		for _, propertyMappingEntry := range mappingEntry.MappingEntries {
			if objectID.HasParent(propertyMappingEntry.OID) {
				switch propertyMappingEntry.Field {
				case "address":
					x := fmt.Sprintf("%s/32", string(value.Index))
					ipAddress.Address = &x
					fieldFound = true
				case "assigned_object":
					if propertyMappingEntry.Relationship != (config.Relationship{}) {
						linkedEntity := entityRegistry.GetOrCreateEntity(EntityType(propertyMappingEntry.Relationship.Type), ObjectIDIndex(value.Value))
						if linkedEntity == nil {
							m.logger.Warn("No linked entity found while mapping assigned object", "relationship", propertyMappingEntry.Relationship)
							continue
						}
						// Handle relationship mapping
						if propertyMappingEntry.Relationship.Type == "interface" {
							ipAddress.AssignedObject = linkedEntity.(*diode.Interface)
							fieldFound = true
						}
					}
				default:
					m.logger.Warn("Unknown field", "field", mappingEntry.Field)
				}
			}
		}
	}

	if fieldFound {
		m.applyDefaults(&ipAddress, defaults)
		if ipAddress.Address != nil {
			m.logger.Debug("Successfully mapped IP address", "address", *ipAddress.Address)
		} else {
			m.logger.Debug("Successfully mapped IP address (address field empty)")
		}
	}

	return &ipAddress
}

// InterfaceMapper is a struct that maps interfaces to entities
type InterfaceMapper struct {
	logger *slog.Logger
}

// NewInterfaceMapper creates a new InterfaceMapper
func NewInterfaceMapper(logger *slog.Logger) *InterfaceMapper {
	return &InterfaceMapper{
		logger: logger,
	}
}

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

	entity.Type = &entityDefaults.Type
}

// Map maps interfaces to entities
func (m *InterfaceMapper) Map(values map[ObjectIDIndex]*ObjectIDValue, mappingEntry *Entry, entityRegistry *EntityRegistry, defaults *config.Defaults) diode.Entity {
	m.logger.Debug("Mapping values to interface entity", "values", values, "mappingEntry", mappingEntry)
	interfaceEntity := entityRegistry.GetOrCreateEntity(InterfaceEntityType, getIndex(values)).(*diode.Interface)

	fieldFound := false
	for objectID, value := range values {
		for _, propertyMappingEntry := range mappingEntry.MappingEntries {
			if objectID.HasParent(propertyMappingEntry.OID) {
				m.logger.Debug("Mapping value to interface entity with mapper", "objectID", objectID, "value", value)
				switch propertyMappingEntry.Field {
				case "name":
					interfaceEntity.Name = &value.Value
					fieldFound = true
				case "speed":
					if value.Value == "" {
						m.logger.Debug("Speed is empty", "value", value.Value)
						continue
					}
					speed, err := strconv.Atoi(value.Value)
					if err != nil {
						m.logger.Warn("Error converting speed to int", "error", err, "value", value.Value)
						continue
					}
					speed64 := int64(speed)
					interfaceEntity.Speed = &speed64
					fieldFound = true
				case "macAddress":
					macAddress, err := m.FormatMACAddress(value.Value)
					if err != nil {
						m.logger.Warn("Error formatting mac address", "error", err, "value", value.Value)
						continue
					}
					interfaceEntity.PrimaryMacAddress = &diode.MACAddress{
						MacAddress: &macAddress, // TODO: This format is not correct - being rejected by netbox
					}
					fieldFound = true
				case "adminStatus":
					enabled := value.Value == "1"
					interfaceEntity.Enabled = &enabled
					fieldFound = true
				default:
					m.logger.Warn("Unknown field", "field", propertyMappingEntry.Field)
				}
			}
		}
	}

	// Apply defaults if available
	if fieldFound {
		m.applyDefaults(interfaceEntity, defaults)
		if interfaceEntity.Name != nil {
			m.logger.Debug("Successfully mapped interface", "name", *interfaceEntity.Name)
		} else {
			m.logger.Debug("Successfully mapped interface (name field empty)")
		}
	}

	return interfaceEntity
}

// FormatMACAddress formats a MAC address from a string to a colon-separated hex string
func (m *InterfaceMapper) FormatMACAddress(input string) (string, error) {
	// Decode the hex string to bytes
	bytes := []byte(input)

	// Check for correct MAC address length
	if len(bytes) != 6 {
		return "", fmt.Errorf("invalid MAC address length: got %d bytes", len(bytes))
	}

	// Format to colon-separated hex string
	var parts []string
	for _, b := range bytes {
		parts = append(parts, fmt.Sprintf("%02x", b))
	}

	output := strings.Join(parts, ":")
	m.logger.Debug("Formatted mac address", "input", input, "output", output)
	return output, nil
}

// DeviceMapper is a struct that maps devices to entities
type DeviceMapper struct {
	manufacturers data.ManufacturerRetriever
	deviceLookup  data.DeviceRetriever
	logger        *slog.Logger
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

// CurrentDeviceIndex is the index of the current device
const CurrentDeviceIndex = "CURRENT"

// NewDeviceMapper creates a new DeviceMapper
func NewDeviceMapper(manufacturers data.ManufacturerRetriever, deviceLookup data.DeviceRetriever, logger *slog.Logger) *DeviceMapper {
	return &DeviceMapper{
		manufacturers: manufacturers,
		deviceLookup:  deviceLookup,
		logger:        logger,
	}
}

// Map maps devices to entities
func (m *DeviceMapper) Map(values map[ObjectIDIndex]*ObjectIDValue, mappingEntry *Entry, entityRegistry *EntityRegistry, defaults *config.Defaults) diode.Entity {
	m.logger.Debug("Mapping values to device entity", "values", values, "mappingEntry", mappingEntry)
	deviceEntity := entityRegistry.GetOrCreateEntity(EntityType(mappingEntry.Entity), CurrentDeviceIndex).(*diode.Device)

	fieldFound := false
	for objectID, value := range values {
		for _, propertyMappingEntry := range mappingEntry.MappingEntries {
			if objectID.HasParent(propertyMappingEntry.OID) {
				m.logger.Debug("Mapping value to device entity with mapper", "objectID", objectID, "value", value, "mappingEntry", propertyMappingEntry)
				switch propertyMappingEntry.Field {
				case "name":
					deviceEntity.Name = &value.Value
					fieldFound = true
				case "description":
					deviceEntity.Description = &value.Value
					fieldFound = true
				case "platform":
					manufacturerID, err := m.getManufacturerID(value.Value)
					if err != nil {
						m.logger.Warn("Error getting device IDs", "error", err, "value", value.Value)
						continue
					}
					manufacturer, err := m.manufacturers.GetManufacturer(manufacturerID)
					if err != nil {
						m.logger.Warn("Error getting manufacturer", "error", err, "manufacturerID", manufacturerID)
						manufacturer = value.Value
					}

					manufacturerEntity := diode.Manufacturer{
						Name: &manufacturer,
					}

					deviceEntity.Platform = &diode.Platform{
						Name:         &manufacturer,
						Slug:         toSlug(&manufacturer),
						Manufacturer: &manufacturerEntity,
					}

					deviceModel, err := m.deviceLookup.GetDevice(value.Value)
					if err != nil {
						m.logger.Warn("Error getting device model falling back to OID", "error", err, "deviceOID", value.Value)
						deviceModel = value.Value
					}
					deviceEntity.DeviceType = &diode.DeviceType{
						Model:        &deviceModel,
						Manufacturer: &manufacturerEntity,
					}
					fieldFound = true
				default:
					m.logger.Warn("Unknown field", "field", propertyMappingEntry.Field)
				}
			}
		}
	}

	// Apply defaults if available
	if fieldFound {
		m.applyDefaults(deviceEntity, defaults)
		if deviceEntity.Name != nil {
			m.logger.Debug("Successfully mapped device", "name", *deviceEntity.Name)
		} else {
			m.logger.Debug("Successfully mapped device (name field empty)")
		}
	}

	return deviceEntity
}

func (m *DeviceMapper) getManufacturerID(objectID string) (string, error) {
	parts := strings.Split(objectID, ".")
	if len(parts) > 0 && parts[0] == "" {
		parts = parts[1:]
	}

	const ManufacturerIDIndex = 6
	// Check if we have enough parts to extract manufacturer and model IDs
	if len(parts) > ManufacturerIDIndex {
		return parts[ManufacturerIDIndex], nil
	}

	return "", fmt.Errorf("invalid objectID: %s", objectID)
}

func toSlug(input *string) *string {
	// Convert to lowercase
	slug := strings.ToLower(*input)

	// Remove all non-word characters (except spaces and dashes)
	re := regexp.MustCompile(`[^\w\s-]`)
	slug = re.ReplaceAllString(slug, "")

	// Replace spaces and underscores with dashes
	slug = strings.ReplaceAll(slug, " ", "-")
	slug = strings.ReplaceAll(slug, "_", "-")

	// Collapse multiple dashes into one
	re = regexp.MustCompile(`-+`)
	slug = re.ReplaceAllString(slug, "-")

	// Trim leading/trailing dashes
	slug = strings.Trim(slug, "-")

	return &slug
}
