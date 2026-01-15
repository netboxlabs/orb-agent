package mapping

import (
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/data"
)

// Interface speed constants
const (
	minInterfaceSpeed = 0
	maxInterfaceSpeed = 2147483647
)

// MTU constants
const (
	minInterfaceMTU = 1
	maxInterfaceMTU = 2147483647
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
	var extractedIP string // Store the IP address extracted from any field

	extractIPFromIndex := func(value *ObjectIDValue, field string) {
		if extractedIP != "" {
			return
		}
		if value.Index != "" {
			if ip := net.ParseIP(string(value.Index)); ip != nil && ip.To4() != nil {
				extractedIP = ip.String()
				m.logger.Debug("Extracted IP address", "field", field, "ip", extractedIP)
			}
		}
	}

	extractIPFromValueOrIndex := func(value *ObjectIDValue, field string) bool {
		if extractedIP != "" {
			return true // Already extracted
		}
		// Try to extract from value field first
		if value.Value != "" {
			if ip := net.ParseIP(value.Value); ip != nil && ip.To4() != nil {
				extractedIP = ip.String()
				m.logger.Debug("Extracted IP address", "field", field, "ip", extractedIP)
				return true
			}
		}
		// Fall back to extracting from index
		extractIPFromIndex(value, field)
		return extractedIP != ""
	}

	setOrUpdateAddress := func(newAddress string) {
		ipAddress.Address = &newAddress
	}

	for objectID, value := range values {
		m.logger.Debug("Mapping value to ipAddress entity", "objectID", objectID, "value", value)
		for _, propertyMappingEntry := range mappingEntry.MappingEntries {
			if objectID.HasParent(propertyMappingEntry.OID) {
				switch propertyMappingEntry.Field {
				case "address":
					if !extractIPFromValueOrIndex(value, propertyMappingEntry.Field) {
						m.logger.Warn("Could not extract valid IP address from any field")
						continue
					}
					if ipAddress.Address != nil && strings.HasPrefix(*ipAddress.Address, "/") {
						// Prefix was processed first, prepend IP
						setOrUpdateAddress(fmt.Sprintf("%s%s", extractedIP, *ipAddress.Address))
					} else if ipAddress.Address == nil || *ipAddress.Address == "" {
						// No prefix yet, set IP with default /32
						setOrUpdateAddress(fmt.Sprintf("%s/32", extractedIP))
					}
					fieldFound = true
				case "addressPrefixSize":
					extractIPFromIndex(value, propertyMappingEntry.Field)
					prefixLength, err := maskToPrefixSize(value.Value)
					if err != nil {
						m.logger.Warn("Error converting mask to prefix size", "error", err, "value", value.Value)
						continue
					}
					if ipAddress.Address == nil || *ipAddress.Address == "" {
						// No address set yet
						if extractedIP != "" {
							// Use extracted IP with the prefix
							setOrUpdateAddress(fmt.Sprintf("%s/%d", extractedIP, prefixLength))
						} else {
							// No IP available, store just the prefix (will be rejected by validation)
							setOrUpdateAddress(fmt.Sprintf("/%d", prefixLength))
						}
						fieldFound = true
					} else {
						// Address already set, update the prefix
						prefixParts := strings.Split(*ipAddress.Address, "/")
						if len(prefixParts) >= 1 {
							setOrUpdateAddress(fmt.Sprintf("%s/%d", prefixParts[0], prefixLength))
						} else {
							setOrUpdateAddress(fmt.Sprintf("%s/%d", *ipAddress.Address, prefixLength))
						}
						fieldFound = true
					}
				case "assignedObject":
					extractIPFromIndex(value, propertyMappingEntry.Field)
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

	// Validate the final IP/CIDR before storage
	if ipAddress.Address != nil && *ipAddress.Address != "" {
		if !ValidateIPv4CIDR(*ipAddress.Address) {
			m.logger.Warn("Invalid IP/CIDR format, skipping",
				"address", *ipAddress.Address)
			return &diode.IPAddress{} // Empty entity won't be added
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

func maskToPrefixSize(maskStr string) (int, error) {
	parts := strings.Split(maskStr, ".")
	if len(parts) != 4 {
		return 0, fmt.Errorf("invalid mask format: %s", maskStr)
	}

	// Convert string to IP mask
	ip := net.ParseIP(maskStr)
	if ip == nil {
		return 0, fmt.Errorf("could not parse IP: %s", maskStr)
	}

	// Convert to 4-byte representation and compute prefix
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("not an IPv4 address: %s", maskStr)
	}

	mask := net.IPv4Mask(ip[0], ip[1], ip[2], ip[3])
	ones, _ := mask.Size()

	return ones, nil
}

// ValidateIPv4CIDR validates an IPv4 address in CIDR notation (e.g., "192.168.1.1/24").
// Returns true if the format is valid, false otherwise.
func ValidateIPv4CIDR(cidr string) bool {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	// Verify it's IPv4 (not IPv6)
	if ip.To4() == nil {
		return false
	}

	// Verify prefix is in valid range (0-32 for IPv4)
	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones < 0 || ones > 32 {
		return false
	}

	return true
}

// InterfaceMapper is a struct that maps interfaces to entities
type InterfaceMapper struct {
	logger           *slog.Logger
	patternMatcher   *PatternMatcher
	userPatternCount int
}

// NewInterfaceMapper creates a new InterfaceMapper
func NewInterfaceMapper(logger *slog.Logger, patterns []config.InterfacePattern) (*InterfaceMapper, error) {
	var patternMatcher *PatternMatcher
	userPatternCount := len(patterns)

	// Always merge patterns to include built-in defaults
	mergedPatterns := MergePatterns(patterns, true)

	// Create pattern matcher if we have any patterns (user or built-in)
	if len(mergedPatterns) > 0 {
		var err error
		patternMatcher, err = NewPatternMatcher(mergedPatterns, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create pattern matcher: %w", err)
		}
	}

	return &InterfaceMapper{
		logger:           logger,
		patternMatcher:   patternMatcher,
		userPatternCount: userPatternCount,
	}, nil
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

	if entity.Type == nil || *entity.Type == "" {
		entity.Type = &entityDefaults.Type
	}
}

// Map maps interfaces to entities
func (m *InterfaceMapper) Map(values map[ObjectIDIndex]*ObjectIDValue, mappingEntry *Entry, entityRegistry *EntityRegistry, defaults *config.Defaults) diode.Entity {
	m.logger.Debug("Mapping values to interface entity", "values", values, "mappingEntry", mappingEntry)
	interfaceEntity := entityRegistry.GetOrCreateEntity(InterfaceEntityType, getIndex(values)).(*diode.Interface)

	fieldFound := false
	var snmpIfType string // Store SNMP ifType for final type resolution

	valueKeys := make([]ObjectIDIndex, 0, len(values))
	for objectID := range values {
		valueKeys = append(valueKeys, objectID)
	}
	// Sort the keys to ensure a consistent processing order.
	// Reverse the keys to prioritize fields like speed before type during mapping.
	slices.Sort(valueKeys)
	slices.Reverse(valueKeys)
	for _, objectID := range valueKeys {
		value := values[objectID]
		for _, propertyMappingEntry := range mappingEntry.MappingEntries {
			if objectID.HasParent(propertyMappingEntry.OID) {
				m.logger.Debug("Mapping value to interface entity with mapper", "objectID", objectID, "value", value)
				switch propertyMappingEntry.Field {
				case "name":
					interfaceEntity.Name = &value.Value
					fieldFound = true
				case "description":
					description := strings.TrimRight(value.Value, " \t\n\r")
					if len(description) > 200 {
						description = description[:197] + "..."
					}
					interfaceEntity.Description = &description
					fieldFound = true
				case "type":
					// Store SNMP ifType but defer type resolution until after all fields are processed
					// This ensures name and speed are available for pattern matching
					snmpIfType = value.Value
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
					bitsPerSecond := int64(speed)
					kiloBitsPerSecond := bitsPerSecond / 1000
					// Check if speed is within valid range (0 to 2147483647 inclusive)
					if kiloBitsPerSecond < minInterfaceSpeed || kiloBitsPerSecond > maxInterfaceSpeed {
						m.logger.Warn("Interface speed is outside valid range (0-2147483647)", "speed", speed, "value",
							value.Value, "mappingID", propertyMappingEntry.OID, "interfaceIndex", objectID)
						continue
					}
					if interfaceEntity.Speed != nil && *interfaceEntity.Speed > 0 {
						m.logger.Debug("Interface speed already set, skipping", "existingSpeed", *interfaceEntity.Speed,
							"newSpeed", kiloBitsPerSecond, "interfaceIndex", objectID)
						continue
					}
					interfaceEntity.Speed = &kiloBitsPerSecond
					fieldFound = true
				case "highSpeed":
					if value.Value == "" {
						m.logger.Debug("highSpeed is empty", "value", value.Value)
						continue
					}
					highSpeed, err := strconv.Atoi(value.Value)
					if err != nil {
						m.logger.Warn("Error converting highSpeed to int", "error", err, "value", value.Value)
						continue
					}
					speedMbps := int64(highSpeed)
					// Check if highSpeed is within valid range (0 to 2147483647 inclusive)
					if speedMbps < minInterfaceSpeed || speedMbps > maxInterfaceSpeed {
						m.logger.Warn("Interface highSpeed is outside valid range (0-2147483647)", "highSpeed",
							highSpeed, "value", value.Value, "mappingID", propertyMappingEntry.OID, "interfaceIndex", objectID)
						continue
					}
					kiloBitsPerSecond := speedMbps * 1000
					interfaceEntity.Speed = &kiloBitsPerSecond
					fieldFound = true
				case "mtu":
					if value.Value == "" {
						m.logger.Debug("mtu is empty", "value", value.Value)
						continue
					}
					mtu, err := strconv.ParseInt(value.Value, 10, 64)
					if err != nil {
						m.logger.Warn("Error converting mtu to int64", "error", err, "value", value.Value)
						continue
					}
					if mtu == 0 {
						m.logger.Debug("mtu is zero, skipping", "value", value.Value)
						continue
					}
					// Check if MTU is within valid range (1 to 2147483647 inclusive) and not overflowing int32
					if mtu < minInterfaceMTU || mtu > maxInterfaceMTU {
						m.logger.Warn("Interface MTU is outside valid range (1-2147483647) or overflows int32", "mtu", mtu,
							"value", value.Value, "mappingID", propertyMappingEntry.OID, "interfaceIndex", objectID)
						continue
					}
					mtu64 := mtu
					interfaceEntity.Mtu = &mtu64
					fieldFound = true
				case "macAddress":
					macAddress, err := m.FormatMACAddress(value.Value)
					if err != nil {
						m.logger.Debug("Error formatting mac address", "error", err, "value", value.Value)
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

	// Resolve interface type after all fields are collected
	// This ensures name and speed are available for pattern matching
	if snmpIfType != "" {
		var interfaceName string
		if interfaceEntity.Name != nil {
			interfaceName = *interfaceEntity.Name
		}

		defaultType := ""
		if defaults != nil && defaults.Interface.Type != "" {
			defaultType = defaults.Interface.Type
		}

		interfaceType := ResolveInterfaceType(
			interfaceName,
			snmpIfType,
			interfaceEntity.Speed,
			defaultType,
			m.patternMatcher,
			m.userPatternCount,
		)
		interfaceEntity.Type = &interfaceType
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

	// Check if MAC address is all zeros (00:00:00:00:00:00)
	allZeros := true
	for _, b := range bytes {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		return "", fmt.Errorf("invalid MAC address: 00:00:00:00:00:00 is not a valid hardware address")
	}

	// Format to colon-separated hex string
	var parts []string
	for _, b := range bytes {
		parts = append(parts, fmt.Sprintf("%02X", b))
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
					description := strings.TrimRight(value.Value, " \t\n\r")
					if len(description) > 200 {
						description = description[:197] + "..."
					}
					deviceEntity.Description = &description
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
