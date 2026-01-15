package mapping

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/data"
)

// Value is a struct that contains a value and a type of an SNMP object
type Value struct {
	Value          string
	Type           Asn1BER
	IdentifierSize int
}

// Asn1BER is a type that represents the type of an SNMP object
type Asn1BER byte

// Asn1BER constants
const (
	EndOfContents     Asn1BER = 0x00
	UnknownType       Asn1BER = 0x00
	Boolean           Asn1BER = 0x01
	Integer           Asn1BER = 0x02
	BitString         Asn1BER = 0x03
	OctetString       Asn1BER = 0x04
	Null              Asn1BER = 0x05
	ObjectIdentifier  Asn1BER = 0x06
	ObjectDescription Asn1BER = 0x07
	IPAddress         Asn1BER = 0x40
	Counter32         Asn1BER = 0x41
	Gauge32           Asn1BER = 0x42
	TimeTicks         Asn1BER = 0x43
	Opaque            Asn1BER = 0x44
	NsapAddress       Asn1BER = 0x45
	Counter64         Asn1BER = 0x46
	Uinteger32        Asn1BER = 0x47
	OpaqueFloat       Asn1BER = 0x78
	OpaqueDouble      Asn1BER = 0x79
	NoSuchObject      Asn1BER = 0x80
	NoSuchInstance    Asn1BER = 0x81
	EndOfMibView      Asn1BER = 0x82
)

// EntityRegistry is a struct that contains a map of entities
type EntityRegistry struct {
	entities map[EntityType]map[ObjectIDIndex]diode.Entity
	logger   *slog.Logger
}

// NewEntityRegistry creates a new EntityRegistry
func NewEntityRegistry(logger *slog.Logger) *EntityRegistry {
	return &EntityRegistry{
		entities: make(map[EntityType]map[ObjectIDIndex]diode.Entity),
		logger:   logger,
	}
}

// GetOrCreateEntity returns an entity from the EntityRegistry or creates a new one if it doesn't exist
func (r *EntityRegistry) GetOrCreateEntity(entityType EntityType, index ObjectIDIndex) diode.Entity {
	r.logger.Debug("Getting entity", "entityType", entityType, "index", index, "from", r.entities)
	if r.entities[entityType] == nil {
		r.entities[entityType] = make(map[ObjectIDIndex]diode.Entity)
	}
	if r.entities[entityType][index] == nil {
		entity, err := createEntity(entityType)
		r.logger.Debug("Entity not found, creating", "entityType", entityType, "index", index, "entity", entity)
		if err != nil {
			r.logger.Warn("Error creating entity", "error", err, "entityType", entityType, "index", index)
			return nil
		}
		r.entities[entityType][index] = entity
	}
	return r.entities[entityType][index]
}

func createEntity(entityType EntityType) (diode.Entity, error) {
	switch entityType {
	case "ipAddress":
		return &diode.IPAddress{
			Address: StringPtr(""),
		}, nil
	case "interface":
		return &diode.Interface{
			Name: StringPtr("unknown"),
		}, nil
	case "device":
		return &diode.Device{}, nil
	}
	return nil, fmt.Errorf("unimplemented entity type: %s", entityType)
}

// StringPtr is a helper function to create a pointer to a string
func StringPtr(s string) *string {
	return &s
}

// ObjectIDValueMap is a map of ObjectIDs to their values
type ObjectIDValueMap map[string]Value

// EntityType is a type that represents an entity type
type EntityType string

const (
	// DeviceEntityType is the type of the device entity
	DeviceEntityType EntityType = "device"
	// InterfaceEntityType is the type of the interface entity
	InterfaceEntityType EntityType = "interface"
	// IPAddressEntityType is the type of the IP address entity
	IPAddressEntityType EntityType = "ipAddress"
)

// ObjectIDMapper is a struct that maps ObjectIDs to entities
type ObjectIDMapper struct {
	mappingConfig *Config
	logger        *slog.Logger
	registry      *EntityRegistry
	defaults      *config.Defaults
}

// Entry is a struct that contains a mapping entry
type Entry struct {
	OID            string
	Entity         string
	Field          string
	MappingEntries []Entry
	Mapper         orbToEntityMapper
	IdentifierSize int
	Relationship   config.Relationship
}

// MapToEntity maps a value to an entity
func (m *Entry) MapToEntity(pdus map[ObjectIDIndex]*ObjectIDValue, entityRegistry *EntityRegistry, defaults *config.Defaults, logger *slog.Logger) diode.Entity {
	logger.Debug("Mapping value to entity", "entity", m.Entity, "value", pdus)

	if m.Mapper == nil {
		logger.Warn("No mapper found for entity. Ignoring.", "entity", m.Entity)
		return nil
	}
	entity := m.Mapper.Map(pdus, m, entityRegistry, defaults)
	logger.Debug("Entity returned from mapper", "entity", entity)
	if entity == nil {
		logger.Warn("No entity returned from mapper. Ignoring.", "entity", m.Entity)
		return nil
	}
	return entity
}

// Config is a struct that contains a mapping of ObjectIDs to Entries
type Config struct {
	mapping map[string]*Entry
}

// NewConfig creates a new Config
func NewConfig(mappings []config.MappingEntry, logger *slog.Logger, manufacturers data.ManufacturerRetriever,
	deviceLookup data.DeviceRetriever, defaults *config.Defaults,
) (*Config, error) {
	// Create InterfaceMapper with pattern support
	var interfacePatterns []config.InterfacePattern
	if defaults != nil {
		interfacePatterns = defaults.InterfacePatterns
	}

	interfaceMapper, err := NewInterfaceMapper(logger, interfacePatterns)
	if err != nil {
		return nil, fmt.Errorf("failed to create interface mapper: %w", err)
	}

	entityMappers := map[string]orbToEntityMapper{
		"ipAddress": &IPAddressMapper{
			logger: logger,
		},
		"interface": interfaceMapper,
		"device": &DeviceMapper{
			logger:        logger,
			manufacturers: manufacturers,
			deviceLookup:  deviceLookup,
		},
	}
	mapping := make(map[string]*Entry)
	for _, m := range mappings {
		logger.Debug("Adding mapping", "oid", m.OID, "entity", m.Entity, "field", m.Field, "relationship", m.Relationship)
		Entry := newMappingEntry(m, logger, entityMappers)
		if Entry == nil {
			continue
		}
		mapping[m.OID] = Entry
	}
	return &Config{
		mapping: mapping,
	}, nil
}

// NewObjectIDMapper creates a new ObjectIDMapper
func NewObjectIDMapper(mappingConfig *Config, logger *slog.Logger, defaults *config.Defaults) *ObjectIDMapper {
	return &ObjectIDMapper{
		mappingConfig: mappingConfig,
		logger:        logger,
		registry:      NewEntityRegistry(logger),
		defaults:      defaults,
	}
}

type orbToEntityMapper interface {
	Map(pdus map[ObjectIDIndex]*ObjectIDValue, Entry *Entry, entityRegistry *EntityRegistry, defaults *config.Defaults) diode.Entity
}

func getIndex(values map[ObjectIDIndex]*ObjectIDValue) ObjectIDIndex {
	for _, pdu := range values {
		return pdu.Index
	}
	return ""
}

func newMappingEntry(m config.MappingEntry, logger *slog.Logger, entityMappers map[string]orbToEntityMapper) *Entry {
	mapper := entityMappers[m.Entity]
	if mapper == nil {
		logger.Warn("No mapper found for entity. Ignoring.", "entity", m.Entity)
		return nil
	}
	return &Entry{
		OID:            m.OID,
		Entity:         m.Entity,
		Field:          m.Field,
		Mapper:         mapper,
		IdentifierSize: m.IdentifierSize,
		MappingEntries: newChildMappingEntries(m.MappingEntries, logger, m.IdentifierSize),
		Relationship:   m.Relationship,
	}
}

func newChildMappingEntries(configMappingEntries []config.MappingEntry, logger *slog.Logger, parentIdentifierSize int) []Entry {
	childMappingEntries := make([]Entry, 0, len(configMappingEntries))
	for _, m := range configMappingEntries {
		logger.Debug("Adding child mapping entry", "oid", m.OID, "entity", m.Entity, "field", m.Field, "relationship", m.Relationship)

		// Use child's IdentifierSize if specified, otherwise inherit from parent
		identifierSize := m.IdentifierSize
		if identifierSize == 0 {
			identifierSize = parentIdentifierSize
		}

		child := &Entry{
			OID:            m.OID,
			Entity:         m.Entity,
			Field:          m.Field,
			IdentifierSize: identifierSize,
			MappingEntries: newChildMappingEntries(m.MappingEntries, logger, identifierSize),
			Relationship:   m.Relationship,
		}
		childMappingEntries = append(childMappingEntries, *child)
	}
	return childMappingEntries
}

// ObjectIDIndex is a type that represents an ObjectID index
type ObjectIDIndex string

// HasParent returns true if the ObjectIDIndex has a parent
func (o *ObjectIDIndex) HasParent(parent string) bool {
	child := string(*o)
	parentParts := strings.Split(parent, ".")
	childParts := strings.Split(child, ".")

	if len(parentParts) > len(childParts) {
		return false
	}

	for i := 0; i < len(parentParts); i++ {
		if parentParts[i] != childParts[i] {
			return false // Mismatch found
		}
	}

	return true
}

// ObjectIDIndexDetails is a struct that contains an index and a map of values
type ObjectIDIndexDetails struct {
	Index  string
	Values map[ObjectIDIndex]*ObjectIDValue
}

// ObjectIDValue represents a value associated with an ObjectID
type ObjectIDValue struct {
	OID    string
	Index  ObjectIDIndex
	Parent string
	Value  string
	Type   Asn1BER
}

// NewObjectIDIndexDetails creates a new ObjectIDIndexDetails
func NewObjectIDIndexDetails(index string) *ObjectIDIndexDetails {
	return &ObjectIDIndexDetails{
		Index:  index,
		Values: make(map[ObjectIDIndex]*ObjectIDValue),
	}
}

// MapObjectIDsToEntity maps ObjectIDs to entities
func (m *ObjectIDMapper) MapObjectIDsToEntity(objectIDs ObjectIDValueMap) []diode.Entity {
	objectIDIndexMap := m.groupByObjectIDIndex(objectIDs)
	uniqueEntities := make(map[diode.Entity]bool)
	for index, value := range objectIDIndexMap {
		m.logger.Debug("Mapping objectIDIndex", "objectIDIndex", index, "values", value.Values)
		entry, err := m.mappingConfig.getMappingEntry(value.Index)
		if err != nil {
			m.logger.Warn("Error finding mapping entry", "error", err, "objectID", value.Index)
			continue
		}
		newEntity := entry.MapToEntity(value.Values, m.registry, m.defaults, m.logger)
		uniqueEntities[newEntity] = true
	}

	currentDevice := m.registry.GetOrCreateEntity(DeviceEntityType, CurrentDeviceIndex).(*diode.Device)

	assignedInterfaceIndices := m.getAssignedInterfaces(uniqueEntities)

	// Build final entity list, excluding assigned interfaces to sending duplicates for ingestion
	entities := make([]diode.Entity, 0, len(uniqueEntities))
	for entity := range uniqueEntities {
		if diodeInterface, ok := entity.(*diode.Interface); ok {
			isAssigned := false
			if assignedInterfaceIndices[diodeInterface] {
				isAssigned = true
			}
			diodeInterface.Device = currentDevice
			if !isAssigned {
				entities = append(entities, entity)
			}
		} else {
			entities = append(entities, entity)
		}
	}
	return entities
}

func (*ObjectIDMapper) getAssignedInterfaces(uniqueEntities map[diode.Entity]bool) map[diode.Entity]bool {
	assignedInterfaceIndices := make(map[diode.Entity]bool)
	for entity := range uniqueEntities {
		if ipAddress, ok := entity.(*diode.IPAddress); ok {
			if ipAddress.AssignedObject != nil {
				if assignedInterface, ok := ipAddress.AssignedObject.(*diode.Interface); ok {
					assignedInterfaceIndices[assignedInterface] = true
				}
			}
		}
	}
	return assignedInterfaceIndices
}

func (m *ObjectIDMapper) groupByObjectIDIndex(objectIDs ObjectIDValueMap) map[ObjectIDIndex]*ObjectIDIndexDetails {
	objectIDIndexMap := make(map[ObjectIDIndex]*ObjectIDIndexDetails)
	for objectID, value := range objectIDs {
		objectIDValue, err := newObjectIDValue(objectID, value)
		if err != nil {
			m.logger.Warn("Error creating objectIDValue", "error", err, "objectID", objectID)
			continue
		}

		if objectIDIndexMap[objectIDValue.Index] == nil {
			objectIDIndexMap[objectIDValue.Index] = NewObjectIDIndexDetails(objectIDValue.Parent)
		}
		objectIDIndexMap[objectIDValue.Index].Values[ObjectIDIndex(objectID)] = objectIDValue
	}
	return objectIDIndexMap
}

func newObjectIDValue(objectID string, value Value) (*ObjectIDValue, error) {
	parts := strings.Split(objectID, ".")
	if len(parts) <= value.IdentifierSize {
		return nil, fmt.Errorf("invalid ObjectID length for type")
	}
	objectIDValue := ObjectIDValue{
		OID:    objectID,
		Index:  ObjectIDIndex(strings.Join(parts[len(parts)-value.IdentifierSize:], ".")),
		Parent: strings.Join(parts[:len(parts)-value.IdentifierSize], "."),
		Value:  value.Value,
		Type:   value.Type,
	}
	return &objectIDValue, nil
}

// Gets the mapper for the closest parent objectID
func (m *Config) getMappingEntry(objectID string) (*Entry, error) {
	for {
		if value, found := m.mapping[objectID]; found {
			return value, nil
		}
		// Split the key by the last '.'
		lastDotIndex := strings.LastIndex(objectID, ".")
		if lastDotIndex == -1 {
			break
		}
		objectID = objectID[:lastDotIndex]
	}
	return nil, fmt.Errorf("no mapping entry found")
}

// ObjectIDs returns the ObjectIDs that the ObjectIDMapper can map
func (m *Config) ObjectIDs() map[string]int {
	objectIDs := make(map[string]int)
	for _, entry := range m.mapping {
		// If the entry has child mapping entries, add the child OIDs
		if len(entry.MappingEntries) > 0 {
			for _, childEntry := range entry.MappingEntries {
				if childEntry.IdentifierSize == 0 {
					objectIDs[childEntry.OID] = 1
				} else {
					// Use the child's IdentifierSize if it is non-zero; otherwise, use the parent's IdentifierSize.
					objectIDs[childEntry.OID] = childEntry.IdentifierSize
				}
			}
		} else {
			// If no child entries, add the parent OID itself
			if entry.IdentifierSize == 0 {
				objectIDs[entry.OID] = 1
			} else {
				objectIDs[entry.OID] = entry.IdentifierSize
			}
		}
	}
	return objectIDs
}
