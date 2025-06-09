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
		return &diode.IPAddress{}, nil
	case "interface":
		return &diode.Interface{
			Name: StringPtr("Unknown"),
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

// ObjectIDMapper is a struct that maps ObjectIDs to entities
type ObjectIDMapper struct {
	mapping  map[string]*Entry
	logger   *slog.Logger
	registry *EntityRegistry
	defaults *config.Defaults
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
func (m *Entry) MapToEntity(pdus map[ObjectIDIndex]*ObjectIDValue, entityRegistry *EntityRegistry, defaults *config.Defaults, logger *slog.Logger) []diode.Entity {
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
	return []diode.Entity{entity}
}

// NewObjectIDMapper creates a new ObjectIDMapper
func NewObjectIDMapper(mappings []config.MappingEntry, logger *slog.Logger, devices data.DeviceDataRetreiver, defaults *config.Defaults) *ObjectIDMapper {
	entityMappers := map[string]orbToEntityMapper{
		"ipAddress": &IPAddressMapper{
			logger: logger,
		},
		"interface": &InterfaceMapper{
			logger: logger,
		},
		"device": &DeviceMapper{
			logger:  logger,
			devices: devices,
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

	return &ObjectIDMapper{
		mapping:  mapping,
		logger:   logger,
		registry: NewEntityRegistry(logger),
		defaults: defaults,
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
		MappingEntries: newChildMappingEntries(m.MappingEntries, logger),
		Relationship:   m.Relationship,
	}
}

func newChildMappingEntries(configMappingEntries []config.MappingEntry, logger *slog.Logger) []Entry {
	childMappingEntries := make([]Entry, 0, len(configMappingEntries))
	for _, m := range configMappingEntries {
		logger.Debug("Adding child mapping entry", "oid", m.OID, "entity", m.Entity, "field", m.Field, "relationship", m.Relationship)
		child := &Entry{
			OID:            m.OID,
			Entity:         m.Entity,
			Field:          m.Field,
			MappingEntries: newChildMappingEntries(m.MappingEntries, logger),
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
	return strings.HasPrefix(string(*o), parent)
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
	entities := make([]diode.Entity, 0, len(objectIDIndexMap))
	for index, value := range objectIDIndexMap {
		m.logger.Debug("Mapping objectIDIndex", "objectIDIndex", index, "values", value.Values)
		Entry, err := m.getMappingEntry(value.Index)
		if err != nil {
			m.logger.Warn("Error finding mapping entry", "error", err, "objectID", value.Index)
			continue
		}
		newEntities := Entry.MapToEntity(value.Values, m.registry, m.defaults, m.logger)
		entities = append(entities, newEntities...)
	}

	var currentDevice *diode.Device
	for _, entity := range entities {
		// check if it's a diode.Device
		if device, ok := entity.(*diode.Device); ok {
			if currentDevice != nil {
				m.logger.Warn("Multiple devices found. Ignoring.", "device", device)
			}
			// check if the device has a name
			currentDevice = device
		}
	}
	if currentDevice == nil {
		m.logger.Warn("No device found.")
	}
	for _, entity := range entities {
		if diodeInterface, ok := entity.(*diode.Interface); ok {
			diodeInterface.Device = currentDevice
		}
	}
	return entities
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
func (m *ObjectIDMapper) getMappingEntry(objectID string) (*Entry, error) {
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
func (m *ObjectIDMapper) ObjectIDs() map[string]int {
	objectIDs := make(map[string]int)
	for objectID := range m.mapping {
		if m.mapping[objectID].IdentifierSize == 0 {
			objectIDs[objectID] = 1
		} else {
			objectIDs[objectID] = m.mapping[objectID].IdentifierSize
		}
	}
	return objectIDs
}
