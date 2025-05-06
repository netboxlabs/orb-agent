package mapping

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
)

// Value is a struct that contains a value and a type of an SNMP object
type Value struct {
	Value string
	Type  Asn1BER
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

// ObjectIDValueMap is a map of ObjectIDs to their values
type ObjectIDValueMap map[string]Value

// ObjectIDMapper is a struct that maps ObjectIDs to entities
type ObjectIDMapper struct {
	mapping map[string]*mappingEntry
	logger  *slog.Logger
}

type mappingEntry struct {
	OID            string
	Entity         string
	Field          string
	MappingEntries []mappingEntry
	Mapper         orbToEntityMapper
	IdentifierSize int
}

var entityMappers = map[string]orbToEntityMapper{
	"ipAddress": &ipAddressMapper{},
	"interface": &interfaceMapper{},
}

func (m *mappingEntry) MapToEntity(object map[ObjectIDIndex]*ObjectIDValue, logger *slog.Logger) []diode.Entity {
	logger.Debug("Mapping value to entity", "value", object)
	if m.Mapper == nil {
		logger.Warn("No mapper found for entity. Ignoring.", "entity", m.Entity)
		return nil
	}
	entity := m.Mapper.Map(object, m, logger)
	logger.Debug("Entity returned from mapper", "entity", entity)
	if entity == nil {
		logger.Warn("No entity returned from mapper. Ignoring.", "entity", m.Entity)
		return nil
	}
	return []diode.Entity{entity}
}

// NewObjectIDMapper creates a new ObjectIDMapper
func NewObjectIDMapper(mappings []config.MappingEntry, logger *slog.Logger) *ObjectIDMapper {
	mapping := make(map[string]*mappingEntry)
	for _, m := range mappings {
		logger.Debug("Adding mapping", "oid", m.OID, "entity", m.Entity, "field", m.Field)
		mappingEntry := newMappingEntry(m, logger)
		if mappingEntry == nil {
			continue
		}
		mapping[m.OID] = mappingEntry
		logger.Debug("Mapping entry added", "oid", mappingEntry.OID, "entity", mappingEntry.Entity, "field", mappingEntry.Field)
	}
	return &ObjectIDMapper{
		mapping: mapping,
		logger:  logger,
	}
}

type orbToEntityMapper interface {
	Map(values map[ObjectIDIndex]*ObjectIDValue, mappingEntry *mappingEntry, logger *slog.Logger) diode.Entity
}

type ipAddressMapper struct{}

func (m *ipAddressMapper) Map(values map[ObjectIDIndex]*ObjectIDValue, mappingEntry *mappingEntry, logger *slog.Logger) diode.Entity {
	logger.Debug("Mapping values to ipAddress entity", "values", values, "mappingEntry", mappingEntry)
	ipAddress := diode.IPAddress{}

	// for each value in the map, map it to the ip address entity
	for objectID, value := range values {
		for _, propertyMappingEntry := range mappingEntry.MappingEntries {
			if objectID.HasParent(mappingEntry.OID) {
				switch propertyMappingEntry.Field {
				case "address":
					addressCopy := value.Value
					ipAddress.Address = &addressCopy
				default:
					logger.Warn("Unknown field", "field", mappingEntry.Field)
				}
			}
		}
	}
	return &ipAddress
}

type interfaceMapper struct{}

func (m *interfaceMapper) Map(values map[ObjectIDIndex]*ObjectIDValue, mappingEntry *mappingEntry, logger *slog.Logger) diode.Entity {
	logger.Debug("Mapping values to interface entity", "values", values, "mappingEntry", mappingEntry)
	interfaceEntity := diode.Interface{}
	for objectID, value := range values {
		for _, propertyMappingEntry := range mappingEntry.MappingEntries {
			if objectID.HasParent(propertyMappingEntry.OID) {
				logger.Debug("Mapping value to interface entity with mapper", "objectID", objectID, "value", value, "mappingEntry", propertyMappingEntry)
				switch propertyMappingEntry.Field {
				case "name":
					interfaceEntity.Name = &value.Value
				case "speed":
					speed, err := strconv.Atoi(value.Value)
					if err != nil {
						logger.Warn("Error converting speed to int", "error", err, "value", value.Value)
					}
					speed64 := int64(speed)
					interfaceEntity.Speed = &speed64
				case "macAddress":
					interfaceEntity.PrimaryMacAddress = &diode.MACAddress{
						MacAddress: &value.Value,
					}
				case "adminStatus":
					enabled := value.Value == "1"
					interfaceEntity.Enabled = &enabled
				default:
					logger.Warn("Unknown field", "field", propertyMappingEntry.Field)
				}
			}
		}
	}
	return &interfaceEntity
}

func newMappingEntry(m config.MappingEntry, logger *slog.Logger) *mappingEntry {
	mapper := entityMappers[m.Entity]
	if mapper == nil {
		logger.Warn("No mapper found for entity. Ignoring.", "entity", m.Entity)
		return nil
	}
	return &mappingEntry{
		OID:            m.OID,
		Entity:         m.Entity,
		Field:          m.Field,
		Mapper:         mapper,
		IdentifierSize: m.IdentifierSize,
		MappingEntries: newChildMappingEntries(m.MappingEntries, logger),
	}
}

func newChildMappingEntries(configMappingEntries []config.MappingEntry, logger *slog.Logger) []mappingEntry {
	childMappingEntries := make([]mappingEntry, 0, len(configMappingEntries))
	for _, m := range configMappingEntries {
		child := &mappingEntry{
			OID:            m.OID,
			Entity:         m.Entity,
			Field:          m.Field,
			MappingEntries: newChildMappingEntries(m.MappingEntries, logger),
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

// getIDSize returns the number of parts to use as ID based on the value type
func getIDSize(value Value) int {
	if value.Type == IPAddress {
		return 4
	}
	return 1
}

// MapObjectIDsToEntity maps ObjectIDs to entities
func (m *ObjectIDMapper) MapObjectIDsToEntity(objectIDs ObjectIDValueMap) []diode.Entity {
	objectIDIndexMap := m.groupByObjectIDIndex(objectIDs)

	m.logger.Debug("ObjectIDIndexMap", "objectIDIndexMap", objectIDIndexMap)

	entities := make([]diode.Entity, 0, len(objectIDIndexMap))
	for _, value := range objectIDIndexMap {
		mappingEntry, err := m.getMappingEntry(value.Index)
		if err != nil {
			m.logger.Warn("Error finding mapping entry", "error", err, "objectID", value.Index)
			continue
		}
		entities = append(entities, mappingEntry.MapToEntity(value.Values, m.logger)...)
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
	idSize := getIDSize(value)
	if len(parts) <= idSize {
		return nil, fmt.Errorf("invalid ObjectID length for type")
	}
	objectIDValue := ObjectIDValue{
		OID:    objectID,
		Index:  ObjectIDIndex(strings.Join(parts[len(parts)-idSize:], ".")),
		Parent: strings.Join(parts[:len(parts)-idSize], "."),
		Value:  value.Value,
		Type:   value.Type,
	}
	return &objectIDValue, nil
}

// Gets the mapper for the closest parent objectID
func (m *ObjectIDMapper) getMappingEntry(objectID string) (*mappingEntry, error) {
	mappingKeys := make([]string, 0, len(m.mapping))
	for k := range m.mapping {
		mappingKeys = append(mappingKeys, k)
	}
	m.logger.Debug("Getting mapping entry for objectID", "objectID", objectID, "mappingKeys", mappingKeys)

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
func (m *ObjectIDMapper) ObjectIDs() []string {
	objectIDs := make([]string, 0, len(m.mapping))
	for objectID := range m.mapping {
		objectIDs = append(objectIDs, objectID)
	}
	return objectIDs
}
