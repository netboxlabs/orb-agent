package mapping

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

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
	entities           map[EntityType]map[ObjectIDIndex]diode.Entity
	logger             *slog.Logger
	excludedInterfaces map[string]struct{}
}

// NewEntityRegistry creates a new EntityRegistry
func NewEntityRegistry(logger *slog.Logger) *EntityRegistry {
	return &EntityRegistry{
		entities:           make(map[EntityType]map[ObjectIDIndex]diode.Entity),
		logger:             logger,
		excludedInterfaces: make(map[string]struct{}),
	}
}

// ExcludeInterface marks an interface name as excluded so it is skipped during lookups
func (r *EntityRegistry) ExcludeInterface(name string) {
	r.excludedInterfaces[name] = struct{}{}
}

// IsInterfaceExcluded checks whether an interface name is excluded
func (r *EntityRegistry) IsInterfaceExcluded(name string) bool {
	_, excluded := r.excludedInterfaces[name]
	return excluded
}

// GetInterfaceByName searches for an interface entity by its name field
func (r *EntityRegistry) GetInterfaceByName(interfaceName string) *diode.Interface {
	if r.IsInterfaceExcluded(interfaceName) {
		return nil
	}
	if r.entities[InterfaceEntityType] == nil {
		return nil
	}

	// Search through all interface entities to find one with matching name
	for _, entity := range r.entities[InterfaceEntityType] {
		if iface, ok := entity.(*diode.Interface); ok {
			if iface.Name != nil && *iface.Name == interfaceName {
				return iface
			}
		}
	}
	return nil
}

// ResolveSubinterfaceParents resolves parent interface relationships for all subinterfaces
// This must be called after all interfaces have been discovered and mapped
func (r *EntityRegistry) ResolveSubinterfaceParents() {
	if r.entities[InterfaceEntityType] == nil {
		return
	}

	r.logger.Debug("resolving parent interfaces for subinterfaces")
	resolvedCount := 0
	notFoundCount := 0

	// Iterate through all interfaces to find subinterfaces
	for _, entity := range r.entities[InterfaceEntityType] {
		iface, ok := entity.(*diode.Interface)
		if !ok || iface.Name == nil {
			continue
		}

		// Check if this is a subinterface
		parentName := ExtractParentInterfaceName(*iface.Name)
		if parentName == "" {
			continue // Not a subinterface
		}

		// Look up the parent interface by name
		parent := r.GetInterfaceByName(parentName)
		if parent != nil {
			// Set the parent reference
			iface.Parent = &diode.Interface{
				Name:   parent.Name,
				Type:   parent.Type,
				Device: parent.Device,
			}
			r.logger.Debug("resolved parent interface",
				"subinterface", *iface.Name,
				"parent", parentName)
			resolvedCount++
		} else {
			r.logger.Debug("parent interface not found",
				"subinterface", *iface.Name,
				"parent", parentName)
			notFoundCount++
		}
	}

	if resolvedCount > 0 {
		r.logger.Info("resolved subinterface parents",
			"resolved", resolvedCount,
			"not_found", notFoundCount)
	}
}

// GetOrCreateEntity returns an entity from the EntityRegistry or creates a new one if it doesn't exist
func (r *EntityRegistry) GetOrCreateEntity(entityType EntityType, index ObjectIDIndex) diode.Entity {
	r.logger.Debug("getting entity", "entity_type", entityType, "index", index, "from", r.entities)
	if r.entities[entityType] == nil {
		r.entities[entityType] = make(map[ObjectIDIndex]diode.Entity)
	}
	if r.entities[entityType][index] == nil {
		entity, err := createEntity(entityType)
		r.logger.Debug("entity not found, creating", "entity_type", entityType, "index", index, "entity", entity)
		if err != nil {
			r.logger.Warn("error creating entity", "error", err, "entity_type", entityType, "index", index)
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
	mappingConfig   *Config
	logger          *slog.Logger
	registry        *EntityRegistry
	defaults        *config.Defaults
	excludePatterns []*regexp.Regexp
	targetHost      string
	resolver        hostResolver
	ctx             context.Context
}

// SetContext stores the scan's context on the mapper. If set, the primary-IP
// DNS lookup will derive its 2s timeout from this parent context so that a
// cancelled scan also aborts the lookup.
func (m *ObjectIDMapper) SetContext(ctx context.Context) {
	m.ctx = ctx
}

// hostResolver is the minimal DNS lookup surface used by ObjectIDMapper.
// It is satisfied by *net.Resolver (including net.DefaultResolver) and
// overridable in tests.
type hostResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
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
	logger.Debug("mapping value to entity", "entity", m.Entity, "value", pdus)

	if m.Mapper == nil {
		logger.Warn("no mapper found for entity, ignoring", "entity", m.Entity)
		return nil
	}
	entity := m.Mapper.Map(pdus, m, entityRegistry, defaults)
	logger.Debug("entity returned from mapper", "entity", entity)
	if entity == nil {
		logger.Warn("no entity returned from mapper, ignoring", "entity", m.Entity)
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
		logger.Debug("adding mapping", "oid", m.OID, "entity", m.Entity, "field", m.Field, "relationship", m.Relationship)
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

// NewObjectIDMapper creates a new ObjectIDMapper for a given SNMP target host.
func NewObjectIDMapper(mappingConfig *Config, logger *slog.Logger, defaults *config.Defaults, targetHost string) *ObjectIDMapper {
	return newObjectIDMapperWithResolver(mappingConfig, logger, defaults, targetHost, net.DefaultResolver)
}

// newObjectIDMapperWithResolver is the test seam that allows injecting a
// custom DNS resolver. Production code uses NewObjectIDMapper.
func newObjectIDMapperWithResolver(mappingConfig *Config, logger *slog.Logger, defaults *config.Defaults, targetHost string, resolver hostResolver) *ObjectIDMapper {
	return &ObjectIDMapper{
		mappingConfig:   mappingConfig,
		logger:          logger,
		registry:        NewEntityRegistry(logger),
		defaults:        defaults,
		excludePatterns: compileExcludePatterns(defaults, logger),
		targetHost:      targetHost,
		resolver:        resolver,
	}
}

func compileExcludePatterns(defaults *config.Defaults, logger *slog.Logger) []*regexp.Regexp {
	if defaults == nil || len(defaults.InterfaceExcludePatterns) == 0 {
		return nil
	}
	patterns := make([]*regexp.Regexp, 0, len(defaults.InterfaceExcludePatterns))
	for _, p := range defaults.InterfaceExcludePatterns {
		p = strings.TrimSpace(p)
		if p == "" {
			logger.Warn("empty interface exclude pattern, skipping")
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			logger.Warn("invalid interface exclude pattern, skipping", "pattern", p, "error", err)
			continue
		}
		patterns = append(patterns, re)
	}
	return patterns
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
		logger.Warn("no mapper found for entity, ignoring", "entity", m.Entity)
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
		logger.Debug("adding child mapping entry", "oid", m.OID, "entity", m.Entity, "field", m.Field, "relationship", m.Relationship)

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
		m.logger.Debug("mapping object ID index", "object_id_index", index, "values", value.Values)
		entry, err := m.mappingConfig.getMappingEntry(value.Index)
		if err != nil {
			m.logger.Warn("error finding mapping entry", "error", err, "object_id", value.Index)
			continue
		}
		newEntity := entry.MapToEntity(value.Values, m.registry, m.defaults, m.logger)
		if newEntity != nil {
			uniqueEntities[newEntity] = true
		}
	}

	m.filterExcludedEntities(uniqueEntities)

	currentDevice := m.registry.GetOrCreateEntity(DeviceEntityType, CurrentDeviceIndex).(*diode.Device)

	// ResolveSubinterfaceParents must run after filterExcludedEntities: excluded interface
	// names are marked in the registry so GetInterfaceByName returns nil for them,
	// preventing subinterfaces from receiving a parent pointer to an excluded interface.
	m.registry.ResolveSubinterfaceParents()

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
			if diodeInterface.Parent != nil && diodeInterface.Parent.Device == nil {
				diodeInterface.Parent.Device = currentDevice
			}
			if !isAssigned {
				entities = append(entities, entity)
			}
		} else {
			entities = append(entities, entity)
		}
	}

	m.assignPrimaryIP(currentDevice, uniqueEntities)

	return entities
}

// assignPrimaryIP points currentDevice.PrimaryIp4 at the surviving IPAddress
// entity whose address matches the SNMP target host (literal IPv4 or DNS-
// resolved). No-op when the target is not IPv4-addressable, when DNS lookup
// fails, or when no surviving IPAddress entity matches.
func (m *ObjectIDMapper) assignPrimaryIP(device *diode.Device, entities map[diode.Entity]bool) {
	if m.targetHost == "" {
		return
	}

	candidates := m.resolveTargetIPv4s()
	if len(candidates) == 0 {
		m.logger.Debug("no IPv4 candidates for primary IP assignment", "target", m.targetHost)
		return
	}

	type hit struct {
		key     string
		ip      *diode.IPAddress
		content string // stable, data-derived tiebreaker when key collides
	}
	var hits []hit
	for entity := range entities {
		ip, ok := entity.(*diode.IPAddress)
		if !ok || ip.Address == nil {
			continue
		}
		// Enforce the "verified interface IP" guarantee: only accept
		// addresses that were discovered on an interface during the walk.
		if _, assigned := ip.AssignedObject.(*diode.Interface); !assigned {
			continue
		}
		stripped := stripPrefix(*ip.Address)
		for _, cand := range candidates {
			if stripped == cand {
				hits = append(hits, hit{
					key:     primaryIPSortKey(ip),
					ip:      ip,
					content: primaryIPContentKey(ip),
				})
				break
			}
		}
	}

	if len(hits) == 0 {
		m.logger.Debug("no matching IP for primary IP assignment", "target", m.targetHost)
		return
	}

	// Primary sort by composite key; content hash is a data-derived,
	// run-to-run-stable tiebreaker for the rare case of two entries
	// sharing a key.
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].key != hits[j].key {
			return hits[i].key < hits[j].key
		}
		return hits[i].content < hits[j].content
	})

	if len(hits) > 1 {
		all := make([]string, 0, len(hits))
		for _, h := range hits {
			all = append(all, h.key)
		}
		m.logger.Warn("multiple IP candidates for primary IP assignment; picking deterministic first",
			"target", m.targetHost, "candidates", all)
	}

	// Break the reference cycle before attaching. The matched IPAddress is
	// also emitted as a standalone entity whose AssignedObject points at an
	// Interface whose Device points back at the same currentDevice. Sharing
	// that pointer graph into device.PrimaryIp4 would make the diode SDK's
	// proto serializer recurse forever (device -> primary_ip4 -> ip ->
	// interface -> device -> ...). We detach with a shallow snapshot: copy
	// the IPAddress and (if present) the assigned Interface, then replace
	// the interface's Device with a Device copy that has PrimaryIp4 nil.
	// The snapshot is then a tree (no back-edge), and the nested Device
	// still satisfies Diode's validation requirement that an Interface
	// reference a Device. The standalone emitted entities keep their full
	// graph untouched.
	device.PrimaryIp4 = detachForPrimaryIP(hits[0].ip, device)
}

// detachForPrimaryIP returns a shallow copy of the matched IPAddress
// suitable to attach as Device.PrimaryIp4 without introducing a reference
// cycle. The assigned Interface (if any) is copied; its Device pointer is
// replaced with a copy of the owning Device that has PrimaryIp4 cleared,
// and all *Interface / *Module relationship fields (Parent, Bridge, Lag,
// Module) are cleared -- otherwise a subinterface's Parent (or similar
// back-reference) would point at another *diode.Interface whose Device
// still carries PrimaryIp4, reintroducing the cycle. The standalone
// emitted Interface entities keep their full graph; only the snapshot is
// pruned.
func detachForPrimaryIP(ip *diode.IPAddress, owner *diode.Device) *diode.IPAddress {
	if ip == nil {
		return nil
	}
	snapshot := *ip
	if iface, ok := snapshot.AssignedObject.(*diode.Interface); ok && iface != nil {
		ifaceCopy := *iface
		if owner != nil {
			deviceCopy := *owner
			deviceCopy.PrimaryIp4 = nil
			ifaceCopy.Device = &deviceCopy
		}
		// Prune relationship pointers that can transitively reach a
		// Device with PrimaryIp4 set. See the function doc for why.
		ifaceCopy.Parent = nil
		ifaceCopy.Bridge = nil
		ifaceCopy.Lag = nil
		ifaceCopy.Module = nil
		snapshot.AssignedObject = &ifaceCopy
	}
	return &snapshot
}

// primaryIPSortKey returns a stable composite ordering key for an IPAddress
// entity: "<address>|<interface-name>". Deterministic even when two
// IPAddresses share the same stripped address.
func primaryIPSortKey(ip *diode.IPAddress) string {
	addr := ""
	if ip.Address != nil {
		addr = *ip.Address
	}
	ifName := ""
	if iface, ok := ip.AssignedObject.(*diode.Interface); ok && iface != nil && iface.Name != nil {
		ifName = *iface.Name
	}
	return addr + "|" + ifName
}

// primaryIPContentKey returns a run-to-run-stable secondary ordering key
// derived from the IPAddress entity's content. Used as a tiebreaker when
// two entries produce the same primaryIPSortKey. JSON marshalling is
// deterministic for a given struct value (encoding/json sorts map keys,
// and diode.IPAddress has no time.Time or custom MarshalJSON with
// randomness), so the returned string is the same across process
// invocations for the same input. The fallback dereferences scalar
// pointer fields explicitly and never embeds pointer addresses.
//
// If two *distinct* IPAddress entities produce byte-for-byte identical
// content (identical address, description, tags, interface, ...), the
// selection between them is semantically equivalent — the NetBox
// payload for either is the same — so the residual non-determinism in
// that case has no observable effect on downstream data.
func primaryIPContentKey(ip *diode.IPAddress) string {
	if ip == nil {
		return ""
	}
	if b, err := json.Marshal(ip); err == nil {
		return string(b)
	}
	// Fallback for the unlikely case json.Marshal fails (e.g. a custom
	// field that contains a channel or function). Explicit dereferences
	// avoid the process-local pointer addresses that %+v would print.
	// We pull every scalar field that could legitimately distinguish
	// two otherwise-matching IPAddress entities.
	parts := []string{
		derefString(ip.Address),
		derefString(ip.Description),
		derefString(ip.Comments),
		derefString(ip.DnsName),
		derefString(ip.Status),
		derefString(ip.Role),
	}
	if ip.Tenant != nil {
		parts = append(parts, derefString(ip.Tenant.Name))
	}
	if ip.Vrf != nil {
		parts = append(parts, derefString(ip.Vrf.Name))
	}
	if iface, ok := ip.AssignedObject.(*diode.Interface); ok && iface != nil {
		parts = append(parts, derefString(iface.Name))
	}
	for _, tag := range ip.Tags {
		if tag != nil {
			parts = append(parts, derefString(tag.Name))
		}
	}
	return strings.Join(parts, "\x00")
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// resolveTargetIPv4s returns the IPv4 candidate addresses for the current
// SNMP target. If targetHost is an IPv4 literal, the single address is
// returned. Otherwise DNS is consulted with a 2s timeout and IPv4 results
// are returned. Returns an empty slice on any failure.
func (m *ObjectIDMapper) resolveTargetIPv4s() []string {
	if ip := net.ParseIP(m.targetHost); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return []string{v4.String()}
		}
		return nil
	}
	if m.resolver == nil {
		return nil
	}
	parent := m.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	addrs, err := m.resolver.LookupHost(ctx, m.targetHost)
	if err != nil {
		m.logger.Debug("target host DNS lookup failed", "target", m.targetHost, "error", err)
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				out = append(out, v4.String())
			}
		}
	}
	return out
}

// stripPrefix removes a "/prefix" suffix from an IP/CIDR string.
func stripPrefix(addr string) string {
	if i := strings.IndexByte(addr, '/'); i >= 0 {
		return addr[:i]
	}
	return addr
}

func (m *ObjectIDMapper) filterExcludedEntities(entities map[diode.Entity]bool) {
	// Deletion from a map during range is safe in Go: deleted entries are not
	// visited in subsequent iterations.
	if len(m.excludePatterns) == 0 {
		return
	}
	for entity := range entities {
		iface, ok := entity.(*diode.Interface)
		if !ok || iface.Name == nil {
			continue
		}
		for _, pat := range m.excludePatterns {
			if pat.MatchString(*iface.Name) {
				m.registry.ExcludeInterface(*iface.Name)
				delete(entities, entity)
				m.logger.Debug("excluding interface by pattern", "name", *iface.Name)
				break
			}
		}
	}
	for entity := range entities {
		ip, ok := entity.(*diode.IPAddress)
		if !ok || ip.AssignedObject == nil {
			continue
		}
		iface, ok := ip.AssignedObject.(*diode.Interface)
		if !ok || iface.Name == nil {
			continue
		}
		if m.registry.IsInterfaceExcluded(*iface.Name) {
			delete(entities, entity)
			m.logger.Debug("excluding IP for excluded interface", "interface", *iface.Name)
		}
	}
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
			m.logger.Warn("error creating object ID value", "error", err, "object_id", objectID)
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
