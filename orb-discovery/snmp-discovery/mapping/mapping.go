package mapping

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"regexp"
	"slices"
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
	ipSource           map[*diode.IPAddress]string
	verifiedInterfaces map[*diode.Interface]struct{}
}

// NewEntityRegistry creates a new EntityRegistry
func NewEntityRegistry(logger *slog.Logger) *EntityRegistry {
	return &EntityRegistry{
		entities:           make(map[EntityType]map[ObjectIDIndex]diode.Entity),
		logger:             logger,
		excludedInterfaces: make(map[string]struct{}),
		ipSource:           make(map[*diode.IPAddress]string),
		verifiedInterfaces: make(map[*diode.Interface]struct{}),
	}
}

// MarkInterfaceVerified records that an Interface has been the subject
// of an InterfaceMapper.Map call — i.e. real interface-related PDUs
// (from ifTable, ifXTable, or any other column wired into the
// interface mapping) populated it during this walk. Used to
// distinguish such interfaces from placeholders fabricated by
// GetOrCreateEntity when ipAddressIfIndex references an ifIndex that
// no interface PDUs ever populated.
//
// Note: an interface marked here may have been observed only via
// ifXTable columns (e.g. ifName) without any ifTable column being
// returned; the guarantee is "the interface mapper saw at least one
// PDU for this entity," not "ifTable was specifically walked."
func (r *EntityRegistry) MarkInterfaceVerified(iface *diode.Interface) {
	if iface == nil {
		return
	}
	if r.verifiedInterfaces == nil {
		r.verifiedInterfaces = make(map[*diode.Interface]struct{})
	}
	r.verifiedInterfaces[iface] = struct{}{}
}

// IsInterfaceVerified reports whether the given Interface was marked
// via MarkInterfaceVerified.
func (r *EntityRegistry) IsInterfaceVerified(iface *diode.Interface) bool {
	if iface == nil {
		return false
	}
	_, ok := r.verifiedInterfaces[iface]
	return ok
}

// MarkIPSource records the source table ("legacy" or "modern") for an
// IP address entity. Used by cross-table dedup to prefer the modern
// (RFC 4293) table over the legacy (RFC 1213) table when both have a
// row for the same address.
func (r *EntityRegistry) MarkIPSource(ip *diode.IPAddress, source string) {
	if r.ipSource == nil {
		r.ipSource = make(map[*diode.IPAddress]string)
	}
	r.ipSource[ip] = source
}

// IPSource returns the source table for an IP address, or "" if unknown.
func (r *EntityRegistry) IPSource(ip *diode.IPAddress) string {
	return r.ipSource[ip]
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

// GetEntity returns the entity for (entityType, index), or nil if absent.
// Differs from GetOrCreateEntity in that it never creates a new entity.
func (r *EntityRegistry) GetEntity(entityType EntityType, index ObjectIDIndex) diode.Entity {
	if r.entities[entityType] == nil {
		return nil
	}
	return r.entities[entityType][index]
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

// DefaultInterfaceName is the placeholder assigned to a freshly created
// Interface entity before any PDU has populated its name. Mapper
// fallback handlers (e.g. ifName → name_alternate) treat this sentinel
// as "not yet populated" so they can overwrite it safely.
const DefaultInterfaceName = "unknown"

func createEntity(entityType EntityType) (diode.Entity, error) {
	switch entityType {
	case "ipAddress":
		return &diode.IPAddress{
			Address: StringPtr(""),
		}, nil
	case "interface":
		return &diode.Interface{
			Name: StringPtr(DefaultInterfaceName),
		}, nil
	case "device":
		return &diode.Device{}, nil
	case "vlan":
		return &diode.VLAN{}, nil
	case "interface_vlan":
		return nil, fmt.Errorf("entity type %q is post-pass only and has no row entity", entityType)
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
	// VLANEntityType is the type of the VLAN entity (Q-BRIDGE-MIB derived).
	VLANEntityType EntityType = "vlan"
	// InterfaceVLANEntityType is a pseudo-entity that flags an OID as
	// belonging to the VlanMapper PostMap pipeline (e.g., Cisco-overlay
	// rows). createEntity returns an error for this type — there is no
	// row-scoped entity to construct.
	InterfaceVLANEntityType EntityType = "interface_vlan"
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
	postPassMappers []postPassMapper
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
	IndexKind      string
	Relationship   config.Relationship
	Vendor         string
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
		// Mappers return nil to intentionally drop a row — RFC 4293
		// filters (non-unicast, tentative, non-active) and invalid
		// CIDR validation are the common cases. These are expected on
		// normal walks, so a warn would create noise. Debug keeps
		// it observable without flooding.
		logger.Debug("entity dropped by mapper", "entity", m.Entity)
		return nil
	}
	return entity
}

// Config is a struct that contains a mapping of ObjectIDs to Entries
type Config struct {
	mapping map[string]*Entry
	// inetAddressEntries is the subset of `mapping` whose IndexKind is
	// "inet_address". Pre-computed so groupByObjectIDIndex can skip the
	// per-PDU getMappingEntry call (an O(depth) prefix walk) when the
	// OID falls outside any inet_address-using table.
	inetAddressEntries map[string]*Entry
	// postPassPrefixes is the pre-computed list of OID prefixes that
	// belong to post-pass-only entity types (vlan, interface_vlan).
	// groupByObjectIDIndex consults this slice via HasPrefix per PDU
	// instead of resolving the parent entry for every walked OID
	// (which would defeat the inet_address fast-path optimization).
	// Each prefix ends with a literal "." so a parent OID does not
	// accidentally match a sibling sharing a numeric prefix.
	postPassPrefixes []string
	postPassMappers  []postPassMapper
	options          config.Options
}

// NewConfig creates a new Config
func NewConfig(mappings []config.MappingEntry, logger *slog.Logger, manufacturers data.ManufacturerRetriever,
	deviceLookup data.DeviceRetriever, defaults *config.Defaults, options config.Options,
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

	vlanMapper := NewVlanMapper(logger, options)
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
		"vlan":           vlanMapper,
		"interface_vlan": vlanMapper,
	}
	postPassMappers := []postPassMapper{vlanMapper}
	// Validate index_kind on every entry (top-level and nested). A typo
	// would otherwise silently fall through to the legacy fixed-size
	// path and could regress modern-only devices to "no IPs discovered"
	// — fail fast at config load instead.
	if err := validateIndexKind(mappings); err != nil {
		return nil, err
	}

	mapping := make(map[string]*Entry)
	inetAddressEntries := make(map[string]*Entry)
	var postPassPrefixes []string
	for _, m := range mappings {
		logger.Debug("adding mapping", "oid", m.OID, "entity", m.Entity, "field", m.Field, "relationship", m.Relationship)
		Entry := newMappingEntry(m, logger, entityMappers)
		if Entry == nil {
			continue
		}
		mapping[m.OID] = Entry
		// inetAddressEntryFor uses these to anchor the column boundary
		// in newObjectIDValueForEntry. Only top-level table entries
		// belong here: the anchor is `<table-OID>` (column sub-OID is
		// the next sub-OID under it). Children inherit IndexKind via
		// newChildMappingEntries; caching them too would let a column
		// OID win the longest-prefix scan and miscompute columnDepth.
		if Entry.IndexKind == "inet_address" {
			inetAddressEntries[m.OID] = Entry
		}
		// Cache top-level OID prefixes for post-pass-only entity types
		// so groupByObjectIDIndex can skip these PDUs without doing a
		// per-PDU getMappingEntry walk. Adding the trailing "." prevents
		// a parent OID from accidentally matching a sibling whose OID
		// starts with the same numeric prefix.
		if Entry.Entity == string(VLANEntityType) || Entry.Entity == string(InterfaceVLANEntityType) {
			postPassPrefixes = append(postPassPrefixes, m.OID+".")
		}
	}
	return &Config{
		mapping:            mapping,
		inetAddressEntries: inetAddressEntries,
		postPassPrefixes:   postPassPrefixes,
		postPassMappers:    postPassMappers,
		options:            options,
	}, nil
}

// validIndexKinds enumerates the values index_kind may take. An empty
// string keeps the historical fixed-size behavior. Anything else must
// match exactly — typos like "inetaddress" or "InetAddress" are
// rejected so misconfigurations surface immediately.
var validIndexKinds = map[string]struct{}{
	"":             {},
	"fixed":        {},
	"inet_address": {},
}

// validateIndexKind walks every entry (top-level and nested) and
// rejects unknown index_kind values. It also enforces that
// index_kind is declared ONLY on a top-level table entry: the
// fast-path cache keys on top-level OIDs, and a child-only
// declaration would pass YAML loading but silently fall through to
// fixed-size parsing at the cache layer (re-triggering the
// "modern-only device, no IPs" regression). Children inherit
// IndexKind by leaving the field empty.
func validateIndexKind(entries []config.MappingEntry) error {
	return validateIndexKindWithParent(entries, "", true)
}

func validateIndexKindWithParent(entries []config.MappingEntry, parentKind string, isTopLevel bool) error {
	for _, m := range entries {
		if _, ok := validIndexKinds[m.IndexKind]; !ok {
			return fmt.Errorf("invalid index_kind %q on mapping entry %q (allowed: \"\", \"fixed\", \"inet_address\")", m.IndexKind, m.OID)
		}
		if !isTopLevel && m.IndexKind != "" {
			// Child explicitly setting index_kind is rejected even
			// when it matches the parent: it adds noise to the YAML
			// without changing semantics, and a divergent value
			// would silently misbehave (the cache only sees
			// top-level entries).
			return fmt.Errorf("index_kind must be declared only on the top-level table entry; child %q sets it explicitly (parent's effective kind is %q)", m.OID, parentKind)
		}
		// inet_address requires the top-level OID to be a table-row
		// prefix with at least one child column underneath it: the
		// parser builds full row OIDs as `<entry.OID>.<column>.<index>`.
		// A scalar or childless entry would pass every other check
		// here and then silently skip all rows in
		// newObjectIDValueForEntry as malformed.
		if isTopLevel && m.IndexKind == "inet_address" && len(m.MappingEntries) == 0 {
			return fmt.Errorf("index_kind \"inet_address\" requires the top-level entry %q to have at least one child mapping_entry (column OID); a scalar/childless entry would skip every row as malformed", m.OID)
		}
		effective := m.IndexKind
		if effective == "" {
			effective = parentKind
		}
		if err := validateIndexKindWithParent(m.MappingEntries, effective, false); err != nil {
			return err
		}
	}
	return nil
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
		postPassMappers: mappingConfig.postPassMappers,
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

// postPassMapper is the optional second-pass interface implemented by
// mappers that need full host context (every Map() call already complete)
// before they can do their work — typically because they cross-reference
// entities the per-row Map pipeline produces.
//
// PostMap runs once per host, after every registered mapper's Map has been
// called for every row, and after the standard dedup/exclusion sweep
// inside MapObjectIDsToEntity. It can both mutate registry-resident
// entities in place AND return new entities to append to the host output.
//
// Ordering: post-pass mappers run in the order they were registered in
// ObjectIDMapper.postPassMappers (see post_pass_test.go).
type postPassMapper interface {
	PostMap(allObjectIDs ObjectIDValueMap, entityRegistry *EntityRegistry, defaults *config.Defaults) []diode.Entity
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
		IndexKind:      m.IndexKind,
		MappingEntries: newChildMappingEntries(m.MappingEntries, logger, m.IdentifierSize, m.IndexKind),
		Relationship:   m.Relationship,
		Vendor:         m.Vendor,
	}
}

func newChildMappingEntries(configMappingEntries []config.MappingEntry, logger *slog.Logger, parentIdentifierSize int, parentIndexKind string) []Entry {
	childMappingEntries := make([]Entry, 0, len(configMappingEntries))
	for _, m := range configMappingEntries {
		logger.Debug("adding child mapping entry", "oid", m.OID, "entity", m.Entity, "field", m.Field, "relationship", m.Relationship)

		// Use child's IdentifierSize if specified, otherwise inherit from parent
		identifierSize := m.IdentifierSize
		if identifierSize == 0 {
			identifierSize = parentIdentifierSize
		}
		indexKind := m.IndexKind
		if indexKind == "" {
			indexKind = parentIndexKind
		}

		child := &Entry{
			OID:            m.OID,
			Entity:         m.Entity,
			Field:          m.Field,
			IdentifierSize: identifierSize,
			IndexKind:      indexKind,
			MappingEntries: newChildMappingEntries(m.MappingEntries, logger, identifierSize, indexKind),
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
	sortedIndexes := make([]ObjectIDIndex, 0, len(objectIDIndexMap))
	for index := range objectIDIndexMap {
		sortedIndexes = append(sortedIndexes, index)
	}
	slices.SortFunc(sortedIndexes, compareOIDsNumerically)
	for _, index := range sortedIndexes {
		value := objectIDIndexMap[index]
		m.logger.Debug("mapping object ID index", "object_id_index", index, "values", value.Values)
		entry, err := m.resolveMappingEntry(value)
		if err != nil {
			m.logger.Warn("error finding mapping entry", "error", err, "object_id", value.Index)
			continue
		}
		newEntity := entry.MapToEntity(value.Values, m.registry, m.defaults, m.logger)
		if newEntity != nil {
			uniqueEntities[newEntity] = true
		}
	}

	// Dedup must run BEFORE filterExcludedEntities. Otherwise:
	// legacy row (assigned to excluded interface) + modern row
	// (missing ipAddressIfIndex) would have the legacy row removed
	// by exclusion first, leaving only the unassigned modern
	// duplicate. Dedup with assigned-wins consolidates to the
	// legacy row so the subsequent exclusion sweep can drop the
	// IP entirely.
	m.dedupIPAddresses(uniqueEntities)
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

	// Phase 2: PostMap pass. Mappers that need cross-row / cross-mapper
	// context (e.g., VlanMapper which must see all *diode.Interface
	// instances before it can emit VLAN refs) run here. Order is
	// registration order; new mappers append to the slice.
	for _, ppm := range m.postPassMappers {
		extra := ppm.PostMap(objectIDs, m.registry, m.defaults)
		entities = append(entities, extra...)
	}

	return entities
}

// assignPrimaryIP points currentDevice.PrimaryIp4 / PrimaryIp6 at
// surviving IPAddress entities whose address matches the SNMP target
// host. The two families are matched independently: a missing v4 hit
// does not block a v6 assignment and vice-versa. No-op when the target
// resolves to no IPs of either family or when no surviving IPAddress
// entity matches.
func (m *ObjectIDMapper) assignPrimaryIP(device *diode.Device, entities map[diode.Entity]bool) {
	if m.targetHost == "" {
		return
	}

	v4Cands, v6Cands := m.resolveTargetIPs()

	if len(v4Cands) > 0 {
		if hit := pickPrimaryIPHit(m.logger, m.registry, m.targetHost, entities, v4Cands, false); hit != nil {
			// Break the reference cycle before attaching. See
			// detachForPrimaryIP doc.
			device.PrimaryIp4 = detachForPrimaryIP(hit, device)
		}
	} else {
		m.logger.Debug("no IPv4 candidates for primary IP assignment", "target", m.targetHost)
	}

	if len(v6Cands) > 0 {
		if hit := pickPrimaryIPHit(m.logger, m.registry, m.targetHost, entities, v6Cands, true); hit != nil {
			device.PrimaryIp6 = detachForPrimaryIP6(hit, device)
		}
	} else {
		m.logger.Debug("no IPv6 candidates for primary IP assignment", "target", m.targetHost)
	}
}

// pickPrimaryIPHit filters `entities` to IP addresses of the requested
// family, intersects them with `candidates`, and returns the
// deterministically-chosen winner (or nil).
//
// Family detection uses the textual address form rather than
// net.IP.To4(): an IPv4-mapped IPv6 address like ::ffff:10.0.0.1 has
// To4() != nil and would otherwise be silently reclassified as IPv4,
// despite being encoded as RFC 4001 addrType=2 in ipAddressTable.
// Canonicalization goes through netip.ParseAddr which preserves the
// mapped form on String(), keeping the v4/v6 distinction intact for the
// candidate comparison too.
func pickPrimaryIPHit(logger *slog.Logger, registry *EntityRegistry, target string, entities map[diode.Entity]bool, candidates []string, wantV6 bool) *diode.IPAddress {
	canonCands := make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		addr, err := netip.ParseAddr(c)
		if err != nil {
			continue
		}
		canonCands[addr.String()] = struct{}{}
	}
	if len(canonCands) == 0 {
		return nil
	}

	type hit struct {
		key, content string
		ip           *diode.IPAddress
	}
	var hits []hit
	for entity := range entities {
		ip, ok := entity.(*diode.IPAddress)
		if !ok || ip.Address == nil {
			continue
		}
		// Enforce the "verified interface IP" guarantee: only accept
		// addresses that were discovered on an interface during the
		// walk. assignedObject creates a placeholder Interface with
		// Name=DefaultInterfaceName whenever the row's ifIndex was
		// referenced but the corresponding ifTable row was never
		// walked; treating that placeholder as "verified" would
		// point primary IP at an interface we didn't actually
		// discover.
		if !registry.hasVerifiedInterface(ip) {
			continue
		}
		stripped := stripPrefix(*ip.Address)
		// Detect family from the address text — a colon means IPv6,
		// even for IPv4-mapped form (::ffff:a.b.c.d).
		isV6 := strings.Contains(stripped, ":")
		if isV6 != wantV6 {
			continue
		}
		addr, err := netip.ParseAddr(stripped)
		if err != nil {
			continue
		}
		if _, ok := canonCands[addr.String()]; !ok {
			continue
		}
		hits = append(hits, hit{
			key:     primaryIPSortKey(ip),
			content: primaryIPContentKey(ip),
			ip:      ip,
		})
	}
	if len(hits) == 0 {
		family := "v4"
		if wantV6 {
			family = "v6"
		}
		logger.Debug("no matching IP for primary-IP assignment", "target", target, "family", family)
		return nil
	}
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
		family := "v4"
		if wantV6 {
			family = "v6"
		}
		logger.Warn("multiple IP candidates for primary IP assignment; picking deterministic first",
			"target", target, "family", family, "candidates", all)
	}
	return hits[0].ip
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
			// Clear BOTH primary-IP fields on the embedded device
			// copy. Clearing only PrimaryIp4 here would still embed
			// the (already-set) PrimaryIp6 sub-graph, bloating the
			// payload and re-introducing cycle risk if the v6 pass
			// runs first or call order changes. The standalone
			// emitted entities keep their full graph; only the
			// snapshot is pruned.
			deviceCopy.PrimaryIp4 = nil
			deviceCopy.PrimaryIp6 = nil
			ifaceCopy.Device = &deviceCopy
		}
		// Prune relationship pointers that can transitively reach a
		// Device with PrimaryIp4/PrimaryIp6 set. See the function doc.
		ifaceCopy.Parent = nil
		ifaceCopy.Bridge = nil
		ifaceCopy.Lag = nil
		ifaceCopy.Module = nil
		snapshot.AssignedObject = &ifaceCopy
	}
	return &snapshot
}

// detachForPrimaryIP6 mirrors detachForPrimaryIP for IPv6: returns a
// shallow copy suitable to attach as Device.PrimaryIp6 without
// introducing a reference cycle. Both PrimaryIp4 and PrimaryIp6 are
// cleared on the embedded device copy so the snapshot is independent
// of evaluation order between the v4 and v6 passes.
func detachForPrimaryIP6(ip *diode.IPAddress, owner *diode.Device) *diode.IPAddress {
	if ip == nil {
		return nil
	}
	snapshot := *ip
	if iface, ok := snapshot.AssignedObject.(*diode.Interface); ok && iface != nil {
		ifaceCopy := *iface
		if owner != nil {
			deviceCopy := *owner
			deviceCopy.PrimaryIp4 = nil
			deviceCopy.PrimaryIp6 = nil
			ifaceCopy.Device = &deviceCopy
		}
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

// resolveTargetIPs returns the IPv4 and IPv6 candidate addresses for the
// current SNMP target. Literal IPs populate the matching family slice;
// hostname targets are resolved via DNS (2s timeout) and split by
// family. Empty slices are returned on lookup failure.
//
// Family detection uses the textual form: any address containing a
// colon is IPv6, even IPv4-mapped IPv6 literals like "::ffff:10.0.0.1".
// This matches the way ipAddressTable rows preserve the mapped form,
// so a target literal of "::ffff:10.0.0.1" lines up against an IP
// entity emitted as "::ffff:10.0.0.1/N" rather than being collapsed
// to v4 here and missing the v6 entity in pickPrimaryIPHit.
func (m *ObjectIDMapper) resolveTargetIPs() (v4, v6 []string) {
	classifyLiteral := func(s string) (canonical string, isV6 bool, ok bool) {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return "", false, false
		}
		// netip preserves the textual form: an IPv4-mapped IPv6
		// literal stays Is6() and Is4In6(); only a plain IPv4 literal
		// is purely Is4().
		return addr.String(), addr.Is6(), true
	}
	if canonical, isV6, ok := classifyLiteral(m.targetHost); ok {
		if isV6 {
			return nil, []string{canonical}
		}
		return []string{canonical}, nil
	}
	if m.resolver == nil {
		return nil, nil
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
		return nil, nil
	}
	for _, a := range addrs {
		canonical, isV6, ok := classifyLiteral(a)
		if !ok {
			continue
		}
		if isV6 {
			v6 = append(v6, canonical)
			continue
		}
		v4 = append(v4, canonical)
	}
	return v4, v6
}

// stripPrefix removes a "/prefix" suffix from an IP/CIDR string.
func stripPrefix(addr string) string {
	if i := strings.IndexByte(addr, '/'); i >= 0 {
		return addr[:i]
	}
	return addr
}

// hasVerifiedInterface reports whether the IPAddress entity is bound
// to an interface that was actually discovered during the walk (as
// opposed to the placeholder Interface that GetOrCreateEntity
// fabricates whenever ipAddressIfIndex references an ifIndex whose
// ifTable row never came back).
//
// The signal is the registry's verified set, populated by
// InterfaceMapper.Map. Checking only Name != DefaultInterfaceName
// would also reject legitimately-walked interfaces whose ifDescr and
// ifName happened to be empty (the existing
// "both name sources empty leaves default unknown" path in
// InterfaceMapper); the registry-backed check accepts those because
// the Interface DID receive a Map() call.
func (r *EntityRegistry) hasVerifiedInterface(ip *diode.IPAddress) bool {
	if ip == nil {
		return false
	}
	iface, ok := ip.AssignedObject.(*diode.Interface)
	if !ok || iface == nil {
		return false
	}
	return r.IsInterfaceVerified(iface)
}

// dedupIPAddresses resolves cross-table overlap for *diode.IPAddress
// entities that share the same canonical address (prefix-stripped).
// When both a legacy (ipAddrTable) and modern (ipAddressTable) entry
// exist for the same address, the modern entry wins by default — it
// carries the authoritative RFC 4293 metadata and is IPv6-capable.
//
// The interface binding (AssignedObject) takes priority over source:
// if the modern row is missing AssignedObject (e.g. an ACL hid
// ipAddressIfIndex during the walk, or the row was a partial response)
// but the legacy row carries one, we keep the legacy row instead.
// Otherwise pickPrimaryIPHit (which requires an Interface assignment)
// would drop both candidates and primary-IP selection would regress.
//
// Same-source duplicates are not collapsed here; the upstream grouping
// prevents them within a single table.
func (m *ObjectIDMapper) dedupIPAddresses(entities map[diode.Entity]bool) {
	type bucket struct {
		modern *diode.IPAddress
		legacy *diode.IPAddress
	}
	groups := make(map[string]*bucket)
	for entity := range entities {
		ip, ok := entity.(*diode.IPAddress)
		if !ok || ip.Address == nil {
			continue
		}
		key := stripPrefix(*ip.Address)
		if groups[key] == nil {
			groups[key] = &bucket{}
		}
		switch m.registry.IPSource(ip) {
		case "modern":
			groups[key].modern = ip
		default:
			groups[key].legacy = ip
		}
	}
	hasAssignedInterface := m.registry.hasVerifiedInterface
	for _, b := range groups {
		if b.modern == nil || b.legacy == nil {
			continue
		}
		// Prefer the entry with an interface binding when only one of
		// them has it; otherwise default to modern.
		modernAssigned := hasAssignedInterface(b.modern)
		legacyAssigned := hasAssignedInterface(b.legacy)
		drop := b.legacy
		kept := "modern"
		if !modernAssigned && legacyAssigned {
			drop = b.modern
			kept = "legacy"
		}
		// entities is keyed by the entity pointer itself; drop is that
		// pointer, so delete directly without a second scan.
		delete(entities, drop)
		m.logger.Debug("deduped overlapping ipAddress",
			"address", *drop.Address, "kept", kept)
	}
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

// resolveMappingEntry returns the top-level mapping Entry for a group of
// PDUs sharing an ObjectIDIndex. groupByObjectIDIndex captures only the
// Parent OID of the FIRST PDU iterated per index; when that parent's
// subtree has no registered top-level entry (e.g. ifXTable-only OIDs
// like .1.3.6.1.2.1.31.1.1.1.* are registered as CHILDREN of the
// interface entry .1.3.6.1.2.1.2.2.1, not as top-level parents
// themselves), getMappingEntry on it fails. Go map iteration is
// randomised, so relying on whichever Parent landed first is
// nondeterministic. Fall back to trying each PDU's Parent until one
// resolves.
func (m *ObjectIDMapper) resolveMappingEntry(details *ObjectIDIndexDetails) (*Entry, error) {
	entry, err := m.mappingConfig.getMappingEntry(details.Index)
	if err == nil {
		return entry, nil
	}
	for _, pdu := range details.Values {
		if pdu.Parent == details.Index {
			continue
		}
		if e, e2 := m.mappingConfig.getMappingEntry(pdu.Parent); e2 == nil {
			return e, nil
		}
	}
	return nil, err
}

func (m *ObjectIDMapper) groupByObjectIDIndex(objectIDs ObjectIDValueMap) map[ObjectIDIndex]*ObjectIDIndexDetails {
	objectIDIndexMap := make(map[ObjectIDIndex]*ObjectIDIndexDetails)
	for objectID, value := range objectIDs {
		// Skip PDUs that belong to a post-pass-only entity (vlan,
		// interface_vlan). Their entries are walked but not row-mapped:
		// VlanMapper.PostMap reads directly from the full
		// ObjectIDValueMap and consumes them itself.
		//
		// Without this skip, a VLAN VID and an ifIndex with the same
		// numeric value (e.g., VID 10 + GigabitEthernet0/10 → ifIndex 10)
		// would collide in this index-keyed map, and Go map iteration
		// would nondeterministically pick one parent's entry to dispatch,
		// silently dropping the other table's data.
		//
		// Uses the pre-computed postPassPrefixes slice — typically 5-7
		// short prefixes — so this stays O(k) per PDU and preserves
		// the inet_address fast-path below (no getMappingEntry call).
		if m.mappingConfig.isPostPassOIDPrefix(objectID) {
			continue
		}
		// Fast path: only inet_address-indexed tables need an Entry to
		// switch on IndexKind during parsing. The legacy fixed-size
		// path uses value.IdentifierSize and ignores entry. Skipping
		// the per-PDU getMappingEntry call (an O(depth) prefix walk)
		// avoids a noticeable CPU hit on large walks where 99% of PDUs
		// belong to fixed-index tables.
		entry := m.mappingConfig.inetAddressEntryFor(objectID)
		objectIDValue, err := newObjectIDValueForEntry(objectID, value, entry)
		if err != nil {
			// errMalformedInetAddress covers the expected skip cases —
			// scoped IPv6 (ipv4z/ipv6z), dns-form rows, and otherwise
			// malformed inet_address indices. Anything else (e.g., a
			// legacy fixed-index parse failure from an unexpected
			// IdentifierSize / OID-depth mismatch) likely indicates a
			// real walk or config problem and should remain visible.
			if errors.Is(err, errMalformedInetAddress) {
				m.logger.Debug("skipping inet_address row with unparseable index", "object_id", objectID, "error", err)
			} else {
				m.logger.Warn("error creating object ID value", "object_id", objectID, "error", err)
			}
			continue
		}

		if objectIDIndexMap[objectIDValue.Index] == nil {
			objectIDIndexMap[objectIDValue.Index] = NewObjectIDIndexDetails(objectIDValue.Parent)
		}
		objectIDIndexMap[objectIDValue.Index].Values[ObjectIDIndex(objectID)] = objectIDValue
	}
	return objectIDIndexMap
}

// isPostPassOIDPrefix reports whether the given OID belongs to an
// entity type that is consumed exclusively by a postPassMapper (today:
// vlan and interface_vlan, both routed through VlanMapper).
//
// Uses the pre-computed postPassPrefixes slice (populated in NewConfig)
// instead of resolving the parent entry via getMappingEntry, which
// would be an O(depth) prefix walk per PDU on the hot path. Today the
// slice has ~5-7 short prefixes, so the linear scan stays cheaper than
// a single map lookup against the full mapping. Nil receiver / empty
// slice short-circuits to false.
func (m *Config) isPostPassOIDPrefix(objectID string) bool {
	if m == nil || len(m.postPassPrefixes) == 0 {
		return false
	}
	for _, p := range m.postPassPrefixes {
		if strings.HasPrefix(objectID, p) {
			return true
		}
	}
	return false
}

// newObjectIDValueForEntry parses an OID and its value into an ObjectIDValue.
// When entry.IndexKind == "inet_address", the trailing sub-OIDs are decoded
// per RFC 4001 (variable length); otherwise the legacy fixed-size slicing
// applies, identical to historical behavior.
//
// IMPORTANT: index_kind="inet_address" only handles tables whose row
// index is a *pure* InetAddress: the suffix immediately after the
// column sub-OID must be exactly <addrType>.<addrLen>.<addrBytes...>.
// Tables with composite indices that include other components before
// or after the InetAddress (e.g. ifIndex + InetAddress, or
// InetAddress + something) will have all rows skipped as malformed.
// Today this knob is wired up only for ipAddressTable, which has a
// pure InetAddress index. Reusing it for a composite-index table
// requires extending the parser; reviewers and contributors should
// validate the table shape before adding new entries.
//
// For inet_address entries, the column boundary is computed from
// entry.OID rather than guessed from the suffix length. Suffix-based
// guessing is unsound: an IPv6 row whose final 6 sub-OIDs happen to
// look like a valid IPv4 InetAddress (`1.4.x.x.x.x`) would be silently
// misclassified as IPv4. Using the entry OID's depth as the anchor
// removes the ambiguity.
func newObjectIDValueForEntry(objectID string, value Value, entry *Entry) (*ObjectIDValue, error) {
	parts := strings.Split(objectID, ".")
	if entry != nil && entry.IndexKind == "inet_address" {
		entryParts := strings.Split(entry.OID, ".")
		// Resolved entry's OID is the table-row prefix
		// (e.g. ".1.3.6.1.2.1.4.34.1"). The column sub-OID immediately
		// follows, then the InetAddress index.
		columnDepth := len(entryParts) + 1
		if len(parts) <= columnDepth {
			return nil, errMalformedInetAddress
		}
		suffix := parts[columnDepth:]
		canonical, ok := decodeInetAddressIndex(suffix)
		if !ok {
			return nil, errMalformedInetAddress
		}
		parent := strings.Join(parts[:columnDepth], ".")
		return &ObjectIDValue{
			OID:    objectID,
			Index:  ObjectIDIndex(canonical),
			Parent: parent,
			Value:  value.Value,
			Type:   value.Type,
		}, nil
	}

	if len(parts) <= value.IdentifierSize {
		return nil, fmt.Errorf("invalid ObjectID length for type")
	}
	return &ObjectIDValue{
		OID:    objectID,
		Index:  ObjectIDIndex(strings.Join(parts[len(parts)-value.IdentifierSize:], ".")),
		Parent: strings.Join(parts[:len(parts)-value.IdentifierSize], "."),
		Value:  value.Value,
		Type:   value.Type,
	}, nil
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

// inetAddressEntryFor returns the inet_address-indexed Entry whose OID
// is the longest prefix of the given objectID, or nil when no such
// entry exists. It walks `inetAddressEntries` (which contains ONLY the
// top-level table OIDs, not their column children — caching children
// would let a column OID win the longest-prefix scan and miscompute
// columnDepth in newObjectIDValueForEntry; see NewConfig) instead of
// the full `mapping`, so the common case where no inet_address table
// is configured is a single map-len check. Returning the longest match
// matches getMappingEntry's most-specific-wins semantics, which
// matters when two distinct inet_address tables are registered.
//
// Nil receiver is treated as "no inet_address tables configured" so
// that an ObjectIDMapper constructed without a Config (used in some
// internal tests) doesn't panic on the hot path.
func (m *Config) inetAddressEntryFor(objectID string) *Entry {
	if m == nil || len(m.inetAddressEntries) == 0 {
		return nil
	}
	var best *Entry
	bestLen := -1
	for prefix, entry := range m.inetAddressEntries {
		if objectID != prefix && !strings.HasPrefix(objectID, prefix+".") {
			continue
		}
		if len(prefix) > bestLen {
			best = entry
			bestLen = len(prefix)
		}
	}
	return best
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

// GenericObjectIDs returns the OIDs to walk on every host (entries with
// empty Vendor field). It applies the same child-expansion logic as
// ObjectIDs: when an entry has child MappingEntries, the child OIDs are
// emitted rather than the parent OID.
func (m *Config) GenericObjectIDs() map[string]int {
	return m.objectIDsForVendor("", true)
}

// VendorObjectIDs returns the OIDs to walk for a specific vendor key.
// Returns an empty map when no entries are scoped to the vendor.
func (m *Config) VendorObjectIDs(vendor string) map[string]int {
	if vendor == "" {
		return make(map[string]int)
	}
	return m.objectIDsForVendor(vendor, false)
}

// objectIDsForVendor is the shared implementation behind GenericObjectIDs
// and VendorObjectIDs. When generic==true it selects entries with an empty
// Vendor field; otherwise it selects entries matching the given vendor string.
// Child-expansion follows the same rules as ObjectIDs.
func (m *Config) objectIDsForVendor(vendor string, generic bool) map[string]int {
	out := make(map[string]int)
	for _, entry := range m.mapping {
		if generic {
			if entry.Vendor != "" {
				continue
			}
		} else {
			if entry.Vendor != vendor {
				continue
			}
		}
		if len(entry.MappingEntries) > 0 {
			for _, childEntry := range entry.MappingEntries {
				if childEntry.IdentifierSize == 0 {
					out[childEntry.OID] = 1
				} else {
					out[childEntry.OID] = childEntry.IdentifierSize
				}
			}
		} else {
			if entry.IdentifierSize == 0 {
				out[entry.OID] = 1
			} else {
				out[entry.OID] = entry.IdentifierSize
			}
		}
	}
	return out
}
