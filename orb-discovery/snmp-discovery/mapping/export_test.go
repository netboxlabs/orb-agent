package mapping

import (
	"log/slog"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

// HostResolverForTest is the resolver interface re-exported for tests.
type HostResolverForTest = hostResolver

// OrbToEntityMapper is the mapper interface re-exported for tests.
type OrbToEntityMapper = orbToEntityMapper

// NewMappingEntry is the newMappingEntry constructor re-exported for tests.
func NewMappingEntry(m config.MappingEntry, logger *slog.Logger, entityMappers map[string]OrbToEntityMapper) *Entry {
	return newMappingEntry(m, logger, entityMappers)
}

// NewObjectIDMapperForTest exposes the resolver-injection constructor to
// tests in other files of this package.
func NewObjectIDMapperForTest(mappingConfig *Config, logger *slog.Logger, defaults *config.Defaults, targetHost string, resolver HostResolverForTest) *ObjectIDMapper {
	return newObjectIDMapperWithResolver(mappingConfig, logger, defaults, targetHost, resolver)
}

// CurrentDevice returns the current-device entity held by the mapper's
// registry. Test-only helper so assertions can reach the device even when
// it has no observable emitted reference (e.g. when its only interface was
// excluded).
func (m *ObjectIDMapper) CurrentDevice() *diode.Device {
	entity := m.registry.GetOrCreateEntity(DeviceEntityType, CurrentDeviceIndex)
	if d, ok := entity.(*diode.Device); ok {
		return d
	}
	return nil
}

// AssignPrimaryIPForTest invokes the unexported primary-IP assignment
// with a synthetic entities set, so tests can construct multi-match
// scenarios that are hard to trigger through the real OID pipeline.
// Synthetic Interface entities reachable through the IP entities are
// marked verified so the registry's verified-interface gate accepts
// them without the test having to weave through InterfaceMapper.
func (m *ObjectIDMapper) AssignPrimaryIPForTest(device *diode.Device, entities map[diode.Entity]bool) {
	for entity := range entities {
		if ip, ok := entity.(*diode.IPAddress); ok {
			if iface, ok := ip.AssignedObject.(*diode.Interface); ok {
				m.registry.MarkInterfaceVerified(iface)
			}
		}
	}
	m.assignPrimaryIP(device, entities)
}

// CreateEntity exposes the createEntity function for tests.
var CreateEntity = createEntity

// ConfigEntries exposes the unexported mapping field of Config for tests.
var ConfigEntries = func(c *Config) map[string]*Entry { return c.mapping }
