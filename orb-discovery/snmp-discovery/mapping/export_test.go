package mapping

import (
	"log/slog"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
)

// HostResolverForTest is the resolver interface re-exported for tests.
type HostResolverForTest = hostResolver

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

// AssignPrimaryIPForTest invokes the unexported primary-IP assignment with
// a synthetic entities set, so tests can construct multi-match scenarios
// that are hard to trigger through the real OID pipeline.
func (m *ObjectIDMapper) AssignPrimaryIPForTest(device *diode.Device, entities map[diode.Entity]bool) {
	m.assignPrimaryIP(device, entities)
}
