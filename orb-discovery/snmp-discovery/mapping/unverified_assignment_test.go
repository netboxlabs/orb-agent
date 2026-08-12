package mapping_test

import (
	"log/slog"
	"os"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/mapping"
)

// TestMapObjectIDsToEntity_UnverifiedInterfaceAssignmentLeavesUnassigned
// reproduces ENGHLP-1566. A legacy ipAddrTable row binds 10.32.136.102 to
// ifIndex 65000, but no ifTable/ifXTable row for 65000 came back during the
// walk. GetOrCreateEntity therefore fabricates a placeholder Interface named
// "unknown" with no device and no type, and it is attached as the address's
// assigned_object. NetBox then rejects the auto-vivified dcim.interface
// (device required, type blank), failing the whole bulk-plan.
//
// The mapper cannot know at row-mapping time whether ifIndex 65000 will be
// walked (ordering), so the guard belongs at finalization, where the registry
// knows the interface was never verified. Desired behaviour mirrors the
// ipAddressIfIndex=0 case: keep the address, but leave it unassigned rather
// than emitting an unusable placeholder.
func TestMapObjectIDsToEntity_UnverifiedInterfaceAssignmentLeavesUnassigned(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mappingEntries := []config.MappingEntry{
		{
			OID:            ".1.3.6.1.2.1.2.2.1",
			Entity:         "interface",
			Field:          "_id",
			IdentifierSize: 1,
			MappingEntries: []config.MappingEntry{
				{OID: ".1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
			},
		},
		{
			OID:            ".1.3.6.1.2.1.4.20.1",
			Entity:         "ipAddress",
			Field:          "_id",
			IdentifierSize: 4,
			MappingEntries: []config.MappingEntry{
				{OID: ".1.3.6.1.2.1.4.20.1.1", Entity: "ipAddress", Field: "address"},
				{OID: ".1.3.6.1.2.1.4.20.1.3", Entity: "ipAddress", Field: "addressPrefixSize"},
				{
					OID:          ".1.3.6.1.2.1.4.20.1.2",
					Entity:       "ipAddress",
					Field:        "assignedObject",
					Relationship: config.Relationship{Type: "interface", Field: "_id"},
				},
			},
		},
	}

	// One real, walked interface (ifIndex 1) plus an IP whose ifIndex (65000)
	// has NO interface row — the dangling reference that triggers the bug.
	objectIDs := mapping.ObjectIDValueMap{
		".1.3.6.1.2.1.2.2.1.2.1": mapping.Value{Value: "GigabitEthernet1/0/1", Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1},

		".1.3.6.1.2.1.4.20.1.1.10.32.136.102": mapping.Value{Value: "10.32.136.102", Type: mapping.Asn1BER(mapping.IPAddress), IdentifierSize: 4},
		".1.3.6.1.2.1.4.20.1.3.10.32.136.102": mapping.Value{Value: "255.255.255.0", Type: mapping.Asn1BER(mapping.IPAddress), IdentifierSize: 4},
		".1.3.6.1.2.1.4.20.1.2.10.32.136.102": mapping.Value{Value: "65000", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 4},
	}

	mappingConfig, err := mapping.NewConfig(mappingEntries, logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
	require.NoError(t, err)

	defaults := &config.Defaults{Interface: config.InterfaceDefaults{Type: "other"}}
	mapper := mapping.NewObjectIDMapper(mappingConfig, logger, defaults, "")

	entities := mapper.MapObjectIDsToEntity(objectIDs)

	var ip *diode.IPAddress
	for _, e := range entities {
		if got, ok := e.(*diode.IPAddress); ok && got.Address != nil && *got.Address == "10.32.136.102/24" {
			ip = got
			break
		}
	}
	require.NotNil(t, ip, "expected the 10.32.136.102/24 address to be emitted")

	assert.Nil(t, ip.AssignedObject,
		"an IP whose owning interface was never walked must be left unassigned, not bound to a placeholder interface with no device/type")
}

// TestMapObjectIDsToEntity_VerifiedInterfaceAssignmentSurvives guards the other
// direction of the ENGHLP-1566 fix: when the owning interface WAS walked
// (verified), its IP assignment must be preserved. This prevents
// dropUnverifiedInterfaceAssignments from over-stripping legitimate bindings.
func TestMapObjectIDsToEntity_VerifiedInterfaceAssignmentSurvives(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mappingEntries := []config.MappingEntry{
		{
			OID:            ".1.3.6.1.2.1.2.2.1",
			Entity:         "interface",
			Field:          "_id",
			IdentifierSize: 1,
			MappingEntries: []config.MappingEntry{
				{OID: ".1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
			},
		},
		{
			OID:            ".1.3.6.1.2.1.4.20.1",
			Entity:         "ipAddress",
			Field:          "_id",
			IdentifierSize: 4,
			MappingEntries: []config.MappingEntry{
				{OID: ".1.3.6.1.2.1.4.20.1.1", Entity: "ipAddress", Field: "address"},
				{OID: ".1.3.6.1.2.1.4.20.1.3", Entity: "ipAddress", Field: "addressPrefixSize"},
				{
					OID:          ".1.3.6.1.2.1.4.20.1.2",
					Entity:       "ipAddress",
					Field:        "assignedObject",
					Relationship: config.Relationship{Type: "interface", Field: "_id"},
				},
			},
		},
	}

	// IP bound to ifIndex 1, which IS walked (a real ifTable row exists).
	objectIDs := mapping.ObjectIDValueMap{
		".1.3.6.1.2.1.2.2.1.2.1": mapping.Value{Value: "GigabitEthernet1/0/1", Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1},

		".1.3.6.1.2.1.4.20.1.1.192.0.2.10": mapping.Value{Value: "192.0.2.10", Type: mapping.Asn1BER(mapping.IPAddress), IdentifierSize: 4},
		".1.3.6.1.2.1.4.20.1.3.192.0.2.10": mapping.Value{Value: "255.255.255.0", Type: mapping.Asn1BER(mapping.IPAddress), IdentifierSize: 4},
		".1.3.6.1.2.1.4.20.1.2.192.0.2.10": mapping.Value{Value: "1", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 4},
	}

	mappingConfig, err := mapping.NewConfig(mappingEntries, logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, config.Options{})
	require.NoError(t, err)

	defaults := &config.Defaults{Interface: config.InterfaceDefaults{Type: "other"}}
	mapper := mapping.NewObjectIDMapper(mappingConfig, logger, defaults, "")

	entities := mapper.MapObjectIDsToEntity(objectIDs)

	var ip *diode.IPAddress
	for _, e := range entities {
		if got, ok := e.(*diode.IPAddress); ok && got.Address != nil && *got.Address == "192.0.2.10/24" {
			ip = got
			break
		}
	}
	require.NotNil(t, ip, "expected the 192.0.2.10/24 address to be emitted")

	iface, ok := ip.AssignedObject.(*diode.Interface)
	require.True(t, ok && iface != nil, "IP assigned to a walked interface must keep its assignment")
	assert.Equal(t, "GigabitEthernet1/0/1", derefStr(iface.Name),
		"the surviving assignment must point at the real walked interface")
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
