package mapping_test

import (
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

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

	// Deliberately a raw != nil comparison rather than assert.Nil. A *typed*
	// nil (*diode.Interface)(nil) stored in this interface field would satisfy
	// assert.Nil (reflection unwraps the pointer) but serializes to
	// "assigned_object_interface": {}, which the Diode NetBox plugin treats as
	// an explicit CLEAR of the generic FK — actively unassigning a correct IP.
	// Only the raw comparison distinguishes the two. See
	// TestRawNilComparisonDetectsTypedNil below.
	if ip.AssignedObject != nil {
		t.Fatalf("an IP whose owning interface was never walked must be left unassigned "+
			"(a typed-nil ref would serialize to {} and CLEAR the NetBox assignment), got %#v",
			ip.AssignedObject)
	}
}

// TestClearedAssignmentSerializesWithoutTheKey pins the actual wire contract
// the fix depends on. Diode/NetBox distinguish two states that look identical
// in Go: an ABSENT assigned_object_interface key means "leave the existing
// NetBox assignment untouched" (the plugin applies updates with DRF
// partial=True), whereas an empty object means "clear this FK". The SDK guards
// the field with a raw `if e.AssignedObject != nil`, so a typed-nil
// (*diode.Interface)(nil) would pass that check and serialize as {} — silently
// unassigning a correct IP. Asserting on the serialized form is the only way to
// tell the two apart, since assert.Nil cannot.
func TestClearedAssignmentSerializesWithoutTheKey(t *testing.T) {
	ip := &diode.IPAddress{Address: diode.String("10.32.136.102/24")}
	ip.AssignedObject = nil // exactly what dropUnverifiedInterfaceAssignments does

	raw, err := protojson.Marshal(ip.ConvertToProtoMessage())
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))

	_, present := decoded["assignedObjectInterface"]
	_, presentSnake := decoded["assigned_object_interface"]
	assert.False(t, present || presentSnake,
		"a cleared assignment must be ABSENT from the payload, not an empty object: "+
			"absent means leave-unchanged, {} means clear-the-FK in NetBox. got %s", string(raw))
}

// TestMapObjectIDsToEntity_RecordsIfIndexOfClearedAssignment covers the VRF
// recovery path. Clearing AssignedObject removes the only pointer AttachVrfs
// can key on (it maps interface pointer -> ifIndex), so the discovered VRF for
// that address would be silently forfeited. The mapper therefore records the
// placeholder's ifIndex before clearing, so a later pass can still resolve the
// VRF for the now-unassigned address.
func TestMapObjectIDsToEntity_RecordsIfIndexOfClearedAssignment(t *testing.T) {
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
	require.NotNil(t, ip)

	recorded := mapper.UnverifiedAssignmentIfIndexes()
	require.NotNil(t, recorded, "the mapper must record cleared assignments so the VRF can still be resolved")
	idx, ok := recorded[ip]
	require.True(t, ok, "the unassigned address must be recorded against the ifIndex it was bound to")
	assert.Equal(t, 65000, idx)
}

// TestAttachVrfsToUnverified_AttachesDiscoveredVrfAndRecordsAddress verifies
// the recovery itself: an address that was unassigned because its interface was
// never walked still receives the VRF discovered for that ifIndex, and the
// address is recorded in vrfByAddress so prefix derivation carries the same VRF
// onto the derived Prefix.
func TestAttachVrfsToUnverified_AttachesDiscoveredVrfAndRecordsAddress(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	ip := &diode.IPAddress{Address: diode.String("10.32.136.102/24")}
	vrf := &diode.VRF{Name: diode.String("CUSTOMER-A")}

	recorded := map[*diode.IPAddress]int{ip: 65000}
	vrfByIfIndex := map[int]*diode.VRF{65000: vrf}
	vrfByAddress := map[string]*diode.VRF{}

	mapping.AttachVrfsToUnverified(recorded, vrfByIfIndex, vrfByAddress, logger)

	require.NotNil(t, ip.Vrf, "the discovered VRF must survive the assignment being cleared")
	assert.Equal(t, "CUSTOMER-A", derefStr(ip.Vrf.Name))
	assert.Equal(t, vrf, vrfByAddress["10.32.136.102/24"],
		"the address must be recorded so DerivePrefixes carries the same VRF onto the prefix")
}

// TestAttachVrfsToUnverified_LeavesAddressAloneWhenNoVrfDiscovered guards the
// common case: no VRF discovery data for that ifIndex means no VRF is invented,
// and the configured defaults (applied earlier by the mapper) stay in force.
func TestAttachVrfsToUnverified_LeavesAddressAloneWhenNoVrfDiscovered(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	preset := &diode.VRF{Name: diode.String("DEFAULT-FROM-POLICY")}
	ip := &diode.IPAddress{Address: diode.String("10.32.136.102/24"), Vrf: preset}

	recorded := map[*diode.IPAddress]int{ip: 65000}
	vrfByIfIndex := map[int]*diode.VRF{999: {Name: diode.String("OTHER")}}
	vrfByAddress := map[string]*diode.VRF{}

	mapping.AttachVrfsToUnverified(recorded, vrfByIfIndex, vrfByAddress, logger)

	assert.Equal(t, preset, ip.Vrf, "an unrelated ifIndex must not overwrite the configured VRF default")
	assert.Empty(t, vrfByAddress, "no discovered VRF means nothing to record for prefix derivation")
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
