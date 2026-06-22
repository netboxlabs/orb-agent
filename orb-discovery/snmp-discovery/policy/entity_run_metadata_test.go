package policy

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnnotateEntitiesWithRunID_device(t *testing.T) {
	dev := &diode.Device{Name: diode.String("r1")}
	entities := []diode.Entity{dev}
	annotateEntitiesWithRunID(entities, "run-abc")
	require.Contains(t, dev.Metadata, "run_id")
	assert.Equal(t, "run-abc", dev.Metadata["run_id"])
}

func TestAnnotateEntitiesWithRunID_interfaceNestedDevice(t *testing.T) {
	dev := &diode.Device{Name: diode.String("core")}
	iface := &diode.Interface{
		Name:   diode.String("eth0"),
		Device: dev,
	}
	entities := []diode.Entity{iface}
	annotateEntitiesWithRunID(entities, "run-xyz")
	require.Contains(t, iface.Metadata, "run_id")
	assert.Equal(t, "run-xyz", iface.Metadata["run_id"])
	require.Contains(t, dev.Metadata, "run_id")
	assert.Equal(t, "run-xyz", dev.Metadata["run_id"])
}

func TestAnnotateEntitiesWithRunID_ipAssignedToInterface(t *testing.T) {
	dev := &diode.Device{Name: diode.String("d")}
	iface := &diode.Interface{Name: diode.String("gi0"), Device: dev}
	ip := &diode.IPAddress{
		Address:        diode.String("10.0.0.1/32"),
		AssignedObject: iface,
	}
	entities := []diode.Entity{ip}
	annotateEntitiesWithRunID(entities, "run-ip")
	require.Contains(t, ip.Metadata, "run_id")
	require.Contains(t, iface.Metadata, "run_id")
	require.Contains(t, dev.Metadata, "run_id")
}

func TestAnnotateEntitiesWithRunID_sharedDeviceVisitedOnce(t *testing.T) {
	dev := &diode.Device{Name: diode.String("shared")}
	if1 := &diode.Interface{Name: diode.String("a"), Device: dev}
	if2 := &diode.Interface{Name: diode.String("b"), Device: dev}
	entities := []diode.Entity{if1, if2}
	annotateEntitiesWithRunID(entities, "run-shared")
	assert.Equal(t, "run-shared", dev.Metadata["run_id"])
}

func TestAnnotateDeviceWithSourceMatch_sets_metadata(t *testing.T) {
	dev := &diode.Device{Name: diode.String("r1")}
	entities := []diode.Entity{dev}
	annotateDeviceWithSourceMatch(entities, 42)
	require.Contains(t, dev.Metadata, "source_match")
	nested, ok := dev.Metadata["source_match"].(diode.Metadata)
	require.True(t, ok, "source_match value should be diode.Metadata")
	assert.Equal(t, 42, nested["netbox_id"])
}

func TestAnnotateDeviceWithSourceMatch_no_device_is_noop(t *testing.T) {
	iface := &diode.Interface{Name: diode.String("eth0")}
	entities := []diode.Entity{iface}
	// Should not panic when no *diode.Device is present
	annotateDeviceWithSourceMatch(entities, 99)
	assert.Nil(t, iface.Metadata)
}

func TestAnnotateDeviceWithSourceMatch_nested_in_interface(t *testing.T) {
	dev := &diode.Device{Name: diode.String("r1")}
	iface := &diode.Interface{Name: diode.String("eth0"), Device: dev}
	entities := []diode.Entity{iface}
	annotateDeviceWithSourceMatch(entities, 42)
	require.Contains(t, dev.Metadata, "source_match")
	nested, ok := dev.Metadata["source_match"].(diode.Metadata)
	require.True(t, ok)
	assert.Equal(t, 42, nested["netbox_id"])
}

func TestAnnotateDeviceWithSourceMatch_nested_in_ip_address(t *testing.T) {
	dev := &diode.Device{Name: diode.String("r1")}
	iface := &diode.Interface{Name: diode.String("eth0"), Device: dev}
	ip := &diode.IPAddress{Address: diode.String("10.0.0.1/24"), AssignedObject: iface}
	entities := []diode.Entity{ip}
	annotateDeviceWithSourceMatch(entities, 7)
	require.Contains(t, dev.Metadata, "source_match")
	nested, ok := dev.Metadata["source_match"].(diode.Metadata)
	require.True(t, ok)
	assert.Equal(t, 7, nested["netbox_id"])
}

func TestAnnotateDeviceWithSourceMatch_shared_device_annotated_once(t *testing.T) {
	dev := &diode.Device{Name: diode.String("shared")}
	if1 := &diode.Interface{Name: diode.String("a"), Device: dev}
	if2 := &diode.Interface{Name: diode.String("b"), Device: dev}
	entities := []diode.Entity{if1, if2}
	annotateDeviceWithSourceMatch(entities, 5)
	assert.Equal(t, diode.Metadata{"netbox_id": 5}, dev.Metadata["source_match"])
}

func TestAnnotateEntitiesWithRunID_vlan_toplevel(t *testing.T) {
	vlan := &diode.VLAN{
		Vid:  int64Ptr(100),
		Name: stringPtr("VLAN100"),
	}
	entities := []diode.Entity{vlan}
	annotateEntitiesWithRunID(entities, "run-vlan")
	require.Contains(t, vlan.Metadata, "run_id")
	assert.Equal(t, "run-vlan", vlan.Metadata["run_id"])
}

func TestAnnotateEntitiesWithRunID_interface_untaggedVlan(t *testing.T) {
	vlan := &diode.VLAN{
		Vid:  int64Ptr(100),
		Name: stringPtr("VLAN100"),
	}
	iface := &diode.Interface{
		Name:         diode.String("gi0"),
		UntaggedVlan: vlan,
	}
	entities := []diode.Entity{iface}
	annotateEntitiesWithRunID(entities, "run-untagged")
	require.Contains(t, iface.Metadata, "run_id")
	assert.Equal(t, "run-untagged", iface.Metadata["run_id"])
	require.Contains(t, vlan.Metadata, "run_id")
	assert.Equal(t, "run-untagged", vlan.Metadata["run_id"])
}

func TestAnnotateEntitiesWithRunID_interface_taggedVlans(t *testing.T) {
	vlan1 := &diode.VLAN{Vid: int64Ptr(100), Name: stringPtr("VLAN100")}
	vlan2 := &diode.VLAN{Vid: int64Ptr(200), Name: stringPtr("VLAN200")}
	iface := &diode.Interface{
		Name:        diode.String("gi1"),
		TaggedVlans: []*diode.VLAN{vlan1, vlan2},
	}
	entities := []diode.Entity{iface}
	annotateEntitiesWithRunID(entities, "run-tagged")
	require.Contains(t, iface.Metadata, "run_id")
	assert.Equal(t, "run-tagged", iface.Metadata["run_id"])
	require.Contains(t, vlan1.Metadata, "run_id")
	assert.Equal(t, "run-tagged", vlan1.Metadata["run_id"])
	require.Contains(t, vlan2.Metadata, "run_id")
	assert.Equal(t, "run-tagged", vlan2.Metadata["run_id"])
}

func TestAnnotateEntitiesWithRunID_interface_both_untagged_and_tagged(t *testing.T) {
	vlanUntagged := &diode.VLAN{Vid: int64Ptr(1), Name: stringPtr("VLAN1")}
	vlanTagged1 := &diode.VLAN{Vid: int64Ptr(100), Name: stringPtr("VLAN100")}
	vlanTagged2 := &diode.VLAN{Vid: int64Ptr(200), Name: stringPtr("VLAN200")}
	iface := &diode.Interface{
		Name:         diode.String("gi2"),
		UntaggedVlan: vlanUntagged,
		TaggedVlans:  []*diode.VLAN{vlanTagged1, vlanTagged2},
	}
	entities := []diode.Entity{iface}
	annotateEntitiesWithRunID(entities, "run-both")
	// Interface should be annotated
	require.Contains(t, iface.Metadata, "run_id")
	assert.Equal(t, "run-both", iface.Metadata["run_id"])
	// Untagged VLAN should be annotated
	require.Contains(t, vlanUntagged.Metadata, "run_id")
	assert.Equal(t, "run-both", vlanUntagged.Metadata["run_id"])
	// All tagged VLANs should be annotated
	require.Contains(t, vlanTagged1.Metadata, "run_id")
	assert.Equal(t, "run-both", vlanTagged1.Metadata["run_id"])
	require.Contains(t, vlanTagged2.Metadata, "run_id")
	assert.Equal(t, "run-both", vlanTagged2.Metadata["run_id"])
}

func TestAnnotateEntitiesWithRunID_vlan_idempotent(t *testing.T) {
	vlan := &diode.VLAN{Vid: int64Ptr(100), Name: stringPtr("VLAN100")}
	entities := []diode.Entity{vlan}
	// Call twice to ensure idempotency
	annotateEntitiesWithRunID(entities, "run-idempotent")
	annotateEntitiesWithRunID(entities, "run-idempotent")
	require.Contains(t, vlan.Metadata, "run_id")
	assert.Equal(t, "run-idempotent", vlan.Metadata["run_id"])
}

func TestAnnotateEntitiesWithRunID_shared_vlan_visited_once(t *testing.T) {
	sharedVlan := &diode.VLAN{Vid: int64Ptr(100), Name: stringPtr("VLAN100")}
	if1 := &diode.Interface{Name: diode.String("a"), UntaggedVlan: sharedVlan}
	if2 := &diode.Interface{Name: diode.String("b"), TaggedVlans: []*diode.VLAN{sharedVlan}}
	entities := []diode.Entity{if1, if2}
	annotateEntitiesWithRunID(entities, "run-shared-vlan")
	// Both interfaces should be annotated
	assert.Equal(t, "run-shared-vlan", if1.Metadata["run_id"])
	assert.Equal(t, "run-shared-vlan", if2.Metadata["run_id"])
	// VLAN should be annotated only once (seen map prevents re-processing)
	require.Contains(t, sharedVlan.Metadata, "run_id")
	assert.Equal(t, "run-shared-vlan", sharedVlan.Metadata["run_id"])
}

func TestAnnotateDeviceWithSourceMatch_SkipsMemberDevices(t *testing.T) {
	pos := int64(2)
	master := &diode.Device{Name: stringPtr("master")}
	member := &diode.Device{
		Name:       stringPtr("master-2"),
		VcPosition: &pos, // member identity signal
	}
	annotateDeviceWithSourceMatch([]diode.Entity{master, member}, 42)

	assert.Equal(t, diode.Metadata{"netbox_id": 42}, master.Metadata["source_match"])
	_, hasSM := member.Metadata["source_match"]
	assert.False(t, hasSM, "member Devices (VcPosition != nil) must NOT receive master's source_match")
}

func TestAnnotateDeviceWithSourceMatch_AnnotatesVirtualChassisMaster(t *testing.T) {
	// masterRef is the shared inline Device used as VirtualChassis.Master
	// on the top-level VC entity AND on each member's VirtualChassis.Master.
	masterRef := &diode.Device{Name: stringPtr("3850-stack"), Serial: stringPtr("FCW001")}

	two := int64(2)
	// member Device: VcPosition != nil, so the member itself must NOT get source_match.
	memberDev := &diode.Device{
		Name:       stringPtr("3850-stack-2"),
		VcPosition: &two,
		VirtualChassis: &diode.VirtualChassis{
			Name:   stringPtr("3850-stack"),
			Master: masterRef,
		},
	}
	// top-level VC entity.
	vcEntity := &diode.VirtualChassis{
		Name:   stringPtr("3850-stack"),
		Master: masterRef,
	}

	entities := []diode.Entity{vcEntity, memberDev}
	annotateDeviceWithSourceMatch(entities, 42)

	wantSM := diode.Metadata{"netbox_id": 42}

	// Top-level VC's Master must carry source_match.
	require.NotNil(t, vcEntity.Master.Metadata, "VC.Master must have Metadata set")
	assert.Equal(t, wantSM, vcEntity.Master.Metadata["source_match"],
		"top-level VC.Master must carry source_match")

	// Member's VirtualChassis.Master (same pointer) must carry source_match.
	require.NotNil(t, memberDev.VirtualChassis.Master.Metadata,
		"member.VirtualChassis.Master must have Metadata set")
	assert.Equal(t, wantSM, memberDev.VirtualChassis.Master.Metadata["source_match"],
		"member.VirtualChassis.Master must carry source_match")

	// Member device itself must NOT carry source_match (VcPosition != nil → skipped).
	_, hasSM := memberDev.Metadata["source_match"]
	assert.False(t, hasSM, "member Device (VcPosition != nil) must NOT receive source_match")
}

func TestAnnotateEntitiesWithRunID_StampsVirtualChassis(t *testing.T) {
	vc := &diode.VirtualChassis{Name: stringPtr("stack")}
	annotateEntitiesWithRunID([]diode.Entity{vc}, "run-123")
	assert.Equal(t, "run-123", vc.Metadata["run_id"])
}

// Helper function for tests
func int64Ptr(v int64) *int64 {
	return &v
}

func stringPtr(v string) *string {
	return &v
}
