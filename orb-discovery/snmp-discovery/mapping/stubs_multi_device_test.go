package mapping

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
)

func TestPruneNestedRefs_MultiDevice_InterfaceRoutesToOwningMember(t *testing.T) {
	dtype := &diode.DeviceType{
		Model:        strPtr("WS-C3850-48P"),
		Manufacturer: &diode.Manufacturer{Name: strPtr("Cisco")},
	}
	master := &diode.Device{
		Name:       strPtr("master-1"),
		Serial:     strPtr("M1"),
		DeviceType: dtype,
	}
	member := &diode.Device{
		Name:       strPtr("master-1-stack-2"),
		Serial:     strPtr("M2"),
		DeviceType: dtype,
	}

	ifaceOnMaster := &diode.Interface{
		Name:   strPtr("Gi1/0/1"),
		Device: master,
	}
	ifaceOnMember := &diode.Interface{
		Name:   strPtr("Gi2/0/1"),
		Device: member,
	}

	entities := []diode.Entity{master, member, ifaceOnMaster, ifaceOnMember}
	PruneNestedRefs(entities, master, nil)

	// Top-level Devices stay rich — pruning must not touch their own DeviceType.
	assert.NotNil(t, master.DeviceType, "rich master must remain rich (no top-level pruning)")
	assert.NotNil(t, member.DeviceType, "rich member must remain rich")
	// Interface.Device must point to a stub of its OWN owner, not master.
	assert.Equal(t, "master-1-stack-2", *ifaceOnMember.Device.Name,
		"member iface's Device ref must resolve to the member, not master")
}

// TestPruneNestedRefs_MultiDevice_ParentBridgeLagRefsResolveToOwningMember
// guards finding #13: when TranslateAsStack reroutes a member's
// Interface.Device, any nested Parent/Bridge/Lag on that interface
// must also resolve to the SAME member, not be left pointing at
// master (which would happen if ResolveSubinterfaceParents ran before
// TranslateAsStack — it does today).
func TestPruneNestedRefs_MultiDevice_ParentBridgeLagRefsResolveToOwningMember(t *testing.T) {
	dtype := &diode.DeviceType{
		Model:        strPtr("WS-C3850-48P"),
		Manufacturer: &diode.Manufacturer{Name: strPtr("Cisco")},
	}
	master := &diode.Device{Name: strPtr("master-1"), DeviceType: dtype}
	member := &diode.Device{Name: strPtr("master-1-stack-2"), DeviceType: dtype}

	parent := &diode.Interface{Name: strPtr("Gi2/0/1"), Device: member}
	sub := &diode.Interface{
		Name:   strPtr("Gi2/0/1.10"),
		Device: member,
		// Parent.Device was set by ResolveSubinterfaceParents BEFORE
		// TranslateAsStack reassigned ownership; it currently points
		// at the old (master) ref. The multi-device pruning step must
		// re-resolve by name -> member.
		Parent: &diode.Interface{Name: strPtr("Gi2/0/1"), Device: master},
	}

	entities := []diode.Entity{master, member, parent, sub}
	PruneNestedRefs(entities, master, nil)

	assert.Equal(t, "master-1-stack-2", *sub.Parent.Device.Name,
		"subinterface's Parent.Device must resolve to the member, not stale master")
}

func TestPruneNestedRefs_MultiDevice_IPAddressRoutesViaInterface(t *testing.T) {
	master := &diode.Device{Name: strPtr("master-1")}
	member := &diode.Device{Name: strPtr("master-1-stack-2")}
	memberIface := &diode.Interface{Name: strPtr("Gi2/0/1"), Device: member}
	ip := &diode.IPAddress{
		Address:        strPtr("10.0.0.2/24"),
		AssignedObject: memberIface,
	}
	entities := []diode.Entity{master, member, memberIface, ip}
	PruneNestedRefs(entities, master, nil)

	stub, ok := ip.AssignedObject.(*diode.Interface)
	assert.True(t, ok)
	assert.Equal(t, "master-1-stack-2", *stub.Device.Name)
}

func TestPruneNestedRefs_SingleDevice_BehaviorUnchanged(t *testing.T) {
	dev := &diode.Device{Name: strPtr("only"), Serial: strPtr("X")}
	iface := &diode.Interface{Name: strPtr("Gi0/0/0"), Device: dev}
	ip := &diode.IPAddress{Address: strPtr("10.0.0.1/24"), AssignedObject: iface}
	entities := []diode.Entity{dev, iface, ip}
	PruneNestedRefs(entities, dev, nil)

	stub, _ := ip.AssignedObject.(*diode.Interface)
	assert.Equal(t, "only", *stub.Device.Name)
}

// TestPruneNestedRefs_DuplicateIfaceNamesAcrossMembersPreserveExistingOwner
// guards finding #14: in a stack where two members both expose an
// interface with the same name (e.g. per-member `me0` on Junos VC,
// per-member `mgmt0` on Cisco StackWise), the by-name lookup must NOT
// rebind a nested ref's owner Device to the wrong member. The
// stubForIface override only applies when the lookup is unambiguous;
// duplicate names preserve the nested ref's existing Device pointer.
func TestPruneNestedRefs_DuplicateIfaceNamesAcrossMembersPreserveExistingOwner(t *testing.T) {
	dtype := &diode.DeviceType{
		Model:        strPtr("EX4300"),
		Manufacturer: &diode.Manufacturer{Name: strPtr("Juniper")},
	}
	master := &diode.Device{Name: strPtr("vc-edge"), DeviceType: dtype}
	member := &diode.Device{Name: strPtr("vc-edge-2"), DeviceType: dtype}

	// Two top-level "me0" interfaces — one on each member.
	masterMe0 := &diode.Interface{Name: strPtr("me0"), Device: master}
	memberMe0 := &diode.Interface{Name: strPtr("me0"), Device: member}
	// A subinterface owned by master.me0. Its Parent.Device starts
	// correctly on master — the bug under guard would rebind it to
	// whichever me0 was iterated last into ifaceByName.
	masterMe0Sub := &diode.Interface{
		Name:   strPtr("me0.0"),
		Device: master,
		Parent: &diode.Interface{Name: strPtr("me0"), Device: master},
	}
	// And a subinterface owned by member.me0.
	memberMe0Sub := &diode.Interface{
		Name:   strPtr("me0.0"),
		Device: member,
		Parent: &diode.Interface{Name: strPtr("me0"), Device: member},
	}

	entities := []diode.Entity{master, member, masterMe0, memberMe0, masterMe0Sub, memberMe0Sub}
	PruneNestedRefs(entities, master, nil)

	// Each subinterface's Parent.Device stub must resolve to the
	// member it was originally pointing at, not be rebound across
	// members by the ambiguous name lookup.
	assert.Equal(t, "vc-edge", *masterMe0Sub.Parent.Device.Name,
		"master.me0.0 Parent.Device must stay on master, not rebind to member")
	assert.Equal(t, "vc-edge-2", *memberMe0Sub.Parent.Device.Name,
		"member.me0.0 Parent.Device must stay on member, not rebind to master")
}

// TestPruneNestedRefs_UniqueIfaceNameStillCorrectsStaleParent retains
// the pre-existing corrective behavior for the unambiguous case:
// when only one top-level interface matches the ref's name, the
// override still fixes a stale Parent.Device set by
// ResolveSubinterfaceParents before TranslateAsStack ran.
func TestPruneNestedRefs_UniqueIfaceNameStillCorrectsStaleParent(t *testing.T) {
	dtype := &diode.DeviceType{
		Model:        strPtr("WS-C3850-48P"),
		Manufacturer: &diode.Manufacturer{Name: strPtr("Cisco")},
	}
	master := &diode.Device{Name: strPtr("sw1"), DeviceType: dtype}
	member := &diode.Device{Name: strPtr("sw1-2"), DeviceType: dtype}

	// Only ONE top-level Gi2/0/1, and it lives on the member (correct
	// post-TranslateAsStack ownership).
	memberPort := &diode.Interface{Name: strPtr("Gi2/0/1"), Device: member}
	// Subinterface still has a stale Parent.Device = master from
	// ResolveSubinterfaceParents (which ran before TranslateAsStack
	// reassigned the parent to member).
	sub := &diode.Interface{
		Name:   strPtr("Gi2/0/1.100"),
		Device: member,
		Parent: &diode.Interface{Name: strPtr("Gi2/0/1"), Device: master},
	}

	entities := []diode.Entity{master, member, memberPort, sub}
	PruneNestedRefs(entities, master, nil)

	assert.Equal(t, "sw1-2", *sub.Parent.Device.Name,
		"unique-name lookup must still rewrite stale Parent.Device to the correct member")
}
