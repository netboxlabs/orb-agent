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

// --- primary-IP snapshot pruning ---
//
// detachForPrimaryIP shallow-copies the Device into Device.PrimaryIp4/6 during
// mapping, before TranslateAsStack, the annotators and name suppression run.
// PruneNestedRefs must rebuild that subtree or the payload describes one device
// twice with divergent values.

func snapshotDevice(t *testing.T, ip *diode.IPAddress) *diode.Device {
	t.Helper()
	iface, ok := ip.AssignedObject.(*diode.Interface)
	if !ok || iface == nil {
		t.Fatal("primary-IP snapshot lost its assigned interface")
	}
	return iface.Device
}

func TestPruneNestedRefs_PrimaryIPSnapshotUsesPostMutationDeviceType(t *testing.T) {
	addr := "10.0.0.1/24"
	dev := &diode.Device{
		Name:       strPtr("sw1"),
		Site:       &diode.Site{Name: strPtr("dc1")},
		DeviceType: &diode.DeviceType{Model: strPtr("platform-family-label")},
	}
	iface := &diode.Interface{Name: strPtr("Vlan12"), Device: dev}
	dev.PrimaryIp4 = detachForPrimaryIP(&diode.IPAddress{Address: &addr, AssignedObject: iface}, dev)

	// TranslateAsStack replaces the pointer with the real product model.
	dev.DeviceType = &diode.DeviceType{Model: strPtr("REAL-PRODUCT-MODEL")}
	PruneNestedRefs([]diode.Entity{dev}, dev, nil)

	got := snapshotDevice(t, dev.PrimaryIp4)
	assert.Equal(t, "REAL-PRODUCT-MODEL", *got.DeviceType.Model,
		"snapshot must carry the model the rich device ended up with, not the one it started with")
}

// Pins the postcondition BOTH mechanisms share: detachForPrimaryIP clears these
// by hand and the stubs lack them by construction. It therefore cannot fail when
// the prune is reverted — that revert is killed by the five tests around it. Its
// value is catching a stub constructor that starts carrying a structural ref.
func TestPruneNestedRefs_PrimaryIPSnapshotStaysCycleFree(t *testing.T) {
	addr := "10.0.0.1/24"
	v6 := "2001:db8::1/64"
	dev := &diode.Device{
		Name: strPtr("sw1"), Site: &diode.Site{Name: strPtr("dc1")},
		DeviceType: &diode.DeviceType{Model: strPtr("M")},
	}
	mk := func(name string) *diode.Interface {
		return &diode.Interface{
			Name: strPtr(name), Device: dev,
			Parent: &diode.Interface{Name: strPtr("parent"), Device: dev},
			Bridge: &diode.Interface{Name: strPtr("bridge"), Device: dev},
			Lag:    &diode.Interface{Name: strPtr("lag"), Device: dev},
			Module: &diode.Module{Device: dev},
		}
	}
	dev.PrimaryIp4 = detachForPrimaryIP(&diode.IPAddress{Address: &addr, AssignedObject: mk("Vlan12")}, dev)
	dev.PrimaryIp6 = detachForPrimaryIP6(&diode.IPAddress{Address: &v6, AssignedObject: mk("Vlan12")}, dev)
	PruneNestedRefs([]diode.Entity{dev}, dev, nil)

	for label, ip := range map[string]*diode.IPAddress{"v4": dev.PrimaryIp4, "v6": dev.PrimaryIp6} {
		iface := ip.AssignedObject.(*diode.Interface)
		assert.Nil(t, iface.Device.PrimaryIp4, label+": nested device must not regain a primary IP")
		assert.Nil(t, iface.Device.PrimaryIp6, label+": nested device must not regain a primary IP")
		assert.Nil(t, iface.Parent, label+": relationship pointers reintroduce the cycle")
		assert.Nil(t, iface.Bridge, label)
		assert.Nil(t, iface.Lag, label)
		assert.Nil(t, iface.Module, label)
	}
}

func TestPruneNestedRefs_PrimaryIPSnapshotCarriesSourceMatch(t *testing.T) {
	addr := "10.0.0.1/24"
	dev := &diode.Device{
		Name: strPtr("sw1"), Site: &diode.Site{Name: strPtr("dc1")},
		DeviceType: &diode.DeviceType{Model: strPtr("M")},
	}
	iface := &diode.Interface{Name: strPtr("Vlan12"), Device: dev}
	dev.PrimaryIp4 = detachForPrimaryIP(&diode.IPAddress{Address: &addr, AssignedObject: iface}, dev)

	// Stamped AFTER the snapshot, onto a freshly allocated map — the production
	// order. Stamping before would share the map and pass without the fix.
	dev.Metadata = diode.Metadata{"source_match": diode.Metadata{"netbox_id": 7}}
	PruneNestedRefs([]diode.Entity{dev}, dev, nil)

	got := snapshotDevice(t, dev.PrimaryIp4)
	_, ok := got.Metadata["source_match"]
	assert.True(t, ok,
		"both representations must resolve via the same matcher path, or they can create a duplicate device")
}

// The snapshot's interface must be attributed to the member that owns it.
//
// The IP-assigned interface is deliberately absent from the top-level entity
// slice (MapObjectIDsToEntity excludes it), which is why the owner is resolved
// from the live IPAddress entity by address rather than by interface name. A
// fixture that registers it as a top-level Interface passes without the fix.
func TestPruneNestedRefs_PrimaryIPSnapshotRoutesToOwningMember(t *testing.T) {
	addr := "10.0.0.1/24"
	dtype := &diode.DeviceType{Model: strPtr("M")}
	master := &diode.Device{Name: strPtr("sw1"), Site: &diode.Site{Name: strPtr("dc1")}, DeviceType: dtype}
	member := &diode.Device{Name: strPtr("sw1-2"), Site: &diode.Site{Name: strPtr("dc1")}, DeviceType: dtype}

	master.PrimaryIp4 = detachForPrimaryIP(&diode.IPAddress{
		Address:        &addr,
		AssignedObject: &diode.Interface{Name: strPtr("Gi2/0/48"), Device: master},
	}, master)

	// The live entity, already routed to the member by TranslateAsStack.
	liveIP := &diode.IPAddress{
		Address:        &addr,
		AssignedObject: &diode.Interface{Name: strPtr("Gi2/0/48"), Device: member},
	}

	PruneNestedRefs([]diode.Entity{master, member, liveIP}, master,
		map[*diode.IPAddress]bool{liveIP: true})

	assert.Equal(t, "sw1-2", *snapshotDevice(t, master.PrimaryIp4).Name,
		"one port must not be claimed by two devices, and two devices must not claim one unique primary_ip4")
}

func TestPruneNestedRefs_PrimaryIPSnapshotAmbiguousAddressLeftAlone(t *testing.T) {
	addr := "10.0.0.1/24"
	dtype := &diode.DeviceType{Model: strPtr("M")}
	master := &diode.Device{Name: strPtr("sw1"), Site: &diode.Site{Name: strPtr("dc1")}, DeviceType: dtype}
	m2 := &diode.Device{Name: strPtr("sw1-2"), Site: &diode.Site{Name: strPtr("dc1")}, DeviceType: dtype}
	m3 := &diode.Device{Name: strPtr("sw1-3"), Site: &diode.Site{Name: strPtr("dc1")}, DeviceType: dtype}

	master.PrimaryIp4 = detachForPrimaryIP(&diode.IPAddress{
		Address:        &addr,
		AssignedObject: &diode.Interface{Name: strPtr("Vlan12"), Device: master},
	}, master)
	ip2 := &diode.IPAddress{
		Address:        &addr,
		AssignedObject: &diode.Interface{Name: strPtr("Vlan12"), Device: m2},
	}
	ip3 := &diode.IPAddress{
		Address:        &addr,
		AssignedObject: &diode.Interface{Name: strPtr("Vlan12"), Device: m3},
	}

	// A post-snapshot model change, so this also dies on a full revert rather
	// than only on the len==1 -> len>0 weakening.
	master.DeviceType = &diode.DeviceType{Model: strPtr("REAL-PRODUCT-MODEL")}
	PruneNestedRefs([]diode.Entity{master, m2, m3, ip2, ip3}, master, nil)

	got := snapshotDevice(t, master.PrimaryIp4)
	assert.Equal(t, "sw1", *got.Name,
		"two interfaces claiming one address is ambiguous: keep the existing owner rather than guessing")
	assert.Equal(t, "REAL-PRODUCT-MODEL", *got.DeviceType.Model,
		"ambiguity suppresses only the owner rewrite, not the rebuild")
}

// The v6 twin. Without this, a fix applied only to detachForPrimaryIP's subtree
// would ship green: the cycle-free assertions above hold either way, because the
// shallow copy also nils both primary families.
func TestPruneNestedRefs_PrimaryIP6SnapshotUsesPostMutationDeviceType(t *testing.T) {
	v6 := "2001:db8::1/64"
	dev := &diode.Device{
		Name:       strPtr("sw1"),
		Site:       &diode.Site{Name: strPtr("dc1")},
		DeviceType: &diode.DeviceType{Model: strPtr("platform-family-label")},
	}
	iface := &diode.Interface{Name: strPtr("Vlan12"), Device: dev}
	dev.PrimaryIp6 = detachForPrimaryIP6(&diode.IPAddress{Address: &v6, AssignedObject: iface}, dev)

	dev.DeviceType = &diode.DeviceType{Model: strPtr("REAL-PRODUCT-MODEL")}
	PruneNestedRefs([]diode.Entity{dev}, dev, nil)

	assert.Equal(t, "REAL-PRODUCT-MODEL", *snapshotDevice(t, dev.PrimaryIp6).DeviceType.Model,
		"the v6 path must be fixed too; the capture that surfaced this had no IPv6 primary")
}

// The index is keyed by ADDRESS, not by interface name, and that is load-bearing:
// two members can expose same-named interfaces (per-member mgmt ports), so a
// name-keyed index could bind the primary to an unrelated device. Re-keying
// liveIfaceByAddr by name leaves the rest of the suite green, so this is the only
// test that pins the decision.
func TestPruneNestedRefs_PrimaryIPSnapshotKeysOnAddressNotInterfaceName(t *testing.T) {
	dtype := &diode.DeviceType{Model: strPtr("M")}
	master := &diode.Device{Name: strPtr("sw1"), Site: &diode.Site{Name: strPtr("dc1")}, DeviceType: dtype}
	m2 := &diode.Device{Name: strPtr("sw1-2"), Site: &diode.Site{Name: strPtr("dc1")}, DeviceType: dtype}
	m3 := &diode.Device{Name: strPtr("sw1-3"), Site: &diode.Site{Name: strPtr("dc1")}, DeviceType: dtype}

	mine, theirs := "10.0.0.1/24", "10.0.0.2/24"
	master.PrimaryIp4 = detachForPrimaryIP(&diode.IPAddress{
		Address:        &mine,
		AssignedObject: &diode.Interface{Name: strPtr("mgmt0"), Device: master},
	}, master)

	// Both members expose an interface called mgmt0; only one holds this address.
	ipMine := &diode.IPAddress{
		Address:        &mine,
		AssignedObject: &diode.Interface{Name: strPtr("mgmt0"), Device: m2},
	}
	ipTheirs := &diode.IPAddress{
		Address:        &theirs,
		AssignedObject: &diode.Interface{Name: strPtr("mgmt0"), Device: m3},
	}

	PruneNestedRefs([]diode.Entity{master, m2, m3, ipMine, ipTheirs}, master, nil)

	assert.Equal(t, "sw1-2", *snapshotDevice(t, master.PrimaryIp4).Name,
		"the address must select the owner; a name-keyed lookup could pick sw1-3")
}

// stubFor returns the ref unchanged when it can resolve no owning Device (no
// name/serial match and no currentDevice). Writing that rich ref into the
// snapshot would leave a Device carrying its own primary IP reachable from that
// same primary IP, and the SDK's proto conversion has no cycle detection, so it
// would be a hard crash rather than an ingest error. Unreachable from the runner,
// which always passes a currentDevice, but PruneNestedRefs is exported.
func TestPruneNestedRefs_PrimaryIPSnapshotNeverWritesBackARichDevice(t *testing.T) {
	addr := "10.0.0.1/24"
	dtype := &diode.DeviceType{Model: strPtr("M")}
	dev := &diode.Device{Name: strPtr("sw1"), Site: &diode.Site{Name: strPtr("dc1")}, DeviceType: dtype}
	dev.PrimaryIp4 = detachForPrimaryIP(&diode.IPAddress{
		Address:        &addr,
		AssignedObject: &diode.Interface{Name: strPtr("Vlan12"), Device: dev},
	}, dev)

	// A live entity whose owner is resolvable from neither index.
	foreign := &diode.Device{Name: strPtr("absent-from-entities"), DeviceType: dtype}
	foreign.PrimaryIp4 = &diode.IPAddress{Address: &addr}
	liveIP := &diode.IPAddress{
		Address:        &addr,
		AssignedObject: &diode.Interface{Name: strPtr("Vlan12"), Device: foreign},
	}

	PruneNestedRefs([]diode.Entity{dev, liveIP}, nil, nil)

	got := snapshotDevice(t, dev.PrimaryIp4)
	assert.Nil(t, got.PrimaryIp4,
		"a device reachable from a primary IP must never itself carry one")
	assert.Nil(t, got.PrimaryIp6, "same for the v6 family")
}
