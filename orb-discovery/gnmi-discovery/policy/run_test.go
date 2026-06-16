package policy

import (
	"errors"
	"testing"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/require"
)

func TestRunStoreLifecycle(t *testing.T) {
	rs := NewRunStore()
	r1 := rs.CreateRun("p1", "10.0.0.1:6030")
	require.NotEmpty(t, r1.ID)
	require.Equal(t, RunStatusRunning, r1.Status)
	rs.UpdateRun("p1", "10.0.0.1:6030", r1.ID, RunStatusCompleted, nil, 7)

	runs := rs.GetRunsForPolicy("p1")
	require.Len(t, runs, 1)
	require.Equal(t, RunStatusCompleted, runs[0].Status)
	require.Equal(t, 7, runs[0].EntityCount)
}

func TestRunStoreKeepsLastN(t *testing.T) {
	rs := NewRunStore()
	for i := 0; i < 5; i++ {
		r := rs.CreateRun("p1", "h:1")
		rs.UpdateRun("p1", "h:1", r.ID, RunStatusFailed, errors.New("x"), 0)
	}
	require.Len(t, rs.GetRunsForPolicy("p1"), maxRunsPerTarget) // capped
}

func TestGetRunsNewestFirst(t *testing.T) {
	rs := NewRunStore()
	r1 := rs.CreateRun("p1", "h:1")
	rs.UpdateRun("p1", "h:1", r1.ID, RunStatusCompleted, nil, 1)
	time.Sleep(1 * time.Millisecond)
	r2 := rs.CreateRun("p1", "h:1")
	rs.UpdateRun("p1", "h:1", r2.ID, RunStatusCompleted, nil, 2)
	time.Sleep(1 * time.Millisecond)
	r3 := rs.CreateRun("p1", "h:1")
	rs.UpdateRun("p1", "h:1", r3.ID, RunStatusCompleted, nil, 3)

	runs := rs.GetRunsForPolicy("p1")
	require.Len(t, runs, 3)
	require.GreaterOrEqual(t, runs[0].CreatedAt, runs[1].CreatedAt)
	require.GreaterOrEqual(t, runs[1].CreatedAt, runs[2].CreatedAt)
}

func TestAnnotateEntitiesWithRunID(t *testing.T) {
	devName := "router1"
	dev := &diode.Device{
		Name:     &devName,
		Metadata: diode.Metadata{"source_match": "orig"},
	}
	ifName := "Ethernet1"
	iface := &diode.Interface{
		Name:   &ifName,
		Device: dev,
	}
	mod := &diode.Module{Device: dev}
	bay := &diode.ModuleBay{Device: dev}

	entities := []diode.Entity{dev, iface, mod, bay}
	annotateEntitiesWithRunID(entities, "RID")

	// Every top-level entity gets run_id.
	require.Equal(t, "RID", dev.Metadata["run_id"])
	require.Equal(t, "RID", iface.Metadata["run_id"])
	require.Equal(t, "RID", mod.Metadata["run_id"])
	require.Equal(t, "RID", bay.Metadata["run_id"])

	// Nested Device on Interface/Module/ModuleBay also gets run_id.
	require.Equal(t, "RID", iface.Device.Metadata["run_id"])
	require.Equal(t, "RID", mod.Device.Metadata["run_id"])
	require.Equal(t, "RID", bay.Device.Metadata["run_id"])

	// Pre-existing key on Device is preserved.
	require.Equal(t, "orig", dev.Metadata["source_match"])
}

func TestAnnotateRunIDCoversIPAddress(t *testing.T) {
	dev := &diode.Device{Name: strPtrT("r1")}
	iface := &diode.Interface{Device: dev, Name: strPtrT("Ethernet1")}
	ip := &diode.IPAddress{Address: strPtrT("10.0.0.1/31"), AssignedObject: iface}
	// Pass ONLY dev + ip (NOT iface) as top-level entities. iface is reachable
	// solely through ip.AssignedObject, so if it ends up annotated, that proves
	// the new *diode.IPAddress case did it — not the pre-existing Interface case.
	annotateEntitiesWithRunID([]diode.Entity{dev, ip}, "RID")
	require.Equal(t, "RID", ip.Metadata["run_id"])
	require.Equal(t, "RID", iface.Metadata["run_id"])        // assigned interface annotated via the IP path
	require.Equal(t, "RID", iface.Device.Metadata["run_id"]) // and its Device
}

func TestAnnotateRunIDCoversInterfaceLag(t *testing.T) {
	dev := &diode.Device{Name: strPtrT("r1")}
	lag := &diode.Interface{Device: dev, Name: strPtrT("Port-Channel1")}
	member := &diode.Interface{Device: dev, Name: strPtrT("Ethernet1"), Lag: lag}
	annotateEntitiesWithRunID([]diode.Entity{dev, member}, "RID")
	require.Equal(t, "RID", member.Metadata["run_id"])
	require.Equal(t, "RID", lag.Metadata["run_id"]) // reached via member.Lag
}

// regression: an Interface with a Lag ref must convert to proto without recursing.
func TestInterfaceLagNoReferenceCycle(t *testing.T) {
	dev := &diode.Device{Name: strPtrT("r1")}
	lag := &diode.Interface{Device: dev, Name: strPtrT("Port-Channel1")}
	member := &diode.Interface{Device: dev, Name: strPtrT("Ethernet1"), Lag: lag}
	require.NotNil(t, member.ConvertToProtoMessage())
}

func TestAnnotateRunIDCoversVLANs(t *testing.T) {
	dev := &diode.Device{Name: strPtrT("r1")}
	v10 := &diode.VLAN{Vid: int64Ptr(10), Name: strPtrT("VLAN10")}
	v20 := &diode.VLAN{Vid: int64Ptr(20), Name: strPtrT("VLAN20")}
	iface := &diode.Interface{Device: dev, Name: strPtrT("Ethernet1"), UntaggedVlan: v10, TaggedVlans: []*diode.VLAN{v20}}
	annotateEntitiesWithRunID([]diode.Entity{dev, iface, v10, v20}, "RID")
	require.Equal(t, "RID", iface.Metadata["run_id"])
	require.Equal(t, "RID", v10.Metadata["run_id"]) // top-level VLAN case
	require.Equal(t, "RID", v20.Metadata["run_id"])
}

// regression: an Interface with VLAN refs converts to proto without recursing.
func TestInterfaceVlanNoReferenceCycle(t *testing.T) {
	dev := &diode.Device{Name: strPtrT("r1")}
	v10 := &diode.VLAN{Vid: int64Ptr(10), Name: strPtrT("VLAN10")}
	iface := &diode.Interface{Device: dev, Name: strPtrT("Ethernet1"), UntaggedVlan: v10}
	require.NotNil(t, iface.ConvertToProtoMessage())
}

func TestAnnotateRunIDCoversVRF(t *testing.T) {
	dev := &diode.Device{Name: strPtrT("r1")}
	vrf := &diode.VRF{Name: strPtrT("blue")}
	iface := &diode.Interface{Device: dev, Name: strPtrT("Ethernet2"), Vrf: vrf}
	ip := &diode.IPAddress{Address: strPtrT("10.0.0.1/31"), AssignedObject: iface, Vrf: vrf}
	annotateEntitiesWithRunID([]diode.Entity{dev, iface, ip, vrf}, "RID")
	require.Equal(t, "RID", iface.Metadata["run_id"])
	require.Equal(t, "RID", ip.Metadata["run_id"])
	require.Equal(t, "RID", vrf.Metadata["run_id"])
}

// regression: an Interface + IPAddress with a VRF ref converts to proto cleanly.
func TestVrfNoReferenceCycle(t *testing.T) {
	dev := &diode.Device{Name: strPtrT("r1")}
	vrf := &diode.VRF{Name: strPtrT("blue")}
	iface := &diode.Interface{Device: dev, Name: strPtrT("Ethernet2"), Vrf: vrf}
	ip := &diode.IPAddress{Address: strPtrT("10.0.0.1/31"), AssignedObject: iface, Vrf: vrf}
	require.NotNil(t, iface.ConvertToProtoMessage())
	require.NotNil(t, ip.ConvertToProtoMessage())
}

func TestAnnotateRunIDCoversPrefix(t *testing.T) {
	pfx := &diode.Prefix{Prefix: strPtrT("10.0.0.0/31")}
	annotateEntitiesWithRunID([]diode.Entity{pfx}, "RID")
	require.Equal(t, "RID", pfx.Metadata["run_id"])
}

func TestPrefixNoReferenceCycle(t *testing.T) {
	vrf := &diode.VRF{Name: strPtrT("blue")}
	pfx := &diode.Prefix{Prefix: strPtrT("10.0.0.0/31"), Vrf: vrf, Scope: &diode.Site{Name: strPtrT("lab")}}
	require.NotNil(t, pfx.ConvertToProtoMessage())
}

func int64Ptr(i int64) *int64 { return &i }

// strPtrT returns a pointer to the given string value — test helper.
func strPtrT(s string) *string { return &s }
