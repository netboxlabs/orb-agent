package mapping

import (
	"log/slog"
	"os"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

// Shapes taken from the two switches reported in the EX4550 VLAN issue: one
// whose dot1q indices are internal and need the enterprise table to resolve,
// and one whose indices are already the VLAN IDs and has no enterprise table
// at all. Both are Juniper, which is why the vendor alone cannot decide.

const (
	jnxSysObjectID = ".1.3.6.1.4.1.2636.1.1.1.2.92"
	ciscoSysObjID  = ".1.3.6.1.4.1.9.1.2494"
)

// internalIndexWalk is the EX4550 shape: dot1q index 17 is not VLAN 17, the
// enterprise table says it is VLAN 156, and index 31 resolves to tag 0, which
// is not a VLAN ID at all.
func internalIndexWalk() ObjectIDValueMap {
	return ObjectIDValueMap{
		oidSysObjectIDScalar:               {Value: jnxSysObjectID},
		oidDot1qVlanStaticName + "17":      {Value: "VL156"},
		oidDot1qVlanStaticName + "18":      {Value: "VL178"},
		oidDot1qVlanStaticName + "31":      {Value: "default"},
		oidDot1qVlanStaticRowStatus + "17": {Value: "1"},
		oidDot1qVlanStaticRowStatus + "31": {Value: "1"},
		oidJnxExVlanTag + "17":             {Value: "156"},
		oidJnxExVlanTag + "18":             {Value: "178"},
		oidJnxExVlanTag + "31":             {Value: "0"},
	}
}

func TestResolveJuniperVlanIndices_TranslatesStaticTable(t *testing.T) {
	out := resolveJuniperVlanIndices(internalIndexWalk(), slog.New(slog.NewTextHandler(os.Stderr, nil)))

	if _, ok := out[oidDot1qVlanStaticName+"156"]; !ok {
		t.Error("index 17 must be rekeyed to its tag 156")
	}
	if _, ok := out[oidDot1qVlanStaticName+"17"]; ok {
		t.Error("the internal index must not survive alongside the tag")
	}
	if got := out[oidDot1qVlanStaticName+"156"].Value; got != "VL156" {
		t.Errorf("the row's value must travel with it, got %q", got)
	}
	if _, ok := out[oidDot1qVlanStaticRowStatus+"156"]; !ok {
		t.Error("every column of the static table is keyed by the same index and must be rekeyed too")
	}
}

func TestResolveJuniperVlanIndices_DropsUnusableTag(t *testing.T) {
	out := resolveJuniperVlanIndices(internalIndexWalk(), slog.New(slog.NewTextHandler(os.Stderr, nil)))

	// Tag 0 is not a VLAN ID. Neither it nor the internal index it came from
	// may reach the emitted entities: index 31 as a VID would be a VLAN the
	// device never had.
	for _, oid := range []string{
		oidDot1qVlanStaticName + "0", oidDot1qVlanStaticName + "31",
		oidDot1qVlanStaticRowStatus + "0", oidDot1qVlanStaticRowStatus + "31",
	} {
		if _, ok := out[oid]; ok {
			t.Errorf("%s must not survive: tag 0 is not a VLAN", oid)
		}
	}
}

func TestResolveJuniperVlanIndices_PassesThroughWithoutTheEnterpriseTable(t *testing.T) {
	// The QFX shape: indices already are the VLAN IDs, and the enterprise
	// table answers No Such Object, so nothing is walked. Translating here
	// would corrupt a device that is correct today.
	in := ObjectIDValueMap{
		oidSysObjectIDScalar:           {Value: jnxSysObjectID},
		oidDot1qVlanStaticName + "156": {Value: "VL156+156"},
		oidDot1qVlanStaticName + "1":   {Value: "default+1"},
	}
	out := resolveJuniperVlanIndices(in, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	for oid, v := range in {
		got, ok := out[oid]
		if !ok || got.Value != v.Value {
			t.Errorf("%s must be untouched when there is no enterprise table", oid)
		}
	}
}

func TestResolveJuniperVlanIndices_LeavesPvidsAlone(t *testing.T) {
	// The reported device carries real tags in dot1qPvid while its static
	// table carries indices. Translating PVIDs would look up a tag as though
	// it were an index, which is wrong whenever the two spaces collide.
	in := internalIndexWalk()
	in[oidDot1qPvid+"536"] = Value{Value: "888"}
	in[oidDot1qPvid+"5"] = Value{Value: "17"}

	out := resolveJuniperVlanIndices(in, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	if got := out[oidDot1qPvid+"536"].Value; got != "888" {
		t.Errorf("PVID 888 is already a tag and must not be translated, got %q", got)
	}
	if got := out[oidDot1qPvid+"5"].Value; got != "17" {
		t.Errorf("PVID 17 must survive verbatim even though 17 is a valid index, got %q", got)
	}
}

func TestStripVlanNameTagSuffix(t *testing.T) {
	// Juniper ELS reports a bridge domain as <name>+<tag>. Stripping is
	// anchored on the VLAN's own id so an operator's own naming survives.
	for _, tc := range []struct {
		name string
		vid  int
		want string
	}{
		{"VL156+156", 156, "VL156"},
		{"default+1", 1, "default"},
		{"BroadbandMgmt_702", 702, "BroadbandMgmt_702"},
		{"VL156+157", 156, "VL156+157"},
		{"a+b+10", 10, "a+b"},
		{"+156", 156, "+156"},
		{"VL156", 156, "VL156"},
		{"", 156, ""},
	} {
		if got := stripVlanNameTagSuffix(tc.name, tc.vid); got != tc.want {
			t.Errorf("stripVlanNameTagSuffix(%q, %d) = %q, want %q", tc.name, tc.vid, got, tc.want)
		}
	}
}

func TestVlanNamesByVid_StripsTheSuffixOnlyForJuniper(t *testing.T) {
	jnx := ObjectIDValueMap{
		oidSysObjectIDScalar:           {Value: jnxSysObjectID},
		oidDot1qVlanStaticName + "156": {Value: "VL156+156"},
	}
	if got := vlanNamesByVid(jnx)[156]; got != "VL156" {
		t.Errorf("Juniper name must have its +tag suffix removed, got %q", got)
	}

	// Another vendor could legitimately name a VLAN this way, and we have no
	// evidence it means what it means on Junos.
	other := ObjectIDValueMap{
		oidSysObjectIDScalar:           {Value: ciscoSysObjID},
		oidDot1qVlanStaticName + "156": {Value: "VL156+156"},
	}
	if got := vlanNamesByVid(other)[156]; got != "VL156+156" {
		t.Errorf("a non-Juniper name must be left alone, got %q", got)
	}
}

// TestVlanMapper_PostMap_JuniperInternalIndices_EmitVlansAtTheirTags is the
// reported bug end to end: the switch is discovered with the VLAN IDs an
// operator configured rather than the indices the agent happens to read.
func TestVlanMapper_PostMap_JuniperInternalIndices_EmitVlansAtTheirTags(t *testing.T) {
	vm := NewVlanMapper(slog.New(slog.NewTextHandler(os.Stderr, nil)), config.Options{})
	got := vm.PostMap(internalIndexWalk(), NewEntityRegistry(slog.Default()), &config.Defaults{})

	byVid := map[int64]string{}
	for _, e := range got {
		v, ok := e.(*diode.VLAN)
		if !ok || v == nil || v.Vid == nil {
			continue
		}
		name := ""
		if v.Name != nil {
			name = *v.Name
		}
		byVid[*v.Vid] = name
	}

	if byVid[156] != "VL156" || byVid[178] != "VL178" {
		t.Errorf("expected VLANs at their real tags, got %v", byVid)
	}
	for _, gone := range []int64{17, 18, 31, 0} {
		if _, ok := byVid[gone]; ok {
			t.Errorf("VID %d must not be emitted: it is an internal index or an unusable tag, got %v", gone, byVid)
		}
	}
}

// TestShippedPolicyWalksTheJuniperVlanTable pins the wiring rather than the
// logic. The translation is worthless if the column is never walked, and
// nothing else in this file would notice: every other test here supplies the
// enterprise rows directly.
func TestShippedPolicyWalksTheJuniperVlanTable(t *testing.T) {
	cfg := newTestMappingConfig(t, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	const column = ".1.3.6.1.4.1.2636.3.40.1.5.1.5.1.5"

	if _, ok := cfg.VendorObjectIDs("juniper")[column]; !ok {
		t.Errorf("a Juniper host must walk %s, got %v", column, cfg.VendorObjectIDs("juniper"))
	}
	// Every other host pays nothing: the column is vendor-scoped, so it is
	// absent from the generic walk that every target performs.
	if _, ok := cfg.GenericObjectIDs()[column]; ok {
		t.Error("the enterprise column must not be walked on every host")
	}
}

// TestResolveJuniperVlanIndices_RefusesAmbiguousTags covers a device that
// contradicts itself: two internal indices claiming one tag.
//
// The rows are rewritten per OID, so without this the name column would keep
// whichever index Go's map iteration yielded last and the ports column could
// keep the other, pairing one VLAN's name with another's ports. Map order is
// random, so the pairing would differ between polls of identical data and the
// VLAN would be rewritten on every ingest. Neither index is emitted, because
// nothing available says which one the tag belongs to.
func TestResolveJuniperVlanIndices_RefusesAmbiguousTags(t *testing.T) {
	in := ObjectIDValueMap{
		oidSysObjectIDScalar:                {Value: jnxSysObjectID},
		oidDot1qVlanStaticName + "5":        {Value: "FIRST"},
		oidDot1qVlanStaticEgressPorts + "5": {Value: "\x01"},
		oidDot1qVlanStaticName + "9":        {Value: "SECOND"},
		oidDot1qVlanStaticEgressPorts + "9": {Value: "\x02"},
		oidDot1qVlanStaticName + "7":        {Value: "FINE"},
		oidJnxExVlanTag + "5":               {Value: "100"},
		oidJnxExVlanTag + "9":               {Value: "100"},
		oidJnxExVlanTag + "7":               {Value: "200"},
	}

	// Repeated because the failure this guards against is order-dependent:
	// a single pass could agree with itself by luck.
	for i := 0; i < 25; i++ {
		out := resolveJuniperVlanIndices(in, slog.New(slog.NewTextHandler(os.Stderr, nil)))

		if _, ok := out[oidDot1qVlanStaticName+"100"]; ok {
			t.Fatal("a tag two indices both claim must not be emitted")
		}
		for _, oid := range []string{oidDot1qVlanStaticName + "5", oidDot1qVlanStaticName + "9"} {
			if _, ok := out[oid]; ok {
				t.Fatalf("%s: the internal index must not be emitted in its place either", oid)
			}
		}
		// The unambiguous VLAN in the same walk is unaffected.
		if got := out[oidDot1qVlanStaticName+"200"].Value; got != "FINE" {
			t.Fatalf("an unambiguous VLAN must still translate, got %q", got)
		}
	}
}
