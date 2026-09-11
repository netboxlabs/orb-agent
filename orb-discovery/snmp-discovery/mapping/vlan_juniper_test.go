package mapping

import (
	"log/slog"
	"os"
	"reflect"
	"strings"
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

// internalIndexWalk is the EX4550 shape, with the index and tag spaces
// deliberately overlapping the way the real capture does: index 24 resolves
// to tag 32 while index 32 exists in its own right and resolves to 666. A
// rewrite done in place rather than into a fresh map would corrupt that and
// leave a fixture of disjoint values intact.
//
// Values are taken from the reporter's capture: index 17 is VL156 at tag 156,
// index 31 is the default VLAN at tag 0.
func internalIndexWalk() ObjectIDValueMap {
	return ObjectIDValueMap{
		oidSysObjectIDScalar: {Value: jnxSysObjectID},

		oidDot1qVlanStaticName + "17":          {Value: "VL156"},
		oidDot1qVlanStaticEgressPorts + "17":   {Value: "\x80"},
		oidDot1qVlanStaticUntaggedPorts + "17": {Value: "\x40"},
		oidDot1qVlanStaticRowStatus + "17":     {Value: "1"},

		oidDot1qVlanStaticName + "24":        {Value: "VL32"},
		oidDot1qVlanStaticEgressPorts + "24": {Value: "\x20"},

		oidDot1qVlanStaticName + "32":        {Value: "VL666"},
		oidDot1qVlanStaticEgressPorts + "32": {Value: "\x10"},

		oidDot1qVlanStaticName + "31":      {Value: "default"},
		oidDot1qVlanStaticRowStatus + "31": {Value: "1"},

		oidJnxExVlanTag + "17": {Value: "156"},
		oidJnxExVlanTag + "24": {Value: "32"},
		oidJnxExVlanTag + "32": {Value: "666"},
		oidJnxExVlanTag + "31": {Value: "0"},
	}
}

func TestResolveJuniperVlanIndices_TranslatesStaticTable(t *testing.T) {
	out := ResolveJuniperVlanIndices(internalIndexWalk(), slog.New(slog.NewTextHandler(os.Stderr, nil)))

	// Every column of the table is keyed by the same index, so every column
	// must move together. Rekeying the name and not the port masks would file
	// VLAN 156 in NetBox carrying the ports of whichever VLAN was at index
	// 156, which is the failure this design exists to prevent.
	for _, want := range []struct{ oid, value string }{
		{oidDot1qVlanStaticName + "156", "VL156"},
		{oidDot1qVlanStaticEgressPorts + "156", "\x80"},
		{oidDot1qVlanStaticUntaggedPorts + "156", "\x40"},
		{oidDot1qVlanStaticRowStatus + "156", "1"},
		// The overlapping pair: 24 becomes 32, and the row that was already
		// at 32 becomes 666 rather than being overwritten.
		{oidDot1qVlanStaticName + "32", "VL32"},
		{oidDot1qVlanStaticEgressPorts + "32", "\x20"},
		{oidDot1qVlanStaticName + "666", "VL666"},
		{oidDot1qVlanStaticEgressPorts + "666", "\x10"},
	} {
		got, ok := out[want.oid]
		if !ok {
			t.Errorf("%s missing: the column did not travel with its VLAN", want.oid)
			continue
		}
		if got.Value != want.value {
			t.Errorf("%s = %q, want %q", want.oid, got.Value, want.value)
		}
	}

	// No internal index may survive alongside the tag it resolved to.
	for _, gone := range []string{
		oidDot1qVlanStaticName + "17", oidDot1qVlanStaticEgressPorts + "17",
		oidDot1qVlanStaticUntaggedPorts + "17", oidDot1qVlanStaticRowStatus + "17",
		oidDot1qVlanStaticName + "24", oidDot1qVlanStaticEgressPorts + "24",
	} {
		if _, ok := out[gone]; ok {
			t.Errorf("%s must not survive: it is an internal index", gone)
		}
	}
}

func TestResolveJuniperVlanIndices_DropsUnusableTag(t *testing.T) {
	out := ResolveJuniperVlanIndices(internalIndexWalk(), slog.New(slog.NewTextHandler(os.Stderr, nil)))

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

func TestResolveJuniperVlanIndices_DropsEverySentinelTag(t *testing.T) {
	// CoerceVid owns the range, and this pins that the resolver defers to it
	// rather than special-casing the tag 0 we happen to have seen.
	in := ObjectIDValueMap{oidSysObjectIDScalar: {Value: jnxSysObjectID}}
	for idx, tag := range map[string]string{
		"41": "0", "42": "4095", "43": "4096", "44": "-1", "45": "nonsense", "46": "",
	} {
		in[oidDot1qVlanStaticName+idx] = Value{Value: "NAME" + idx}
		in[oidJnxExVlanTag+idx] = Value{Value: tag}
	}
	// One usable VLAN, so the table still covers every index and translation runs.
	in[oidDot1qVlanStaticName+"40"] = Value{Value: "GOOD"}
	in[oidJnxExVlanTag+"40"] = Value{Value: "500"}

	out := ResolveJuniperVlanIndices(in, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	if got := out[oidDot1qVlanStaticName+"500"].Value; got != "GOOD" {
		t.Errorf("the usable VLAN must still translate, got %q", got)
	}
	for _, idx := range []string{"41", "42", "43", "44", "45", "46"} {
		if _, ok := out[oidDot1qVlanStaticName+idx]; ok {
			t.Errorf("index %s must not be emitted in place of an unusable tag", idx)
		}
	}
	for _, tag := range []string{"0", "4095", "4096", "-1"} {
		if _, ok := out[oidDot1qVlanStaticName+tag]; ok {
			t.Errorf("tag %s is not a VLAN ID and must not be emitted", tag)
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
	want := ObjectIDValueMap{
		oidSysObjectIDScalar:           {Value: jnxSysObjectID},
		oidDot1qVlanStaticName + "156": {Value: "VL156+156"},
		oidDot1qVlanStaticName + "1":   {Value: "default+1"},
	}

	// Compared against a separate literal rather than against the input: the
	// pass-through returns the same map value, so asserting input against
	// output would compare a map with itself and hold for any implementation.
	if got := ResolveJuniperVlanIndices(in, slog.New(slog.NewTextHandler(os.Stderr, nil))); !reflect.DeepEqual(got, want) {
		t.Errorf("walk must be unchanged when there is no enterprise table\n got %v\nwant %v", got, want)
	}
}

// TestResolveJuniperVlanIndices_SaysSoWhenTheTableIsUnreadable separates a
// device that has no enterprise table from one whose table answered with
// nothing usable. The first is normal and silent; the second means the
// reported bug is about to reappear untranslated, which an operator can only
// act on if it is said.
func TestResolveJuniperVlanIndices_SaysSoWhenTheTableIsUnreadable(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	in := ObjectIDValueMap{
		oidSysObjectIDScalar:          {Value: jnxSysObjectID},
		oidDot1qVlanStaticName + "17": {Value: "VL156"},
		oidJnxExVlanTag + "17":        {Value: ""}, // walked, but no usable value
	}
	out := ResolveJuniperVlanIndices(in, logger)

	if _, ok := out[oidDot1qVlanStaticName+"17"]; !ok {
		t.Error("an unusable table must leave the walk alone, not delete it")
	}
	if !strings.Contains(buf.String(), "no row was usable") {
		t.Errorf("an unreadable enterprise table must be reported, got %q", buf.String())
	}

	// And the ordinary absence stays quiet.
	buf.Reset()
	ResolveJuniperVlanIndices(ObjectIDValueMap{
		oidSysObjectIDScalar:           {Value: jnxSysObjectID},
		oidDot1qVlanStaticName + "156": {Value: "VL156"},
	}, logger)
	if buf.Len() != 0 {
		t.Errorf("a device with no enterprise table must stay quiet, got %q", buf.String())
	}
}

func TestResolveJuniperVlanIndices_LeavesPvidsAlone(t *testing.T) {
	// The reported device carries real tags in dot1qPvid while its static
	// table carries indices. Translating PVIDs would look up a tag as though
	// it were an index, which is wrong whenever the two spaces collide.
	in := internalIndexWalk()
	in[oidDot1qPvid+"536"] = Value{Value: "888"}
	in[oidDot1qPvid+"5"] = Value{Value: "17"}

	out := ResolveJuniperVlanIndices(in, slog.New(slog.NewTextHandler(os.Stderr, nil)))

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
	// sysObjectID arrives in more shapes than the canonical one: agents pad
	// with NUL and spaces, and the leading dot is not guaranteed. Each of
	// these must reach the same verdict, and the near-miss enterprise arc
	// must not, which is what the trailing dot on the prefix is for.
	for _, tc := range []struct {
		what      string
		sysObject string
		want      string
	}{
		{"canonical", ".1.3.6.1.4.1.2636.1.1.1.2.92", "VL156"},
		{"no leading dot", "1.3.6.1.4.1.2636.1.1.1.2.92", "VL156"},
		{"NUL padded", ".1.3.6.1.4.1.2636.1.1.1.2.92\x00", "VL156"},
		{"space padded", "  .1.3.6.1.4.1.2636.1.1.1.2.92  ", "VL156"},
		{"another vendor", ciscoSysObjID, "VL156+156"},
		{"enterprise arc that merely starts the same", ".1.3.6.1.4.1.26361.1", "VL156+156"},
		{"no sysObjectID at all", "", "VL156+156"},
	} {
		all := ObjectIDValueMap{oidDot1qVlanStaticName + "156": {Value: "VL156+156"}}
		if tc.sysObject != "" {
			all[oidSysObjectIDScalar] = Value{Value: tc.sysObject}
		}
		if got := vlanNamesByVid(all)[156]; got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.what, got, tc.want)
		}
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

	want := map[int64]string{156: "VL156", 32: "VL32", 666: "VL666"}
	for vid, name := range want {
		if byVid[vid] != name {
			t.Errorf("expected VLAN %d named %q, got %v", vid, name, byVid)
		}
	}
	if len(byVid) != len(want) {
		t.Errorf("expected exactly %d VLANs, got %v", len(want), byVid)
	}
	for _, gone := range []int64{17, 24, 31, 0} {
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

	out := ResolveJuniperVlanIndices(in, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	if _, ok := out[oidDot1qVlanStaticName+"100"]; ok {
		t.Error("a tag two indices both claim must not be emitted")
	}
	for _, oid := range []string{oidDot1qVlanStaticName + "5", oidDot1qVlanStaticName + "9"} {
		if _, ok := out[oid]; ok {
			t.Errorf("%s: the internal index must not be emitted in its place either", oid)
		}
	}
	// The unambiguous VLAN in the same walk is unaffected: one contradictory
	// tag must not cost the device its other VLANs.
	if got := out[oidDot1qVlanStaticName+"200"].Value; got != "FINE" {
		t.Errorf("an unambiguous VLAN must still translate, got %q", got)
	}
}

// TestResolveJuniperVlanIndices_DoesNotMutateTheWalk pins that the rewrite
// builds a new map.
//
// The runner normalises the same walk a second time for the SVI resolver, and
// other post-pass mappers read the same map, so rewriting in place would
// change what they see. It would also make the rewrite order-dependent: a row
// rekeyed onto an index not yet visited would be re-read as though it were an
// index, which a fixture of disjoint values would never reveal and the real
// device, whose index and tag spaces overlap, would hit immediately.
func TestResolveJuniperVlanIndices_DoesNotMutateTheWalk(t *testing.T) {
	in := internalIndexWalk()
	before := make(ObjectIDValueMap, len(in))
	for k, v := range in {
		before[k] = v
	}

	first := ResolveJuniperVlanIndices(in, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	if !reflect.DeepEqual(in, before) {
		t.Error("the walk handed in must be unchanged")
	}
	// Idempotent, which is what lets the runner and VlanMapper each normalise
	// without coordinating: the second pass finds a tag-keyed table the
	// enterprise rows do not describe, and returns it untouched.
	if second := ResolveJuniperVlanIndices(first, slog.New(slog.NewTextHandler(os.Stderr, nil))); !reflect.DeepEqual(second, first) {
		t.Error("a second normalisation must be a no-op")
	}
}

// TestResolveJuniperVlanIndices_RefusesWhenTheTableDoesNotExplainEveryRow
// covers a Junos device that publishes the enterprise table AND already keys
// the static table by the tag.
//
// The two are independent properties, and the presence of the enterprise
// table is not evidence about how the static table is keyed. Translating on
// that assumption looks up tag-keyed rows as though they were indices: every
// lookup misses and the device loses every VLAN it reports correctly today.
// Worse, where a tag-keyed row number happens to be a valid index, the
// identity is swapped rather than dropped.
func TestResolveJuniperVlanIndices_RefusesWhenTheTableDoesNotExplainEveryRow(t *testing.T) {
	// Static rows keyed by tag (156, 178); enterprise rows keyed by an index
	// space of its own (1, 2). Nothing lines up.
	in := ObjectIDValueMap{
		oidSysObjectIDScalar:                  {Value: jnxSysObjectID},
		oidDot1qVlanStaticName + "156":        {Value: "VL156"},
		oidDot1qVlanStaticName + "178":        {Value: "VL178"},
		oidDot1qVlanStaticEgressPorts + "156": {Value: "\x01"},
		oidJnxExVlanTag + "1":                 {Value: "156"},
		oidJnxExVlanTag + "2":                 {Value: "178"},
	}
	out := ResolveJuniperVlanIndices(in, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	for _, oid := range []string{
		oidDot1qVlanStaticName + "156", oidDot1qVlanStaticName + "178",
		oidDot1qVlanStaticEgressPorts + "156",
	} {
		if _, ok := out[oid]; !ok {
			t.Errorf("%s must survive: the enterprise table does not describe this index space", oid)
		}
	}
}

// TestResolveJuniperVlanIndices_RefusesOnAPartialEnterpriseTable is the same
// guard reached a different way.
//
// The walk layer deliberately keeps the rows it collected when a table ends
// early, so a truncated enterprise walk arrives as a short but non-empty
// map. Translating then would delete every static row past the cut, which is
// worse than the wrong VLAN IDs it was meant to fix: those VLANs are emitted
// today, and an incomplete answer is not grounds to remove them.
func TestResolveJuniperVlanIndices_RefusesOnAPartialEnterpriseTable(t *testing.T) {
	in := internalIndexWalk()
	delete(in, oidJnxExVlanTag+"24") // walk cut short before this row

	out := ResolveJuniperVlanIndices(in, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	if _, ok := out[oidDot1qVlanStaticName+"24"]; !ok {
		t.Error("a row the partial table cannot explain must be kept, not deleted")
	}
	if _, ok := out[oidDot1qVlanStaticName+"156"]; ok {
		t.Error("and no row may be translated from a table that is incomplete")
	}
}
