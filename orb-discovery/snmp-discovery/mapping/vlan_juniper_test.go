package mapping

import (
	"bytes"
	"log/slog"
	"os"
	"reflect"
	"strconv"
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

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(os.Stderr, nil)) }

// capturingLogger returns a logger and the buffer it writes to.
func capturingLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

// internalIndexWalk is the EX4550 shape, with the index and tag spaces
// deliberately overlapping the way the real capture does: index 24 resolves
// to tag 32 while index 32 exists in its own right and resolves to 666. A
// rewrite done in place rather than into a fresh map would corrupt that and
// leave a fixture of disjoint values intact.
//
// Values are taken from the reporter's capture: index 17 is VL156 at tag 156,
// index 31 is the default bridge domain at tag 0. Both VLAN tables carry the
// same name for each index, which is how the real device answers and what the
// corroboration gate requires.
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

		oidJnxExVlanName + "17": {Value: "VL156"},
		oidJnxExVlanName + "24": {Value: "VL32"},
		oidJnxExVlanName + "32": {Value: "VL666"},
		oidJnxExVlanName + "31": {Value: "default"},

		oidJnxExVlanTag + "17": {Value: "156"},
		oidJnxExVlanTag + "24": {Value: "32"},
		oidJnxExVlanTag + "32": {Value: "666"},
		oidJnxExVlanTag + "31": {Value: "0"},
	}
}

func TestResolveJuniperVlanIndices_TranslatesStaticTable(t *testing.T) {
	out := ResolveJuniperVlanIndices(internalIndexWalk(), testLogger())

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
		// at 32 becomes 666. Both must land on their own tag.
		{oidDot1qVlanStaticName + "32", "VL32"},
		{oidDot1qVlanStaticEgressPorts + "32", "\x20"},
		{oidDot1qVlanStaticName + "666", "VL666"},
		{oidDot1qVlanStaticEgressPorts + "666", "\x10"},
		// Untouched: not part of the table being rekeyed.
		{oidSysObjectIDScalar, jnxSysObjectID},
	} {
		if got := out[want.oid].Value; got != want.value {
			t.Errorf("%s = %q, want %q", want.oid, got, want.value)
		}
	}

	// Every index must be gone, including 17 and 24 whose numbers are not
	// also tags on this device. A translation that merely ADDED the tag rows
	// would leave the device reporting each VLAN twice.
	for _, gone := range []string{
		oidDot1qVlanStaticName + "17",
		oidDot1qVlanStaticEgressPorts + "17",
		oidDot1qVlanStaticUntaggedPorts + "17",
		oidDot1qVlanStaticRowStatus + "17",
		oidDot1qVlanStaticName + "24",
		oidDot1qVlanStaticEgressPorts + "24",
	} {
		if _, ok := out[gone]; ok {
			t.Errorf("%s survived: the internal index must not reach NetBox as a VLAN ID", gone)
		}
	}
}

// TestResolveJuniperVlanIndices_DropsTheUntaggedDomain covers the one row the
// translation drops rather than refusing the device over.
//
// Junos reports an untagged bridge domain with tag 0, so a healthy switch has
// one of these on every poll. Dropping the row is safe precisely because
// nothing else can name it: dot1qPvid is the only other reference to a VID and
// CoerceVid rejects 0 there too, so no placeholder VLAN can be fabricated in
// its place.
func TestResolveJuniperVlanIndices_DropsTheUntaggedDomain(t *testing.T) {
	out := ResolveJuniperVlanIndices(internalIndexWalk(), testLogger())

	for _, gone := range []string{
		oidDot1qVlanStaticName + "31",
		oidDot1qVlanStaticRowStatus + "31",
		oidDot1qVlanStaticName + "0",
		oidDot1qVlanStaticRowStatus + "0",
	} {
		if _, ok := out[gone]; ok {
			t.Errorf("%s must not survive: tag 0 is not a VLAN", gone)
		}
	}
}

// TestResolveJuniperVlanIndices_DropsEverySentinelTag walks the boundary of
// what CoerceVid accepts, so the translation cannot drift away from the one
// definition of a VLAN ID the rest of the package uses.
func TestResolveJuniperVlanIndices_DropsEverySentinelTag(t *testing.T) {
	in := ObjectIDValueMap{
		oidSysObjectIDScalar: {Value: jnxSysObjectID},

		oidDot1qVlanStaticName + "40": {Value: "REAL"},
		oidJnxExVlanName + "40":       {Value: "REAL"},
		oidJnxExVlanTag + "40":        {Value: "4094"},
	}
	// Every value CoerceVid refuses. Each gets its own static row so a
	// translation that let one through would be visible.
	for i, tag := range []string{"0", "4095", "4096", "-1", "65535"} {
		index := strconv.Itoa(41 + i)
		in[oidDot1qVlanStaticName+index] = Value{Value: "SENTINEL" + index}
		in[oidJnxExVlanName+index] = Value{Value: "SENTINEL" + index}
		in[oidJnxExVlanTag+index] = Value{Value: tag}
	}

	out := ResolveJuniperVlanIndices(in, testLogger())

	if got := out[oidDot1qVlanStaticName+"4094"].Value; got != "REAL" {
		t.Errorf("the usable VLAN must still translate, got %q", got)
	}
	// Scoped to the static table: the enterprise rows are not rekeyed and
	// pass through by design, so only a surviving dot1qVlanStaticTable row
	// would mean a sentinel reached NetBox as a VLAN.
	for oid, v := range out {
		if _, _, isStatic := splitStaticVlanOID(oid); isStatic && strings.HasPrefix(v.Value, "SENTINEL") {
			t.Errorf("%s = %q survived: a sentinel tag is not a VLAN ID", oid, v.Value)
		}
	}
}

// TestResolveJuniperVlanIndices_PassesThroughWithoutTheEnterpriseTable is the
// QFX in the same report: Juniper, and already keyed by the VLAN ID.
//
// Refusing to emit VLANs from a Juniper that publishes no enterprise table
// would break a device that is correct today, which is why the vendor alone
// never decides anything here.
func TestResolveJuniperVlanIndices_PassesThroughWithoutTheEnterpriseTable(t *testing.T) {
	logger, logged := capturingLogger()
	out := ResolveJuniperVlanIndices(ObjectIDValueMap{
		oidSysObjectIDScalar:              {Value: jnxSysObjectID},
		oidDot1qVlanStaticName + "156":    {Value: "VL156+156"},
		oidDot1qVlanStaticName + "1":      {Value: "default+1"},
		oidDot1qVlanStaticRowStatus + "1": {Value: "1"},
	}, logger)

	// Compared against a separate literal rather than against the input, so a
	// function that returned its own argument could not pass by identity.
	want := ObjectIDValueMap{
		oidSysObjectIDScalar:              {Value: jnxSysObjectID},
		oidDot1qVlanStaticName + "156":    {Value: "VL156+156"},
		oidDot1qVlanStaticName + "1":      {Value: "default+1"},
		oidDot1qVlanStaticRowStatus + "1": {Value: "1"},
	}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("a Juniper without the enterprise table must be untouched\n got %v\nwant %v", out, want)
	}
	// Nothing is wrong with this device, so nothing is said about it. A
	// warning here would fire on every poll of every correct Junos switch.
	if logged.Len() != 0 {
		t.Errorf("a device needing no translation must log nothing, got %q", logged.String())
	}
}

// TestResolveJuniperVlanIndices_RefusesWhenATagIsUnreadable covers a tag
// column that answered with something that is not a number.
//
// The whole device is refused rather than the one row dropped. A dropped row
// leaves no VLAN entity while dot1qPvid may still name that VID, and
// VlanMapper would then fabricate a "VLAN<vid>" placeholder — which Diode
// PATCHes over the operator's real VLAN name. Refusing leaves the reported bug
// in place, visibly, which is recoverable; the rename is not.
func TestResolveJuniperVlanIndices_RefusesWhenATagIsUnreadable(t *testing.T) {
	in := ObjectIDValueMap{
		oidSysObjectIDScalar:          {Value: jnxSysObjectID},
		oidDot1qVlanStaticName + "17": {Value: "VL156"},
		oidJnxExVlanName + "17":       {Value: "VL156"},
		oidJnxExVlanTag + "17":        {Value: "156"},
		oidDot1qVlanStaticName + "18": {Value: "VLOTHER"},
		oidJnxExVlanName + "18":       {Value: "VLOTHER"},
		oidJnxExVlanTag + "18":        {Value: "No Such Instance"},
	}
	logger, logged := capturingLogger()
	out := ResolveJuniperVlanIndices(in, logger)

	if !reflect.DeepEqual(out, in) {
		t.Errorf("one unreadable tag must abandon the whole translation, got %v", out)
	}
	if !strings.Contains(logged.String(), "tag_unreadable=1") {
		t.Errorf("the refusal must name what was unreadable, got %q", logged.String())
	}
}

// TestResolveJuniperVlanIndices_RefusesAmbiguousTags covers a device that
// contradicts itself: two static rows claiming one tag. Nothing available says
// which row owns it, and the same placeholder-rename hazard applies, so the
// device is refused rather than the two rows dropped.
func TestResolveJuniperVlanIndices_RefusesAmbiguousTags(t *testing.T) {
	in := ObjectIDValueMap{
		oidSysObjectIDScalar:                {Value: jnxSysObjectID},
		oidDot1qVlanStaticName + "5":        {Value: "FIRST"},
		oidDot1qVlanStaticEgressPorts + "5": {Value: "\x01"},
		oidDot1qVlanStaticName + "9":        {Value: "SECOND"},
		oidDot1qVlanStaticEgressPorts + "9": {Value: "\x02"},
		oidDot1qVlanStaticName + "11":       {Value: "UNAMBIGUOUS"},
		oidJnxExVlanName + "5":              {Value: "FIRST"},
		oidJnxExVlanName + "9":              {Value: "SECOND"},
		oidJnxExVlanName + "11":             {Value: "UNAMBIGUOUS"},
		oidJnxExVlanTag + "5":               {Value: "100"},
		oidJnxExVlanTag + "9":               {Value: "100"},
		oidJnxExVlanTag + "11":              {Value: "200"},
	}
	logger, logged := capturingLogger()
	out := ResolveJuniperVlanIndices(in, logger)

	if !reflect.DeepEqual(out, in) {
		t.Errorf("a contradictory tag must abandon the whole translation, got %v", out)
	}
	if !strings.Contains(logged.String(), "tag=100") {
		t.Errorf("the refusal must name the contested tag, got %q", logged.String())
	}
}

// TestResolveJuniperVlanIndices_IgnoresAmbiguityTheStaticTableDoesNotUse keeps
// the ambiguity check scoped to rows that are about to be rewritten.
//
// The enterprise table can describe VLANs the static table never lists. A
// collision between two of those decides nothing about any row being
// translated, and refusing over it would abandon a device on the strength of
// data it is not using.
func TestResolveJuniperVlanIndices_IgnoresAmbiguityTheStaticTableDoesNotUse(t *testing.T) {
	out := ResolveJuniperVlanIndices(ObjectIDValueMap{
		oidSysObjectIDScalar:          {Value: jnxSysObjectID},
		oidDot1qVlanStaticName + "17": {Value: "VL156"},
		oidJnxExVlanName + "17":       {Value: "VL156"},
		oidJnxExVlanTag + "17":        {Value: "156"},
		// Two enterprise-only rows sharing a tag. Neither has a static row.
		oidJnxExVlanName + "80": {Value: "GHOST_A"},
		oidJnxExVlanTag + "80":  {Value: "900"},
		oidJnxExVlanName + "81": {Value: "GHOST_B"},
		oidJnxExVlanTag + "81":  {Value: "900"},
	}, testLogger())

	if got := out[oidDot1qVlanStaticName+"156"].Value; got != "VL156" {
		t.Errorf("a collision among rows the static table never lists must not block translation, got %q", got)
	}
}

// TestResolveJuniperVlanIndices_RefusesWhenTheNamesDisagree is the gate that
// counting rows cannot provide.
//
// This device keys dot1qVlanStaticTable by the TAG already — it needs no
// translation — but its tags happen to be small numbers that are also valid
// enterprise indices. Coverage is satisfied and no tag is contested, so
// without the names every VLAN here would be re-emitted under a stranger's ID:
// VLAN_ONE would reach NetBox as VLAN 100, silently.
//
// The device generates both names from one configuration, so their
// disagreement at an index is the device itself denying that the two rows
// describe the same VLAN.
func TestResolveJuniperVlanIndices_RefusesWhenTheNamesDisagree(t *testing.T) {
	in := ObjectIDValueMap{
		oidSysObjectIDScalar: {Value: jnxSysObjectID},

		// Static table, keyed by tag: VLAN 1 and VLAN 2.
		oidDot1qVlanStaticName + "1":        {Value: "VLAN_ONE"},
		oidDot1qVlanStaticEgressPorts + "1": {Value: "\x01"},
		oidDot1qVlanStaticName + "2":        {Value: "VLAN_TWO"},
		oidDot1qVlanStaticEgressPorts + "2": {Value: "\x02"},

		// Enterprise table, keyed by index: two unrelated VLANs that happen
		// to sit at indices 1 and 2.
		oidJnxExVlanName + "1": {Value: "MGMT"},
		oidJnxExVlanTag + "1":  {Value: "100"},
		oidJnxExVlanName + "2": {Value: "USERS"},
		oidJnxExVlanTag + "2":  {Value: "200"},
	}
	logger, logged := capturingLogger()
	out := ResolveJuniperVlanIndices(in, logger)

	if !reflect.DeepEqual(out, in) {
		t.Errorf("a tag-keyed static table must be left alone, got %v", out)
	}
	for _, mustNotExist := range []string{
		oidDot1qVlanStaticName + "100",
		oidDot1qVlanStaticName + "200",
	} {
		if _, ok := out[mustNotExist]; ok {
			t.Errorf("%s: a VLAN was re-identified as a different one", mustNotExist)
		}
	}
	if !strings.Contains(logged.String(), "first_disagreeing_index=1") {
		t.Errorf("the refusal must name the first VLAN the tables disagree on, got %q", logged.String())
	}
}

// TestResolveJuniperVlanIndices_RefusesWhenNothingCorroborates covers a tag
// table with no names to check it against. Absence of contradiction is not
// agreement: without a single matching name there is no evidence the two
// tables are keyed alike, and the rewrite is exactly as destructive as it is
// in the disagreeing case.
func TestResolveJuniperVlanIndices_RefusesWhenNothingCorroborates(t *testing.T) {
	in := ObjectIDValueMap{
		oidSysObjectIDScalar:          {Value: jnxSysObjectID},
		oidDot1qVlanStaticName + "17": {Value: "VL156"},
		oidJnxExVlanTag + "17":        {Value: "156"},
	}
	logger, logged := capturingLogger()
	out := ResolveJuniperVlanIndices(in, logger)

	if !reflect.DeepEqual(out, in) {
		t.Errorf("an uncorroborated tag table must not be acted on, got %v", out)
	}
	if !strings.Contains(logged.String(), "nothing corroborates") {
		t.Errorf("the refusal must say what is missing, got %q", logged.String())
	}
}

// TestResolveJuniperVlanIndices_CorroboratesThroughTheElsNameSuffix keeps the
// gate from rejecting a device over a cosmetic difference: an ELS switch
// appends "+<tag>" to a bridge domain's name, and only one of the two tables
// may carry it.
func TestResolveJuniperVlanIndices_CorroboratesThroughTheElsNameSuffix(t *testing.T) {
	// Stripped from both sides: no capture shows which table carries it, so
	// the gate must not depend on guessing. Either direction is a cosmetic
	// difference, and reading one as a disagreement would refuse a device
	// whose two tables agree about every VLAN on it.
	for _, tc := range []struct{ what, static, enterprise string }{
		{"static carries it", "VL156+156", "VL156"},
		{"enterprise carries it", "VL156", "VL156+156"},
		{"both carry it", "VL156+156", "VL156+156"},
		{"neither carries it", "VL156", "VL156"},
	} {
		out := ResolveJuniperVlanIndices(ObjectIDValueMap{
			oidSysObjectIDScalar:          {Value: jnxSysObjectID},
			oidDot1qVlanStaticName + "17": {Value: tc.static},
			oidJnxExVlanName + "17":       {Value: tc.enterprise},
			oidJnxExVlanTag + "17":        {Value: "156"},
		}, testLogger())

		if got := out[oidDot1qVlanStaticName+"156"].Value; got != tc.static {
			t.Errorf("%s: the suffix must not be read as a disagreement, got %q", tc.what, got)
		}
	}
}

// TestResolveJuniperVlanIndices_RefusesWhenTheTableDoesNotExplainEveryRow
// covers the case the corroboration gate cannot see: the tag table is keyed in
// a different space entirely, so most static rows have no entry at all.
func TestResolveJuniperVlanIndices_RefusesWhenTheTableDoesNotExplainEveryRow(t *testing.T) {
	in := ObjectIDValueMap{
		oidSysObjectIDScalar:           {Value: jnxSysObjectID},
		oidDot1qVlanStaticName + "100": {Value: "MGMT"},
		oidDot1qVlanStaticName + "200": {Value: "USERS"},
		// Keyed elsewhere: neither static row is described.
		oidJnxExVlanName + "1": {Value: "MGMT"},
		oidJnxExVlanTag + "1":  {Value: "100"},
		oidJnxExVlanName + "2": {Value: "USERS"},
		oidJnxExVlanTag + "2":  {Value: "200"},
	}
	logger, logged := capturingLogger()
	out := ResolveJuniperVlanIndices(in, logger)

	if !reflect.DeepEqual(out, in) {
		t.Errorf("a table keyed in another space must not be acted on, got %v", out)
	}
	if !strings.Contains(logged.String(), "not_described=2") {
		t.Errorf("the refusal must count the rows it could not explain, got %q", logged.String())
	}
}

// TestResolveJuniperVlanIndices_RefusesOnAPartialEnterpriseTable covers the
// truncated walk. The walk layer keeps what it collected when a table ends
// early, so a cut table arrives short but non-empty — and translating on it
// would silently delete every static row past the cut.
func TestResolveJuniperVlanIndices_RefusesOnAPartialEnterpriseTable(t *testing.T) {
	in := internalIndexWalk()
	delete(in, oidJnxExVlanTag+"32")
	delete(in, oidJnxExVlanName+"32")

	logger, logged := capturingLogger()
	out := ResolveJuniperVlanIndices(in, logger)

	if !reflect.DeepEqual(out, in) {
		t.Error("a partial enterprise table must not delete the rows it fails to describe")
	}
	if !strings.Contains(logged.String(), "not_described=1") {
		t.Errorf("the refusal must count the rows it could not explain, got %q", logged.String())
	}
}

func TestResolveJuniperVlanIndices_LeavesPvidsAlone(t *testing.T) {
	// The reported device carries real tags in dot1qPvid while its static
	// table carries indices. Translating PVIDs would look up a tag as though
	// it were an index, which is wrong whenever the two spaces collide.
	in := internalIndexWalk()
	in[oidDot1qPvid+"536"] = Value{Value: "888"}
	in[oidDot1qPvid+"5"] = Value{Value: "17"}

	out := ResolveJuniperVlanIndices(in, testLogger())

	if got := out[oidDot1qPvid+"536"].Value; got != "888" {
		t.Errorf("PVID 888 is already a tag and must not be translated, got %q", got)
	}
	if got := out[oidDot1qPvid+"5"].Value; got != "17" {
		t.Errorf("PVID 17 must survive verbatim even though 17 is a valid index, got %q", got)
	}
}

// TestResolveJuniperVlanIndices_DoesNotMutateTheWalk pins the property the
// overlapping index and tag spaces make load-bearing: the caller's map is
// shared with every other mapper, and a rewrite done in place would have
// index 24's row land on 32 and then be read again as index 32.
func TestResolveJuniperVlanIndices_DoesNotMutateTheWalk(t *testing.T) {
	in := internalIndexWalk()
	before := make(ObjectIDValueMap, len(in))
	for k, v := range in {
		before[k] = v
	}

	out := ResolveJuniperVlanIndices(in, testLogger())

	if !reflect.DeepEqual(in, before) {
		t.Error("the caller's map was mutated; every other mapper reads the same map")
	}
	// Same input, same output: nothing about the result may depend on the
	// order Go's map iteration happened to yield.
	if second := ResolveJuniperVlanIndices(in, testLogger()); !reflect.DeepEqual(out, second) {
		t.Error("two calls on identical input disagreed")
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
		{"office_100", 100, "office_100"},
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

// TestJuniperInternalIndices_EmitVlansAtTheirTags is the reported bug end to
// end, through the composition the runner performs: normalise the walk once,
// then map it. The switch is discovered with the VLAN IDs an operator
// configured rather than the indices the agent happens to read.
func TestJuniperInternalIndices_EmitVlansAtTheirTags(t *testing.T) {
	oids := ResolveJuniperVlanIndices(internalIndexWalk(), testLogger())

	vm := NewVlanMapper(testLogger(), config.Options{})
	got := vm.PostMap(oids, NewEntityRegistry(slog.Default()), &config.Defaults{})

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

// TestVlanMapper_PostMap_DoesNotNormaliseAgain pins the half of the
// single-call contract that lives in this package.
//
// Normalisation is the runner's, done once before anything reads the walk, so
// the VLAN catalog, the port masks and the SVI resolver all see one keying and
// a refusal is reported once per target rather than once per reader. If
// PostMap normalised too, every warning would appear twice in an operator's
// log and read as two different devices.
func TestVlanMapper_PostMap_DoesNotNormaliseAgain(t *testing.T) {
	logger, logged := capturingLogger()
	vm := NewVlanMapper(logger, config.Options{})
	got := vm.PostMap(internalIndexWalk(), NewEntityRegistry(slog.Default()), &config.Defaults{})

	vids := map[int64]struct{}{}
	for _, e := range got {
		if v, ok := e.(*diode.VLAN); ok && v != nil && v.Vid != nil {
			vids[*v.Vid] = struct{}{}
		}
	}
	// Untranslated input in, untranslated VIDs out: PostMap read what it was
	// given rather than repeating the runner's work.
	if _, ok := vids[17]; !ok {
		t.Errorf("PostMap must not normalise; it is the runner's single call, got %v", vids)
	}
	if strings.Contains(logged.String(), "Juniper VLAN") {
		t.Errorf("PostMap must not log about the translation, got %q", logged.String())
	}
}

// TestShippedPolicyWalksTheJuniperVlanTable pins the wiring rather than the
// logic. The translation is worthless if the columns are never walked, and
// nothing else in this file would notice: every other test here supplies the
// enterprise rows directly.
func TestShippedPolicyWalksTheJuniperVlanTable(t *testing.T) {
	cfg := newTestMappingConfig(t, testLogger())
	// Both columns are required. The tag is what the translation reads; the
	// name is what permits it to act at all, so a policy that walked only the
	// tag would refuse every device.
	for _, column := range []string{
		".1.3.6.1.4.1.2636.3.40.1.5.1.5.1.5",
		".1.3.6.1.4.1.2636.3.40.1.5.1.5.1.2",
	} {
		if _, ok := cfg.VendorObjectIDs("juniper")[column]; !ok {
			t.Errorf("a Juniper host must walk %s, got %v", column, cfg.VendorObjectIDs("juniper"))
		}
		// Every other host pays nothing: the columns are vendor-scoped, so
		// they are absent from the generic walk every target performs.
		if _, ok := cfg.GenericObjectIDs()[column]; ok {
			t.Errorf("%s must not be walked on every host", column)
		}
	}
}
