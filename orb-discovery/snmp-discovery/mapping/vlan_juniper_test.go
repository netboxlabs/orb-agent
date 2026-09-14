package mapping

import (
	"bytes"
	"log/slog"
	"os"
	"reflect"
	"sort"
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

// internalIndexWalk is the pre-ELS shape: a static table keyed by internal
// index, with an enterprise table naming and tagging every row.
//
// Two properties come from the reported capture — an index that is not its own
// tag, and one bridge domain reported at tag 0 — and both tables carrying the
// same name per index is how that device answers, which is what the
// corroboration gate reads.
//
// The index and tag spaces are made to OVERLAP here, which the capture does not
// do: index 24 resolves to tag 32 while index 32 exists in its own right. That
// is constructed deliberately, because a rewrite done in place rather than into
// a fresh map would corrupt exactly that shape and leave a fixture of disjoint
// values intact.
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

func TestResolveJuniperVlanIndices_LeavesAResolvabledPvidAlone(t *testing.T) {
	// The reported device carries real tags in dot1qPvid while its static
	// table carries indices. A PVID that names a tag the rekey resolved is
	// already correct and must survive verbatim: translating it would look up
	// a tag as though it were an index.
	in := internalIndexWalk()
	in[oidDot1qPvid+"536"] = Value{Value: "156"}
	in[oidDot1qPvid+"537"] = Value{Value: "0"}

	out := ResolveJuniperVlanIndices(in, testLogger())

	for _, port := range []string{"536", "537"} {
		if got, want := out[oidDot1qPvid+port].Value, in[oidDot1qPvid+port].Value; got != want {
			t.Errorf("PVID on port %s names a resolved tag and must not be touched: got %q, want %q", port, got, want)
		}
	}
}

// TestResolveJuniperVlanIndices_DropsAPvidTheCatalogCannotName is a regression
// test for a corruption path the rekey itself opens.
//
// RFC 4363 types dot1qPvid as VlanIndex, the same convention as
// dot1qVlanIndex, so a device that numbers VLANs internally may report PVIDs
// in that same internal space — and an internal number is an in-range small
// integer that no range check can tell from a tag. Left alone, such a PVID
// names a VID the rekeyed catalog no longer holds, VlanMapper fabricates a
// "VLAN<vid>" placeholder for it, and Diode PATCHes that over the name of
// whatever real VLAN the operator has at that number.
//
// Before the rekey the same PVID matched its static row and no placeholder was
// created, so this is a hazard the fix introduces rather than one it inherits.
func TestResolveJuniperVlanIndices_DropsAPvidTheCatalogCannotName(t *testing.T) {
	in := internalIndexWalk()
	// 17 is an internal index on this device, and is not any VLAN's tag.
	in[oidDot1qPvid+"5"] = Value{Value: "17"}
	// Unparseable: it can name no VID, so it can fabricate nothing, and
	// discarding it would only hide a malformed agent.
	in[oidDot1qPvid+"6"] = Value{Value: "No Such Instance"}

	logger, logged := capturingLogger()
	out := ResolveJuniperVlanIndices(in, logger)

	// Zeroed rather than removed: the row's presence is what tells the
	// Q-BRIDGE reader the port is bridged at all, and 0 is the device's own
	// way of saying bridged with no untagged VLAN.
	if got, ok := out[oidDot1qPvid+"5"]; !ok || got.Value != "0" {
		t.Errorf("a PVID naming no resolved tag must be zeroed, not removed: got %q, present=%v", got.Value, ok)
	}
	if got := out[oidDot1qPvid+"6"].Value; got != "No Such Instance" {
		t.Errorf("an unparseable PVID names nothing and must be left alone, got %q", got)
	}
	if !strings.Contains(logged.String(), "ports=1") {
		t.Errorf("the drop must be reported, got %q", logged.String())
	}
}

// TestJuniperRekey_DoesNotRenameAnOperatorVlanThroughAPvid proves the same
// thing end to end, through the path that does the damage.
//
// Without the PVID guard this emits a VLAN with vid 17 named "VLAN17" and
// binds the port to it. Diode applies partial updates, so that renames the
// operator's real VLAN 17 and attaches a port to a VLAN the agent invented.
func TestJuniperRekey_DoesNotRenameAnOperatorVlanThroughAPvid(t *testing.T) {
	logger := testLogger()
	registry := NewEntityRegistry(logger)
	ifaces := interfacesFor(registry, map[int]string{101: "ge-0/0/0"})

	in := ObjectIDValueMap{
		oidSysObjectIDScalar: {Value: jnxSysObjectID},
		// Internal indices 17 and 20, resolving to tags 156 and 200.
		oidDot1qVlanStaticName + "17":        {Value: "NAME17"},
		oidDot1qVlanStaticEgressPorts + "17": {Value: "\x80"},
		oidDot1qVlanStaticName + "20":        {Value: "NAME20"},
		oidJnxExVlanName + "17":              {Value: "NAME17"},
		oidJnxExVlanTag + "17":               {Value: "156"},
		oidJnxExVlanName + "20":              {Value: "NAME20"},
		oidJnxExVlanTag + "20":               {Value: "200"},
		// Bridge port 1 is ifIndex 101, and its PVID is reported in the
		// device's internal space rather than as a tag.
		oidDot1dBasePortIfIndex + "1": {Value: "101"},
		oidIfAdminStatus + "101":      {Value: "1"},
		oidIfType + "101":             {Value: "6"},
		oidDot1qPvid + "1":            {Value: "17"},
	}

	vm := NewVlanMapper(logger, config.Options{})
	got := vm.PostMap(ResolveJuniperVlanIndices(in, logger), registry, &config.Defaults{})

	for _, e := range got {
		v, ok := e.(*diode.VLAN)
		if !ok || v == nil || v.Vid == nil {
			continue
		}
		if *v.Vid == 17 {
			name := ""
			if v.Name != nil {
				name = *v.Name
			}
			t.Errorf("a VLAN was invented at the internal index: vid 17 named %q", name)
		}
	}
	if u := ifaces[101].UntaggedVlan; u != nil && u.Vid != nil && *u.Vid == 17 {
		t.Error("the port was bound to a VLAN the agent invented")
	}
}

// TestResolveJuniperVlanIndices_DoesNotMutateTheWalk pins the property the
// overlapping index and tag spaces make load-bearing: the caller's map is
// shared with every other mapper, and a rewrite done in place would have
// index 24's row land on 32 and then be read again as index 32.
func TestResolveJuniperVlanIndices_DoesNotMutateTheWalk(t *testing.T) {
	in := internalIndexWalk()
	// Includes a PVID the catalog cannot name, so the one path that ASSIGNS to
	// a walked value is covered. The map holds values rather than pointers, so
	// the range variable is a copy — but that is a property of a type
	// declaration elsewhere, and this is the test that would notice it change.
	in[oidDot1qPvid+"5"] = Value{Value: "17"}
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
		// Two decorated VLANs, so the device-convention gate is satisfied and
		// the vendor gate is the only thing under test here.
		all := ObjectIDValueMap{
			oidDot1qVlanStaticName + "156": {Value: "VL156+156"},
			oidDot1qVlanStaticName + "162": {Value: "VL162+162"},
		}
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

	// A translating fixture logs nothing to begin with, so the assertion above
	// could not fail on its own. Run a REFUSING one through the same path: the
	// refusal is the message that would appear twice per target if PostMap
	// normalised as well, which is the whole point of the single call.
	refusing := internalIndexWalk()
	delete(refusing, oidJnxExVlanTag+"32")
	delete(refusing, oidJnxExVlanName+"32")

	direct, directLog := capturingLogger()
	if ResolveJuniperVlanIndices(refusing, direct); !strings.Contains(directLog.String(), "not translating Juniper VLAN indices") {
		t.Fatalf("fixture does not refuse, so this test proves nothing: %q", directLog.String())
	}

	viaMapper, mapperLog := capturingLogger()
	NewVlanMapper(viaMapper, config.Options{}).PostMap(refusing, NewEntityRegistry(slog.Default()), &config.Defaults{})
	if strings.Contains(mapperLog.String(), "not translating Juniper VLAN indices") {
		t.Errorf("PostMap repeated the runner's refusal; it would be logged twice per target: %q", mapperLog.String())
	}
}

// TestResolveJuniperVlanIndices_ToleratesATruncatedStaticName keeps one long
// VLAN name from disabling the fix for a whole switch.
//
// RFC 4363 bounds dot1qVlanStaticName at 32 octets; JUNIPER-VLAN-MIB does not
// bound jnxExVlanName. A VLAN named past that arrives cut in one table and
// whole in the other, which a strict comparison reads as the device denying
// that the two rows describe the same VLAN. Junos names routinely run long.
func TestResolveJuniperVlanIndices_ToleratesATruncatedStaticName(t *testing.T) {
	const long = "a-deliberately-long-vlan-name-that-exceeds-the-column"
	if len(long) <= dot1qVlanStaticNameMax {
		t.Fatalf("fixture name is not long enough to truncate: %d", len(long))
	}

	out := ResolveJuniperVlanIndices(ObjectIDValueMap{
		oidSysObjectIDScalar: {Value: jnxSysObjectID},

		oidDot1qVlanStaticName + "17": {Value: long[:dot1qVlanStaticNameMax]},
		oidJnxExVlanName + "17":       {Value: long},
		oidJnxExVlanTag + "17":        {Value: "156"},
		// A second VLAN whose name fits, so the device still corroborates
		// somewhere. The long name must not veto the switch.
		oidDot1qVlanStaticName + "20": {Value: "MGMT"},
		oidJnxExVlanName + "20":       {Value: "MGMT"},
		oidJnxExVlanTag + "20":        {Value: "200"},
	}, testLogger())

	if got := out[oidDot1qVlanStaticName+"156"].Value; got != long[:dot1qVlanStaticNameMax] {
		t.Errorf("a name cut by its own column bound must not veto the rekey, got %q", got)
	}

	// The tolerance is scoped to the bound: a short name that merely starts
	// the same is a different VLAN, and must still refuse.
	in := ObjectIDValueMap{
		oidSysObjectIDScalar:          {Value: jnxSysObjectID},
		oidDot1qVlanStaticName + "17": {Value: "MGMT"},
		oidJnxExVlanName + "17":       {Value: "MGMT-UPLINK"},
		oidJnxExVlanTag + "17":        {Value: "156"},
	}
	if got := ResolveJuniperVlanIndices(in, testLogger()); !reflect.DeepEqual(got, in) {
		t.Error("a short name that is merely a prefix of another must still disagree")
	}
}

// TestResolveJuniperVlanIndices_RefusesWhenOnlyTruncatedNamesMatch closes the
// other half of the truncation problem, which matters more than the first.
//
// Two VLANs on one switch sharing a 32-octet prefix is ordinary under
// structured naming, and once the standard column cuts them they are
// indistinguishable. If a cut name counted as agreement, a device whose static
// table is ALREADY tag-keyed could satisfy the gate on nothing but prefixes and
// have every VLAN re-emitted under a stranger's ID — the exact catastrophe the
// name gate exists to prevent. A cut name is therefore evidence of nothing, and
// the rekey still needs one full agreement somewhere.
func TestResolveJuniperVlanIndices_RefusesWhenOnlyTruncatedNamesMatch(t *testing.T) {
	const prefix = "campus-west-building12-floor3-vl" // exactly the column bound
	if len(prefix) != dot1qVlanStaticNameMax {
		t.Fatalf("fixture prefix must sit exactly on the bound, got %d", len(prefix))
	}
	in := ObjectIDValueMap{
		oidSysObjectIDScalar: {Value: jnxSysObjectID},

		// A tag-keyed static table: these keys are VLAN IDs already.
		oidDot1qVlanStaticName + "100": {Value: prefix},
		oidDot1qVlanStaticName + "200": {Value: prefix},
		// An enterprise table keyed by index, describing different VLANs whose
		// names merely share that prefix.
		oidJnxExVlanName + "100": {Value: prefix + "an-alpha"},
		oidJnxExVlanTag + "100":  {Value: "300"},
		oidJnxExVlanName + "200": {Value: prefix + "an-beta"},
		oidJnxExVlanTag + "200":  {Value: "400"},
	}
	logger, logged := capturingLogger()
	out := ResolveJuniperVlanIndices(in, logger)

	if !reflect.DeepEqual(out, in) {
		t.Errorf("prefixes alone must not carry the rekey, got %v", out)
	}
	for _, mustNotExist := range []string{oidDot1qVlanStaticName + "300", oidDot1qVlanStaticName + "400"} {
		if _, ok := out[mustNotExist]; ok {
			t.Errorf("%s: a VLAN was re-identified on the strength of a shared prefix", mustNotExist)
		}
	}
	if !strings.Contains(logged.String(), "nothing corroborates") {
		t.Errorf("the refusal must say the evidence is missing, got %q", logged.String())
	}
}

// TestResolveJuniperVlanIndices_DropsAPvidNamingAnEnterpriseOnlyTag covers the
// gap between "the enterprise table mentions this tag" and "the emitted catalog
// holds this VLAN".
//
// Gate 1 requires the enterprise table to cover the static rows, not the
// reverse, so it may describe VLANs with no static row — which is what a
// protocol-learned bridge domain looks like. Such a tag names nothing in the
// catalog, so a PVID for it fabricates a placeholder exactly as an internal
// index would.
func TestResolveJuniperVlanIndices_DropsAPvidNamingAnEnterpriseOnlyTag(t *testing.T) {
	out := ResolveJuniperVlanIndices(ObjectIDValueMap{
		oidSysObjectIDScalar:          {Value: jnxSysObjectID},
		oidDot1qVlanStaticName + "17": {Value: "MGMT"},
		oidJnxExVlanName + "17":       {Value: "MGMT"},
		oidJnxExVlanTag + "17":        {Value: "156"},
		// Described by the enterprise table, absent from the static table.
		oidJnxExVlanName + "20": {Value: "LEARNED"},
		oidJnxExVlanTag + "20":  {Value: "900"},

		oidDot1qPvid + "1": {Value: "900"},
		oidDot1qPvid + "2": {Value: "156"},
	}, testLogger())

	if got := out[oidDot1qPvid+"1"].Value; got != "0" {
		t.Errorf("a PVID naming a VLAN the catalog does not hold must be zeroed, got %q", got)
	}
	if got := out[oidDot1qPvid+"2"].Value; got != "156" {
		t.Errorf("a PVID naming a catalog VLAN must survive, got %q", got)
	}
}

// TestResolveJuniperVlanIndices_RefusesWhenOnlyAnIndexEqualToItsTagAgrees
// covers the coincidence the name gate exists to catch.
//
// A row whose index equals its tag reads identically whether the static table
// is keyed by index or by tag, so it cannot discriminate between them — and it
// is the row most devices have: VLAN 1, named "default", at index 1. Counting
// it would hand the rekey a free pass on exactly one coincidence.
func TestResolveJuniperVlanIndices_RefusesWhenOnlyAnIndexEqualToItsTagAgrees(t *testing.T) {
	in := ObjectIDValueMap{
		oidSysObjectIDScalar: {Value: jnxSysObjectID},

		// The undiscriminating row: index 1, tag 1, same name in both.
		oidDot1qVlanStaticName + "1": {Value: "default"},
		oidJnxExVlanName + "1":       {Value: "default"},
		oidJnxExVlanTag + "1":        {Value: "1"},

		// Every other row is described but unnamed by the enterprise table,
		// so nothing else corroborates.
		oidDot1qVlanStaticName + "17": {Value: "MGMT"},
		oidJnxExVlanTag + "17":        {Value: "156"},
	}
	logger, logged := capturingLogger()
	out := ResolveJuniperVlanIndices(in, logger)

	if !reflect.DeepEqual(out, in) {
		t.Errorf("a row that cannot discriminate must not carry the rekey, got %v", out)
	}
	if !strings.Contains(logged.String(), "nothing corroborates") {
		t.Errorf("the refusal must say the evidence is missing, got %q", logged.String())
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

// TestVlanNamesByVid_StripsTheSuffixOnlyWhenTheDeviceIsConsistent gates a
// rename against the device's own convention.
//
// Stripping rewrites VLAN names in NetBox, which Diode PATCHes over whatever
// the operator has there, so it is held to the same bar as the rekey: evidence,
// not plausibility. A switch that decorates one bridge domain decorates all of
// them, while operator naming is not uniform — so one VLAN an operator called
// "site+100" must not make the agent shorten it, nor drag every other VLAN on
// that switch through a rename with it.
func TestVlanNamesByVid_StripsTheSuffixOnlyWhenTheDeviceIsConsistent(t *testing.T) {
	juniper := func(names map[int]string) ObjectIDValueMap {
		all := ObjectIDValueMap{oidSysObjectIDScalar: {Value: jnxSysObjectID}}
		for vid, name := range names {
			all[oidDot1qVlanStaticName+strconv.Itoa(vid)] = Value{Value: name}
		}
		return all
	}

	// The measured ELS shape: every name carries its own tag.
	got := vlanNamesByVid(juniper(map[int]string{1: "default+1", 156: "VL156+156", 162: "VL162+162"}))
	for vid, want := range map[int]string{1: "default", 156: "VL156", 162: "VL162"} {
		if got[vid] != want {
			t.Errorf("a device-wide convention must be stripped: vid %d = %q, want %q", vid, got[vid], want)
		}
	}

	// One operator-named VLAN among plain ones. Nothing is a convention here,
	// so nothing is renamed — including the VLAN that looks decorated.
	mixed := map[int]string{100: "site+100", 200: "USERS", 300: "MGMT"}
	got = vlanNamesByVid(juniper(mixed))
	for vid, want := range mixed {
		if got[vid] != want {
			t.Errorf("operator naming must survive: vid %d = %q, want %q", vid, got[vid], want)
		}
	}

	// One conforming name is enough. Requiring two made the verdict depend on
	// how many SHORT names the switch happens to have, which flaps — see the
	// exhaustive test below.
	if got = vlanNamesByVid(juniper(map[int]string{100: "site+100"})); got[100] != "site" {
		t.Errorf("one conforming name and nothing contradicting it is a convention, got %q", got[100])
	}

	// A name the 32-octet column cut short lost its suffix on the wire. It is
	// evidence of nothing, and must not veto the convention for every other
	// VLAN on the switch — otherwise configuring one long-named VLAN renames
	// all the others, and deleting it renames them back.
	cut := "operator-chosen-vlan-name-here+1" // exactly the column bound
	if len(cut) != dot1qVlanStaticNameMax {
		t.Fatalf("fixture must sit exactly on the bound, got %d", len(cut))
	}
	got = vlanNamesByVid(juniper(map[int]string{100: "office+100", 200: "eng+200", 1234: cut}))
	for vid, want := range map[int]string{100: "office", 200: "eng", 1234: cut} {
		if got[vid] != want {
			t.Errorf("a truncated name must not flip the convention: vid %d = %q, want %q", vid, got[vid], want)
		}
	}

	// A name that is nothing but the suffix is kept whole by the strip, and
	// must count as carrying the convention rather than as breaking it.
	got = vlanNamesByVid(juniper(map[int]string{100: "office+100", 300: "+300"}))
	if got[100] != "office" || got[300] != "+300" {
		t.Errorf("a suffix-only name must not veto the convention, got %v", got)
	}

	// A name that sits ON the bound and STILL ends in its own id cannot have
	// had a suffix cut off — the suffix is right there. It is evidence of the
	// convention, and discarding it is the device-wide rename in mirror image:
	// with only one other conforming VLAN the device drops below the count and
	// stripping switches off for all of them, then back on when any unrelated
	// VLAN is added.
	onBound := "aaaaaaaaaaaaaaaaaaaaaaaaaaa+1234"
	if len(onBound) != dot1qVlanStaticNameMax {
		t.Fatalf("fixture must sit exactly on the bound, got %d", len(onBound))
	}
	twoVlans := vlanNamesByVid(juniper(map[int]string{100: "office+100", 1234: onBound}))
	threeVlans := vlanNamesByVid(juniper(map[int]string{100: "office+100", 1234: onBound, 200: "eng+200"}))
	if twoVlans[100] != "office" {
		t.Errorf("a conforming name on the bound is still evidence, got %q", twoVlans[100])
	}
	if twoVlans[100] != threeVlans[100] {
		t.Errorf("adding an unrelated VLAN renamed an existing one: %q then %q — every ingest rewrites NetBox",
			twoVlans[100], threeVlans[100])
	}
}

// TestResolveJuniperVlanIndices_OnlyActsOnJuniper keeps the reasoning local to
// the vendor it is about.
//
// The enterprise columns are vendor-scoped in the shipped policy, so in
// practice only a Juniper target walks them — but that is a property of a YAML
// file, and everything this function concludes is about how Junos numbers
// VLANs. Without the check, a policy edit that widened the scope would silently
// point the rekey at another vendor's OIDs.
func TestResolveJuniperVlanIndices_OnlyActsOnJuniper(t *testing.T) {
	in := internalIndexWalk()
	in[oidSysObjectIDScalar] = Value{Value: ciscoSysObjID}

	logger, logged := capturingLogger()
	out := ResolveJuniperVlanIndices(in, logger)

	if !reflect.DeepEqual(out, in) {
		t.Errorf("a non-Juniper walk must not be rekeyed, got %v", out)
	}
	if logged.Len() != 0 {
		t.Errorf("nothing is wrong with another vendor's device, so nothing is said: %q", logged.String())
	}
	// And with no sysObjectID at all, which is the same absence of evidence.
	delete(in, oidSysObjectIDScalar)
	if out = ResolveJuniperVlanIndices(in, testLogger()); !reflect.DeepEqual(out, in) {
		t.Error("an unidentified device must not be rekeyed either")
	}
}

// TestResolveJuniperVlanIndices_IgnoresAmbiguityAmongTagsItWillDrop keeps the
// ambiguity gate to tags a row could actually be rewritten to.
//
// Junos reports an untagged bridge domain with tag 0 and a switch may have
// more than one. Both rows are dropped moments later, so there is no VLAN for
// the two to be confused about — refusing the device over them would abandon
// every other VLAN on it and buy nothing.
func TestResolveJuniperVlanIndices_IgnoresAmbiguityAmongTagsItWillDrop(t *testing.T) {
	out := ResolveJuniperVlanIndices(ObjectIDValueMap{
		oidSysObjectIDScalar: {Value: jnxSysObjectID},

		oidDot1qVlanStaticName + "17": {Value: "MGMT"},
		oidJnxExVlanName + "17":       {Value: "MGMT"},
		oidJnxExVlanTag + "17":        {Value: "156"},
		// Two untagged bridge domains, both reported at tag 0.
		oidDot1qVlanStaticName + "30": {Value: "DOMAIN_A"},
		oidJnxExVlanName + "30":       {Value: "DOMAIN_A"},
		oidJnxExVlanTag + "30":        {Value: "0"},
		oidDot1qVlanStaticName + "31": {Value: "DOMAIN_B"},
		oidJnxExVlanName + "31":       {Value: "DOMAIN_B"},
		oidJnxExVlanTag + "31":        {Value: "0"},
	}, testLogger())

	if got := out[oidDot1qVlanStaticName+"156"].Value; got != "MGMT" {
		t.Errorf("two rows sharing a tag that neither will be rewritten to must not refuse the device, got %q", got)
	}
	if _, ok := out[oidDot1qVlanStaticName+"0"]; ok {
		t.Error("tag 0 is still not a VLAN ID")
	}
}

// TestVlanNamesByVid_NoVlanChangesAnotherVlansName is the property that matters
// more than any single case here, checked exhaustively rather than asserted.
//
// The suffix strip renames VLANs in NetBox, and Diode PATCHes names on the
// vid+group matcher. So if adding or removing one VLAN can change what a
// DIFFERENT VLAN is called, every ingest after that configuration change
// rewrites operator data — and reverting the change rewrites it back. Two
// separate versions of this gate shipped with exactly that defect, in opposite
// directions, which is why this is a search rather than an example.
//
// The one deliberate exception is a name that DENIES the convention: one with
// no suffix that cannot have lost one to the column bound. That is the device
// telling us it has no such convention, and it is allowed to turn stripping off
// for the switch. Those are held in contradicting, and the search covers device
// states that contain them while not counting their arrival as a violation.
func TestVlanNamesByVid_NoVlanChangesAnotherVlansName(t *testing.T) {
	onBound := "aaaaaaaaaaaaaaaaaaaaaaaaaaa+1234"   // conforming, exactly at the bound
	cutSuffix := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb+1" // a cut "+1234", also at the bound
	if len(onBound) != dot1qVlanStaticNameMax || len(cutSuffix) != dot1qVlanStaticNameMax {
		t.Fatalf("fixtures must sit on the bound: %d, %d", len(onBound), len(cutSuffix))
	}
	// Names that are evidence FOR the convention, or evidence of nothing.
	neutral := map[int]string{
		100:  "office+100", // conforming, short
		200:  "eng+200",    // conforming, short
		300:  "+300",       // nothing but the suffix
		400:  "",           // unnamed
		1234: onBound,      // conforming, on the bound
		1235: cutSuffix,    // suffix cut away by the bound: unreadable either way
	}
	// Names that deny the convention. A short one could not have been cut; a
	// long one proves the agent does not cut at the bound at all, so it could
	// not have been cut either. Both legitimately veto.
	contradicting := map[int]string{
		500:  "plain",
		1236: "a-name-far-longer-than-the-column-bound",
	}

	pool := map[int]string{}
	for vid, name := range neutral {
		pool[vid] = name
	}
	for vid, name := range contradicting {
		pool[vid] = name
	}

	names := func(vids map[int]struct{}) map[int]string {
		all := ObjectIDValueMap{oidSysObjectIDScalar: {Value: jnxSysObjectID}}
		for vid := range vids {
			all[oidDot1qVlanStaticName+strconv.Itoa(vid)] = Value{Value: pool[vid]}
		}
		return vlanNamesByVid(all)
	}

	keys := make([]int, 0, len(pool))
	for vid := range pool {
		keys = append(keys, vid)
	}
	sort.Ints(keys)
	additions := make([]int, 0, len(neutral))
	for vid := range neutral {
		additions = append(additions, vid)
	}
	sort.Ints(additions)

	// Every subset of the pool, and every non-contradicting VLAN that could be
	// added to it.
	for mask := 0; mask < 1<<len(keys); mask++ {
		state := map[int]struct{}{}
		for i, vid := range keys {
			if mask&(1<<i) != 0 {
				state[vid] = struct{}{}
			}
		}
		before := names(state)

		for _, added := range additions {
			if _, present := state[added]; present {
				continue
			}
			state[added] = struct{}{}
			after := names(state)
			delete(state, added)

			for vid, was := range before {
				if now := after[vid]; now != was {
					t.Fatalf("adding VLAN %d renamed VLAN %d: %q -> %q (state %v)",
						added, vid, was, now, state)
				}
			}
		}
	}
}

// TestVlanNamesByVid_ALongUnsuffixedNameDeniesTheConvention pins the direction
// the length test must NOT be read as a minimum.
//
// A name longer than the column bound proves this agent does not cut at the
// bound, so its missing suffix cannot be truncation — it is the device saying
// plainly that it has no such convention, and the strongest counter-evidence
// available. Setting it aside would strip every other VLAN's name on exactly
// the device that just denied the premise.
func TestVlanNamesByVid_ALongUnsuffixedNameDeniesTheConvention(t *testing.T) {
	long := "a-name-far-longer-than-the-column-bound"
	if len(long) <= dot1qVlanStaticNameMax {
		t.Fatalf("fixture must exceed the bound, got %d", len(long))
	}
	got := vlanNamesByVid(ObjectIDValueMap{
		oidSysObjectIDScalar:           {Value: jnxSysObjectID},
		oidDot1qVlanStaticName + "100": {Value: "office+100"},
		oidDot1qVlanStaticName + "200": {Value: "eng+200"},
		oidDot1qVlanStaticName + "300": {Value: long},
	})
	for vid, want := range map[int]string{100: "office+100", 200: "eng+200", 300: long} {
		if got[vid] != want {
			t.Errorf("a name too long to have been cut must deny the convention: vid %d = %q, want %q",
				vid, got[vid], want)
		}
	}
}

// TestResolveJuniperVlanIndices_ALongNameStillDisagrees is the same rule on the
// corroboration side, where reading the length test as a minimum is worse.
//
// Laundering a genuine disagreement into "no evidence" does not merely lose a
// vote: a disagreement is a hard refusal, so it would let a device that should
// be refused proceed to a full rekey and re-emit every VLAN under another
// VLAN's ID.
func TestResolveJuniperVlanIndices_ALongNameStillDisagrees(t *testing.T) {
	long := "a-static-name-that-runs-past-the-column-bound"
	if len(long) <= dot1qVlanStaticNameMax {
		t.Fatalf("fixture must exceed the bound, got %d", len(long))
	}
	in := ObjectIDValueMap{
		oidSysObjectIDScalar: {Value: jnxSysObjectID},

		oidDot1qVlanStaticName + "17": {Value: long},
		oidJnxExVlanName + "17":       {Value: long + "-different-vlan-entirely"},
		oidJnxExVlanTag + "17":        {Value: "156"},
		// A row that does agree, so the refusal can only come from the above.
		oidDot1qVlanStaticName + "20": {Value: "MGMT"},
		oidJnxExVlanName + "20":       {Value: "MGMT"},
		oidJnxExVlanTag + "20":        {Value: "200"},
	}
	logger, logged := capturingLogger()
	out := ResolveJuniperVlanIndices(in, logger)

	if !reflect.DeepEqual(out, in) {
		t.Errorf("a name too long to have been cut must contradict, not abstain, got %v", out)
	}
	if !strings.Contains(logged.String(), "disagree") {
		t.Errorf("the refusal must name the disagreement, got %q", logged.String())
	}
}

// TestResolveJuniperVlanIndices_LeavesAZeroPvidAloneAndSilent covers the
// healthy all-tagged trunk.
//
// A PVID of 0 is the device saying "bridged, nothing untagged". It names no
// VLAN, so it can fabricate none, and 0 is already the value the guard would
// write. On a switch with no untagged bridge domain, tag 0 is not among the
// resolved tags — so without a short-circuit every such trunk is reported as
// having lost its untagged VLAN, on every poll, forever, when nothing is wrong.
func TestResolveJuniperVlanIndices_LeavesAZeroPvidAloneAndSilent(t *testing.T) {
	logger, logged := capturingLogger()
	out := ResolveJuniperVlanIndices(ObjectIDValueMap{
		oidSysObjectIDScalar: {Value: jnxSysObjectID},
		// No tag-0 row anywhere on this device.
		oidDot1qVlanStaticName + "17": {Value: "MGMT"},
		oidJnxExVlanName + "17":       {Value: "MGMT"},
		oidJnxExVlanTag + "17":        {Value: "156"},

		oidDot1qPvid + "1": {Value: "0"},
	}, logger)

	if got := out[oidDot1qPvid+"1"].Value; got != "0" {
		t.Errorf("a PVID of 0 must survive verbatim, got %q", got)
	}
	if logged.Len() != 0 {
		t.Errorf("an all-tagged trunk is healthy and must not be reported as losing anything: %q", logged.String())
	}
}

// TestResolveJuniperVlanIndices_RefusesWhenOnlyDroppedRowsCorroborate scopes
// corroboration to the rows the rekey will actually produce.
//
// Agreement from a row that is discarded moments later is evidence about
// nothing that reaches NetBox. It also lets the index != tag exclusion be
// sidestepped: that exclusion exists to deny the rekey a free pass on "VLAN 1,
// named default, at index 1", and on a box whose default bridge domain is
// untagged the enterprise tag there is 0, so 1 != 0 and the coincidence would
// have counted after all.
func TestResolveJuniperVlanIndices_RefusesWhenOnlyDroppedRowsCorroborate(t *testing.T) {
	in := ObjectIDValueMap{
		oidSysObjectIDScalar: {Value: jnxSysObjectID},

		// The only rows both tables name are untagged bridge domains, which
		// are dropped rather than rewritten.
		oidDot1qVlanStaticName + "1": {Value: "default"},
		oidJnxExVlanName + "1":       {Value: "default"},
		oidJnxExVlanTag + "1":        {Value: "0"},
		// The row that WOULD be rewritten is unnamed by the enterprise table,
		// so nothing corroborates it.
		oidDot1qVlanStaticName + "17": {Value: "MGMT"},
		oidJnxExVlanTag + "17":        {Value: "156"},
	}
	logger, logged := capturingLogger()
	out := ResolveJuniperVlanIndices(in, logger)

	if !reflect.DeepEqual(out, in) {
		t.Errorf("agreement from rows that will be dropped must not carry the rekey, got %v", out)
	}
	if !strings.Contains(logged.String(), "nothing corroborates") {
		t.Errorf("the refusal must say the evidence is missing, got %q", logged.String())
	}
}

// TestResolveJuniperVlanIndices_RefusesWhenBothColumnsAreCutToTheSamePrefix
// closes the case where truncation defeats the name gate from both sides at
// once, which is the maximal-harm outcome the gate exists to prevent.
//
// Bounding dot1qVlanStaticName at 32 octets is RFC 4363. jnxExVlanName carrying
// no such bound is an assumption the captures cannot confirm, since every name
// on them is short. If some Junos build bounds it too, a device with structured
// names ("<site>-<building>-<floor>-vlanNNN") has both columns cut to the same
// 32 octets — so the names arrive EQUAL, never reach the length test, and count
// as full agreement.
//
// The device here already keys its static table by the tag and needs no rekey.
// Its tags are also valid enterprise indices, so coverage passes; its tags are
// distinct, so ambiguity passes. Without the symmetric check, every VLAN is
// re-emitted carrying another VLAN's name, ports and row status, silently.
func TestResolveJuniperVlanIndices_RefusesWhenBothColumnsAreCutToTheSamePrefix(t *testing.T) {
	const shared = "campus-west-building12-floor3-vl" // exactly the column bound
	if len(shared) != dot1qVlanStaticNameMax {
		t.Fatalf("fixture must sit exactly on the bound, got %d", len(shared))
	}
	in := ObjectIDValueMap{oidSysObjectIDScalar: {Value: jnxSysObjectID}}
	// Static table keyed by tag; enterprise table keyed by index, rotated one
	// place so every row describes a different VLAN than the static row it
	// shares a key with.
	tags := []int{100, 101, 102, 103}
	for i, tag := range tags {
		key := strconv.Itoa(tag)
		in[oidDot1qVlanStaticName+key] = Value{Value: shared}
		in[oidDot1qVlanStaticEgressPorts+key] = Value{Value: "ports-of-" + key}
		in[oidJnxExVlanName+key] = Value{Value: shared}
		in[oidJnxExVlanTag+key] = Value{Value: strconv.Itoa(tags[(i+1)%len(tags)])}
	}

	logger, logged := capturingLogger()
	out := ResolveJuniperVlanIndices(in, logger)

	if !reflect.DeepEqual(out, in) {
		t.Errorf("names that may both be truncations must not corroborate, got %v", out)
	}
	for i, tag := range tags {
		key := strconv.Itoa(tag)
		if got, want := out[oidDot1qVlanStaticEgressPorts+key].Value, "ports-of-"+key; got != want {
			t.Errorf("VLAN %d carries another VLAN's ports: %q, want %q", tags[i], got, want)
		}
	}
	if !strings.Contains(logged.String(), "nothing corroborates") {
		t.Errorf("the refusal must say the evidence is missing, got %q", logged.String())
	}
}

// TestCompareVlanNames_TruncationIsAskedSymmetrically pins the verdict table
// directly, since the whole-device tests above exercise only some of it.
func TestCompareVlanNames_TruncationIsAskedSymmetrically(t *testing.T) {
	onBound := "campus-west-building12-floor3-vl"
	if len(onBound) != dot1qVlanStaticNameMax {
		t.Fatalf("fixture must sit on the bound, got %d", len(onBound))
	}
	for _, tc := range []struct {
		what               string
		static, enterprise string
		want               nameVerdict
	}{
		{"both short and equal", "MGMT", "MGMT", namesAgree},
		{"both short and different", "MGMT", "USERS", namesDisagree},
		{"static cut, enterprise continues it", onBound, onBound + "an-alpha", namesInconclusive},
		{"enterprise cut, static continues it", onBound + "an-alpha", onBound, namesInconclusive},
		{"both cut to the same octets", onBound, onBound, namesInconclusive},
		{"one cut, surviving prefixes differ", onBound, "MGMT", namesDisagree},
		{"longer than the bound, so not a cut", onBound + "x", onBound + "y", namesDisagree},
		{"the ELS suffix, short", "office+100", "office", namesAgree},

		// A complete SHORT name cannot be the same VLAN as a name that was
		// cut at the bound: the short one ended where it ended, and the cut
		// one runs on past it. An undirected prefix test abstained here and
		// lost the hard refusal that should follow.
		{"cut static, complete short enterprise", onBound, "campus", namesDisagree},
		{"complete short static, cut enterprise", "campus", onBound, namesDisagree},
		{"cut static, single-character enterprise", onBound, "c", namesDisagree},

		// One octet below the bound is a NUL-terminated cut, and is treated
		// as possibly cut for corroboration.
		{"NUL-terminated cut, enterprise continues it", onBound[:31], onBound + "an-alpha", namesInconclusive},
		{"both NUL-terminated to the same octets", onBound[:31], onBound[:31], namesInconclusive},

		// A visible suffix proves the end survived, so the name is complete
		// however long it is, and it corroborates rather than abstaining.
		{"suffix intact on the bound", "campus-west-building12-floor+100", "campus-west-building12-floor", namesAgree},
	} {
		if got := compareVlanNames(tc.static, tc.enterprise, 100); got != tc.want {
			t.Errorf("%s: compareVlanNames(%q, %q) = %v, want %v", tc.what, tc.static, tc.enterprise, got, tc.want)
		}
	}
}

// TestResolveJuniperVlanIndices_RefusesWhenANameIsCutOneOctetShort covers the
// blind spot an agent's NUL terminator opens.
//
// trimSNMPString strips NUL bytes, so an agent that writes into a 32-octet
// buffer and NUL-terminates delivers 31 octets of text. Read as a complete
// name, that is the same silent full-rekey as the both-cut case one octet
// higher: an already tag-keyed device whose structured names all collapse to
// the same prefix passes coverage and ambiguity, and every VLAN is re-emitted
// carrying the next VLAN's name, ports and row status.
//
// Covering it costs this gate only a vote — the rekey needs its evidence from
// an uncut row instead. The ELS convention gate cannot make the same trade, and
// does not.
func TestResolveJuniperVlanIndices_RefusesWhenANameIsCutOneOctetShort(t *testing.T) {
	shared := "campus-west-building12-floor3-v" // one octet below the bound
	if len(shared) != dot1qVlanStaticNameMax-1 {
		t.Fatalf("fixture must sit one octet below the bound, got %d", len(shared))
	}
	in := ObjectIDValueMap{oidSysObjectIDScalar: {Value: jnxSysObjectID}}
	tags := []int{100, 101, 102, 103}
	for i, tag := range tags {
		key := strconv.Itoa(tag)
		in[oidDot1qVlanStaticName+key] = Value{Value: shared}
		in[oidDot1qVlanStaticEgressPorts+key] = Value{Value: "ports-of-" + key}
		in[oidJnxExVlanName+key] = Value{Value: shared}
		in[oidJnxExVlanTag+key] = Value{Value: strconv.Itoa(tags[(i+1)%len(tags)])}
	}

	logger, logged := capturingLogger()
	out := ResolveJuniperVlanIndices(in, logger)

	if !reflect.DeepEqual(out, in) {
		t.Errorf("names that may all be truncations must not corroborate, got %v", out)
	}
	for _, tag := range tags {
		key := strconv.Itoa(tag)
		if got, want := out[oidDot1qVlanStaticEgressPorts+key].Value, "ports-of-"+key; got != want {
			t.Errorf("VLAN %s carries another VLAN's ports: %q, want %q", key, got, want)
		}
	}
	if !strings.Contains(logged.String(), "nothing corroborates") {
		t.Errorf("the refusal must say the evidence is missing, got %q", logged.String())
	}
}

// TestResolveJuniperVlanIndices_ACompleteShortNameStillDisagrees is the
// device-level form of the directed prefix rule.
//
// Before it, a row whose enterprise name was a complete short string and whose
// static name was cut at the bound abstained instead of contradicting — so a
// device with one agreeing row and one such row was rekeyed, and the row that
// should have refused the device was re-emitted under the wrong identity.
func TestResolveJuniperVlanIndices_ACompleteShortNameStillDisagrees(t *testing.T) {
	onBound := "campus-west-building12-floor3-vl"
	if len(onBound) != dot1qVlanStaticNameMax {
		t.Fatalf("fixture must sit on the bound, got %d", len(onBound))
	}
	in := ObjectIDValueMap{
		oidSysObjectIDScalar: {Value: jnxSysObjectID},

		// A row that genuinely agrees, so the refusal can only come from below.
		oidDot1qVlanStaticName + "17": {Value: "VL156"},
		oidJnxExVlanName + "17":       {Value: "VL156"},
		oidJnxExVlanTag + "17":        {Value: "156"},

		// The static name was cut; the enterprise name is complete and short.
		// They cannot be one VLAN under any reading.
		oidDot1qVlanStaticName + "24":        {Value: onBound},
		oidDot1qVlanStaticEgressPorts + "24": {Value: "ports-of-24"},
		oidJnxExVlanName + "24":              {Value: "campus"},
		oidJnxExVlanTag + "24":               {Value: "32"},
	}
	logger, logged := capturingLogger()
	out := ResolveJuniperVlanIndices(in, logger)

	if !reflect.DeepEqual(out, in) {
		t.Errorf("a proven contradiction must refuse the device, got %v", out)
	}
	if !strings.Contains(logged.String(), "disagree") {
		t.Errorf("the refusal must name the disagreement, got %q", logged.String())
	}
}

// TestShippedPolicyWalksNoUnrekeyedStaticColumn converts a comment into a guard.
//
// dot1qVlanStaticColumns says it and the shipped policy "have to stay in step",
// and nothing enforced that. Adding a fifth column to mapping.yaml without
// adding it here would leave that column keyed by the internal index while the
// other four move to the tag — which files one VLAN's ports under another
// VLAN's ID, the precise failure the whole rekey is built to avoid, and no
// existing test would notice.
func TestShippedPolicyWalksNoUnrekeyedStaticColumn(t *testing.T) {
	const staticTable = ".1.3.6.1.2.1.17.7.1.4.3."

	rekeyed := map[string]struct{}{}
	for _, col := range dot1qVlanStaticColumns {
		rekeyed[col] = struct{}{}
	}

	cfg := newTestMappingConfig(t, testLogger())
	walked := 0
	for oid := range cfg.GenericObjectIDs() {
		if !strings.HasPrefix(oid, staticTable) {
			continue
		}
		walked++
		if _, ok := rekeyed[oid+"."]; !ok {
			t.Errorf("%s is walked but not rekeyed: it would keep the device's internal index "+
				"while the other columns move to the tag", oid)
		}
	}
	if walked != len(dot1qVlanStaticColumns) {
		t.Errorf("walked %d columns of dot1qVlanStaticTable, rekey covers %d", walked, len(dot1qVlanStaticColumns))
	}
}

// TestResolveJuniperVlanIndices_ZeroesAPvidAmbiguousWithAnInternalIndex closes
// the last reading of a PVID that names two different VLANs.
//
// On a device that numbers VLANs internally a PVID may be in either space. A
// value that is a real tag AND also one of the device's internal indices
// pointing at a different VLAN therefore names one VLAN under each reading,
// with nothing to say which the device meant. Keeping it binds the port to a
// specific VLAN on a coin flip.
//
// The collision is a property of real hardware: on the reported switch two of
// the 39 tags are also indices resolving elsewhere. Neither is used as a PVID
// there, which is why this costs that device nothing.
func TestResolveJuniperVlanIndices_ZeroesAPvidAmbiguousWithAnInternalIndex(t *testing.T) {
	in := ObjectIDValueMap{
		oidSysObjectIDScalar: {Value: jnxSysObjectID},

		// Index 17 holds the VLAN tagged 156.
		oidDot1qVlanStaticName + "17": {Value: "VL156"},
		oidJnxExVlanName + "17":       {Value: "VL156"},
		oidJnxExVlanTag + "17":        {Value: "156"},
		// Index 40 holds the VLAN tagged 17. So the value 17 is both a real
		// tag and an internal index naming a different VLAN.
		oidDot1qVlanStaticName + "40": {Value: "VL17"},
		oidJnxExVlanName + "40":       {Value: "VL17"},
		oidJnxExVlanTag + "40":        {Value: "17"},
		// Index 41 holds the VLAN tagged 900, which is no index at all.
		oidDot1qVlanStaticName + "41": {Value: "VL900"},
		oidJnxExVlanName + "41":       {Value: "VL900"},
		oidJnxExVlanTag + "41":        {Value: "900"},

		oidDot1qPvid + "1": {Value: "17"},  // ambiguous
		oidDot1qPvid + "2": {Value: "900"}, // a tag, and no index: unambiguous
		oidDot1qPvid + "3": {Value: "156"}, // likewise
	}
	logger, logged := capturingLogger()
	out := ResolveJuniperVlanIndices(in, logger)

	if got := out[oidDot1qPvid+"1"].Value; got != "0" {
		t.Errorf("a PVID that names one VLAN as a tag and another as an index must be zeroed, got %q", got)
	}
	for port, want := range map[string]string{"2": "900", "3": "156"} {
		if got := out[oidDot1qPvid+port].Value; got != want {
			t.Errorf("an unambiguous PVID must survive: port %s = %q, want %q", port, got, want)
		}
	}
	// The rekey itself still happens; only the one port loses its PVID.
	if got := out[oidDot1qVlanStaticName+"156"].Value; got != "VL156" {
		t.Errorf("an ambiguous PVID must not abandon the rekey, got %q", got)
	}
	if !strings.Contains(logged.String(), "ports=1") {
		t.Errorf("the drop must be reported, got %q", logged.String())
	}
}

// TestResolvablePvidValues_KeepsAnIdentityRow pins the exclusion's one carve-out.
//
// A tag that is also its own index is not ambiguous: both readings name the
// same VLAN. Excluding it would zero PVIDs on every device whose internal
// numbering happens to agree with its tags for some rows.
func TestResolvablePvidValues_KeepsAnIdentityRow(t *testing.T) {
	staticIndices := map[int]struct{}{17: {}, 20: {}, 40: {}}
	described := map[int]struct{}{17: {}, 20: {}, 40: {}}
	tagByIndex := map[int]int{
		17: 156, // 156 is no index: unambiguous
		20: 20,  // identity: both readings agree
		40: 17,  // 17 is index 17, which holds 156: ambiguous
	}
	got := resolvablePvidValues(staticIndices, described, tagByIndex)

	for _, want := range []int{156, 20} {
		if _, ok := got[want]; !ok {
			t.Errorf("tag %d names exactly one VLAN and must stay resolvable, got %v", want, got)
		}
	}
	if _, ok := got[17]; ok {
		t.Errorf("tag 17 is also an index naming a different VLAN and must not be resolvable, got %v", got)
	}
}

// TestResolveJuniperVlanIndices_ZeroesAPvidAmbiguousWithAnEnterpriseOnlyIndex
// keeps the two index questions apart.
//
// Whether a PVID value NAMES a VLAN is asked of the static rows, since those
// are the catalog that reaches NetBox. Whether it could be an INDEX has to be
// asked of every row the enterprise table describes, because that is the space
// the device numbers in — and it may describe bridge domains the static table
// never lists, which is what a protocol-learned one looks like.
//
// Asking the second question of the static rows alone kept a PVID whose value
// is an enterprise-only index, binding the port to the VLAN with that tag when
// the device may have meant the VLAN at that index.
func TestResolveJuniperVlanIndices_ZeroesAPvidAmbiguousWithAnEnterpriseOnlyIndex(t *testing.T) {
	in := ObjectIDValueMap{
		oidSysObjectIDScalar: {Value: jnxSysObjectID},

		// The only static row: index 5 holds the VLAN tagged 17.
		oidDot1qVlanStaticName + "5": {Value: "VL17"},
		oidJnxExVlanName + "5":       {Value: "VL17"},
		oidJnxExVlanTag + "5":        {Value: "17"},
		// Index 17 exists in the enterprise table only, holding tag 200. So
		// the value 17 is a real tag AND an index naming a different VLAN.
		oidJnxExVlanName + "17": {Value: "LEARNED"},
		oidJnxExVlanTag + "17":  {Value: "200"},

		oidDot1qPvid + "1": {Value: "17"},
	}
	out := ResolveJuniperVlanIndices(in, testLogger())

	if got := out[oidDot1qPvid+"1"].Value; got != "0" {
		t.Errorf("a PVID whose value is an enterprise-only index must be zeroed, got %q", got)
	}
	// The rekey still happens; only the ambiguous port loses its PVID.
	if got := out[oidDot1qVlanStaticName+"17"].Value; got != "VL17" {
		t.Errorf("an ambiguous PVID must not abandon the rekey, got %q", got)
	}
}

// TestResolvablePvidValues_AsksTheIndexQuestionOfEveryDescribedRow is the same
// distinction at the unit level, where the two sets can be told apart directly.
func TestResolvablePvidValues_AsksTheIndexQuestionOfEveryDescribedRow(t *testing.T) {
	staticIndices := map[int]struct{}{5: {}}
	// 17 is described by the enterprise table but has no static row.
	described := map[int]struct{}{5: {}, 17: {}}
	tagByIndex := map[int]int{5: 17, 17: 200}

	got := resolvablePvidValues(staticIndices, described, tagByIndex)
	if _, ok := got[17]; ok {
		t.Errorf("tag 17 is also an enterprise-only index naming a different VLAN, got %v", got)
	}

	// With that row absent from the enterprise table, 17 is only ever a tag.
	got = resolvablePvidValues(staticIndices, map[int]struct{}{5: {}}, map[int]int{5: 17})
	if _, ok := got[17]; !ok {
		t.Errorf("tag 17 names exactly one VLAN here and must stay resolvable, got %v", got)
	}
}
