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

	// A single decorated VLAN is still not a convention: with nothing to
	// compare it against, the device has said nothing.
	if got = vlanNamesByVid(juniper(map[int]string{100: "site+100"})); got[100] != "site+100" {
		t.Errorf("one VLAN is not evidence of a convention, got %q", got[100])
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
