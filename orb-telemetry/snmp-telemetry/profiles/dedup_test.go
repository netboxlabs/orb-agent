package profiles

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exportNames returns every metric name a resolved profile still declares, in
// declaration order, so a test can say what survived and what did not.
func exportNames(p *Profile) []string {
	var out []string
	for i := range p.Metrics {
		if p.Metrics[i].Symbol != nil {
			out = append(out, p.Metrics[i].Symbol.ExportName())
		}
		for j := range p.Metrics[i].Symbols {
			out = append(out, p.Metrics[i].Symbols[j].ExportName())
		}
	}
	return out
}

// declaredNames returns the `name:` of every symbol a resolved profile still
// declares, which is what says which of two symbols sharing a metric name won.
func declaredNames(p *Profile) []string {
	var out []string
	for i := range p.Metrics {
		if p.Metrics[i].Symbol != nil {
			out = append(out, p.Metrics[i].Symbol.Name)
		}
		for j := range p.Metrics[i].Symbols {
			out = append(out, p.Metrics[i].Symbols[j].Name)
		}
	}
	return out
}

func TestResolve_MarksInheritedEntriesFromExtended(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "grandparent.yml", `
metrics:
  - MIB: TEST-MIB
    symbol: {name: fromGrandparent, OID: 1.1.0}
`)
	writeYAML(t, dir, "parent.yml", `
extends: [grandparent.yml]
metrics:
  - MIB: TEST-MIB
    symbol: {name: fromParent, OID: 1.2.0}
`)
	writeYAML(t, dir, "child.yml", `
extends: [parent.yml]
sysobjectid: 1.3.6.1.4.1.9.1.46
metrics:
  - MIB: TEST-MIB
    symbol: {name: fromChild, OID: 1.3.0}
`)
	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)

	child, err := l.Resolve("child.yml")
	require.NoError(t, err)
	got := map[string]bool{}
	for _, e := range child.Metrics {
		got[e.Symbol.Name] = e.FromExtended
	}
	assert.Equal(t, map[string]bool{
		"fromGrandparent": true,
		"fromParent":      true,
		"fromChild":       false,
	}, got, "everything but the profile's own file counts as extended")

	// The parent is cached and shared with the child. Marking the child's copy
	// must not have marked the parent's own entry.
	parent, err := l.Resolve("parent.yml")
	require.NoError(t, err)
	for _, e := range parent.Metrics {
		if e.Symbol.Name == "fromParent" {
			assert.False(t, e.FromExtended, "a profile's own entry is not extended in its own resolution")
		}
	}
}

func TestResolve_OwnSymbolBeatsInheritedOneOfTheSameName(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "base.yml", `
metrics:
  - MIB: UCD-SNMP-MIB
    symbol: {name: laLoadInt1Min, OID: 1.3.6.1.4.1.2021.10.1.5.1, tag: CPU}
`)
	writeYAML(t, dir, "device.yml", `
extends: [base.yml]
sysobjectid: 1.3.6.1.4.1.9.1.46
metrics:
  - MIB: VENDOR-MIB
    symbol: {name: vendorCPU, OID: 1.3.6.1.4.1.9.9.305.1.1.1.0, tag: CPU}
`)
	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)

	p, err := l.Resolve("device.yml")
	require.NoError(t, err)
	assert.Equal(t, []string{"vendorCPU"}, declaredNames(p),
		"the profile's own symbol wins whatever the inherited OID length")
	assert.Equal(t, []string{"CPU"}, exportNames(p))

	// The inherited entry lost its only symbol, so nothing is left to walk for it.
	assert.Len(t, p.Metrics, 1)
}

func TestResolve_LongerOIDWinsWhenNeitherIsInherited(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "device.yml", `
sysobjectid: 1.3.6.1.4.1.9.1.46
metrics:
  - MIB: TEST-MIB
    symbols:
      - {name: ioReadBytes, OID: 1.3.6.1.4.1.37447.1.3.8}
      - {name: ioReadBytes, OID: 1.3.6.1.4.1.37447.1.3.8.0}
`)
	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)

	p, err := l.Resolve("device.yml")
	require.NoError(t, err)
	require.Len(t, p.Metrics, 1)
	require.Len(t, p.Metrics[0].Symbols, 1)
	assert.Equal(t, "1.3.6.1.4.1.37447.1.3.8.0", p.Metrics[0].Symbols[0].OID)
}

func TestResolve_LongerOIDDoesNotBeatTheProfilesOwnSymbol(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "base.yml", `
metrics:
  - MIB: TEST-MIB
    symbol: {name: load, OID: 1.3.6.1.4.1.2021.10.1.5.1.99.99}
`)
	writeYAML(t, dir, "device.yml", `
extends: [base.yml]
sysobjectid: 1.3.6.1.4.1.9.1.46
metrics:
  - MIB: TEST-MIB
    symbol: {name: load, OID: 1.2.3.0}
`)
	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)

	p, err := l.Resolve("device.yml")
	require.NoError(t, err)
	require.Len(t, p.Metrics, 1)
	assert.Equal(t, "1.2.3.0", p.Metrics[0].Symbol.OID,
		"the inherited rule is decided before the OID length rule")
}

func TestResolve_AllowDuplicateKeepsTheLoser(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "device.yml", `
sysobjectid: 1.3.6.1.4.1.9.1.46
metrics:
  - MIB: TEST-MIB
    symbols:
      - {name: cempMemPoolUsed, OID: 1.3.6.1.4.1.9.9.221.1.1.1.1.7.1.1, tag: MemoryUsed, allow_duplicate: true}
      - {name: cempMemPoolHCUsed, OID: 1.3.6.1.4.1.9.9.221.1.1.1.1.18, tag: MemoryUsed, allow_duplicate: true}
`)
	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)

	p, err := l.Resolve("device.yml")
	require.NoError(t, err)
	assert.Equal(t, []string{"cempMemPoolUsed", "cempMemPoolHCUsed"}, declaredNames(p),
		"a symbol declaring allow_duplicate is never dropped")
}

// A symbol declaring allow_duplicate protects itself and nothing else: it takes
// part in the contest on the same terms and can still evict a symbol that does
// not declare it.
func TestResolve_AllowDuplicateStillEvictsAnotherSymbol(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "device.yml", `
sysobjectid: 1.3.6.1.4.1.9.1.46
metrics:
  - MIB: TEST-MIB
    symbols:
      - {name: shortOne, OID: 1.2.3.4, tag: CPU}
      - {name: longOne, OID: 1.2.3.4.5.6, tag: CPU, allow_duplicate: true}
`)
	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)

	p, err := l.Resolve("device.yml")
	require.NoError(t, err)
	assert.Equal(t, []string{"longOne"}, declaredNames(p))
}

// A tag renames the metric, so two symbols named the same that carry different
// tags no longer collide, and two symbols named differently that carry one tag
// now do.
func TestResolve_TheContestIsOnTheExportedNameNotTheDeclaredOne(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "device.yml", `
sysobjectid: 1.3.6.1.4.1.9.1.46
metrics:
  - MIB: TEST-MIB
    symbols:
      - {name: hrProcessorLoad, OID: 1.3.6.1.2.1.25.3.3.1.2}
      - {name: hrProcessorLoad, OID: 1.3.6.1.2.1.25.3.3.1.2, tag: CPU}
`)
	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)

	p, err := l.Resolve("device.yml")
	require.NoError(t, err)
	assert.Equal(t, []string{"hrProcessorLoad", "CPU"}, exportNames(p),
		"one name and one tag are two metrics, so neither is dropped")
}

// Two symbols left tied on both rules are separated by declaration order, so a
// device exports the same series on every restart. Upstream leaves this to map
// iteration order.
func TestResolve_ATieIsBrokenByDeclarationOrder(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "device.yml", `
sysobjectid: 1.3.6.1.4.1.9.1.46
metrics:
  - MIB: TEST-MIB
    symbols:
      - {name: fanStatus, OID: 1.3.6.1.4.1.23022.100.2.2.1.2.5.1.2}
      - {name: fanStatus, OID: 1.3.6.1.4.1.23022.100.2.3.1.8.1.1.4}
`)
	for i := 0; i < 20; i++ {
		l, err := NewLoader(dir, silentLogger)
		require.NoError(t, err)
		p, err := l.Resolve("device.yml")
		require.NoError(t, err)
		require.Len(t, p.Metrics[0].Symbols, 1)
		require.Equal(t, "1.3.6.1.4.1.23022.100.2.2.1.2.5.1.2", p.Metrics[0].Symbols[0].OID)
	}
}

// A symbol with neither a name nor a tag exports nothing, so it collides with
// nothing and evicts nothing. One bundled profile declares such a symbol.
func TestResolve_ANamelessSymbolTakesNoPartInTheContest(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "device.yml", `
sysobjectid: 1.3.6.1.4.1.9.1.46
metrics:
  - MIB: TEST-MIB
    symbols:
      - {name: "", OID: ""}
      - {name: "", OID: 1.2.3.4}
      - {name: realOne, OID: 1.2.3.5}
`)
	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)

	p, err := l.Resolve("device.yml")
	require.NoError(t, err)
	assert.Equal(t, []string{"", "", "realOne"}, declaredNames(p))
}

// Inheritance reads the merged parent, not the pruned one. A symbol a parent
// dropped because the parent declared it itself is inherited all the same, and
// in the child both are inherited, where the longer OID decides. Pruning the
// parent first would carry the parent's answer into a contest that is not the
// parent's, and this is the shape where the two answers differ.
func TestResolve_InheritanceReadsTheMergedParent(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "grandparent.yml", `
metrics:
  - MIB: TEST-MIB
    symbol: {name: fromGrandparent, OID: 1.3.6.1.4.1.2021.10.1.5.1.99, tag: CPU}
`)
	writeYAML(t, dir, "parent.yml", `
extends: [grandparent.yml]
metrics:
  - MIB: TEST-MIB
    symbol: {name: fromParent, OID: 1.2.3.0, tag: CPU}
`)
	writeYAML(t, dir, "child.yml", `
extends: [parent.yml]
sysobjectid: 1.3.6.1.4.1.9.1.46
`)
	for _, resolveParentFirst := range []bool{false, true} {
		l, err := NewLoader(dir, silentLogger)
		require.NoError(t, err)
		if resolveParentFirst {
			_, err = l.Resolve("parent.yml")
			require.NoError(t, err)
		}

		child, err := l.Resolve("child.yml")
		require.NoError(t, err)
		assert.Equal(t, []string{"fromGrandparent"}, declaredNames(child),
			"both are inherited in the child, so the longer OID decides")

		parent, err := l.Resolve("parent.yml")
		require.NoError(t, err)
		assert.Equal(t, []string{"fromParent"}, declaredNames(parent),
			"the parent's own resolution still prefers the symbol it declares")
	}
}

// AllResolved returns the profiles the Matcher indexes, so it has to hand back
// the deduplicated ones. The bundled Cisco ISE profile inherits laLoadInt1Min
// tagged CPU from the UCD base profile and declares hrProcessorLoadCombined
// under the same tag.
func TestAllResolved_ReturnsDeduplicatedProfiles(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)
	all, err := l.AllResolved()
	require.NoError(t, err)

	var ise *Profile
	for _, p := range all {
		if p.RelPath == "cisco/cisco-ise.yml" {
			ise = p
		}
	}
	require.NotNil(t, ise)

	var cpu []string
	for _, n := range declaredNames(ise) {
		if n == "laLoadInt1Min" || n == "hrProcessorLoadCombined" {
			cpu = append(cpu, n)
		}
	}
	assert.Equal(t, []string{"hrProcessorLoadCombined"}, cpu,
		"the inherited symbol lost the CPU name to the profile's own")
}

// An entry that lost every symbol is dropped whole. What is left of it names
// tag columns for a metric nothing collects, and walking those columns would
// cost a request per poll and produce no point.
func TestResolve_AnEntryThatLostEverySymbolIsDropped(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "base.yml", `
metrics:
  - MIB: TEST-MIB
    table: {name: oldTable, OID: 1.2.3}
    symbols:
      - {name: oldLoad, OID: 1.2.3.1.1, tag: CPU}
    metric_tags:
      - tag: old_row
        column: {name: oldName, OID: 1.2.3.1.2}
`)
	writeYAML(t, dir, "device.yml", `
extends: [base.yml]
sysobjectid: 1.3.6.1.4.1.9.1.46
metrics:
  - MIB: TEST-MIB
    symbol: {name: newLoad, OID: 9.9.9.0, tag: CPU}
`)
	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)

	p, err := l.Resolve("device.yml")
	require.NoError(t, err)
	require.Len(t, p.Metrics, 1, "the emptied table entry is gone, tag columns and all")
	assert.Equal(t, "newLoad", p.Metrics[0].Symbol.Name)
}

// An entry that keeps at least one symbol keeps its tag columns and its other
// symbols untouched.
func TestResolve_AnEntryThatKeepsASymbolIsOtherwiseUnchanged(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "device.yml", `
sysobjectid: 1.3.6.1.4.1.9.1.46
metrics:
  - MIB: TEST-MIB
    table: {name: theTable, OID: 1.2.3}
    symbols:
      - {name: dropped, OID: 1.2.3.1.1, tag: CPU}
      - {name: kept, OID: 1.2.3.1.2}
      - {name: winner, OID: 1.2.3.1.3.0, tag: CPU}
    metric_tags:
      - tag: row_name
        column: {name: theName, OID: 1.2.3.1.9}
`)
	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)

	p, err := l.Resolve("device.yml")
	require.NoError(t, err)
	require.Len(t, p.Metrics, 1)
	assert.Equal(t, []string{"kept", "winner"}, declaredNames(p))
	assert.Equal(t, "theTable", p.Metrics[0].Table.Name)
	require.Len(t, p.Metrics[0].MetricTags, 1)
	assert.Equal(t, "row_name", p.Metrics[0].MetricTags[0].Tag)
}

// A profile that declares no contested name is returned as it was rather than
// rebuilt, which is what keeps the loader from copying 205 profiles it has no
// reason to touch.
func TestResolve_AProfileWithNoCollisionIsNotRebuilt(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "device.yml", `
sysobjectid: 1.3.6.1.4.1.9.1.46
metrics:
  - MIB: TEST-MIB
    symbols:
      - {name: one, OID: 1.2.3.1}
      - {name: two, OID: 1.2.3.2}
`)
	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)

	first, err := l.Resolve("device.yml")
	require.NoError(t, err)
	again, err := l.Resolve("device.yml")
	require.NoError(t, err)
	assert.Same(t, first, again)
}

// The operator's question when a metric goes missing is which symbol took its
// name, so the drop names both sides.
func TestResolve_ADroppedSymbolIsLogged(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	dir := t.TempDir()
	writeYAML(t, dir, "base.yml", `
metrics:
  - MIB: UCD-SNMP-MIB
    symbol: {name: laLoadInt1Min, OID: 1.3.6.1.4.1.2021.10.1.5.1, tag: CPU}
`)
	writeYAML(t, dir, "device.yml", `
extends: [base.yml]
sysobjectid: 1.3.6.1.4.1.9.1.46
metrics:
  - MIB: VENDOR-MIB
    symbol: {name: vendorCPU, OID: 1.3.6.1.4.1.9.9.305.1.1.1.0, tag: CPU}
`)
	l, err := NewLoader(dir, logger)
	require.NoError(t, err)
	_, err = l.Resolve("device.yml")
	require.NoError(t, err)

	var matched []string
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if strings.Contains(line, "declares one metric name twice") {
			matched = append(matched, line)
		}
	}
	require.Len(t, matched, 1, "logs: %s", logs.String())
	assert.Contains(t, matched[0], "metric_name=CPU")
	assert.Contains(t, matched[0], "dropped_symbol=laLoadInt1Min")
	assert.Contains(t, matched[0], "kept_symbol=vendorCPU")
	assert.Contains(t, matched[0], "file=device.yml")
}
