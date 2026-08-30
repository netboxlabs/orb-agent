package profiles

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var silentLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

func writeYAML(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestNewLoader_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)
	assert.Equal(t, 0, l.Count())
}

func TestNewLoader_SingleProfile(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "device.yml", `
sysobjectid: 1.3.6.1.4.1.9.1.46
metrics:
  - symbol:
      name: cpuUtil
      OID: 1.3.6.1.4.1.9.2.1.56.0
`)
	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)
	assert.Equal(t, 1, l.Count())
}

func TestResolve_NoExtends(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "device.yml", `
sysobjectid: 1.3.6.1.4.1.9.1.46
metrics:
  - symbol:
      name: cpuUtil
      OID: 1.3.6.1.4.1.9.2.1.56.0
`)
	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)

	p, err := l.Resolve("device.yml")
	require.NoError(t, err)
	require.Len(t, p.Metrics, 1)
	assert.Equal(t, "cpuUtil", p.Metrics[0].Symbol.Name)
}

func TestResolve_WithExtends(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "base.yml", `
metrics:
  - symbol:
      name: sysUpTime
      OID: 1.3.6.1.2.1.1.3.0
`)
	writeYAML(t, dir, "device.yml", `
sysobjectid: 1.3.6.1.4.1.9.1.46
extends:
  - base.yml
metrics:
  - symbol:
      name: cpuUtil
      OID: 1.3.6.1.4.1.9.2.1.56.0
`)
	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)

	p, err := l.Resolve("device.yml")
	require.NoError(t, err)
	require.Len(t, p.Metrics, 2, "parent metric should be prepended")
	assert.Equal(t, "sysUpTime", p.Metrics[0].Symbol.Name, "parent metric should come first")
	assert.Equal(t, "cpuUtil", p.Metrics[1].Symbol.Name)
}

func TestResolve_MultiLevelExtends(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "root.yml", `
metrics:
  - symbol:
      name: rootMetric
      OID: 1.1.1.1
`)
	writeYAML(t, dir, "mid.yml", `
extends:
  - root.yml
metrics:
  - symbol:
      name: midMetric
      OID: 1.1.1.2
`)
	writeYAML(t, dir, "leaf.yml", `
sysobjectid: 1.2.3
extends:
  - mid.yml
metrics:
  - symbol:
      name: leafMetric
      OID: 1.1.1.3
`)
	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)

	p, err := l.Resolve("leaf.yml")
	require.NoError(t, err)
	require.Len(t, p.Metrics, 3)
	assert.Equal(t, "rootMetric", p.Metrics[0].Symbol.Name)
	assert.Equal(t, "midMetric", p.Metrics[1].Symbol.Name)
	assert.Equal(t, "leafMetric", p.Metrics[2].Symbol.Name)
}

func TestResolve_CycleRecovered(t *testing.T) {
	// Cycles are detected internally and the offending parent is skipped (logged).
	// Resolve still succeeds and returns the child's own metrics.
	dir := t.TempDir()
	writeYAML(t, dir, "a.yml", `
extends:
  - b.yml
metrics:
  - symbol:
      name: aMetric
      OID: 1.1.1
`)
	writeYAML(t, dir, "b.yml", `
extends:
  - a.yml
metrics:
  - symbol:
      name: bMetric
      OID: 1.1.2
`)
	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)

	p, err := l.Resolve("a.yml")
	require.NoError(t, err, "cycle should be silently recovered, not returned as error")
	require.NotNil(t, p)
	// Child's own metrics must be present even if cycled parent was skipped
	names := make([]string, len(p.Metrics))
	for i, m := range p.Metrics {
		names[i] = m.Symbol.Name
	}
	assert.Contains(t, names, "aMetric")
}

func TestResolve_MissingParentSkipped(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "device.yml", `
sysobjectid: 1.2.3
extends:
  - nonexistent.yml
metrics:
  - symbol:
      name: myMetric
      OID: 1.1.1.1
`)
	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)

	// Should resolve without error (missing parent is logged and skipped)
	p, err := l.Resolve("device.yml")
	require.NoError(t, err)
	require.Len(t, p.Metrics, 1)
}

func TestResolve_CachedOnSecondCall(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "device.yml", `
sysobjectid: 1.2.3
metrics:
  - symbol:
      name: m
      OID: 1.1.1
`)
	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)

	p1, err := l.Resolve("device.yml")
	require.NoError(t, err)
	p2, err := l.Resolve("device.yml")
	require.NoError(t, err)
	assert.Same(t, p1, p2, "second Resolve should return the cached pointer")
}

func TestAllResolved(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "a.yml", `sysobjectid: 1.1`)
	writeYAML(t, dir, "b.yml", `sysobjectid: 1.2`)

	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)

	all, err := l.AllResolved()
	require.NoError(t, err)
	assert.Len(t, all, 2)
}

func TestNewLoader_SubdirRecursive(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "vendor")
	require.NoError(t, os.Mkdir(sub, 0o755))
	writeYAML(t, sub, "device.yml", `sysobjectid: 1.2.3`)

	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)
	assert.Equal(t, 1, l.Count())
}

// The agent image ships only the binary, so a loader that can read profiles
// solely from disk collects nothing in production while every directory-based
// test passes.
func TestLoadProfiles_EmbeddedSetLoadsWithNoOverrideDir(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, l.Count(), 100,
		"LoadProfiles(\"\") must load the embedded set")

	_, err = l.Resolve("base.yml")
	assert.NoError(t, err, "a known embedded profile must resolve")
}

// An override directory adds to the embedded set rather than replacing it.
func TestLoadProfiles_OverrideDirOverlaysRatherThanReplaces(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "local-only.yml", "provider: local-test\n")

	l, err := LoadProfiles(dir, silentLogger)
	require.NoError(t, err)

	_, err = l.Resolve("local-only.yml")
	assert.NoError(t, err, "override profile must load")

	_, err = l.Resolve("base.yml")
	assert.NoError(t, err, "embedded profiles must survive an override dir")
}

func metricNames(p *Profile) []string {
	names := make([]string, len(p.Metrics))
	for i, m := range p.Metrics {
		names[i] = m.Symbol.Name
	}
	return names
}

// Regression test for a bug where two profiles extending the same parent
// could corrupt each other. Resolve built the merged slice as
// append(parent.Metrics, merged.Metrics...); on the first loop iteration
// merged.Metrics is nil, so that append returns parent.Metrics's own slice
// header unchanged, backing array and all. The next line then appended the
// child's own metrics onto that same array. If the parent's slice had any
// spare capacity, the child's metrics landed inside the parent's backing
// array instead of a new one. A second child extending the same parent
// reused that capacity too, silently overwriting the first child's already
// -cached resolved profile.
//
// The existing loader tests never caught this because their fixtures are
// two- or three-file chains where the parent slice is built with exactly
// enough capacity for its own elements (no spare left over). This test
// crafts a parent with spare capacity explicitly, the same shape a
// multi-level extends chain produces in practice (see
// TestLoadProfiles_ResolveAllMatchesIsolatedResolve for that happening with
// the real bundled profiles).
func TestResolve_ParentSpareCapacityNotSharedBetweenChildren(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "childA.yml", `
extends:
  - parent.yml
metrics:
  - symbol:
      name: aOnly
      OID: 9.9.9.1
`)
	writeYAML(t, dir, "childB.yml", `
extends:
  - parent.yml
metrics:
  - symbol:
      name: bOnly
      OID: 9.9.9.2
`)

	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)

	// Inject an already-resolved parent whose Metrics slice has one element
	// but room for four, i.e. len 1, cap 4. This is deterministic, unlike
	// relying on incidental append growth from YAML decoding, and it is
	// exactly the shape a cached parent has after its own extends chain
	// resolves with room to spare.
	parentMetrics := make([]MetricEntry, 1, 4)
	parentMetrics[0] = MetricEntry{Symbol: &Symbol{Name: "parentMetric", OID: "1.1.1"}}
	require.Greater(t, cap(parentMetrics), len(parentMetrics), "fixture requires spare capacity in the parent slice")
	l.resolved["parent.yml"] = &Profile{FileName: "parent.yml", Metrics: parentMetrics}

	childA, err := l.Resolve("childA.yml")
	require.NoError(t, err)
	childB, err := l.Resolve("childB.yml")
	require.NoError(t, err)

	// Assert only after both are resolved: the corruption overwrites
	// childA's already-cached slice when childB is resolved next, so
	// checking childA immediately after its own Resolve call would miss it.
	assert.Equal(t, []string{"parentMetric", "aOnly"}, metricNames(childA),
		"childA must keep its own metric untouched by childB's resolve")
	assert.Equal(t, []string{"parentMetric", "bOnly"}, metricNames(childB),
		"childB must have its own metric, not childA's")
}

// This is the check that actually caught the bug, computed directly and in
// O(n) rather than by re-resolving each of the ~200 bundled profiles against
// a freshly built loader (that alternative built a whole new loader, and so
// reparsed the entire embedded set, once per profile - ~200 loaders each
// walking ~200 files - which dominated this package's -race runtime for no
// real benefit).
//
// The invariant Resolve must uphold is that no two resolved profiles ever
// share a backing array for Metrics or MetricTags. That can be checked
// directly: resolve every bundled profile once from a single shared loader
// (so siblings compete for the same cache the way production does), and
// confirm the address of each non-empty slice's first element is unique
// across all of them. Two simultaneously-alive slices can only report the
// same first-element address if they share a backing array - Go's allocator
// cannot hand out the same address to two distinct live objects - so this
// has no false positives.
//
// Against the unfixed code this fails because juniper/juniper-mx-router.yml
// and juniper/juniper-srx-firewalls.yml both extend
// juniper/juniper-all-devices.yml: the buggy Resolve leaves all three
// profiles' Metrics slices pointing at the same backing array.
func TestLoadProfiles_ResolvedProfilesDoNotShareBackingArrays(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)
	require.NotEmpty(t, l.byFile)

	metricsOwner := make(map[*MetricEntry]string, len(l.byFile))
	tagsOwner := make(map[*MetricTag]string, len(l.byFile))

	for name := range l.byFile {
		p, err := l.Resolve(name)
		require.NoError(t, err)

		if len(p.Metrics) > 0 {
			ptr := &p.Metrics[0]
			if owner, seen := metricsOwner[ptr]; seen {
				t.Fatalf("profile %q and %q share a Metrics backing array", owner, name)
			}
			metricsOwner[ptr] = name
		}
		if len(p.MetricTags) > 0 {
			ptr := &p.MetricTags[0]
			if owner, seen := tagsOwner[ptr]; seen {
				t.Fatalf("profile %q and %q share a MetricTags backing array", owner, name)
			}
			tagsOwner[ptr] = name
		}
	}
}

// TestAllResolved_ReportsInertProfile covers a profile written against a
// schema this loader does not read: it parses, but no metric entry carries a
// symbol, symbols block or table, so it can never yield a value. No bundled
// file is in that state, so the report is silent across the bundle and the
// case is exercised from the override directory.
func TestAllResolved_ReportsInertProfile(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "alien.yml", `
sysobjectid: 1.3.6.1.4.1.99.1
metrics:
  - measurement: cpu
    field: busy
`)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	l, err := LoadProfiles(dir, logger)
	require.NoError(t, err)
	_, err = l.AllResolved()
	require.NoError(t, err)

	out := buf.String()
	require.Contains(t, out, "declares no metric the collector can read")
	require.Contains(t, out, "alien.yml")
	require.Equal(t, 1, strings.Count(out, "declares no metric the collector can read"),
		"no bundled profile is inert, and a base profile with no metric entries is not reported")
}

// The bundled Ruckus controller profile is the one file written in the
// alternate schema: the capitalised match key and the flat metric form. Both
// are read now, so the profile claims the Ruckus enterprise subtree and the
// entries the collector can read carry an OID to walk.
func TestLoadProfiles_RuckusControllerMatchesAndCarriesSymbols(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)
	all, err := l.AllResolved()
	require.NoError(t, err)
	m := NewMatcher(all, silentLogger)

	// A SmartZone controller reporting an OID under the Ruckus enterprise that
	// the two narrower profiles do not cover matched nothing at all before.
	p, ok := m.MatchWithDescr("1.3.6.1.4.1.25053.1.8.1", "Ruckus SmartZone")
	require.True(t, ok, "the Ruckus enterprise subtree has no other generic profile")
	require.Equal(t, "Ruckus_Contoller_SNMP.yml", p.FileName)

	byName := make(map[string]string, len(p.Metrics))
	for _, entry := range p.Metrics {
		if entry.Symbol == nil {
			continue
		}
		require.NotEmpty(t, entry.Symbol.Name, "a symbol with no name writes to no metric")
		require.NotEmpty(t, entry.Symbol.OID, "a symbol with no OID walks the whole tree")
		byName[entry.Symbol.Name] = entry.Symbol.OID
	}
	assert.Len(t, byName, 15, "13 gauges and 2 counters, the 3 traps and 3 tables aside")
	assert.Equal(t, ".1.3.6.1.4.1.25053.2.10.2.17", byName["ruckusSCGCPUPerc"])
	assert.Equal(t, "1.3.6.1.4.1.25053.1.8.1.1.1.2.8.1.50", byName["ruckusCtrlClientStatsTxDataBytes"])
	assert.NotContains(t, byName, "ruckusSCGAPRebootTrap")
	assert.NotContains(t, byName, "ruckusCtrlSummaryApEntry")
}

// The new claim is the broadest pattern under the Ruckus enterprise, so the two
// narrower profiles keep the devices they already served.
func TestLoadProfiles_RuckusControllerDoesNotTakeTheNarrowerProfilesDevices(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)
	all, err := l.AllResolved()
	require.NoError(t, err)
	m := NewMatcher(all, silentLogger)

	for oid, want := range map[string]string{
		"1.3.6.1.4.1.25053.3.1.4.91": "ruckus-wap.yml",
		"1.3.6.1.4.1.25053.3.1.4.7":  "ruckus-wap.yml",
		"1.3.6.1.4.1.25053.3.1.5.15": "ruckus-unleashed.yml",
		"1.3.6.1.4.1.25053.3.1.5.99": "ruckus-unleashed.yml",
	} {
		p, ok := m.Match(oid)
		require.True(t, ok, oid)
		assert.Equal(t, want, p.FileName, oid)
	}
}

// A flat entry naming something the collector cannot read is named rather than
// dropped in silence: the profile keeps claiming the device, so the operator
// has to be able to see which of its metrics never arrive.
func TestAllResolved_ReportsFlatEntriesItCannotRead(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	l, err := LoadProfiles("", logger)
	require.NoError(t, err)
	require.Empty(t, buf.String(), "loading stays quiet, the review runs with the rest")
	_, err = l.AllResolved()
	require.NoError(t, err)

	out := buf.String()
	assert.Equal(t, 6, strings.Count(out, "Ignoring metric entry this collector cannot read"),
		"3 traps and 3 tables in the one bundled file that uses the flat form")
	assert.Contains(t, out, "ruckusSCGAPDisconnectedTrap")
	assert.Contains(t, out, "ruckusCtrlSummaryApEntry")
	assert.Contains(t, out, "Ruckus_Contoller_SNMP.yml")
}

// The report is a property of the file, so a profile many others extend is
// reported once rather than once per profile that inherits its entries.
func TestAllResolved_ReportsAnUnreadableFlatEntryOncePerFile(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "base.yml", `
metrics:
  - name: someTrap
    oid: 1.2.3.4
    type: trap
`)
	writeYAML(t, dir, "childa.yml", "extends: [base.yml]\nsysobjectid: 1.2.3.1\n")
	writeYAML(t, dir, "childb.yml", "extends: [base.yml]\nsysobjectid: 1.2.3.2\n")

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	l, err := NewLoader(dir, logger)
	require.NoError(t, err)
	_, err = l.AllResolved()
	require.NoError(t, err)

	assert.Equal(t, 1, strings.Count(buf.String(), "Ignoring metric entry this collector cannot read"))
}
