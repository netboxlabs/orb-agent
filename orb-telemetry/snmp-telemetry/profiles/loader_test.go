package profiles

import (
	"log/slog"
	"os"
	"path/filepath"
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
