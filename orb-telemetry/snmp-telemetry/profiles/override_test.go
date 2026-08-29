package profiles

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bundledExactOID is a sysObjectID carried by exactly one bundled profile.
const (
	bundledExactOID  = "1.3.6.1.4.1.890.1.15"
	bundledExactFile = "zyxel-switch.yml"
	bundledExactPath = "zyxel/zyxel-switch.yml"

	// overrideAfterBundled sorts after bundledExactPath, so an override under
	// this name only wins on the override-beats-bundled tiebreak.
	overrideAfterBundled = "zz-zyxel.yml"
)

func captureLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})), &buf
}

// AllResolved ranged an unordered map, so the profile list it returned changed
// on every call. Everything downstream that resolves a collision by input order
// then changed with it, restart to restart.
func TestAllResolved_StableOrder(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)

	first, err := l.AllResolved()
	require.NoError(t, err)
	require.NotEmpty(t, first)

	for range 20 {
		again, err := l.AllResolved()
		require.NoError(t, err)
		require.Len(t, again, len(first))
		for i := range first {
			require.Equal(t, first[i].RelPath, again[i].RelPath, "AllResolved must return a stable order")
		}
	}
}

// An override file placed at the wrong relative path still claims its
// sysObjectID. The winner used to be decided by map iteration order, so the
// same install matched a different profile on each restart.
//
// The fixture name has to sort AFTER the bundled profile's relative path.
// Sorting before it lets first-one-indexed-wins produce the right answer on
// its own, which is what an earlier version of this test measured.
func TestMatcher_OverrideWinsCollidingSysObjectID(t *testing.T) {
	require.Greater(t, overrideAfterBundled, bundledExactPath,
		"the fixture must sort after the bundled profile or the tiebreak is not exercised")

	dir := t.TempDir()
	writeYAML(t, dir, overrideAfterBundled, `
sysobjectid: `+bundledExactOID+`
metrics:
  - symbol:
      name: overrideMarker
      OID: 1.3.6.1.4.1.890.1.15.1.0
`)

	l, err := LoadProfiles(dir, silentLogger)
	require.NoError(t, err)

	// AllResolved re-reads the loader's map on every call, so repeating it here
	// is what the map iteration order used to vary across.
	for range 20 {
		all, err := l.AllResolved()
		require.NoError(t, err)

		got, ok := NewMatcher(all, silentLogger).Match(bundledExactOID)
		require.True(t, ok)
		assert.Equal(t, overrideAfterBundled, got.FileName, "the override profile must win every time")
	}
}

func TestMatcher_WarnsOnCollidingSysObjectID(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "my-zyxel.yml", "sysobjectid: "+bundledExactOID+"\n")

	l, err := LoadProfiles(dir, silentLogger)
	require.NoError(t, err)
	all, err := l.AllResolved()
	require.NoError(t, err)

	logger, buf := captureLogger()
	NewMatcher(all, logger)

	out := buf.String()
	assert.Contains(t, out, bundledExactOID)
	assert.Contains(t, out, "my-zyxel.yml")
	assert.Contains(t, out, bundledExactFile)
}

// The bundled set carries several files that share a basename, which is not an
// operator's mistake and must not warn on a correct install.
func TestMatcher_BundledSetLoadsWithoutWarnings(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)
	all, err := l.AllResolved()
	require.NoError(t, err)

	logger, buf := captureLogger()
	NewMatcher(all, logger)
	assert.Empty(t, buf.String(), "the bundled profiles must load clean")
}

// An override only replaces a bundled profile when its relative path matches.
// A file dropped at the override root is loaded, but replaces nothing, and
// nothing told the operator that before.
func TestLoadProfiles_WarnsOnOverrideWithoutBundledCounterpart(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "system-mib.yml", "metrics: []\n")

	logger, buf := captureLogger()
	_, err := LoadProfiles(dir, logger)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "system-mib.yml")
	assert.Contains(t, out, "_general/system-mib.yml", "the warning must name the path that would replace the bundled profile")
}

func TestLoadProfiles_CorrectlyPlacedOverrideIsSilent(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "_general"), 0o750))
	writeYAML(t, dir, filepath.Join("_general", "system-mib.yml"), "metrics: []\n")

	logger, buf := captureLogger()
	l, err := LoadProfiles(dir, logger)
	require.NoError(t, err)
	assert.Empty(t, buf.String(), "an override at the bundled path replaces it and must not warn")

	p, err := l.Resolve("_general/system-mib.yml")
	require.NoError(t, err)
	assert.Empty(t, p.MetricTags, "the override must replace the bundled profile, not merge with it")
}

// A file named after a bundled profile but placed at the override root wins the
// byFile lookup that extends resolution tries first, so it becomes the parent of
// every bundled profile that extends that basename. The behaviour is pinned here
// because the no-counterpart warning is what tells the operator about it.
func TestResolve_RootOverrideBecomesParentOfBundledProfiles(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "system-mib.yml", `
metric_tags:
  - column:
      OID: 1.3.6.1.2.1.1.5.0
      name: OverrideSysName
`)

	logger, buf := captureLogger()
	l, err := LoadProfiles(dir, logger)
	require.NoError(t, err)
	require.Contains(t, buf.String(), "system-mib.yml", "the operator must be warned about the misplaced file")

	p, err := l.Resolve("3com/3com.yml")
	require.NoError(t, err)
	names := make([]string, 0, len(p.MetricTags))
	for _, tag := range p.MetricTags {
		if tag.Column != nil {
			names = append(names, tag.Column.Name)
		}
	}
	assert.Contains(t, names, "OverrideSysName", "extends resolves the root file ahead of the bundled one")
}
