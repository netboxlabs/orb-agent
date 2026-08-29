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
func TestLoadProfiles_WarnsOnMisplacedOverride(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "system-mib.yml", "metrics: []\n")

	logger, buf := captureLogger()
	_, err := LoadProfiles(dir, logger)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "system-mib.yml")
	assert.Contains(t, out, "_general/system-mib.yml", "the warning must name the path that would replace the bundled profile")
}

// Adding a vendor the bundled set does not carry is a supported use of the
// override directory. Its basename appears nowhere in the bundled set, so
// there is no bundled profile it could have been meant to replace and nothing
// to warn about.
func TestLoadProfiles_NewVendorProfileIsSilent(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "acme-router.yml", "sysobjectid: 1.3.6.1.4.1.99999.1\n")

	logger, buf := captureLogger()
	l, err := LoadProfiles(dir, logger)
	require.NoError(t, err)
	assert.Empty(t, buf.String(), "a brand-new profile replaces nothing by design and must not warn")

	_, err = l.Resolve("acme-router.yml")
	require.NoError(t, err, "the new profile must still load")
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

// A file named after a bundled profile but placed at the override root used to
// win the byFile lookup extends resolution tried first, so one mislocated file
// became the parent of every bundled profile extending that basename: 164 of
// them for system-mib.yml. A bare basename now goes through the basename index,
// so the bundled parent stays the parent.
func TestResolve_RootOverrideDoesNotReparentBundledProfiles(t *testing.T) {
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

	child, err := l.Resolve("3com/3com.yml")
	require.NoError(t, err)
	assert.NotContains(t, tagColumnNames(child), "OverrideSysName",
		"extends must resolve the bundled parent, not a file at the override root")

	bundledParent, err := l.Resolve("system-mib.yml")
	require.NoError(t, err)
	assert.Equal(t, "_general/system-mib.yml", bundledParent.RelPath,
		"a bare basename must resolve through the basename index")

	// The mislocated file is still loaded, it just parents nothing.
	all, err := l.AllResolved()
	require.NoError(t, err)
	var found *Profile
	for _, p := range all {
		if p.RelPath == "system-mib.yml" {
			found = p
		}
	}
	require.NotNil(t, found, "the mislocated override must still be loaded")
	assert.Contains(t, tagColumnNames(found), "OverrideSysName")
}

func tagColumnNames(p *Profile) []string {
	names := make([]string, 0, len(p.MetricTags))
	for _, tag := range p.MetricTags {
		if tag.Column != nil {
			names = append(names, tag.Column.Name)
		}
	}
	return names
}
