package mapping

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// listKey
// ---------------------------------------------------------------------------

func TestListKeyDefault(t *testing.T) {
	// empty Key field → default is "name"
	l := ListMap{}
	require.Equal(t, "name", l.listKey())
}

func TestListKeyExplicit(t *testing.T) {
	l := ListMap{Key: "index"}
	require.Equal(t, "index", l.listKey())
}

func TestListKeyEmptyListPath(t *testing.T) {
	// ListPath empty, Key empty → still returns "name"
	l := ListMap{ListPath: ""}
	require.Equal(t, "name", l.listKey())
}

// ---------------------------------------------------------------------------
// merge: child OSVersion override branch
// ---------------------------------------------------------------------------

func TestMergeChildOverridesOSVersion(t *testing.T) {
	parent := &Profile{
		Name:   "parent",
		Device: DeviceMap{Hostname: "/system/state/hostname", OSVersion: "/system/state/software-version"},
	}
	child := &Profile{
		Name:   "child",
		Device: DeviceMap{OSVersion: "/system/config/software-version"},
	}
	out := merge(parent, child)
	require.Equal(t, "/system/config/software-version", out.Device.OSVersion)
	// Hostname not set in child, so parent value is preserved.
	require.Equal(t, "/system/state/hostname", out.Device.Hostname)
}

// ---------------------------------------------------------------------------
// mergeList: child Key override branch
// ---------------------------------------------------------------------------

func TestMergeListChildKeyOverridesParent(t *testing.T) {
	parent := ListMap{Key: "name", Keys: map[string]string{"mtu": "state/mtu"}}
	child := ListMap{Key: "index"}
	out := mergeList(parent, child)
	require.Equal(t, "index", out.Key)
	// Parent keys preserved.
	require.Equal(t, "state/mtu", out.Keys["mtu"])
}

// ---------------------------------------------------------------------------
// addProfile
// ---------------------------------------------------------------------------

func TestAddProfileMalformedYAML(t *testing.T) {
	into := map[string]*Profile{}
	err := addProfile(into, "bad.yaml", []byte(":\tinvalid: yaml: ["))
	require.Error(t, err)
	require.Contains(t, err.Error(), "bad.yaml")
}

func TestAddProfileValidYAML(t *testing.T) {
	into := map[string]*Profile{}
	err := addProfile(into, "test.yaml", []byte(`
match:
  vendor: TestVendor
`))
	require.NoError(t, err)
	p, ok := into["test"]
	require.True(t, ok)
	require.Equal(t, "test", p.Name)
	require.Equal(t, "TestVendor", p.Match.Vendor)
}

// ---------------------------------------------------------------------------
// resolve
// ---------------------------------------------------------------------------

func TestResolveInheritanceCycle(t *testing.T) {
	// a → b → a forms a cycle
	raw := map[string]*Profile{
		"a": {Name: "a", Extends: "b"},
		"b": {Name: "b", Extends: "a"},
	}
	_, err := resolve("a", raw, map[string]bool{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "cycle")
}

func TestResolveProfileNotFound(t *testing.T) {
	raw := map[string]*Profile{
		"a": {Name: "a", Extends: "nonexistent"},
	}
	_, err := resolve("a", raw, map[string]bool{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "nonexistent")
}

func TestResolveNoExtends(t *testing.T) {
	raw := map[string]*Profile{
		"standalone": {Name: "standalone"},
	}
	p, err := resolve("standalone", raw, map[string]bool{})
	require.NoError(t, err)
	require.Equal(t, "standalone", p.Name)
}

// ---------------------------------------------------------------------------
// merge / mergeList
// ---------------------------------------------------------------------------

func TestMergeChildOverridesParentFields(t *testing.T) {
	parent := &Profile{
		Name: "parent",
		Device: DeviceMap{
			Hostname:  "/system/state/hostname",
			OSVersion: "/system/state/software-version",
		},
		Interfaces: ListMap{
			ListPath: "/interfaces/interface",
			Key:      "name",
			Keys:     map[string]string{"mtu": "state/mtu"},
		},
	}
	child := &Profile{
		Name:    "child",
		Extends: "parent",
		Match:   Match{Vendor: "ChildCorp"},
		Device:  DeviceMap{Hostname: "/system/config/hostname"}, // override only Hostname
		Interfaces: ListMap{
			Keys: map[string]string{"description": "config/description"},
		},
	}
	out := merge(parent, child)

	// child fields win
	require.Equal(t, "child", out.Name)
	require.Equal(t, "ChildCorp", out.Match.Vendor)
	require.Equal(t, "/system/config/hostname", out.Device.Hostname)
	// parent OSVersion preserved because child left it empty
	require.Equal(t, "/system/state/software-version", out.Device.OSVersion)
	// parent ListPath preserved
	require.Equal(t, "/interfaces/interface", out.Interfaces.ListPath)
	// child key added to parent keys
	require.Equal(t, "config/description", out.Interfaces.Keys["description"])
	// parent key preserved
	require.Equal(t, "state/mtu", out.Interfaces.Keys["mtu"])
}

// TestMergeInheritsParentMatchWhenChildOmitsIt guards the "override only the
// differences" case: a child that does not restate match.vendor must inherit the
// parent's match criteria (not have it cleared), so auto-detection still selects it.
func TestMergeInheritsParentMatchWhenChildOmitsIt(t *testing.T) {
	parent := &Profile{Name: "parent", Match: Match{Vendor: "Arista"}}
	child := &Profile{Name: "child", Extends: "parent"} // no Match restated
	out := merge(parent, child)
	require.Equal(t, "Arista", out.Match.Vendor, "child must inherit parent's match.vendor")

	// A child that DOES restate match still overrides.
	child2 := &Profile{Name: "child2", Extends: "parent", Match: Match{Vendor: "Cisco"}}
	require.Equal(t, "Cisco", merge(parent, child2).Match.Vendor)
}

func TestMergeListBothEmpty(t *testing.T) {
	out := mergeList(ListMap{}, ListMap{})
	require.Equal(t, "", out.ListPath)
	require.Equal(t, "", out.Key)
	require.Empty(t, out.Keys)
}

func TestMergeListParentKeysPreservedWhenChildEmpty(t *testing.T) {
	parent := ListMap{
		ListPath: "/components/component",
		Keys:     map[string]string{"serial": "state/serial-no"},
	}
	child := ListMap{} // empty child
	out := mergeList(parent, child)
	require.Equal(t, "/components/component", out.ListPath)
	require.Equal(t, "state/serial-no", out.Keys["serial"])
}

func TestMergeListChildOverridesExistingKey(t *testing.T) {
	parent := ListMap{
		Keys: map[string]string{"serial": "state/serial-no"},
	}
	child := ListMap{
		Keys: map[string]string{"serial": "state/serial-number"}, // vendor override
	}
	out := mergeList(parent, child)
	require.Equal(t, "state/serial-number", out.Keys["serial"])
}

func TestMergeListChildAddsNewKey(t *testing.T) {
	parent := ListMap{Keys: map[string]string{"serial": "state/serial-no"}}
	child := ListMap{Keys: map[string]string{"part": "state/part-no"}}
	out := mergeList(parent, child)
	require.Equal(t, "state/serial-no", out.Keys["serial"])
	require.Equal(t, "state/part-no", out.Keys["part"])
}

func TestMergeListChildListPathOverridesParent(t *testing.T) {
	parent := ListMap{ListPath: "/components/component"}
	child := ListMap{ListPath: "/platform/component"}
	out := mergeList(parent, child)
	require.Equal(t, "/platform/component", out.ListPath)
}

// ---------------------------------------------------------------------------
// pathOverlaps
// ---------------------------------------------------------------------------

func TestPathOverlapsEqual(t *testing.T) {
	require.True(t, pathOverlaps("/interfaces/interface", "/interfaces/interface"))
}

func TestPathOverlapsAncestorIsA(t *testing.T) {
	// a is ancestor of b
	require.True(t, pathOverlaps("/interfaces", "/interfaces/interface"))
}

func TestPathOverlapsAncestorIsB(t *testing.T) {
	// b is ancestor of a
	require.True(t, pathOverlaps("/interfaces/interface[name=Eth1]/state/mtu", "/interfaces/interface[name=Eth1]"))
}

func TestPathOverlapsEmptyA(t *testing.T) {
	require.False(t, pathOverlaps("", "/interfaces/interface"))
}

func TestPathOverlapsEmptyB(t *testing.T) {
	require.False(t, pathOverlaps("/interfaces/interface", ""))
}

func TestPathOverlapsBothEmpty(t *testing.T) {
	require.False(t, pathOverlaps("", ""))
}

func TestPathOverlapsNonOverlapping(t *testing.T) {
	require.False(t, pathOverlaps("/interfaces/interface", "/components/component"))
}

func TestPathOverlapsSimilarNameNoBoundary(t *testing.T) {
	// "interface-state" is NOT a child of "interface" — no boundary character follows
	require.False(t, pathOverlaps("/interfaces/interface", "/interfaces/interface-state"))
}

// ---------------------------------------------------------------------------
// leafUnderList
// ---------------------------------------------------------------------------

func TestLeafUnderListHappyPath(t *testing.T) {
	leaf, ok := leafUnderList(
		"/interfaces/interface[name=Eth1]/state/mtu",
		"/interfaces/interface",
	)
	require.True(t, ok)
	require.Equal(t, "state/mtu", leaf)
}

func TestLeafUnderListEmptyListPath(t *testing.T) {
	_, ok := leafUnderList("/interfaces/interface[name=Eth1]/state/mtu", "")
	require.False(t, ok)
}

func TestLeafUnderListNoPrefix(t *testing.T) {
	_, ok := leafUnderList("/system/state/hostname", "/interfaces/interface")
	require.False(t, ok)
}

func TestLeafUnderListMissingCloseBracket(t *testing.T) {
	// path starts with listPath+"[" but ']' is absent
	_, ok := leafUnderList(
		"/interfaces/interface[name=Eth1/state/mtu",
		"/interfaces/interface",
	)
	require.False(t, ok)
}

// ---------------------------------------------------------------------------
// LoadProfilesWithLogger: error / fallback branches
// ---------------------------------------------------------------------------

func TestLoadProfilesWithLoggerBadDir(t *testing.T) {
	// Non-existent overrideDir: warning logged, bundled profiles still load.
	var loggedMsg string
	handler := slogCaptureHandler{capture: &loggedMsg}
	logger := slog.New(handler)

	store, err := LoadProfilesWithLogger("/no/such/dir/at/all", logger)
	require.NoError(t, err)
	_, ok := store.Get("_base")
	require.True(t, ok)
	require.Contains(t, loggedMsg, "profiles_dir")
}

func TestLoadProfilesWithLoggerMalformedOverride(t *testing.T) {
	// A malformed YAML override file is skipped; warning is logged.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte(":\t[invalid"), 0o644))

	var loggedMsg string
	handler := slogCaptureHandler{capture: &loggedMsg}
	logger := slog.New(handler)

	store, err := LoadProfilesWithLogger(dir, logger)
	require.NoError(t, err) // bad file is skipped, not fatal
	_, ok := store.Get("_base")
	require.True(t, ok)
	require.Contains(t, loggedMsg, "broken.yaml")
}

func TestLoadProfilesWithLoggerValidOverride(t *testing.T) {
	// A valid override in a temp dir must merge with bundled profiles.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "vendor_x.yaml"), []byte(`
extends: _base
match:
  vendor: VendorX
`), 0o644))

	store, err := LoadProfilesWithLogger(dir, nil)
	require.NoError(t, err)
	p := store.Match(MatchInput{Vendor: "VendorX Corp"})
	require.Equal(t, "vendor_x", p.Name)
	// Inherits _base hostname path.
	require.Equal(t, "/system/state/hostname", p.Device.Hostname)
}

func TestLoadProfilesWithLoggerSubdirSkipped(t *testing.T) {
	// A subdirectory inside the overrideDir must be silently skipped (not loaded).
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "subdir.yaml"), 0o755)) // name ends in .yaml but is a dir

	store, err := LoadProfilesWithLogger(dir, nil)
	require.NoError(t, err)
	_, ok := store.Get("_base")
	require.True(t, ok)
	// The "subdir.yaml" directory must not appear as a profile.
	_, ok = store.Get("subdir")
	require.False(t, ok)
}

func TestLoadProfilesWithLoggerUnreadableFileSkipped(t *testing.T) {
	// os.Chmod(path, 0o000) is a no-op when running as root (e.g. in some CI
	// containers), so skip the test rather than producing a false pass.
	if os.Geteuid() == 0 {
		t.Skip("chmod-based unreadable file is a no-op as root")
	}

	// A file that exists but cannot be read is skipped with a warning.
	dir := t.TempDir()
	path := filepath.Join(dir, "locked.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`match: {}`), 0o644))
	require.NoError(t, os.Chmod(path, 0o000))
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) }) // restore so temp cleanup works

	var loggedMsg string
	handler := slogCaptureHandler{capture: &loggedMsg}
	logger := slog.New(handler)

	store, err := LoadProfilesWithLogger(dir, logger)
	require.NoError(t, err) // unreadable file is skipped, not fatal
	_, ok := store.Get("_base")
	require.True(t, ok)
	// The warning must mention the filename so the operator knows which file was skipped.
	require.Contains(t, loggedMsg, "locked.yaml",
		"warning log must mention the unreadable filename")
}

func TestLoadProfilesWithLoggerBadInheritanceSkipped(t *testing.T) {
	// An override that extends a non-existent profile should be skipped with a
	// warning, leaving _base intact.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "orphan.yaml"), []byte(`
extends: does_not_exist
match:
  vendor: OrphanCorp
`), 0o644))

	var loggedMsg string
	handler := slogCaptureHandler{capture: &loggedMsg}
	logger := slog.New(handler)

	store, err := LoadProfilesWithLogger(dir, logger)
	require.NoError(t, err)
	_, ok := store.Get("orphan")
	require.False(t, ok, "unresolvable profile must be dropped from the store")
	require.Contains(t, loggedMsg, "orphan")
}

// ---------------------------------------------------------------------------
// slogCaptureHandler — minimal slog.Handler that records the last log message
// ---------------------------------------------------------------------------

type slogCaptureHandler struct {
	capture *string
}

func (h slogCaptureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h slogCaptureHandler) Handle(_ context.Context, r slog.Record) error {
	*h.capture = r.Message
	r.Attrs(func(a slog.Attr) bool {
		*h.capture += " " + a.Key + "=" + a.Value.String()
		return true
	})
	return nil
}
func (h slogCaptureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h slogCaptureHandler) WithGroup(_ string) slog.Handler      { return h }
