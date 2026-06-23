package mapping

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVetAssetTag(t *testing.T) {
	// Valid.
	if reason, ok := vetAssetTag("NB-12345"); !ok {
		t.Fatalf("expected valid, got reason=%q", reason)
	}
	// Placeholders (case-insensitive, exact).
	for _, p := range []string{"unknown", "N/A", "None", "no asset tag", "0", "TBD"} {
		if _, ok := vetAssetTag(p); ok {
			t.Errorf("expected placeholder %q to be rejected", p)
		}
	}
	// A real tag that merely contains a placeholder substring still passes.
	if _, ok := vetAssetTag("NA1234"); !ok {
		t.Errorf("expected %q to pass (substring of a placeholder, not equal)", "NA1234")
	}
	// Over NetBox's 50-rune column.
	if _, ok := vetAssetTag(strings.Repeat("a", 51)); ok {
		t.Errorf("expected over-length tag to be rejected")
	}
	if _, ok := vetAssetTag(strings.Repeat("a", 50)); !ok {
		t.Errorf("expected exactly-50-rune tag to pass")
	}
	// Control character / invalid text.
	if _, ok := vetAssetTag("bad\x00tag"); ok {
		t.Errorf("expected control-character tag to be rejected")
	}
}

func TestResolveAssetTag(t *testing.T) {
	snap := map[string]any{
		"/components/component[name=Chassis]/state/id": "ASSET-9",
		"/components/component[name=Chassis]/state/x":  "unknown", // placeholder
		"/components/component[name=Chassis]/state/y":  "",        // empty
	}

	// Literal value (no fetch needed).
	got, ok := ResolveAssetTag("LITERAL-1", snap, nil)
	assert.True(t, ok)
	assert.Equal(t, "LITERAL-1", got)

	// Path reference resolved from the snapshot, vetted.
	got, ok = ResolveAssetTag("/components/component[name=Chassis]/state/id", snap, nil)
	assert.True(t, ok)
	assert.Equal(t, "ASSET-9", got)

	// Path reference resolving to a placeholder → rejected.
	_, ok = ResolveAssetTag("/components/component[name=Chassis]/state/x", snap, nil)
	assert.False(t, ok)

	// Path reference resolving to empty → rejected.
	_, ok = ResolveAssetTag("/components/component[name=Chassis]/state/y", snap, nil)
	assert.False(t, ok)

	// Path reference not in snapshot and no fetch → unresolved.
	_, ok = ResolveAssetTag("/components/component[name=Chassis]/state/missing", snap, nil)
	assert.False(t, ok)

	// Path reference not in snapshot but a fetch provides it (targeted Get).
	fetch := func(path string) (string, bool) {
		if path == "/components/component[name=Chassis]/state/asset-id" {
			return "FETCHED-7", true
		}
		return "", false
	}
	got, ok = ResolveAssetTag("/components/component[name=Chassis]/state/asset-id", snap, fetch)
	assert.True(t, ok)
	assert.Equal(t, "FETCHED-7", got)

	// Fetch miss → unresolved.
	_, ok = ResolveAssetTag("/components/component[name=Chassis]/state/none", snap, fetch)
	assert.False(t, ok)

	// Empty default → not set.
	_, ok = ResolveAssetTag("", snap, nil)
	assert.False(t, ok)
}
