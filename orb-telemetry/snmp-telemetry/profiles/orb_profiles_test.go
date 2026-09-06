package profiles

import (
	"io/fs"
	"path"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	kentikRoot = "snmp-profiles"
	orbRoot    = "orb-profiles"
)

// embeddedYAML lists the profile files under root in fsys, relative to root,
// the way readFS keys them.
func embeddedYAML(t *testing.T, fsys fs.FS, root string) []string {
	t.Helper()
	var out []string
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		if d.IsDir() {
			return nil
		}
		if ext := path.Ext(p); ext != ".yml" && ext != ".yaml" {
			return nil
		}
		out = append(out, strings.TrimPrefix(p, root+"/"))
		return nil
	})
	require.NoError(t, err)
	return out
}

func kentikFiles(t *testing.T) []string { return embeddedYAML(t, embeddedProfiles, kentikRoot) }
func orbFiles(t *testing.T) []string    { return embeddedYAML(t, embeddedOrbProfiles, orbRoot) }

// The second tree is bundled through the same reader as the Kentik one, so
// every file in it is addressable by its relative path.
func TestOrbProfiles_EveryFileIsLoaded(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)
	for _, rel := range orbFiles(t) {
		p, ok := l.byFile[rel]
		require.True(t, ok, "%s must be loaded by LoadProfiles", rel)
		assert.Equal(t, OriginEmbedded, p.Origin, rel)
	}
}

// A second embedded root that carries a relative path the first one already
// loaded would silently replace it. That is the override directory's contract,
// not a bundled tree's, so it is refused.
func TestReadFS_RefusesRelativePathAlreadyEmbedded(t *testing.T) {
	first := fstest.MapFS{"a/vendor/x.yml": {Data: []byte("sysobjectid: 1.3.6.1.4.1.1.1\n")}}
	second := fstest.MapFS{"b/vendor/x.yml": {Data: []byte("sysobjectid: 1.3.6.1.4.1.2.2\n")}}

	l := newEmptyLoader("", silentLogger)
	require.NoError(t, l.readFS(first, "a"))
	err := l.readFS(second, "b")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vendor/x.yml")
	assert.Equal(t, StringOrSlice{"1.3.6.1.4.1.1.1"}, l.byFile["vendor/x.yml"].SysObjectID,
		"the first tree's file must be the one kept")
}

// claimKeys returns the matcher keys a raw profile claims, exact and wildcard,
// normalised the way NewMatcher normalises them.
func claimKeys(p *Profile) (exact, wild []string) {
	for _, raw := range p.SysObjectID {
		oid := normalizeOID(raw)
		if key, ok := wildcardKey(oid); ok {
			wild = append(wild, key)
			continue
		}
		exact = append(exact, oid)
	}
	return exact, wild
}

func hasOIDSymbol(p *Profile) bool {
	for _, m := range p.Metrics {
		if m.Symbol != nil && m.Symbol.OID != "" {
			return true
		}
		for _, s := range m.Symbols {
			if s.OID != "" {
				return true
			}
		}
	}
	return false
}

// `extends` resolves by bare basename and keeps the first one seen, so a
// second tree reusing a Kentik basename would either shadow it or be shadowed
// by it depending on read order.
func TestOrbProfiles_BasenamesAreNotKentikBasenames(t *testing.T) {
	kentik := make(map[string]string)
	for _, rel := range kentikFiles(t) {
		kentik[path.Base(rel)] = rel
	}
	for _, rel := range orbFiles(t) {
		if other, clash := kentik[path.Base(rel)]; clash {
			t.Errorf("%s shares its basename with Kentik's %s", rel, other)
		}
	}
}

// Both trees are read into one relative-path namespace.
func TestOrbProfiles_PathsAreNotKentikPaths(t *testing.T) {
	kentik := make(map[string]bool)
	for _, rel := range kentikFiles(t) {
		kentik[rel] = true
	}
	for _, rel := range orbFiles(t) {
		assert.False(t, kentik[rel], "%s exists in both trees", rel)
	}
}

// Every file in the tree must resolve and, after inheritance and dedupe,
// carry at least one symbol with an OID. A stub inherits its symbols; a
// converted profile declares them.
func TestOrbProfiles_EveryFileResolvesToUsableMetrics(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)
	for _, rel := range orbFiles(t) {
		p, err := l.Resolve(rel)
		require.NoError(t, err, rel)
		assert.True(t, hasOIDSymbol(p), "%s resolves to no symbol with an OID", rel)
	}
}

// The tree is additive. It may claim an exact sysObjectID a Kentik wildcard
// covers (exact wins) or a wildcard longer or shorter than a Kentik wildcard
// (longest prefix wins), but never a key Kentik claims verbatim, because the
// matcher would then settle it by read order and log the loser at Debug.
func TestOrbProfiles_ClaimNoKeyKentikClaims(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)

	kentikExact := make(map[string]string)
	kentikWild := make(map[string]string)
	for _, rel := range kentikFiles(t) {
		exact, wild := claimKeys(l.byFile[rel])
		for _, k := range exact {
			kentikExact[k] = rel
		}
		for _, k := range wild {
			kentikWild[k] = rel
		}
	}
	for _, rel := range orbFiles(t) {
		exact, wild := claimKeys(l.byFile[rel])
		for _, k := range exact {
			if other, ok := kentikExact[k]; ok {
				t.Errorf("%s claims exact %s, already claimed by Kentik's %s", rel, k, other)
			}
		}
		for _, k := range wild {
			if other, ok := kentikWild[k]; ok {
				t.Errorf("%s claims wildcard %s, already claimed by Kentik's %s", rel, k, other)
			}
		}
	}
}

// A stub is named `<family>-models.yml` and adds sysObjectIDs to a bundled
// Kentik profile. Its parents must be bundled Kentik profiles, named by bare
// basename, so a Kentik sync that renames or drops the parent fails here
// rather than in production. Stubs are selected by name rather than by having
// no metrics, because one of them redeclares a parent entry.
func TestOrbProfiles_StubsExtendBundledKentikProfiles(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)
	kentik := make(map[string]bool)
	for _, rel := range kentikFiles(t) {
		kentik[rel] = true
	}
	stubs := 0
	for _, rel := range orbFiles(t) {
		if !strings.HasSuffix(rel, "-models.yml") {
			continue
		}
		raw := l.byFile[rel]
		require.NotEmpty(t, raw.Extends, "%s is named as a stub but extends nothing", rel)
		stubs++
		for _, parent := range raw.Extends {
			assert.False(t, strings.Contains(parent, "/"), "%s: extends %q must be a bare basename", rel, parent)
			target, ok := l.byBase[parent]
			require.True(t, ok, "%s: extends %q resolves to nothing", rel, parent)
			assert.True(t, kentik[target], "%s: extends %q resolves to %s, which is not a Kentik profile", rel, parent, target)
		}
	}
	t.Logf("%d stub profiles checked", stubs)
}

// Loading and resolving the bundled set must not warn about any file in the
// second tree. Warnings name the relative path, so the check is per file.
func TestOrbProfiles_LoadAndResolveWithoutWarnings(t *testing.T) {
	logger, buf := captureLogger()
	l, err := LoadProfiles("", logger)
	require.NoError(t, err)
	_, err = l.AllResolved()
	require.NoError(t, err)
	for _, rel := range orbFiles(t) {
		for _, line := range strings.Split(buf.String(), "\n") {
			if strings.Contains(line, rel) {
				t.Errorf("warning mentions %s: %s", rel, line)
			}
		}
	}
}

// keptSymbols lists what a resolved, deduped profile will export: one entry
// per surviving symbol, as exported metric name and the OID it reads.
func keptSymbols(p *Profile) []string {
	var out []string
	for i := range p.Metrics {
		m := &p.Metrics[i]
		if m.Symbol != nil {
			out = append(out, m.Symbol.MetricName()+"|"+m.Symbol.OID)
		}
		for j := range m.Symbols {
			out = append(out, m.Symbols[j].MetricName()+"|"+m.Symbols[j].OID)
		}
	}
	return out
}

// A stub adds sysObjectIDs to a Kentik family and inherits everything else, so
// a device matched through it exports the same series as one matched by the
// Kentik file directly.
//
// Counting entries is not enough. Every entry a stub carries is marked as
// inherited, while the parent's own entries are not, and the metric-name
// contest in dedup.go ranks an own declaration above an inherited one. A
// parent whose own symbol beats an inherited one on that rule alone would
// resolve differently through the stub, with the same entry count.
func TestOrbProfiles_StubInheritsParentMetrics(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)

	cases := map[string]string{ // stub -> Kentik parent rel path
		"cisco/cisco-catalyst-models.yml": "cisco/cisco-catalyst.yml",
		"cisco/cisco-asr-models.yml":      "cisco/cisco-asr.yml",
		"cisco/cisco-nexus-models.yml":    "cisco/cisco-nexus.yml",
		"cisco/cisco-wlc-models.yml":      "cisco/cisco-wlc.yml",
		"juniper/juniper-ex-models.yml":   "juniper/juniper-ex-switches.yml",
		"juniper/juniper-mx-models.yml":   "juniper/juniper-mx-router.yml",
		"juniper/juniper-srx-models.yml":  "juniper/juniper-srx-firewalls.yml",
		"netapp/netapp-ontap-models.yml":  "netapp/netapp-cluster.yml",
		"avtech/roomalert-32s-models.yml": "avtech/roomalert-32s.yml",
	}
	for stub, parent := range cases {
		s, err := l.Resolve(stub)
		require.NoError(t, err, stub)
		p, err := l.Resolve(parent)
		require.NoError(t, err, parent)
		assert.ElementsMatch(t, keptSymbols(p), keptSymbols(s), "%s must export exactly what %s exports", stub, parent)
		assert.Equal(t, p.Provider, s.Provider, "%s must carry its parent's provider", stub)
		assert.NotEmpty(t, s.SysObjectID, stub)
	}

	all, err := l.AllResolved()
	require.NoError(t, err)
	m := NewMatcher(all, silentLogger)
	for oid, want := range map[string]string{
		"1.3.6.1.4.1.9.1.150":          "cisco/cisco-catalyst-models.yml",
		"1.3.6.1.4.1.9.1.3075":         "cisco/cisco-asr-models.yml",
		"1.3.6.1.4.1.9.1.2666":         "cisco/cisco-asr-models.yml",
		"1.3.6.1.4.1.9.1.1915":         "cisco/cisco-nexus-models.yml",
		"1.3.6.1.4.1.9.1.3324":         "cisco/cisco-wlc-models.yml",
		"1.3.6.1.4.1.2636.1.1.1.2.169": "juniper/juniper-ex-models.yml",
		"1.3.6.1.4.1.2636.1.1.1.2.168": "juniper/juniper-mx-models.yml",
		"1.3.6.1.4.1.2636.1.1.1.2.585": "juniper/juniper-srx-models.yml",
		"1.3.6.1.4.1.789.2.99":         "netapp/netapp-ontap-models.yml",
		"1.3.6.1.4.1.789.2.5":          "netapp/netapp-cluster.yml", // Kentik's exact still wins
		"1.3.6.1.4.1.20916.1.11":       "avtech/roomalert-32s-models.yml",
		"1.3.6.1.4.1.20916":            "avtech/roomalert-32s.yml", // Kentik's exact still wins
	} {
		got, ok := m.Match(oid)
		require.True(t, ok, oid)
		assert.Equal(t, want, got.RelPath, oid)
	}
}
