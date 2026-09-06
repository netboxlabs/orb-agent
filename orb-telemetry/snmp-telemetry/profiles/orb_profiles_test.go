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
