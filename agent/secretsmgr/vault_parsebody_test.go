package secretsmgr

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

// vaultManagerWith returns a vaultManager wired only with the bits parseBody
// reads — no Vault client, no Docker dependency.
func vaultManagerWith(defaultMount string) *vaultManager {
	return &vaultManager{
		config: config.VaultManager{Mount: defaultMount},
	}
}

func TestVaultParseBody_LegacySingleSegmentMount(t *testing.T) {
	// Backward compatibility: every existing placeholder without "//" and
	// without a configured default mount must keep its current semantics.
	v := vaultManagerWith("")

	ref, err := v.parseBody("kv/app/cred/password")
	require.NoError(t, err)
	require.Equal(t, "kv", ref.mount)
	require.Equal(t, "app/cred", ref.path)
	require.Equal(t, "password", ref.field)
}

func TestVaultParseBody_LegacyRequiresThreeSegments(t *testing.T) {
	v := vaultManagerWith("")

	_, err := v.parseBody("kv/password")
	require.Error(t, err)
	require.Contains(t, err.Error(), "legacy form")
}

func TestVaultParseBody_QualifiedMultiSegmentMount(t *testing.T) {
	v := vaultManagerWith("")

	ref, err := v.parseBody("foo/bar//app/cred/password")
	require.NoError(t, err)
	require.Equal(t, "foo/bar", ref.mount)
	require.Equal(t, "app/cred", ref.path)
	require.Equal(t, "password", ref.field)
}

func TestVaultParseBody_QualifiedDeeplyNestedMount(t *testing.T) {
	v := vaultManagerWith("")

	ref, err := v.parseBody("a/b/c/d//team/svc/api_key")
	require.NoError(t, err)
	require.Equal(t, "a/b/c/d", ref.mount)
	require.Equal(t, "team/svc", ref.path)
	require.Equal(t, "api_key", ref.field)
}

func TestVaultParseBody_QualifiedSingleSegmentMount(t *testing.T) {
	v := vaultManagerWith("")

	ref, err := v.parseBody("kv//app/cred/password")
	require.NoError(t, err)
	require.Equal(t, "kv", ref.mount)
	require.Equal(t, "app/cred", ref.path)
	require.Equal(t, "password", ref.field)
}

func TestVaultParseBody_ShortFormUsesDefaultMount(t *testing.T) {
	v := vaultManagerWith("foo/bar")

	ref, err := v.parseBody("app/cred/password")
	require.NoError(t, err)
	require.Equal(t, "foo/bar", ref.mount)
	require.Equal(t, "app/cred", ref.path)
	require.Equal(t, "password", ref.field)
}

func TestVaultParseBody_QualifiedOverridesDefaultMount(t *testing.T) {
	// If a placeholder is explicit (//), it wins over the configured default.
	v := vaultManagerWith("foo/bar")

	ref, err := v.parseBody("other//path/key")
	require.NoError(t, err)
	require.Equal(t, "other", ref.mount)
	require.Equal(t, "path", ref.path)
	require.Equal(t, "key", ref.field)
}

func TestVaultParseBody_RejectsEmptyBody(t *testing.T) {
	v := vaultManagerWith("kv")

	_, err := v.parseBody("")
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty body")
}

func TestVaultParseBody_RejectsEmptyMountBeforeSeparator(t *testing.T) {
	v := vaultManagerWith("")

	_, err := v.parseBody("//path/key")
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty mount")
}

func TestVaultParseBody_RejectsMissingPathInQualified(t *testing.T) {
	v := vaultManagerWith("")

	_, err := v.parseBody("foo/bar//field")
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least one path segment")
}

func TestVaultParseBody_RejectsEmptyRemainderAfterSeparator(t *testing.T) {
	v := vaultManagerWith("")

	_, err := v.parseBody("foo/bar//")
	require.Error(t, err)
}

func TestVaultParseBody_RejectsEmptyFieldShortForm(t *testing.T) {
	v := vaultManagerWith("kv")

	_, err := v.parseBody("app/cred/")
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty field")
}

func TestVaultParseBody_ShortFormRequiresPathAndField(t *testing.T) {
	v := vaultManagerWith("kv")

	_, err := v.parseBody("just-one-segment")
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least one path segment")
}

// TestVaultParseBody_RejectsEmptySegments locks in the contract that every
// path segment (mount, intermediate path, field) is non-empty across all
// three grammars. Without these checks, leading/trailing/consecutive "/"
// in the body would reach the Vault client and produce 404s that are
// hard to trace back to a malformed placeholder.
func TestVaultParseBody_RejectsEmptySegments(t *testing.T) {
	cases := []struct {
		name         string
		defaultMount string
		body         string
		wantContains string
	}{
		// Legacy form (no "//" anywhere in the body).
		{"legacy leading slash → empty mount", "", "/app/cred/password", "empty mount"},
		{"legacy trailing slash → empty field", "", "kv/app/cred/", "empty field"},
		// Qualified form.
		{"qualified empty inner segment in path", "", "foo//a//b/key", "empty path segment"},
		{"qualified triple-slash → empty path segment", "", "kv///app/key", "empty path segment"},
		{"qualified trailing slash → empty field", "", "foo//app/cred/", "empty field"},
		{"qualified mount with leading slash", "", "/foo//app/key", "mount contains an empty path segment"},
		{"qualified mount with inner empty segment", "", "foo//bar//app/key", "empty path segment"},
		// Short form (default mount configured).
		{"short form leading slash → empty path segment", "foo/bar", "/app/key", "empty path segment"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := vaultManagerWith(tc.defaultMount)
			_, err := v.parseBody(tc.body)
			require.Error(t, err, "body %q should have been rejected", tc.body)
			require.Contains(t, err.Error(), tc.wantContains, "body %q: error %q", tc.body, err.Error())
		})
	}
}
