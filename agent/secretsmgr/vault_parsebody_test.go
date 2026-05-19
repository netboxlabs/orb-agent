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
