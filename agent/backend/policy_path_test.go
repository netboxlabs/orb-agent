package backend_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
)

// TestPolicyPathSegment covers the two halves of the contract: names that
// reach the backend intact once escaped, and the one that cannot.
func TestPolicyPathSegment(t *testing.T) {
	// Names that already worked. These must come back byte-identical to what
	// the client was sending before escaping was added, or the escaping is
	// double-encoding: the client was already sending a space as %20.
	for name, want := range map[string]string{
		"dummy-policy-name": "dummy-policy-name",
		"core metrics":      "core%20metrics",
		"café":              "caf%C3%A9",
		"policy-1_v2.0":     "policy-1_v2.0",
		"a+b":               "a+b",
		"a&b":               "a&b",
		"a:b":               "a:b",
	} {
		got, err := backend.PolicyPathSegment(name)
		require.NoError(t, err, "name %q", name)
		assert.Equal(t, want, got, "name %q", name)
	}

	// Characters that never reached the backend before escaping.
	for name, want := range map[string]string{
		"My Office Network #2": "My%20Office%20Network%20%232",
		"reports?live":         "reports%3Flive",
		"100%":                 "100%25",
	} {
		got, err := backend.PolicyPathSegment(name)
		require.NoError(t, err, "name %q", name)
		assert.Equal(t, want, got, "name %q", name)
	}

	// A slash is refused rather than escaped. %2F is decoded back into a
	// separator before the receiving framework routes, so escaping cannot
	// keep the name in one segment; see the helper's doc comment.
	for _, name := range []string{"nightly/", "a/b", "/leading"} {
		_, err := backend.PolicyPathSegment(name)
		require.Error(t, err, "name %q must be refused", name)
		assert.Contains(t, err.Error(), "slash")
	}
}
