package policy

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The documented sample must be a policy this backend accepts. Prose drifts from
// the parser silently, and a sample is the thing operators copy.
func TestTheDocumentedSamplePolicyIsValid(t *testing.T) {
	raw, err := os.ReadFile("../README.md")
	require.NoError(t, err)

	_, rest, ok := strings.Cut(string(raw), "```yaml")
	require.True(t, ok, "README has no yaml block")
	block, _, ok := strings.Cut(rest, "```")
	require.True(t, ok, "README has an unterminated yaml block")

	m := newTestManager()
	_, err = m.ParsePolicies([]byte(block))
	require.NoError(t, err, "the documented sample must parse and validate")
}
