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

// Three bundled profiles were written from vendor documentation and never run
// against a device. An operator choosing one has to be told that on the row
// they read it from, not in a paragraph elsewhere.
func TestTheReadmeMarksPlaceholderProfiles(t *testing.T) {
	raw, err := os.ReadFile("../README.md")
	require.NoError(t, err)

	for _, name := range []string{"arista_eos", "cisco", "juniper"} {
		marked := false
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.Contains(line, name) && strings.Contains(line, "not yet validated") {
				marked = true
				break
			}
		}
		require.True(t, marked, "%s is not marked as not yet validated on its own line", name)
	}
}
