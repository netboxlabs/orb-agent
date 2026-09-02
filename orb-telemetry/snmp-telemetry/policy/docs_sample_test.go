package policy

import (
	"fmt"
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

// The README described a retry validation the runner does not perform: it said
// a policy whose retry ceiling reaches metrics_interval is rejected, where the
// runner warns and starts it. Each claim is checked beside the call that
// decides it, so re-tightening one without rewriting the other fails here.
func TestTheDocumentedRetryRuleMatchesTheRunner(t *testing.T) {
	raw, err := os.ReadFile("../README.md")
	require.NoError(t, err)
	// Collapsed, since the prose is wrapped and a claim can straddle a line.
	doc := strings.Join(strings.Fields(string(raw)), " ")
	says := func(claim string) {
		t.Helper()
		require.Contains(t, doc, claim, "the README does not say this")
	}

	// A single attempt that fills the interval can never produce a sample.
	_, err = NewRunner(t.Context(), testLogger, "p1", policyWithDial(30, 30, 0), &spyCollector{}, nil)
	require.Error(t, err)
	says("is rejected, because a single attempt filling the interval can never produce a sample")

	// A retry sequence that reaches the interval starts anyway, and an
	// unresponsive device gets a truncated sequence rather than a refusal.
	_, err = NewRunner(t.Context(), testLogger, "p1", policyWithDial(10, 9, 10), &spyCollector{}, nil)
	require.NoError(t, err)
	says("warned about rather than rejected")
	says("the retry sequence is cut short when the interval runs out")

	// A count past the ceiling is refused rather than warned about, because
	// the client allocates on it.
	_, err = NewRunner(t.Context(), testLogger, "p1", policyWithDial(10, 9, maxPolicyRetries+1), &spyCollector{}, nil)
	require.Error(t, err)
	says(fmt.Sprintf("`retries` is capped at %d", maxPolicyRetries))
}
