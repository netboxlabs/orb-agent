package policy

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

// The README states the limits on attributes; this holds it to the ones
// validation applies. The agent's docs page links to it rather than stating
// them again, so there is one place for the numbers to drift.
func TestTheReadmeStatesTheAttributeLimits(t *testing.T) {
	raw, err := os.ReadFile("../README.md")
	require.NoError(t, err)
	doc := strings.Join(strings.Fields(string(raw)), " ")
	assert.Contains(t, doc, fmt.Sprintf("string of at most %d bytes", config.MaxKeyBytes))
	assert.Contains(t, doc, fmt.Sprintf("A target carries at most %d attributes", config.MaxAttributes))
	assert.Contains(t, doc, fmt.Sprintf("a string value is at most %d bytes", config.MaxStringBytes))
	assert.Contains(t, doc, fmt.Sprintf("Its keys and string values together are at most %d bytes", config.MaxTotalBytes))
}

// The attributes sample must be accepted, and the README's reading of what
// each target carries must be what the merge gives.
func TestTheDocumentedAttributesSampleIsValid(t *testing.T) {
	raw, err := os.ReadFile("../README.md")
	require.NoError(t, err)
	var block string
	for _, part := range strings.Split(string(raw), "```yaml")[1:] {
		body, _, _ := strings.Cut(part, "```")
		if strings.Contains(body, "attributes:") {
			block = body
			break
		}
	}
	require.NotEmpty(t, block, "README has no yaml block with attributes")

	got, err := newTestManager().ParsePolicies([]byte(block))
	require.NoError(t, err, "the documented sample must parse and validate")
	require.Contains(t, got, "edge_metrics")
	r := &Runner{scope: got["edge_metrics"].Scope}
	expanded, _, err := r.expandTargets()
	require.NoError(t, err)
	require.Len(t, expanded, 2)
	assert.Equal(t, config.Attributes{"netbox.site.name": "dc-west", "netbox.tenant.name": "tenant-a"}, expanded[0].Attributes)
	assert.Equal(t, config.Attributes{"netbox.site.name": "dc-east", "netbox.tenant.name": "tenant-a", "rack_units": 2}, expanded[1].Attributes)
}

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
