package policy

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/config"
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
// each target carries must be what the inheritance gives.
func TestTheDocumentedAttributesSampleIsValid(t *testing.T) {
	raw, err := os.ReadFile("../README.md")
	require.NoError(t, err)
	var block string
	for _, part := range strings.Split(string(raw), "```yaml")[1:] {
		body, _, _ := strings.Cut(part, "```")
		if strings.Contains(body, "attributes:") && strings.Contains(body, "policies:") {
			block = body
			break
		}
	}
	require.NotEmpty(t, block, "README has no policy yaml block with attributes")

	got, err := newTestManager().ParsePolicies([]byte(block))
	require.NoError(t, err, "the documented sample must parse and validate")
	require.Contains(t, got, "edge_metrics")
	targets := got["edge_metrics"].Scope.Targets
	require.Len(t, targets, 2)
	assert.Equal(t, config.Attributes{"netbox.site.name": "dc-west", "netbox.tenant.name": "tenant-a"}, targets[0].Attributes)
	assert.Equal(t, config.Attributes{"netbox.site.name": "dc-east", "netbox.tenant.name": "tenant-a", "rack_units": 2}, targets[1].Attributes)
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
