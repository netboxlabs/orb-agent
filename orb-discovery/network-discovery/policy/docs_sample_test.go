package policy_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/policy"
)

// documentedSamples are the pages whose yaml examples operators copy.
var documentedSamples = map[string]string{
	"module-readme":  "../README.md",
	"backend-readme": "../../../docs/backends/network_discovery.md",
}

// yamlBlocks returns each ```yaml block of a markdown page, without the lines
// that are only "..." (elided content). A block ends at the next fence of any
// kind, so a block left unclosed fails to parse instead of silently
// swallowing the prose after it.
func yamlBlocks(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var blocks []string
	var cur []string
	in := false
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case in && strings.HasPrefix(trimmed, "```"):
			blocks = append(blocks, strings.Join(cur, "\n"))
			cur, in = nil, false
			if trimmed == "```yaml" {
				in = true
			}
		case in && trimmed == "...":
		case in:
			cur = append(cur, line)
		case trimmed == "```yaml":
			in = true
		}
	}
	require.False(t, in, "%s ends inside a yaml block", path)
	return blocks
}

// Every documented policy example must be one this backend accepts: a policy
// parses and validates, and a defaults fragment does once wrapped in a minimal
// policy. Prose drifts from the parser silently, and the examples are what
// operators copy.
func TestDocumentedSamplesAreAccepted(t *testing.T) {
	m := policy.NewManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	for label, page := range documentedSamples {
		for i, block := range yamlBlocks(t, page) {
			t.Run(fmt.Sprintf("%s/block-%d", label, i+1), func(t *testing.T) {
				var doc map[string]any
				require.NoError(t, yaml.Unmarshal([]byte(block), &doc), "block:\n%s", block)

				var policies map[string]any
				switch {
				case doc["policies"] != nil:
					policies = doc["policies"].(map[string]any)
				case doc["orb"] != nil:
					orb, _ := doc["orb"].(map[string]any)
					if p, ok := orb["policies"].(map[string]any); ok && p["network_discovery"] != nil {
						policies = p["network_discovery"].(map[string]any)
					} else {
						t.Skip("agent configuration without network_discovery policies")
					}
				case doc["defaults"] != nil:
					policies = map[string]any{"doc": map[string]any{
						"config": doc,
						"scope":  map[string]any{"targets": []any{"192.0.2.1"}},
					}}
				default:
					t.Fatalf("unrecognised documented block; teach this test its shape:\n%s", block)
				}

				payload, err := yaml.Marshal(map[string]any{"policies": policies})
				require.NoError(t, err)
				_, err = m.ParsePolicies(payload)
				require.NoError(t, err, "block:\n%s", block)
			})
		}
	}
}
