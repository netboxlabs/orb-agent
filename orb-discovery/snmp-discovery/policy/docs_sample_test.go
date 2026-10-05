package policy_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/data"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/policy"
)

// documentedSamples are the pages whose yaml examples operators copy.
var documentedSamples = map[string]string{
	"module-readme":  "../README.md",
	"backend-readme": "../../../docs/backends/snmp_discovery/README.md",
}

var envReference = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// yamlBlocks returns each ```yaml block of a markdown page. A block ends at the
// next fence of any kind, so a block left unclosed fails to parse instead of
// silently swallowing the prose after it.
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
		case in:
			cur = append(cur, line)
		case trimmed == "```yaml":
			in = true
		}
	}
	require.False(t, in, "%s ends inside a yaml block", path)
	return blocks
}

// Every documented example must be one this backend accepts: a policy parses
// and validates, a policy fragment does once wrapped in a minimal policy, and a
// lookup file loads without error. Prose drifts from the parser silently, and
// the examples are what operators copy.
func TestDocumentedSamplesAreAccepted(t *testing.T) {
	m, err := policy.NewManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	require.NoError(t, err)
	target := map[string]any{"host": "192.0.2.1"}
	auth := map[string]any{"protocol_version": "SNMPv2c", "community": "public"}

	for label, page := range documentedSamples {
		for i, block := range yamlBlocks(t, page) {
			t.Run(fmt.Sprintf("%s/block-%d", label, i+1), func(t *testing.T) {
				for _, ref := range envReference.FindAllStringSubmatch(block, -1) {
					t.Setenv(ref[1], "example")
				}
				var doc map[string]any
				require.NoError(t, yaml.Unmarshal([]byte(block), &doc), "block:\n%s", block)

				var policies map[string]any
				switch {
				case doc["policies"] != nil:
					policies = doc["policies"].(map[string]any)
				case doc["orb"] != nil:
					orb, _ := doc["orb"].(map[string]any)
					if p, ok := orb["policies"].(map[string]any); ok && p["snmp_discovery"] != nil {
						policies = p["snmp_discovery"].(map[string]any)
					} else {
						t.Skip("agent configuration without snmp_discovery policies")
					}
				case doc["config"] != nil || doc["scope"] != nil:
					policies = map[string]any{"doc": doc}
				case doc["defaults"] != nil:
					policies = map[string]any{"doc": map[string]any{
						"config": doc,
						"scope":  map[string]any{"targets": []any{target}, "authentication": auth},
					}}
				case doc["authentication"] != nil:
					policies = map[string]any{"doc": map[string]any{
						"scope": map[string]any{"targets": []any{target}, "authentication": doc["authentication"]},
					}}
				case doc["devices"] != nil || doc["modules"] != nil || doc["manufacturers"] != nil:
					dir := t.TempDir()
					require.NoError(t, os.WriteFile(filepath.Join(dir, "doc.yaml"), []byte(block), 0o600))
					lookup, err := data.LoadDeviceLookupExtensions(dir)
					require.NoError(t, err)
					files := lookup.UserExtensionFiles()
					require.Len(t, files, 1)
					require.NoError(t, files[0].Err)
					require.NoError(t, files[0].ModulesErr)
					require.Positive(t, files[0].Entries+files[0].ModuleEntries+files[0].ManufacturerEntries,
						"the lookup example registers nothing")
					return
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
