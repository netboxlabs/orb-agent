package policy_test

import (
	"bytes"
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

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/data"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/policy"
)

// documentedPage is a page whose yaml examples operators copy. A shared page
// also documents other backends, so its blocks for them are skipped.
type documentedPage struct {
	label, path string
	shared      bool
}

var documentedPages = []documentedPage{
	{"module-readme", "../README.md", false},
	{"backend-readme", "../../../docs/backends/snmp_discovery/README.md", false},
	{"interface-doc", "../../../docs/backends/snmp_discovery/interface.md", false},
	{"config-samples", "../../../docs/config_samples.md", true},
}

var (
	envReference = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	fenceLine    = regexp.MustCompile("^\\s*(`{3,}|~{3,})\\s*(\\S*)")
)

type yamlBlock struct {
	line int
	text string
}

// yamlBlocks returns each yaml or yml fenced block of a markdown page. A
// fence with an info string inside an open yaml block means that block was
// never closed, which fails the test rather than swallowing what follows.
func yamlBlocks(t *testing.T, path string) []yamlBlock {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var blocks []yamlBlock
	var cur []string
	var yamlFence, otherFence string
	start := 0
	closes := func(m []string, open string) bool {
		return m != nil && m[2] == "" && m[1][0] == open[0] && len(m[1]) >= len(open)
	}
	for i, line := range strings.Split(string(raw), "\n") {
		m := fenceLine.FindStringSubmatch(line)
		switch {
		case yamlFence != "":
			if closes(m, yamlFence) {
				blocks = append(blocks, yamlBlock{start, strings.Join(cur, "\n")})
				cur, yamlFence = nil, ""
				continue
			}
			require.Nil(t, m, "%s:%d: fence inside the yaml block opened at line %d, which is never closed", path, i+1, start)
			cur = append(cur, line)
		case otherFence != "":
			if closes(m, otherFence) {
				otherFence = ""
			}
		case m != nil:
			if lang := strings.ToLower(m[2]); lang == "yaml" || lang == "yml" {
				yamlFence, start = m[1], i+1
			} else {
				otherFence = m[1]
			}
		}
	}
	require.Empty(t, yamlFence, "%s ends inside the yaml block opened at line %d", path, start)
	return blocks
}

// documentedPatterns compiles every interface_patterns match and
// interface_exclude_patterns entry in v. The policy parser accepts an invalid
// one, which then fails every scan.
func documentedPatterns(t *testing.T, v any) {
	t.Helper()
	switch v := v.(type) {
	case map[string]any:
		for k, child := range v {
			list, _ := child.([]any)
			for _, item := range list {
				switch k {
				case "interface_patterns":
					if p, ok := item.(map[string]any); ok {
						_, err := regexp.Compile(fmt.Sprint(p["match"]))
						require.NoError(t, err)
					}
				case "interface_exclude_patterns":
					_, err := regexp.Compile(fmt.Sprint(item))
					require.NoError(t, err)
				}
			}
			documentedPatterns(t, child)
		}
	case []any:
		for _, child := range v {
			documentedPatterns(t, child)
		}
	}
}

// Every documented example must be one this backend accepts: a policy parses
// and validates with no unknown key, a policy fragment does once wrapped in a
// minimal policy, and a lookup file loads without error. Prose drifts from the
// parser silently, and the examples are what operators copy.
func TestDocumentedSamplesAreAccepted(t *testing.T) {
	m, err := policy.NewManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	require.NoError(t, err)
	target := map[string]any{"host": "192.0.2.1"}
	auth := map[string]any{"protocol_version": "SNMPv2c", "community": "public"}
	minimal := func(cfg map[string]any) map[string]any {
		return map[string]any{"doc": map[string]any{
			"config": cfg,
			"scope":  map[string]any{"targets": []any{target}, "authentication": auth},
		}}
	}

	for _, page := range documentedPages {
		for _, block := range yamlBlocks(t, page.path) {
			t.Run(fmt.Sprintf("%s/line-%d", page.label, block.line), func(t *testing.T) {
				for _, ref := range envReference.FindAllStringSubmatch(block.text, -1) {
					t.Setenv(ref[1], "example")
				}
				var doc map[string]any
				require.NoError(t, yaml.Unmarshal([]byte(block.text), &doc), "block:\n%s", block.text)

				var policies map[string]any
				switch {
				case doc["policies"] != nil:
					policies = doc["policies"].(map[string]any)
				case doc["orb"] != nil:
					orb, _ := doc["orb"].(map[string]any)
					all, ok := orb["policies"].(map[string]any)
					if !ok {
						t.Skip("agent configuration without policies")
					}
					if all["snmp_discovery"] == nil {
						if page.shared {
							t.Skip("policies for other backends")
						}
						t.Fatalf("orb.policies on this backend's page has no snmp_discovery key:\n%s", block.text)
					}
					policies = all["snmp_discovery"].(map[string]any)
				case doc["config"] != nil || doc["scope"] != nil:
					policies = map[string]any{"doc": doc}
				case doc["defaults"] != nil:
					policies = minimal(doc)
				case doc["interface_patterns"] != nil:
					policies = minimal(map[string]any{"defaults": doc})
				case doc["authentication"] != nil:
					policies = map[string]any{"doc": map[string]any{
						"scope": map[string]any{"targets": []any{target}, "authentication": doc["authentication"]},
					}}
				case doc["devices"] != nil || doc["modules"] != nil || doc["manufacturers"] != nil:
					dir := t.TempDir()
					require.NoError(t, os.WriteFile(filepath.Join(dir, "doc.yaml"), []byte(block.text), 0o600))
					lookup, err := data.LoadDeviceLookupExtensions(dir)
					require.NoError(t, err)
					files := lookup.UserExtensionFiles()
					require.Len(t, files, 1)
					require.NoError(t, files[0].Err)
					require.NoError(t, files[0].ModulesErr)
					require.Positive(t, files[0].Entries+files[0].ModuleEntries+files[0].ManufacturerEntries,
						"the lookup example registers nothing")
					return
				case page.shared:
					t.Skip("example for another backend")
				default:
					t.Fatalf("unrecognised documented block; teach this test its shape:\n%s", block.text)
				}

				payload, err := yaml.Marshal(map[string]any{"policies": policies})
				require.NoError(t, err)
				_, err = m.ParsePolicies(payload)
				require.NoError(t, err, "block:\n%s", block.text)

				// ParsePolicies drops a key it does not know; the docs must not use one.
				dec := yaml.NewDecoder(bytes.NewReader(payload))
				dec.KnownFields(true)
				require.NoError(t, dec.Decode(&config.Policies{}), "block:\n%s", block.text)
				documentedPatterns(t, policies)
			})
		}
	}
}
