package policy

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
)

// The documented sample must be a policy this backend actually accepts.
//
// Prose drifts from the parser silently, and a sample is the thing operators
// copy: a key documented one indent level off lands in the wrong block, is
// dropped by the permissive decode, and takes its whole feature with it.
func TestTheDocumentedSamplePolicyIsValid(t *testing.T) {
	t.Setenv("GNMI_USER", "admin")
	t.Setenv("GNMI_PASS", "s3cret")

	for _, tc := range []struct {
		file string
		path []string // keys to descend to reach the {name: policy} map
	}{
		{file: "../README.md", path: []string{"policies"}},
		{file: "../../../docs/backends/gnmi_discovery.md", path: []string{"orb", "policies", "gnmi_discovery"}},
	} {
		t.Run(tc.file, func(t *testing.T) {
			doc := policyBlockFromMarkdown(t, tc.file, tc.path)

			var warnings bytes.Buffer
			m, err := NewManager(context.Background(),
				slog.New(slog.NewTextHandler(&warnings, nil)), nil,
				&gnmi.FakeDialer{Session: &gnmi.FakeSession{}}, "")
			require.NoError(t, err)

			policies, err := m.ParsePolicies(doc)
			require.NoError(t, err, "the documented sample must parse and validate")
			require.NotEmpty(t, policies)
			require.NotContains(t, warnings.String(), "unrecognized",
				"every key in the sample must be one the parser knows")
		})
	}
}

// policyBlockFromMarkdown returns the first fenced yaml block in file, descended
// through path, re-emitted as a {policies: ...} document.
func policyBlockFromMarkdown(t *testing.T, file string, path []string) []byte {
	t.Helper()
	raw, err := os.ReadFile(file)
	require.NoError(t, err)

	// A page has several yaml blocks; take the one that holds a policy map, so
	// adding an unrelated snippet above it does not silently retarget the test.
	rest := string(raw)
	for {
		var ok bool
		_, rest, ok = strings.Cut(rest, "```yaml")
		require.True(t, ok, "%s: no yaml block contains a policy map at %v", file, path)
		var block string
		block, rest, ok = strings.Cut(rest, "```")
		require.True(t, ok, "%s has an unterminated yaml block", file)

		var node map[string]any
		if err := yaml.Unmarshal([]byte(stripElisions(block)), &node); err != nil {
			continue
		}
		if policies, found := descend(node, path); found {
			out, err := yaml.Marshal(map[string]any{"policies": policies})
			require.NoError(t, err)
			return out
		}
	}
}

// descend walks path to the {name: policy} map.
func descend(node map[string]any, path []string) (any, bool) {
	cur := any(node)
	for _, key := range path {
		asMap, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = asMap[key]; !ok {
			return nil, false
		}
	}
	if _, ok := cur.(map[string]any); !ok {
		return nil, false
	}
	return cur, true
}

// stripElisions drops the "..." lines the docs use to mean "surrounding config
// omitted". YAML reads a bare ... as the document-end marker, so a sample
// carrying one does not parse as written.
func stripElisions(block string) string {
	lines := strings.Split(block, "\n")
	kept := lines[:0]
	for _, line := range lines {
		if strings.TrimSpace(line) == "..." {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}
