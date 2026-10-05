package policy_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
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
	// fenceLine matches a fenced code block delimiter: indentation, the fence
	// and its info string.
	fenceLine = regexp.MustCompile("^([ \t]*)(`{3,}|~{3,})(.*)$")
)

type fence struct {
	indent int
	marker string
	info   string
	line   int
	isYAML bool
}

// parseFence returns the fence a markdown line holds, if any. A backtick
// fence cannot carry a backtick in its info string; such a line is inline
// code.
func parseFence(line string, n int) (fence, bool) {
	m := fenceLine.FindStringSubmatch(line)
	if m == nil {
		return fence{}, false
	}
	info := strings.TrimSpace(m[3])
	if m[2][0] == '`' && strings.Contains(info, "`") {
		return fence{}, false
	}
	lang, _, _ := strings.Cut(info, " ")
	lang = strings.ToLower(lang)
	return fence{indent: len(m[1]), marker: m[2], info: info, line: n, isYAML: lang == "yaml" || lang == "yml"}, true
}

// within reports whether f is a fence of open's kind, at least as long and
// indented as a fence at open's level would be. A shorter or deeper one is
// content, as in a markdown example quoting a yaml block.
func (f fence) within(open fence) bool {
	return f.marker[0] == open.marker[0] && len(f.marker) >= len(open.marker) && f.indent <= open.indent+3
}

type yamlBlock struct {
	line int
	text string
}

// yamlBlocks returns each yaml or yml fenced block of a markdown page. A
// fence with an info string inside an open block means that block was never
// closed, which fails rather than swallowing what follows.
func yamlBlocks(page string) ([]yamlBlock, error) {
	var blocks []yamlBlock
	var cur []string
	var open *fence
	for i, line := range strings.Split(page, "\n") {
		f, ok := parseFence(line, i+1)
		switch {
		case open != nil && ok && f.within(*open) && f.info == "":
			if open.isYAML {
				blocks = append(blocks, yamlBlock{open.line, strings.Join(cur, "\n")})
			}
			cur, open = nil, nil
		case open != nil && ok && f.within(*open):
			return nil, fmt.Errorf("line %d: fence inside the block opened at line %d, which is never closed", i+1, open.line)
		case open != nil:
			if open.isYAML {
				cur = append(cur, line)
			}
		case ok:
			open = &f
		}
	}
	if open != nil {
		return nil, fmt.Errorf("the page ends inside the block opened at line %d", open.line)
	}
	return blocks, nil
}

// extraDocument returns an error when docs holds another non-empty yaml
// document, which the checks would never see.
func extraDocument(docs *yaml.Decoder) error {
	for {
		var next any
		err := docs.Decode(&next)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if next != nil {
			return errors.New("a second yaml document would go unchecked")
		}
	}
}

// customMaps are the keys whose mapping form a custom UnmarshalYAML decodes,
// which KnownFields does not reach. vlan.group has one too, but it rejects
// unknown keys itself.
var customMaps = map[string]reflect.Type{
	"vrf":      reflect.TypeFor[config.VrfParameters](),
	"vrf_ipv4": reflect.TypeFor[config.VrfParameters](),
	"vrf_ipv6": reflect.TypeFor[config.VrfParameters](),
	"tenant":   reflect.TypeFor[config.TenantParameters](),
}

// customMapKeys returns an error for a key in a customMaps mapping that its
// type does not declare, which the decoder would drop silently.
func customMapKeys(v any) error {
	switch v := v.(type) {
	case map[string]any:
		for k, child := range v {
			if typ, ok := customMaps[k]; ok {
				if m, ok := child.(map[string]any); ok {
					known := map[string]bool{}
					for field := range typ.Fields() {
						name, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
						known[name] = true
					}
					for key := range m {
						if !known[key] {
							return fmt.Errorf("%s has no %q key", k, key)
						}
					}
				}
			}
			if err := customMapKeys(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range v {
			if err := customMapKeys(child); err != nil {
				return err
			}
		}
	}
	return nil
}

// documentedPatterns returns an error for an interface_patterns match or
// interface_exclude_patterns entry in v that does not compile. The policy
// parser accepts both: an invalid match fails every scan of a target that
// uses it, and an invalid exclude pattern is skipped with a warning.
func documentedPatterns(v any) error {
	switch v := v.(type) {
	case map[string]any:
		for k, child := range v {
			list, _ := child.([]any)
			for _, item := range list {
				var pattern string
				switch k {
				case "interface_patterns":
					p, ok := item.(map[string]any)
					if !ok {
						continue
					}
					pattern = fmt.Sprint(p["match"])
				case "interface_exclude_patterns":
					pattern = fmt.Sprint(item)
				default:
					continue
				}
				if _, err := regexp.Compile(pattern); err != nil {
					return fmt.Errorf("%s: %w", k, err)
				}
			}
			if err := documentedPatterns(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range v {
			if err := documentedPatterns(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func TestYamlBlocks(t *testing.T) {
	for _, tc := range []struct {
		name, page string
		want       []string
		err        string
	}{
		{name: "yaml and yml, any case", page: "```yaml\na: 1\n```\n```YML\nb: 2\n```\n~~~yaml\nc: 3\n~~~", want: []string{"a: 1", "b: 2", "c: 3"}},
		{name: "other languages skipped", page: "```sh\nls\n```\n```yaml\na: 1\n```", want: []string{"a: 1"}},
		{name: "shorter fence is content", page: "````yaml\nc: |\n  ```\n````", want: []string{"c: |\n  ```"}},
		{name: "deeply indented fence is content", page: "```yaml\nc: |\n        ```\nd: 2\n```", want: []string{"c: |\n        ```\nd: 2"}},
		{name: "quoted yaml in markdown", page: "````markdown\n```yaml\na: 1\n```\n````", want: nil},
		{name: "inline code is no fence", page: "```yaml``` is the language\n```yaml\na: 1\n```", want: []string{"a: 1"}},
		{name: "unclosed yaml block", page: "```yaml\na: 1\n```sh\nls\n```", err: "line 3: fence inside the block opened at line 1"},
		{name: "unclosed other block", page: "```sh\nls\n```yaml\na: 1\n```", err: "line 3: fence inside the block opened at line 1"},
		{name: "page ends inside a block", page: "```yaml\na: 1", err: "ends inside the block opened at line 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blocks, err := yamlBlocks(tc.page)
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			var got []string
			for _, b := range blocks {
				got = append(got, b.text)
			}
			require.Equal(t, tc.want, got)
		})
	}
}

func TestExtraDocument(t *testing.T) {
	for text, wantErr := range map[string]bool{
		"a: 1":                 false,
		"---\na: 1":            false,
		"a: 1\n---\n":          false,
		"a: 1\n...\n":          false,
		"a: 1\n---\nb: 2":      true,
		"a: 1\n---\n---\nb: 2": true,
	} {
		docs := yaml.NewDecoder(strings.NewReader(text))
		var first any
		require.NoError(t, docs.Decode(&first))
		require.Equal(t, wantErr, extraDocument(docs) != nil, "%q", text)
	}
}

func TestCustomMapKeys(t *testing.T) {
	require.NoError(t, customMapKeys(map[string]any{"vrf": "mgmt", "tenant": "t1"}))
	require.NoError(t, customMapKeys(map[string]any{"vrf_ipv6": map[string]any{"name": "mgmt", "rd": "65000:1"}}))
	require.ErrorContains(t, customMapKeys(map[string]any{"vrf": map[string]any{"name": "mgmt", "route_distinguisher": "65000:1"}}), `vrf has no "route_distinguisher" key`)
	require.ErrorContains(t, customMapKeys(map[string]any{"tenant": map[string]any{"name": "t1", "grup": "g1"}}), `tenant has no "grup" key`)
	require.Error(t, customMapKeys(map[string]any{"p": []any{map[string]any{"vrf_ipv4": map[string]any{"nme": "mgmt"}}}}), "inside a list")
}

func TestDocumentedPatterns(t *testing.T) {
	require.NoError(t, documentedPatterns(map[string]any{
		"interface_patterns":         []any{map[string]any{"match": "^Gi", "type": "1000base-t"}},
		"interface_exclude_patterns": []any{"^Null"},
	}))
	require.ErrorContains(t, documentedPatterns(map[string]any{"d": map[string]any{
		"interface_patterns": []any{map[string]any{"match": "^Gi(", "type": "1000base-t"}},
	}}), "interface_patterns")
	require.ErrorContains(t, documentedPatterns(map[string]any{"interface_exclude_patterns": []any{"^Null["}}), "interface_exclude_patterns")
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
		raw, err := os.ReadFile(page.path)
		require.NoError(t, err)
		blocks, err := yamlBlocks(string(raw))
		require.NoError(t, err, page.path)
		for _, block := range blocks {
			t.Run(fmt.Sprintf("%s/line-%d", page.label, block.line), func(t *testing.T) {
				for _, ref := range envReference.FindAllStringSubmatch(block.text, -1) {
					t.Setenv(ref[1], "example")
				}
				var doc map[string]any
				docs := yaml.NewDecoder(strings.NewReader(block.text))
				if err := docs.Decode(&doc); err != nil && page.shared && !strings.Contains(block.text, "snmp_discovery") {
					t.Skip("illustrative snippet for another backend")
				} else {
					require.NoError(t, err, "block:\n%s", block.text)
				}

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
					require.NoError(t, extraDocument(docs), "block:\n%s", block.text)
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
				require.NoError(t, extraDocument(docs), "block:\n%s", block.text)

				payload, err := yaml.Marshal(map[string]any{"policies": policies})
				require.NoError(t, err)
				_, err = m.ParsePolicies(payload)
				require.NoError(t, err, "block:\n%s", block.text)

				// ParsePolicies drops a key it does not know; the docs must not use one.
				dec := yaml.NewDecoder(bytes.NewReader(payload))
				dec.KnownFields(true)
				require.NoError(t, dec.Decode(&config.Policies{}), "block:\n%s", block.text)
				require.NoError(t, customMapKeys(policies), "block:\n%s", block.text)
				require.NoError(t, documentedPatterns(policies), "block:\n%s", block.text)
			})
		}
	}
}
