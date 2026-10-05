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
	{"env-config", "../../../docs/advanced_config/env_config.md", true},
	{"agent-yaml", "../../../docs/configs/agent_yaml.md", true},
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
	lang := ""
	if fields := strings.Fields(info); len(fields) > 0 {
		lang = strings.ToLower(fields[0])
	}
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

const backend = "snmp_discovery"

var (
	docTarget = map[string]any{"host": "192.0.2.1"}
	docAuth   = map[string]any{"protocol_version": "SNMPv2c", "community": "public"}
)

// minimalPolicy wraps a config fragment in a policy that validates.
func minimalPolicy(cfg map[string]any) map[string]any {
	return map[string]any{"doc": map[string]any{
		"config": cfg,
		"scope":  map[string]any{"targets": []any{docTarget}, "authentication": docAuth},
	}}
}

// sample is what a documented block holds for this backend: a policy set, or
// a device lookup file.
type sample struct {
	policies map[string]any
	lookup   bool
}

// classify returns what a documented block holds for this backend, or why the
// block is skipped. A shared page is read only for
// orb.policies.snmp_discovery, since its other snippets may belong to any
// backend.
func classify(doc map[string]any, shared bool) (s sample, skip string, err error) {
	if err := backendKeys(doc, ""); err != nil {
		return sample{}, "", err
	}
	switch {
	case doc["orb"] != nil:
		orb, _ := doc["orb"].(map[string]any)
		all, _ := orb["policies"].(map[string]any)
		switch {
		case all[backend] != nil:
			policies, ok := all[backend].(map[string]any)
			if !ok {
				return sample{}, "", fmt.Errorf("orb.policies.%s is not a mapping", backend)
			}
			return sample{policies: policies}, "", nil
		case all == nil || shared:
			return sample{}, "no " + backend + " policies", nil
		}
		return sample{}, "", fmt.Errorf("orb.policies on this backend's page has no %s key", backend)
	case shared:
		return sample{}, "example for another backend", nil
	case doc["policies"] != nil:
		policies, ok := doc["policies"].(map[string]any)
		if !ok {
			return sample{}, "", errors.New("policies is not a mapping")
		}
		return sample{policies: policies}, "", nil
	case doc["config"] != nil || doc["scope"] != nil:
		return sample{policies: map[string]any{"doc": doc}}, "", nil
	case doc["defaults"] != nil:
		return sample{policies: minimalPolicy(doc)}, "", nil
	case doc["interface_patterns"] != nil:
		return sample{policies: minimalPolicy(map[string]any{"defaults": doc})}, "", nil
	case doc["authentication"] != nil:
		return sample{policies: map[string]any{"doc": map[string]any{
			"scope": map[string]any{"targets": []any{docTarget}, "authentication": doc["authentication"]},
		}}}, "", nil
	case doc["devices"] != nil || doc["modules"] != nil || doc["manufacturers"] != nil:
		return sample{lookup: true}, "", nil
	}
	return sample{}, "", errors.New("unrecognised documented block; teach this test its shape")
}

// backendKeys returns an error for this backend's key anywhere but
// orb.backends or orb.policies, where it would be ignored, or for a key one
// edit away from it.
func backendKeys(v any, at string) error {
	switch v := v.(type) {
	case map[string]any:
		for k, child := range v {
			switch {
			case k == backend && at != "orb.backends" && at != "orb.policies":
				return fmt.Errorf("%s sits under %q; it belongs under orb.backends or orb.policies", backend, at)
			case nearMiss(k, backend):
				return fmt.Errorf("%q looks like a misspelt %s", k, backend)
			}
			if err := backendKeys(child, strings.TrimPrefix(at+"."+k, ".")); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range v {
			if err := backendKeys(child, at+"[]"); err != nil {
				return err
			}
		}
	}
	return nil
}

// nearMiss reports whether a and b differ by one edit: a character added,
// dropped or changed, or two neighbours swapped.
func nearMiss(a, b string) bool {
	switch len(a) - len(b) {
	case 0:
		if a == b {
			return false
		}
		i := 0
		for a[i] == b[i] {
			i++
		}
		return a[i+1:] == b[i+1:] || (i+1 < len(a) && a[i] == b[i+1] && a[i+1] == b[i] && a[i+2:] == b[i+2:])
	case 1:
		return dropsOne(a, b)
	case -1:
		return dropsOne(b, a)
	}
	return false
}

// dropsOne reports whether removing one character of long gives short.
func dropsOne(long, short string) bool {
	i := 0
	for i < len(short) && long[i] == short[i] {
		i++
	}
	return long[i+1:] == short[i:]
}

func TestClassify(t *testing.T) {
	ours := map[string]any{"p": map[string]any{"scope": map[string]any{}}}
	for _, tc := range []struct {
		name   string
		doc    map[string]any
		shared bool
		want   sample
		skip   bool
		err    string
	}{
		{name: "agent config", doc: map[string]any{"orb": map[string]any{"policies": map[string]any{backend: ours}}}, want: sample{policies: ours}},
		{name: "agent config on a shared page", doc: map[string]any{"orb": map[string]any{"policies": map[string]any{backend: ours}}}, shared: true, want: sample{policies: ours}},
		{name: "backends only", doc: map[string]any{"orb": map[string]any{"backends": map[string]any{backend: nil}}}, skip: true},
		{name: "other backend on a shared page", doc: map[string]any{"orb": map[string]any{"policies": map[string]any{"device_discovery": ours}}}, shared: true, skip: true},
		{name: "other backend on our page", doc: map[string]any{"orb": map[string]any{"policies": map[string]any{"device_discovery": ours}}}, err: "has no snmp_discovery key"},
		{name: "fragment on a shared page", doc: map[string]any{"scope": map[string]any{}}, shared: true, skip: true},
		{name: "policies root", doc: map[string]any{"policies": ours}, want: sample{policies: ours}},
		{name: "policy body", doc: map[string]any{"scope": map[string]any{}}, want: sample{policies: map[string]any{"doc": map[string]any{"scope": map[string]any{}}}}},
		{name: "defaults", doc: map[string]any{"defaults": map[string]any{}}, want: sample{policies: minimalPolicy(map[string]any{"defaults": map[string]any{}})}},
		{name: "interface patterns", doc: map[string]any{"interface_patterns": []any{}}, want: sample{policies: minimalPolicy(map[string]any{"defaults": map[string]any{"interface_patterns": []any{}}})}},
		{name: "authentication", doc: map[string]any{"authentication": docAuth}, want: sample{policies: map[string]any{"doc": map[string]any{
			"scope": map[string]any{"targets": []any{docTarget}, "authentication": docAuth},
		}}}},
		{name: "lookup file", doc: map[string]any{"modules": map[string]any{}}, want: sample{lookup: true}},
		{name: "outdented policies", doc: map[string]any{"orb": map[string]any{"policies": nil, backend: ours}}, shared: true, err: `sits under "orb"`},
		{name: "misspelt key", doc: map[string]any{"orb": map[string]any{"policies": map[string]any{"snmp_discvoery": ours}}}, shared: true, err: "misspelt"},
		{name: "unrecognised", doc: map[string]any{"targets": []any{}}, err: "unrecognised"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, skip, err := classify(tc.doc, tc.shared)
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.skip, skip != "", skip)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestNearMiss(t *testing.T) {
	for _, k := range []string{"snmp_discvoery", "snmp_discovry", "snmp_discoveryy", "smnp_discovery", "snmp-discovery"} {
		require.True(t, nearMiss(k, backend), k)
	}
	for _, k := range []string{backend, "gnmi_discovery", "device_discovery", "snmp", "snmp_disco"} {
		require.False(t, nearMiss(k, backend), k)
	}
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
		{name: "other fence character is content", page: "~~~yaml\na: |\n  ```\n~~~", want: []string{"a: |\n  ```"}},
		{name: "CRLF and a closer with trailing spaces", page: "```yaml\r\na: 1\r\n```  \r\n", want: []string{"a: 1\r"}},
		{name: "info after a tab", page: "```yaml\tlinenums\na: 1\n```", want: []string{"a: 1"}},
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
				if err := docs.Decode(&doc); err != nil && page.shared && !strings.Contains(block.text, backend) {
					t.Skip("illustrative snippet for another backend")
				} else {
					require.NoError(t, err, "block:\n%s", block.text)
				}

				found, skip, err := classify(doc, page.shared)
				require.NoError(t, err, "block:\n%s", block.text)
				if skip != "" {
					t.Skip(skip)
				}
				require.NoError(t, extraDocument(docs), "block:\n%s", block.text)
				if found.lookup {
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
				}
				policies := found.policies

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
