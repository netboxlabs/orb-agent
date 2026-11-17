package pktvisor

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// bodyWith builds a netprobe policy body with policy-level attributes and one
// target, gw1, carrying its own.
func bodyWith(policy, target any) map[string]any {
	gw1 := map[string]any{"target": "192.0.2.1"}
	if target != nil {
		gw1["attributes"] = target
	}
	doc := map[string]any{
		"kind": "collection",
		"input": map[string]any{
			"input_type": "netprobe",
			"config":     map[string]any{"targets": map[string]any{"gw1": gw1}},
		},
	}
	if policy != nil {
		doc["attributes"] = policy
	}
	return doc
}

func many(n int) map[string]any {
	out := map[string]any{}
	for i := range n {
		out["k"+strings.Repeat("a", i+1)] = "v"
	}
	return out
}

func TestCheckAttributes(t *testing.T) {
	tests := []struct {
		name    string
		body    any
		wantErr []string // every fragment the error must contain; nil means accepted
	}{
		{"no attributes", bodyWith(nil, nil), nil},
		{"policy level", bodyWith(map[string]any{"netbox.site.name": "dc-west"}, nil), nil},
		{"target level", bodyWith(nil, map[string]any{"netbox_id": "netbox-device-1", "device_ip": "192.0.2.1"}), nil},
		{"device dot key is not reserved", bodyWith(map[string]any{"device.x": "v"}, nil), nil},
		{"null policy attributes", map[string]any{"attributes": nil, "input": map[string]any{}}, nil},
		{"null target attributes", bodyWith(map[string]any{"a": "b"}, nil), nil},
		{"yaml int and bool and float", bodyWith(map[string]any{"a": 3, "b": true, "c": 1.5, "d": int64(4)}, nil), nil},
		{"whole float64", bodyWith(map[string]any{"a": float64(3)}, nil), nil},
		{"the policy set is checked on its own", bodyWith(map[string]any{"site": ""}, map[string]any{"site": "dc"}), []string{"policy", `"site"`}},
		{"not a body", "text", nil},
		{"no input", map[string]any{"kind": "collection"}, nil},
		{"config not a map", map[string]any{"input": map[string]any{"config": "x"}}, nil},
		{"targets not a map", map[string]any{"input": map[string]any{"config": map[string]any{"targets": []any{"192.0.2.1"}}}}, nil},
		{"target not a map", map[string]any{"input": map[string]any{"config": map[string]any{"targets": map[string]any{"gw1": "192.0.2.1"}}}}, nil},
		{"targets of another input type", map[string]any{"input": map[string]any{"input_type": "flow", "config": map[string]any{"targets": map[string]any{"t": map[string]any{"attributes": map[string]any{"policy": "x"}}}}}}, []string{`target "t"`, `"policy"`}},

		{"digit first", bodyWith(map[string]any{"2cents": "x"}, nil), []string{"policy", `"2cents"`}},
		{"empty value", bodyWith(map[string]any{"a": ""}, nil), []string{"policy", `"a"`}},
		{"nil value", bodyWith(nil, map[string]any{"a": nil}), []string{`target "gw1"`, `"a"`}},
		{"map value", bodyWith(map[string]any{"a": map[string]any{"b": "c"}}, nil), []string{`"a"`, "map"}},
		{"list value", bodyWith(map[string]any{"a": []any{"b"}}, nil), []string{`"a"`, "list"}},
		{"job", bodyWith(map[string]any{"job": "x"}, nil), []string{`"job"`}},
		{"otel_scope_", bodyWith(map[string]any{"otel_scope_x": "x"}, nil), []string{`"otel_scope_x"`}},
		{"policy", bodyWith(map[string]any{"policy": "x"}, nil), []string{"policy", `"policy"`}},
		{"tap", bodyWith(map[string]any{"tap": "x"}, nil), []string{`"tap"`}},
		{"target on gw1", bodyWith(nil, map[string]any{"target": "x"}), []string{`target "gw1"`, `"target"`}},
		{"device", bodyWith(map[string]any{"device": "x"}, nil), []string{`"device"`}},
		{"handler", bodyWith(map[string]any{"handler": "x"}, nil), []string{`"handler"`}},
		{"le", bodyWith(map[string]any{"le": "x"}, nil), []string{`"le"`}},
		{"quantile", bodyWith(map[string]any{"quantile": "x"}, nil), []string{`"quantile"`}},
		{"orb namespace", bodyWith(map[string]any{"orb.x": "x"}, nil), []string{`"orb.x"`, "orb namespace"}},
		{"two keys one name", bodyWith(map[string]any{"a.b": "x", "a_b": "y"}, nil), []string{`"a.b"`, `"a_b"`}},
		{"unsupported type", bodyWith(map[string]any{"a": json.Number("x")}, nil), []string{`"a"`}},
		{"too many after merge", bodyWith(many(20), many2(20)), []string{`target "gw1"`, "carries"}},
		{"long key", bodyWith(map[string]any{"a" + strings.Repeat("b", 128): "x"}, nil), []string{"longer than the limit of 128"}},
		{"long value", bodyWith(map[string]any{"a": strings.Repeat("b", 257)}, nil), []string{`"a"`, "longer than the limit of 256"}},
		{"too many bytes", bodyWith(map[string]any{"a": strings.Repeat("b", 256), "b": strings.Repeat("b", 256), "c": strings.Repeat("b", 256)}, map[string]any{"d": strings.Repeat("b", 256)}), []string{`target "gw1"`, "1024"}},

		{"policy attributes a string", bodyWith("x", nil), []string{"attributes", "policy", "mapping"}},
		{"policy attributes a list", bodyWith([]any{"x"}, nil), []string{"policy", "mapping"}},
		{"target attributes a number", bodyWith(nil, 3), []string{`target "gw1"`, "mapping"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkAttributes(tt.body)
			if tt.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "attributes")
			for _, frag := range tt.wantErr {
				assert.Contains(t, err.Error(), frag)
			}
		})
	}
}

// The refusal clips an invalid key as it clips every other, so a key of any
// size cannot fill the error.
func TestCheckAttributesInvalidUTF8KeyIsClipped(t *testing.T) {
	err := checkAttributes(bodyWith(map[string]any{"bad\xff" + strings.Repeat("k", 4*maxKeyBytes): "x"}, nil))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `attribute key "bad\xff`+strings.Repeat("k", 28)+`..." is not valid UTF-8`)
}

// many2 is many with other keys, so the merge of the two has 2n attributes.
func many2(n int) map[string]any {
	out := map[string]any{}
	for i := range n {
		out["t"+strings.Repeat("a", i+1)] = "v"
	}
	return out
}

// A body decoded from JSON, as Fleet sends it, carries numbers as float64.
func TestCheckAttributesJSONBody(t *testing.T) {
	decode := func(s string) any {
		var v any
		require.NoError(t, json.Unmarshal([]byte(s), &v))
		return v
	}
	require.NoError(t, checkAttributes(decode(`{"attributes":{"rack":7,"ratio":1.5,"on":true,"site":"dc"},
		"input":{"config":{"targets":{"gw1":{"attributes":{"rack":8}}}}}}`)))

	err := checkAttributes(decode(`{"input":{"config":{"targets":{"gw1":{"attributes":{"target":"x"}}}}}}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `target "gw1"`)

	err = checkAttributes(decode(`{"attributes":{"a":{"b":1}}}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "map")
}

func TestCheckAttributesNamesTheFirstTargetInOrder(t *testing.T) {
	body := map[string]any{"input": map[string]any{"config": map[string]any{"targets": map[string]any{
		"b": map[string]any{"attributes": map[string]any{"tap": "x"}},
		"a": map[string]any{"attributes": map[string]any{"tap": "x"}},
	}}}}
	for range 10 {
		err := checkAttributes(body)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `target "a"`)
	}
}

func TestPrometheusName(t *testing.T) {
	assert.Equal(t, "device_x", prometheusName("device.x"))
	assert.Equal(t, "key_2a", prometheusName("2a"))
	assert.Equal(t, "key_a", prometheusName("_a"))
	assert.Equal(t, "__a", prometheusName("__a"))
	assert.Empty(t, prometheusName(""))
	assert.Equal(t, "caf_", prometheusName("café"))
}

// yamlBody decodes a YAML literal the way the config and policy_yaml paths do.
func yamlBody(t *testing.T, doc string) any {
	t.Helper()
	var v any
	require.NoError(t, yaml.Unmarshal([]byte(doc), &v))
	return v
}

// yaml.v3 decodes a mapping with a key that is not a string as
// map[any]any, so every level of the body is read through both shapes.
func TestCheckAttributesYAMLNonStringKeys(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		wantErr []string // nil means accepted
	}{
		{"numeric target name", `
input:
  config:
    targets:
      101:
        target: 192.0.2.1
        attributes: {target: x}
`, []string{`target "101"`, `"target"`}},
		{"numeric name beside a named one", `
input:
  config:
    targets:
      gw1: {target: 192.0.2.1}
      101:
        target: 192.0.2.2
        attributes: {policy: x}
`, []string{`target "101"`, `"policy"`}},
		{"numeric key under input", `
input:
  7: x
  config:
    targets:
      gw1:
        attributes: {tap: x}
`, []string{`target "gw1"`, `"tap"`}},
		{"numeric key at the top", `
7: x
attributes: {device: x}
`, []string{"policy", `"device"`}},
		{"boolean attribute key is an ordinary key", `
attributes: {true: x}
`, nil},
		{"numeric attribute key does not start with a letter", `
attributes: {101: x}
`, []string{"policy", `"101"`, "must start with a letter"}},
		{"attributes a mapping with a numeric key beside a reserved one", `
attributes: {7: x, policy: y}
`, []string{"policy", `"7"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkAttributes(yamlBody(t, tt.doc))
			if tt.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "map[interface")
			for _, frag := range tt.wantErr {
				assert.Contains(t, err.Error(), frag)
			}
		})
	}
}

// What the decoders hand over for the values the docs promise to refuse or
// keep, and the exact boundaries of the limits.
func TestCheckAttributesBoundaries(t *testing.T) {
	exactly := func(n int) map[string]any { // n attributes, none over the key limits
		out := map[string]any{}
		for i := range n {
			out[fmt.Sprintf("k%02d", i)] = "v"
		}
		return out
	}
	tests := []struct {
		name    string
		body    any
		wantErr []string
	}{
		{"empty key", yamlBody(t, `attributes: {"": x}`), []string{"policy", "empty"}},
		{"unquoted date", yamlBody(t, `attributes: {d: 2026-11-17}`), []string{`"d"`, "timestamp"}},
		{"quoted date", yamlBody(t, `attributes: {d: "2026-11-17"}`), nil},
		{"nan", yamlBody(t, `attributes: {n: .nan}`), []string{`"n"`, "finite"}},
		{"inf", yamlBody(t, `attributes: {n: .inf}`), []string{`"n"`, "finite"}},
		{"minus inf", yamlBody(t, `attributes: {n: -.inf}`), []string{`"n"`, "finite"}},
		{"2^63 unquoted", yamlBody(t, `attributes: {n: 9223372036854775808}`), []string{`"n"`, "64-bit"}},
		{"2^63-1 unquoted", yamlBody(t, `attributes: {n: 9223372036854775807}`), nil},
		{"32 attributes", bodyWith(exactly(32), nil), nil},
		{"33 attributes", bodyWith(exactly(33), nil), []string{"33 attributes", "limit of 32"}},
		// 4 keys of 4 bytes and 4 values of 252 bytes: 4*256 = 1024.
		{"1024 bytes", bodyWith(map[string]any{
			"aaaa": strings.Repeat("v", 252), "bbbb": strings.Repeat("v", 252),
			"cccc": strings.Repeat("v", 252), "dddd": strings.Repeat("v", 252),
		}, nil), nil},
		{"1025 bytes", bodyWith(map[string]any{
			"aaaa": strings.Repeat("v", 253), "bbbb": strings.Repeat("v", 252),
			"cccc": strings.Repeat("v", 252), "dddd": strings.Repeat("v", 252),
		}, nil), []string{"1025 bytes", "limit of 1024"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkAttributes(tt.body)
			if tt.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			for _, frag := range tt.wantErr {
				assert.Contains(t, err.Error(), frag)
			}
		})
	}
}

// withModules gives body the handler modules, in the map or the list form
// pktvisord accepts.
func withModules(body map[string]any, modules any) map[string]any {
	body["handlers"] = map[string]any{"modules": modules}
	return body
}

func TestCheckAttributesHandlerLabels(t *testing.T) {
	netprobe := map[string]any{"probe": map[string]any{"type": "netprobe"}}
	tests := []struct {
		name    string
		body    any
		wantErr []string // nil means accepted
	}{
		{"netprobe status_code", withModules(bodyWith(map[string]any{"status_code": "x"}, nil), netprobe), []string{"policy", `"status_code"`, "netprobe handler"}},
		{"netprobe rcode on a target", withModules(bodyWith(nil, map[string]any{"rcode": "x"}), netprobe), []string{`target "gw1"`, `"rcode"`, "netprobe handler"}},
		{"in Prometheus form", withModules(bodyWith(map[string]any{"status.code": "x"}, nil), netprobe), []string{`"status.code"`, `"status_code"`, "netprobe handler"}},
		{"flow ip", withModules(bodyWith(map[string]any{"ip": "x"}, nil), map[string]any{"f": map[string]any{"type": "flow"}}), []string{`"ip"`, "flow handler"}},
		{"ip on netprobe is fine", withModules(bodyWith(map[string]any{"ip": "x"}, nil), netprobe), nil},
		{"dns direction", withModules(bodyWith(map[string]any{"direction": "x"}, nil), map[string]any{"d": map[string]any{"type": "dns", "require_version": "2.0"}}), []string{`"direction"`, "dns handler"}},
		{"dhcp client", withModules(bodyWith(map[string]any{"client": "x"}, nil), map[string]any{"d": map[string]any{"type": "dhcp"}}), []string{`"client"`, "dhcp handler"}},
		{"net ipv4", withModules(bodyWith(map[string]any{"ipv4": "x"}, nil), map[string]any{"n": map[string]any{"type": "net"}}), []string{`"ipv4"`, "net handler"}},
		{"list form", withModules(bodyWith(map[string]any{"status_code": "x"}, nil), []any{map[string]any{"probe": map[string]any{"type": "netprobe"}}}), []string{`"status_code"`, "netprobe handler"}},
		{"type under the module name", withModules(bodyWith(map[string]any{"status_code": "x"}, nil), map[string]any{"probe": map[string]any{"probe": map[string]any{"type": "netprobe"}}}), []string{`"status_code"`, "netprobe handler"}},
		{"two handlers name the first in order", withModules(bodyWith(map[string]any{"port": "x"}, nil), map[string]any{"f": map[string]any{"type": "flow"}, "d": map[string]any{"type": "dns"}}), []string{`"port"`, "dns handler"}},
		{"unknown handler type", withModules(bodyWith(map[string]any{"ip": "x"}, nil), map[string]any{"x": map[string]any{"type": "other"}}), nil},
		{"modules not a mapping", withModules(bodyWith(map[string]any{"ip": "x"}, nil), "flow"), nil},
		{"no handlers", bodyWith(map[string]any{"ip": "x", "status_code": "x"}, nil), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkAttributes(tt.body)
			if tt.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			for _, frag := range tt.wantErr {
				assert.Contains(t, err.Error(), frag)
			}
		})
	}
}

// A body read from YAML, as a policy written in the agent's config is.
func TestCheckAttributesHandlerLabelsYAML(t *testing.T) {
	var body any
	require.NoError(t, yaml.Unmarshal([]byte(`
kind: collection
input:
  input_type: netprobe
  config:
    targets:
      gw1:
        target: 192.0.2.1
        attributes:
          status_code: "x"
handlers:
  modules:
    - probe:
        type: netprobe
`), &body))
	err := checkAttributes(body)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `target "gw1"`)
	assert.Contains(t, err.Error(), "netprobe handler")
}
