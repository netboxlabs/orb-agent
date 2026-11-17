package pktvisor

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
