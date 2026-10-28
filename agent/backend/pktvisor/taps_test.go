package pktvisor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagedTapType(t *testing.T) {
	cfg := map[string]any{"target_hosts": "192.0.2.1"}
	tests := []struct {
		name    string
		body    any
		want    string
		wantErr string
	}{
		{"netprobe no tap", map[string]any{"input": map[string]any{"input_type": "netprobe", "config": cfg}}, "netprobe", ""},
		{"flow no tap", map[string]any{"input": map[string]any{"input_type": "flow"}}, "flow", ""},
		{"empty tap string", map[string]any{"input": map[string]any{"input_type": "netprobe", "tap": ""}}, "netprobe", ""},
		{"null tap selector", map[string]any{"input": map[string]any{"input_type": "netprobe", "tap_selector": nil}}, "netprobe", ""},
		{"null tap", map[string]any{"input": map[string]any{"input_type": "netprobe", "tap": nil}}, "netprobe", ""},
		{"sflow alias no tap", map[string]any{"input": map[string]any{"input_type": "sflow"}}, "", "use input_type flow"},
		{"named tap", map[string]any{"input": map[string]any{"input_type": "netprobe", "tap": "edge"}}, "", ""},
		{"tap selector", map[string]any{"input": map[string]any{"input_type": "pcap", "tap_selector": map[string]any{"any": []any{map[string]any{"role": "edge"}}}}}, "", ""},
		{"non-string tap", map[string]any{"input": map[string]any{"input_type": "netprobe", "tap": 5}}, "", "input.tap"},
		{"pcap no tap", map[string]any{"input": map[string]any{"input_type": "pcap"}}, "", "must name a tap"},
		{"dnstap no tap", map[string]any{"input": map[string]any{"input_type": "dnstap"}}, "", "must name a tap"},
		{"no input_type no tap", map[string]any{"input": map[string]any{"config": cfg}}, "", "input.input_type"},
		{"reserved tap name", map[string]any{"input": map[string]any{"input_type": "netprobe", "tap": "fleet_netprobe"}}, "", "reserved"},
		{"no input section", map[string]any{"kind": "collection"}, "", "input"},
		{"body not a map", "text", "", "input"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := managedTapType(tt.body)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestManagedTapName(t *testing.T) {
	assert.Equal(t, "fleet_netprobe", managedTapName("netprobe"))
	assert.Equal(t, "fleet_flow", managedTapName("flow"))
}

func TestCheckPolicyName(t *testing.T) {
	require.NoError(t, checkPolicyName("net_probe-1"))
	require.NoError(t, checkPolicyName("_x"))
	for _, name := range []string{"Edge ping", "1abc", "a/b", ""} {
		err := checkPolicyName(name)
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "[a-zA-Z_][a-zA-Z0-9_-]*")
	}
}
