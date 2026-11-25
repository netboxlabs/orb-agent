package fleet

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// dispatchPolicyData sends one agent_policy RPC whose policy data is the JSON
// object data, and returns the data the policy manager was handed, or the
// dispatch error.
func dispatchPolicyData(t *testing.T, data string) (any, error) {
	t.Helper()
	pm := &mockPolicyManager{}
	pm.On("GetPolicyState").Return([]policies.PolicyData{}, nil).Maybe()
	var got any
	pm.On("ManagePolicy", mock.Anything).Run(func(args mock.Arguments) {
		got = args.Get(0).(config.PolicyPayload).Data
	}).Return().Maybe()
	groups := newGroupManager()
	m := NewMessaging(slog.New(slog.NewTextHandler(io.Discard, nil)), pm, make(chan struct{}, 1), &groups, nil)
	rpc := `{"schema_version":"1.0","func":"agent_policy","payload":[{"action":"manage","id":"p1",` +
		`"name":"numbers","backend":"gnmi_telemetry","format":"json","version":1,"data":` + data + `}]}`
	err := m.DispatchToHandlers(context.Background(), []byte(rpc), "org", "agent", TopicActions{})
	return got, err
}

// A policy whose data Fleet sends as a JSON object keeps its whole numbers
// whole, as a YAML policy's do: read as float64s, as json.Unmarshal reads
// them, the backends' YAML encoder would write 1000000 as 1e+06, and the
// backend would read a float.
func TestDispatchToHandlers_KeepsTheWholeNumbersOfAJSONPolicyWhole(t *testing.T) {
	got, err := dispatchPolicyData(t, `{"million": 1000000, "large": 4200000000, "negative": -1000000,`+
		` "small": 999999, "half": 1.5, "exponent": 1e6, "past_int64": 9223372036854775808,`+
		` "past_uint64": 18446744073709551616, "list": [1000000, 2.5],`+
		` "targets": [{"attributes": {"asn": 4200000000, "site": "lab"}}]}`)
	require.NoError(t, err)
	data, ok := got.(map[string]any)
	require.True(t, ok, "the policy manager got %T", got)

	assert.Equal(t, int64(1000000), data["million"])
	assert.Equal(t, int64(4200000000), data["large"])
	assert.Equal(t, int64(-1000000), data["negative"])
	assert.Equal(t, int64(999999), data["small"])
	assert.Equal(t, 1.5, data["half"], "a number with a fraction stays a float")
	assert.Equal(t, 1e6, data["exponent"], "a number written in exponent form stays a float, as JSON wrote it")
	assert.Equal(t, uint64(9223372036854775808), data["past_int64"], "as YAML reads a whole number past int64")
	assert.Equal(t, 1.8446744073709552e+19, data["past_uint64"], "as YAML reads a whole number past 64 bits")
	assert.Equal(t, []any{int64(1000000), 2.5}, data["list"])
	assert.Equal(t, []any{map[string]any{"attributes": map[string]any{"asn": int64(4200000000), "site": "lab"}}}, data["targets"])

	posted, err := yaml.Marshal(data)
	require.NoError(t, err)
	for _, line := range []string{"million: 1000000\n", "large: 4200000000\n", "negative: -1000000\n", "half: 1.5\n", "asn: 4200000000\n"} {
		assert.Contains(t, string(posted), line, "what a backend posts")
	}
}

// A number no float64 holds still fails the RPC, as it did when
// json.Unmarshal decoded it, and no policy is applied.
func TestDispatchToHandlers_RefusesAJSONPolicyNumberNoFloatHolds(t *testing.T) {
	got, err := dispatchPolicyData(t, `{"interval": 1e400}`)
	require.ErrorContains(t, err, "1e400")
	assert.Nil(t, got)
}
