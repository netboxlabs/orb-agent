package pktvisor_test

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend/pktvisor"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// warnRecorder keeps the messages logged at Warn or above.
type warnRecorder struct {
	mu   sync.Mutex
	msgs []string
}

func (w *warnRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (w *warnRecorder) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		w.mu.Lock()
		w.msgs = append(w.msgs, r.Message)
		w.mu.Unlock()
	}
	return nil
}
func (w *warnRecorder) WithAttrs([]slog.Attr) slog.Handler { return w }
func (w *warnRecorder) WithGroup(string) slog.Handler      { return w }

// cleanupWarnings returns the Warn messages the tap cleanup logged. Other
// warnings, such as the one for the 404 on a policy that is not there, are not
// what these tests look at.
func (w *warnRecorder) cleanupWarnings() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for _, m := range w.msgs {
		if strings.HasPrefix(m, "pktvisor tap cleanup") {
			out = append(out, m)
		}
	}
	return out
}

func remove(be interface {
	RemovePolicy(policies.PolicyData) error
}, name string,
) error {
	return be.RemovePolicy(policies.PolicyData{ID: "id-" + name, Name: name})
}

func TestRemoveDeletesAManagedTapWithItsLastPolicy(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	f.addTap("fleet_netprobe", "netprobe", nil, nil)
	f.addPolicy("p1", "fleet_netprobe")

	require.NoError(t, remove(be, "p1"))

	assert.Equal(t, []string{
		"DELETE /api/v1/policies/p1 200",
		"GET /api/v1/taps 200",
		"GET /api/v1/policies 200",
		"DELETE /api/v1/taps/fleet_netprobe 200",
	}, f.log())
	assert.False(t, f.hasTap("fleet_netprobe"))
}

func TestRemoveKeepsAManagedTapStillInUse(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	f.addTap("fleet_netprobe", "netprobe", nil, nil)
	f.addPolicy("p1", "fleet_netprobe")
	f.addPolicy("p2", "fleet_netprobe")

	require.NoError(t, remove(be, "p1"))

	log := f.log()
	assert.Contains(t, log, "GET /api/v1/policies 200")
	assert.Empty(t, tapDeletes(log))
	assert.True(t, f.hasTap("fleet_netprobe"))
}

func TestRemoveKeepsLocalTaps(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	f.addTap("edge", "pcap", nil, nil)
	f.addPolicy("p1", "edge")

	require.NoError(t, remove(be, "p1"))

	log := f.log()
	assert.Contains(t, log, "GET /api/v1/taps 200")
	assert.Empty(t, tapDeletes(log))
	assert.True(t, f.hasTap("edge"))
}

func TestRemoveKeepsAFleetNamedTapItDidNotCreate(t *testing.T) {
	cases := []struct {
		name      string
		tap       string
		inputType string
		config    map[string]any
		tags      map[string]any
	}{
		{"other input type", "fleet_netprobe", "pcap", nil, nil},
		{"with config", "fleet_flow", "flow", map[string]any{"port": 6343}, nil},
		{"with tags", "fleet_flow", "flow", nil, map[string]any{"site": "lab"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakePktvisor(t)
			be := startAgainst(t, f)
			f.addTap(c.tap, c.inputType, c.config, c.tags)
			f.addPolicy("p1", "elsewhere")

			require.NoError(t, remove(be, "p1"))

			assert.Empty(t, tapDeletes(f.log()))
			assert.True(t, f.hasTap(c.tap))
		})
	}
}

func TestRemoveSucceedsWhenCleanupFails(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	f.addTap("fleet_netprobe", "netprobe", nil, nil)

	f.addPolicy("p1", "elsewhere")
	f.with(func() { f.failPolicyList = true })
	require.NoError(t, remove(be, "p1"))
	assert.Contains(t, f.log(), "GET /api/v1/policies 500")
	assert.Empty(t, tapDeletes(f.log()))

	f.clearLog()
	f.addPolicy("p1", "elsewhere")
	f.with(func() { f.failPolicyList = false; f.failTapList = true })
	require.NoError(t, remove(be, "p1"))
	assert.Contains(t, f.log(), "GET /api/v1/taps 500")
	assert.Empty(t, tapDeletes(f.log()))
	assert.True(t, f.hasTap("fleet_netprobe"))

	f.clearLog()
	f.addPolicy("p1", "elsewhere")
	f.with(func() { f.failTapList = false })
	require.NoError(t, remove(be, "p1"))
	assert.Contains(t, f.log(), "DELETE /api/v1/taps/fleet_netprobe 200")
	assert.False(t, f.hasTap("fleet_netprobe"))
}

func TestRemoveKeepsAKeptTap(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	f.addTap("fleet_netprobe", "netprobe", nil, nil)
	f.addPolicy("p2", "elsewhere")
	pktvisor.KeepTap(be, "fleet_netprobe")

	require.NoError(t, remove(be, "p2"))

	assert.Empty(t, tapDeletes(f.log()))
	assert.True(t, f.hasTap("fleet_netprobe"))
}

func TestStartReleasesKeptTaps(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	f.addTap("fleet_netprobe", "netprobe", nil, nil)
	f.addPolicy("p2", "fleet_netprobe")
	pktvisor.KeepTap(be, "fleet_netprobe")

	require.NoError(t, be.FullReset(context.Background()))

	require.NoError(t, remove(be, "p2"))
	assert.Contains(t, f.log(), "DELETE /api/v1/policies/p2 200")
	assert.Contains(t, f.log(), "DELETE /api/v1/taps/fleet_netprobe 200")
	assert.False(t, f.hasTap("fleet_netprobe"))
}

func TestRemoveCleansUpWhenThePolicyIsAlreadyGone(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	f.addTap("fleet_flow", "flow", nil, nil)

	err := remove(be, "p1")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
	assert.Contains(t, f.log(), "DELETE /api/v1/policies/p1 404")
	assert.Contains(t, f.log(), "DELETE /api/v1/taps/fleet_flow 200")
	assert.False(t, f.hasTap("fleet_flow"))
}

func TestRemoveKeepsTapsWhenThePolicyListDoesNotDecode(t *testing.T) {
	cases := []struct{ name, body string }{
		{"taps is a list", `{"p2": {"taps": ["fleet_netprobe"]}}`},
		{"not JSON", `plain text`},
		{"null", `null`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakePktvisor(t)
			be := startAgainst(t, f)
			f.addTap("fleet_netprobe", "netprobe", nil, nil)
			f.addPolicy("p1", "fleet_netprobe")
			f.addPolicy("p2", "fleet_netprobe")
			f.with(func() { f.policyListBody = &c.body })

			require.NoError(t, remove(be, "p1"))

			assert.Contains(t, f.log(), "GET /api/v1/policies 200")
			assert.Empty(t, tapDeletes(f.log()))
			assert.True(t, f.hasTap("fleet_netprobe"))
		})
	}
}

func TestRemoveWarnsWhenThePolicyListDoesNotDecode(t *testing.T) {
	f := newFakePktvisor(t)
	rec := &warnRecorder{}
	be := startAgainstLogging(t, f, slog.New(rec))
	f.addTap("fleet_netprobe", "netprobe", nil, nil)
	f.addPolicy("p1", "fleet_netprobe")
	body := `plain text`
	f.with(func() { f.policyListBody = &body })

	require.NoError(t, remove(be, "p1"))

	assert.Equal(t, []string{"pktvisor tap cleanup: policy list did not decode"}, rec.cleanupWarnings())
}

func TestUpdateOnAnEmptyPktvisorLogsNoWarning(t *testing.T) {
	f := newFakePktvisor(t)
	rec := &warnRecorder{}
	be := startAgainstLogging(t, f, slog.New(rec))

	require.NoError(t, apply(be, "p1", netprobeBody("192.0.2.1"), true))

	assert.Empty(t, rec.cleanupWarnings())
}

func netprobeBody(targets ...string) map[string]any {
	return map[string]any{
		"kind": "collection",
		"input": map[string]any{
			"input_type": "netprobe",
			"config":     map[string]any{"targets": targets},
		},
		"handlers": map[string]any{"modules": map[string]any{}},
	}
}

func flowBody() map[string]any {
	return map[string]any{
		"kind":     "collection",
		"input":    map[string]any{"input_type": "flow"},
		"handlers": map[string]any{"modules": map[string]any{}},
	}
}

func apply(be interface {
	ApplyPolicy(policies.PolicyData, bool) error
}, name string, body any, update bool,
) error {
	return be.ApplyPolicy(policies.PolicyData{ID: "id-" + name, Name: name, Data: body}, update)
}

func TestApplyCreatesTheManagedTapAndNamesIt(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)

	require.NoError(t, apply(be, "p1", netprobeBody("192.0.2.1"), false))

	assert.Equal(t, []string{"POST /api/v1/taps 201", "POST /api/v1/policies 201"}, f.log())
	tap, ok := f.tapNamed("fleet_netprobe")
	require.True(t, ok)
	assert.Equal(t, "netprobe", tap.inputType)
	assert.Empty(t, tap.config)
	pol, ok := f.policyNamed("p1")
	require.True(t, ok)
	input, _ := pol.body["input"].(map[string]any)
	assert.Equal(t, "fleet_netprobe", input["tap"])
	assert.Equal(t, map[string]any{"targets": []any{"192.0.2.1"}}, input["config"])
}

func TestApplyReusesItsManagedTap(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	require.NoError(t, apply(be, "p1", netprobeBody("192.0.2.1"), false))
	f.clearLog()

	require.NoError(t, apply(be, "p2", netprobeBody("192.0.2.2"), false))

	assert.Equal(t, []string{
		"POST /api/v1/taps 409",
		"GET /api/v1/taps/fleet_netprobe 200",
		"POST /api/v1/policies 201",
	}, f.log())
	f.with(func() { assert.Len(t, f.taps, 1) })
}

func TestApplyDropsANullTapSelector(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	body := netprobeBody("192.0.2.1")
	body["input"].(map[string]any)["tap_selector"] = nil

	require.NoError(t, apply(be, "p1", body, false))

	pol, ok := f.policyNamed("p1")
	require.True(t, ok)
	input, _ := pol.body["input"].(map[string]any)
	assert.Equal(t, "fleet_netprobe", input["tap"])
	assert.NotContains(t, input, "tap_selector")
}

func TestApplyRefusesAFleetNamedTapItDidNotCreate(t *testing.T) {
	cases := []struct {
		name      string
		inputType string
		config    map[string]any
	}{
		{"other input type", "pcap", nil},
		{"with config", "netprobe", map[string]any{"targets": []any{"192.0.2.1"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakePktvisor(t)
			be := startAgainst(t, f)
			f.addTap("fleet_netprobe", c.inputType, c.config, nil)

			err := apply(be, "p1", netprobeBody("192.0.2.1"), false)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "not one the agent manages")
			assert.NotContains(t, f.log(), "POST /api/v1/policies 201")
			_, ok := f.policyNamed("p1")
			assert.False(t, ok)
		})
	}
}

func TestApplyLeavesTheStoredBodyUntouched(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	body := netprobeBody("192.0.2.1")

	require.NoError(t, apply(be, "p1", body, false))

	pol, ok := f.policyNamed("p1")
	require.True(t, ok)
	posted, _ := pol.body["input"].(map[string]any)
	assert.Equal(t, "fleet_netprobe", posted["tap"])
	assert.NotContains(t, body["input"], "tap")
}

func TestApplyLeavesNoTapWhenPktvisorRefusesThePolicy(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	f.with(func() { f.refusePolicies = true })

	require.Error(t, apply(be, "p1", netprobeBody("192.0.2.1"), false))

	assert.Equal(t, []string{
		"POST /api/v1/taps 201",
		"POST /api/v1/policies 500",
		"GET /api/v1/taps 200",
		"GET /api/v1/policies 200",
		"DELETE /api/v1/taps/fleet_netprobe 200",
	}, f.log())
	assert.False(t, f.hasTap("fleet_netprobe"))
}

func TestApplyKeepsTheTapWhenThePolicyPostTimesOut(t *testing.T) {
	pktvisor.SetApplyPolicyTimeout(t, 1)
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	f.with(func() { f.stallPolicyPost = true })

	require.Error(t, apply(be, "p1", netprobeBody("192.0.2.1"), false))

	assert.Equal(t, []string{"POST /api/v1/taps 201", "POST /api/v1/policies stalled"}, f.log())
	f.clearLog()

	require.Error(t, remove(be, "p2")) // an unrelated policy: pktvisor answers 404
	assert.Empty(t, tapDeletes(f.log()))
	assert.True(t, f.hasTap("fleet_netprobe"))
	f.clearLog()

	require.Error(t, apply(be, "p1", flowBody(), true))
	assert.Contains(t, f.log(), "DELETE /api/v1/policies/p1 404")
	assert.Empty(t, tapDeletes(f.log()))
	assert.True(t, f.hasTap("fleet_netprobe"))
	assert.True(t, f.hasTap("fleet_flow"))
}

func TestApplyPassesANamedTapThrough(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	f.addTap("edge", "pcap", nil, nil)
	body := map[string]any{
		"kind":     "collection",
		"input":    map[string]any{"input_type": "pcap", "tap": "edge"},
		"handlers": map[string]any{"modules": map[string]any{}},
	}

	require.NoError(t, apply(be, "p1", body, false))

	assert.Equal(t, []string{"POST /api/v1/policies 201"}, f.log())
	pol, ok := f.policyNamed("p1")
	require.True(t, ok)
	assert.Equal(t, body, pol.body)
}

func TestApplyRefusesABadNameBeforeCallingPktvisor(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)

	err := apply(be, "Edge ping", netprobeBody("192.0.2.1"), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must match")

	err = apply(be, "Edge ping", netprobeBody("192.0.2.1"), true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must match")

	f.addPolicy("p1", "elsewhere")
	pcapNoTap := map[string]any{"input": map[string]any{"input_type": "pcap"}}
	err = apply(be, "p1", pcapNoTap, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must name a tap")

	assert.Empty(t, f.log())
	_, ok := f.policyNamed("p1")
	assert.True(t, ok, "a refused edit leaves the running policy alone")
}

func TestApplyRecreatesTheTapAfterARestart(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)

	require.NoError(t, apply(be, "p1", netprobeBody("192.0.2.1"), true))

	assert.Equal(t, []string{
		"DELETE /api/v1/policies/p1 404",
		"GET /api/v1/taps 200",
		"POST /api/v1/taps 201",
		"POST /api/v1/policies 201",
	}, f.log())
}

func TestEditMovesAPolicyOffItsManagedTap(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	f.addTap("edge", "netprobe", nil, nil)
	require.NoError(t, apply(be, "p1", netprobeBody("192.0.2.1"), false))
	body := netprobeBody("192.0.2.1")
	body["input"].(map[string]any)["tap"] = "edge"

	require.NoError(t, apply(be, "p1", body, true))

	assert.False(t, f.hasTap("fleet_netprobe"))
	pol, ok := f.policyNamed("p1")
	require.True(t, ok)
	assert.Equal(t, "edge", pol.tap)
}

func TestEditSwitchesTheManagedTapType(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	require.NoError(t, apply(be, "p1", netprobeBody("192.0.2.1"), false))

	require.NoError(t, apply(be, "p1", flowBody(), true))

	assert.False(t, f.hasTap("fleet_netprobe"))
	assert.True(t, f.hasTap("fleet_flow"))
}

// Fleet is shown the taps a policy can name, not the ones the agent manages.
func TestCapabilitiesLeaveOutManagedTaps(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	f.addTap("edge", "pcap", nil, nil)
	f.addTap("fleet_netprobe", "netprobe", nil, nil)

	caps, err := be.GetCapabilities()
	require.NoError(t, err)
	taps, ok := caps["taps"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, taps, "edge")
	assert.NotContains(t, taps, "fleet_netprobe")
}
