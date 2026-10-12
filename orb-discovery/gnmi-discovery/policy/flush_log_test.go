package policy

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
)

// syncBuf is a Writer the runner's goroutines and the test body can share.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// A target that discovers over a fallback mode must say so once. Without this
// line the only thing a healthy target logs is that on_change was unavailable,
// which reads as a failure and is what it looked like on an IOS-XE box that was
// discovering normally over SAMPLE.
//
// Once per connection, not once per flush: SAMPLE re-sends its snapshot on every
// interval, so a per-flush line would repeat for the life of the target.
func TestRunnerLogsTheFirstFlushOncePerConnection(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)

	fake := &gnmi.FakeSession{
		Caps:            &gnmi.CapabilitiesResult{Vendor: "Cisco"},
		OnChangeSupport: false, // auto walks the ladder down to sample
		SampleSnapshots: []gnmi.Notification{
			{Updates: []gnmi.Update{{Path: "/system/state/hostname", Value: "r1"}}},
			{SyncDone: true},
		},
		SampleReplay: 20 * time.Millisecond,
	}
	logs := &syncBuf{}
	client := &recordingClient{}
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode: config.ModeAuto, DebounceMs: 10,
			Defaults: config.Defaults{Site: "lab", Role: "router"},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: "10.0.0.1:6030"}}},
	}
	r, err := NewRunner(context.Background(), slog.New(slog.NewTextHandler(logs, nil)),
		"p1", pol, client, &gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.Start()
	defer func() { require.NoError(t, r.Stop()) }()

	// several flushes, so a per-flush line would have repeated by now
	require.Eventually(t, func() bool { return client.count() >= 3 }, 3*time.Second, 20*time.Millisecond)

	out := logs.String()
	assert.Equal(t, 1, strings.Count(out, "discovery flushed"),
		"logged once per connection, not once per flush")
	assert.Contains(t, out, "active_mode=sample",
		"the line carries the mode the target settled on")
	assert.Contains(t, out, "on_change not available",
		"the downgrade is still reported, just not as a failure")
}
