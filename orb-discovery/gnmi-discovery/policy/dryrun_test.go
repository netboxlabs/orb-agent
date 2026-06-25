package policy

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
)

type rawNote struct {
	Updates []struct {
		Path  string `json:"path"`
		Value any    `json:"value"`
	} `json:"updates"`
	SyncDone bool `json:"syncDone"`
}

func loadStream(t *testing.T, path string) []gnmi.Notification {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	var raw []rawNote
	require.NoError(t, json.Unmarshal(b, &raw))
	var out []gnmi.Notification
	for _, r := range raw {
		n := gnmi.Notification{SyncDone: r.SyncDone}
		for _, u := range r.Updates {
			n.Updates = append(n.Updates, gnmi.Update{Path: u.Path, Value: u.Value})
		}
		out = append(out, n)
	}
	return out
}

func TestDryRunEOSGolden(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	fake := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{Vendor: "Arista"}, OnChangeSupport: true,
		OnChangeStream: loadStream(t, "testdata/eos_stream.json"),
	}
	rec := &recordingClient{}
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode: config.ModeOnChange, DebounceMs: 30,
			Defaults: config.Defaults{Site: "lab", Role: "spine", Interface: config.InterfaceDefaults{Type: "other"}},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: "10.0.0.1:6030", Profile: "arista_eos"}}},
	}
	r, err := NewRunner(context.Background(), slog.Default(), "eos", pol, rec, &gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.Start()
	defer func() { require.NoError(t, r.Stop()) }()

	require.Eventually(t, func() bool { return rec.count() >= 1 }, 2*time.Second, 20*time.Millisecond)

	// assert the last ingest has device spine1, one interface, one module
	// (the ModuleBay is emitted separately and not counted as Module)
	rec.mu.Lock()
	last := rec.ingested[len(rec.ingested)-1]
	rec.mu.Unlock()
	var dev, ifaces, mods int
	for _, e := range last {
		switch e.(type) {
		case *diode.Device:
			dev++
		case *diode.Interface:
			ifaces++
		case *diode.Module:
			mods++
		}
	}
	require.Equal(t, 1, dev)
	require.Equal(t, 1, ifaces)
	require.Equal(t, 1, mods)
}
