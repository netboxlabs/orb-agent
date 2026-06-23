package policy

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func boolPtr(b bool) *bool { return &b }

func deviceOf(ents []diode.Entity) *diode.Device {
	for _, e := range ents {
		if d, ok := e.(*diode.Device); ok {
			return d
		}
	}
	return nil
}

// capture_config on: the captured CONFIG datastore is fetched once, redacted,
// and attached to the ingested Device as DeviceConfig.Running.
func TestRunnerCapturesAndRedactsConfig(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)

	fake := &gnmi.FakeSession{
		Caps:            &gnmi.CapabilitiesResult{Vendor: "Arista"},
		OnChangeSupport: true,
		OnChangeStream: []gnmi.Notification{
			{Updates: []gnmi.Update{{Path: "/system/state/hostname", Value: "r1"}}},
			{SyncDone: true},
		},
		ConfigBytes: []byte(`{"openconfig-system:system":{"config":{"hostname":"r1","login-password":"s3cret"}}}`),
	}
	client := &recordingClient{}
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode: config.ModeOnChange, DebounceMs: 30,
			Defaults: config.Defaults{Site: "lab", Role: "router"},
			Options:  config.Options{CaptureConfig: boolPtr(true)},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: "10.0.0.1:6030"}}},
	}
	r, err := NewRunner(context.Background(), slog.Default(), "p1", pol, client,
		&gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.Start()
	defer func() { require.NoError(t, r.Stop()) }()

	require.Eventually(t, func() bool { return client.count() >= 1 }, 2*time.Second, 20*time.Millisecond)

	dev := deviceOf(client.lastIngested())
	require.NotNil(t, dev)
	require.NotNil(t, dev.Config, "Device.Config must be set when capture_config is on")
	running := string(dev.Config.Running)
	assert.Contains(t, running, `"hostname":"r1"`, "non-secret config preserved")
	assert.Contains(t, running, "***", "secret leaf redacted")
	assert.NotContains(t, running, "s3cret", "plaintext secret must not survive redaction")
	assert.Nil(t, dev.Config.Startup, "no gNMI startup datastore")

	// Config is fetched once per connection regardless of flush count.
	assert.Equal(t, 1, fake.ConfigGets)
}

// capture_config on but GetConfig fails: the inventory flush still proceeds and
// the Device is ingested without config.
func TestRunnerConfigCaptureFailureDoesNotBlockFlush(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)

	fake := &gnmi.FakeSession{
		Caps:            &gnmi.CapabilitiesResult{Vendor: "Arista"},
		OnChangeSupport: true,
		OnChangeStream: []gnmi.Notification{
			{Updates: []gnmi.Update{{Path: "/system/state/hostname", Value: "r1"}}},
			{SyncDone: true},
		},
		ConfigErr: errors.New("config datastore unavailable"),
	}
	client := &recordingClient{}
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode: config.ModeOnChange, DebounceMs: 30,
			Defaults: config.Defaults{Site: "lab", Role: "router"},
			Options:  config.Options{CaptureConfig: boolPtr(true)},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: "10.0.0.1:6030"}}},
	}
	r, err := NewRunner(context.Background(), slog.Default(), "p1", pol, client,
		&gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.Start()
	defer func() { require.NoError(t, r.Stop()) }()

	require.Eventually(t, func() bool { return client.count() >= 1 }, 2*time.Second, 20*time.Millisecond)
	dev := deviceOf(client.lastIngested())
	require.NotNil(t, dev, "device must still be ingested despite config-capture failure")
	assert.Nil(t, dev.Config, "no config attached when GetConfig failed")
	require.NotNil(t, dev.Name)
	assert.Equal(t, "r1", *dev.Name)
}

// asset_tag as a gNMI path reference is resolved via a targeted Get (GetOnce)
// when the leaf is not in the subscribed snapshot, then attached to the Device.
func TestRunnerResolvesAssetTagByPathRef(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)

	const assetPath = "/components/component[name=Chassis]/state/asset-id"
	fake := &gnmi.FakeSession{
		Caps:            &gnmi.CapabilitiesResult{Vendor: "Arista"},
		OnChangeSupport: true,
		OnChangeStream: []gnmi.Notification{
			{Updates: []gnmi.Update{{Path: "/system/state/hostname", Value: "r1"}}},
			{SyncDone: true},
		},
		// GetOnce (the targeted asset-tag fetch) returns the referenced leaf.
		GetResult: gnmi.Notification{Updates: []gnmi.Update{{Path: assetPath, Value: "RACK42-SLOT3"}}},
	}
	client := &recordingClient{}
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode: config.ModeOnChange, DebounceMs: 30,
			Defaults: config.Defaults{Site: "lab", Role: "router", AssetTag: assetPath},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: "10.0.0.1:6030"}}},
	}
	r, err := NewRunner(context.Background(), slog.Default(), "p1", pol, client,
		&gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.Start()
	defer func() { require.NoError(t, r.Stop()) }()

	require.Eventually(t, func() bool { return client.count() >= 1 }, 2*time.Second, 20*time.Millisecond)
	dev := deviceOf(client.lastIngested())
	require.NotNil(t, dev)
	require.NotNil(t, dev.AssetTag, "asset_tag must be resolved from the path reference")
	assert.Equal(t, "RACK42-SLOT3", *dev.AssetTag)
}

// capture_config off (default): GetConfig is never called and no config is attached.
func TestRunnerConfigCaptureDisabled(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)

	fake := &gnmi.FakeSession{
		Caps:            &gnmi.CapabilitiesResult{Vendor: "Arista"},
		OnChangeSupport: true,
		OnChangeStream: []gnmi.Notification{
			{Updates: []gnmi.Update{{Path: "/system/state/hostname", Value: "r1"}}},
			{SyncDone: true},
		},
		ConfigBytes: []byte(`{"x":1}`),
	}
	client := &recordingClient{}
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode: config.ModeOnChange, DebounceMs: 30,
			Defaults: config.Defaults{Site: "lab", Role: "router"},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: "10.0.0.1:6030"}}},
	}
	r, err := NewRunner(context.Background(), slog.Default(), "p1", pol, client,
		&gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.Start()
	defer func() { require.NoError(t, r.Stop()) }()

	require.Eventually(t, func() bool { return client.count() >= 1 }, 2*time.Second, 20*time.Millisecond)
	dev := deviceOf(client.lastIngested())
	require.NotNil(t, dev)
	assert.Nil(t, dev.Config)
	assert.Equal(t, 0, fake.ConfigGets, "GetConfig must not be called when capture_config is off")
}
