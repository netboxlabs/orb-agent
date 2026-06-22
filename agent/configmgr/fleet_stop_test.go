package configmgr

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet"
	"github.com/netboxlabs/orb-agent/agent/otlpbridge"
)

func TestFleetConfigManager_StartOTLPBridge_Idempotent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mockPMgr := &mockPolicyManagerForFleet{}
	mockPMgr.On("GetRepo").Return(nil)
	mgr := newFleetConfigManager(logger, mockPMgr, nil, nil)

	port := findAvailablePort(t)
	cfg := config.Config{}
	cfg.OrbAgent.ConfigManager.Sources.Fleet.OTLPBridgeGRPCPort = &port

	ctx := context.Background()
	require.NoError(t, mgr.StartOTLPBridge(ctx, cfg))
	bridge := mgr.otlpBridge
	require.NotNil(t, bridge)

	require.NoError(t, mgr.StartOTLPBridge(ctx, cfg))
	assert.Same(t, bridge, mgr.otlpBridge, "second StartOTLPBridge should reuse existing bridge")

	require.NoError(t, mgr.StopOTLPBridge(ctx))
	assert.Nil(t, mgr.otlpBridge)
}

func TestFleetConfigManager_Stop_ShutsDownBridge(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mgr := newFleetConfigManager(logger, nil, nil, nil)

	// Create a real bridge on an ephemeral port
	bridge, err := otlpbridge.NewBridgeServer(otlpbridge.BridgeConfig{ListenAddr: ":0", Encoding: "protobuf"}, nil, logger)
	if err != nil {
		t.Fatalf("unexpected error creating bridge: %v", err)
	}
	if err := bridge.Start(context.Background()); err != nil {
		t.Fatalf("unexpected error starting bridge: %v", err)
	}
	mgr.otlpBridge = bridge

	// Stop should not error
	if err := mgr.Stop(context.Background()); err != nil {
		t.Fatalf("unexpected error stopping manager: %v", err)
	}

	// Second stop is a no-op
	if err := mgr.Stop(context.Background()); err != nil {
		t.Fatalf("unexpected error on second stop: %v", err)
	}
}

func TestFleetConfigManager_Stop_DisconnectsMQTT(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mockConn := &fleet.MockMQTTConnection{}

	mgr := newFleetConfigManagerWithConnection(logger, nil, nil, mockConn)

	// Simulate having successfully connected: set connected flag, heartbeat topic,
	// monitorCtx, and connCtx (both are created by Start() in production).
	monitorCtx, monitorCancel := context.WithCancel(context.Background())
	connCtx, connCancel := context.WithCancel(context.Background())
	mgr.monitorCtx = monitorCtx
	mgr.monitorCancel = monitorCancel
	mgr.connCtx = connCtx
	mgr.connCancel = connCancel
	mgr.connected.Store(true)
	mgr.connectionDetails = fleet.ConnectionDetails{
		Topics: fleet.TokenResponseTopics{Heartbeat: "agents/test/heartbeat"},
	}

	if err := mgr.Stop(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !mockConn.DisconnectCalled() {
		t.Error("expected Disconnect() to be called during Stop(), but it was not")
	}
}

// TestFleetConfigManager_Stop_ConnCtxCancelledAfterStop verifies that the MQTT
// connection context (connCtx) is cancelled after Stop() completes, confirming it
// has a separate lifecycle from monitorCtx and is properly cleaned up.
func TestFleetConfigManager_Stop_ConnCtxCancelledAfterStop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mockConn := &fleet.MockMQTTConnection{}

	mgr := newFleetConfigManagerWithConnection(logger, nil, nil, mockConn)
	monitorCtx, monitorCancel := context.WithCancel(context.Background())
	connCtx, connCancel := context.WithCancel(context.Background())
	mgr.monitorCtx = monitorCtx
	mgr.monitorCancel = monitorCancel
	mgr.connCtx = connCtx
	mgr.connCancel = connCancel
	mgr.connected.Store(true)
	mgr.connectionDetails = fleet.ConnectionDetails{
		Topics: fleet.TokenResponseTopics{Heartbeat: "agents/test/heartbeat"},
	}

	if err := mgr.Stop(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if connCtx.Err() == nil {
		t.Error("connCtx should be cancelled after Stop() completes")
	}
}

func TestFleetConfigManager_Stop_SkipsDisconnectWhenNotStarted(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mockConn := &fleet.MockMQTTConnection{}

	mgr := newFleetConfigManagerWithConnection(logger, nil, nil, mockConn)
	// monitorCtx/monitorCancel are nil — Start() was never called

	if err := mgr.Stop(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mockConn.DisconnectCalled() {
		t.Error("Disconnect() must NOT be called when Start() was never invoked")
	}
}
