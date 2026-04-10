package configmgr

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet"
	"github.com/netboxlabs/orb-agent/agent/otlpbridge"
)

func TestFleetConfigManager_Stop_ShutsDownBridge(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mgr := newFleetConfigManager(logger, nil, nil)

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

	// Simulate having successfully connected: populate heartbeat topic and set monitorCtx.
	ctx, cancel := context.WithCancel(context.Background())
	mgr.monitorCtx = ctx
	mgr.monitorCancel = cancel
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
