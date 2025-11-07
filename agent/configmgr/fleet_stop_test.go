package configmgr

import (
	"context"
	"log/slog"
	"os"
	"testing"

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
