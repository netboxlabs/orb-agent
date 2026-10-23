package fleet

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/eclipse/paho.golang/autopaho"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// minimal policy manager impl for constructor
type noopPM struct{}

func (noopPM) ManagePolicy(_ config.PolicyPayload)                                       {}
func (noopPM) RemovePolicyDataset(_ string, _ string, _ string, _ backend.Backend)       {}
func (noopPM) GetPolicyState() ([]policies.PolicyData, error)                            { return nil, nil }
func (noopPM) GetRepo() policies.PolicyRepo                                              { return nil }
func (noopPM) ApplyBackendPolicies(_ context.Context, _ string, _ backend.Backend) error { return nil }
func (noopPM) RemoveBackendPolicies(_ string, _ backend.Backend, _ bool) error           { return nil }
func (noopPM) RemovePolicy(_ string, _ string, _ string) error                           { return nil }
func (noopPM) SetStarter(_ policymgr.BackendStarter)                                     {}

type noopBackendState struct{}

func (noopBackendState) Get() map[string]*backend.State { return map[string]*backend.State{} }

func TestAddOnReadyHook_RegistersHook(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	reset := make(chan struct{}, 1)
	reconnect := make(chan struct{}, 1)
	conn := NewMQTTConnection(logger, noopPM{}, reset, reconnect, noopBackendState{}, nil)

	if len(conn.onReadyHooks) != 0 {
		t.Fatalf("expected 0 hooks initially, got %d", len(conn.onReadyHooks))
	}

	conn.AddOnReadyHook(func(_ *autopaho.ConnectionManager, _ TokenResponseTopics) {})

	if len(conn.onReadyHooks) != 1 {
		t.Fatalf("expected 1 hook after registration, got %d", len(conn.onReadyHooks))
	}
}

// A lost connection runs every down hook, in order, before onConnectionDown
// returns to the client, and the client keeps reconnecting.
func TestOnConnectionDown_RunsTheDownHooksBeforeTheClientReconnects(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	conn := NewMQTTConnection(logger, noopPM{}, make(chan struct{}, 1), make(chan struct{}, 1), noopBackendState{}, nil)

	var ran []int
	conn.AddOnDownHook(func() { ran = append(ran, 1) })
	conn.AddOnDownHook(func() { ran = append(ran, 2) })

	if !conn.onConnectionDown() {
		t.Fatal("onConnectionDown stopped the client reconnecting")
	}
	if len(ran) != 2 || ran[0] != 1 || ran[1] != 2 {
		t.Fatalf("down hooks ran %v, want [1 2]", ran)
	}
}

func TestConnect_StoresTopicsBeforeConnecting(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	reset := make(chan struct{}, 1)
	reconnect := make(chan struct{}, 1)
	conn := NewMQTTConnection(logger, noopPM{}, reset, reconnect, noopBackendState{}, nil)

	details := ConnectionDetails{
		MQTTURL:  "mqtt://localhost:1883",
		Token:    "",
		AgentID:  "agent-1",
		Topics:   TokenResponseTopics{Inbox: "inbox/x", Heartbeat: "hb/x", Capabilities: "cap/x", Outbox: "out/x", Ingest: "otlp/x", Telemetry: "telemetry/x"},
		ClientID: "client-1",
		Zone:     "zone-a",
	}

	// Tight deadline to fail fast without a broker
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_ = conn.Connect(ctx, ctx, details, map[string]backend.Backend{}, map[string]string{}, "")

	if conn.connectionTopics != details.Topics {
		t.Fatalf("expected connectionTopics to be stored before connect attempt")
	}
}
