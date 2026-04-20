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
)

// minimal policy manager impl for constructor
type noopPM struct{}

func (noopPM) ManagePolicy(_ config.PolicyPayload)                       {}
func (noopPM) RemovePolicyDataset(_ string, _ string, _ backend.Backend) {}
func (noopPM) GetPolicyState() ([]policies.PolicyData, error)            { return nil, nil }
func (noopPM) GetRepo() policies.PolicyRepo                              { return nil }
func (noopPM) ApplyBackendPolicies(_ backend.Backend) error              { return nil }
func (noopPM) RemoveBackendPolicies(_ backend.Backend, _ bool) error     { return nil }
func (noopPM) RemovePolicy(_ string, _ string, _ string) error           { return nil }

type noopBackendState struct{}

func (noopBackendState) Get() map[string]*backend.State { return map[string]*backend.State{} }

func TestAddOnReadyHook_RegistersHook(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	reset := make(chan struct{}, 1)
	reconnect := make(chan struct{}, 1)
	conn := NewMQTTConnection(logger, noopPM{}, reset, reconnect, noopBackendState{})

	if len(conn.onReadyHooks) != 0 {
		t.Fatalf("expected 0 hooks initially, got %d", len(conn.onReadyHooks))
	}

	conn.AddOnReadyHook(func(_ *autopaho.ConnectionManager, _ TokenResponseTopics) {})

	if len(conn.onReadyHooks) != 1 {
		t.Fatalf("expected 1 hook after registration, got %d", len(conn.onReadyHooks))
	}
}

func TestConnect_StoresTopicsBeforeConnecting(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	reset := make(chan struct{}, 1)
	reconnect := make(chan struct{}, 1)
	conn := NewMQTTConnection(logger, noopPM{}, reset, reconnect, noopBackendState{})

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
