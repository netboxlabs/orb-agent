package fleet

import (
	"log/slog"
	"os"
	"testing"

	"github.com/eclipse/paho.golang/paho"
)

// The broker's maximum packet size is kept from its CONNACK for the bridge to
// read; a CONNACK without one, or without properties, keeps zero, and a later
// connection replaces what an earlier one said.
func TestRecordBrokerLimits_KeepsTheConnacksMaximumPacketSize(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	conn := NewMQTTConnection(logger, noopPM{}, make(chan struct{}, 1), make(chan struct{}, 1), noopBackendState{}, nil)
	if got := conn.BrokerMaxPacketSize(); got != 0 {
		t.Fatalf("before any connection: got %d, want 0", got)
	}

	limit := uint32(16 << 20)
	conn.recordBrokerLimits(&paho.Connack{Properties: &paho.ConnackProperties{MaximumPacketSize: &limit}})
	if got := conn.BrokerMaxPacketSize(); got != limit {
		t.Fatalf("got %d, want %d", got, limit)
	}

	conn.recordBrokerLimits(&paho.Connack{Properties: &paho.ConnackProperties{}})
	if got := conn.BrokerMaxPacketSize(); got != 0 {
		t.Fatalf("a broker that sets none: got %d, want 0", got)
	}
	conn.recordBrokerLimits(&paho.Connack{})
	conn.recordBrokerLimits(nil)
	if got := conn.BrokerMaxPacketSize(); got != 0 {
		t.Fatalf("no properties: got %d, want 0", got)
	}
}
