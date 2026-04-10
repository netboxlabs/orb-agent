package otlpbridge

import (
	"context"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
)

// CMAdapterPublisher adapts autopaho.ConnectionManager to implement Publisher.
// It uses synchronous Publish so that MQTT failures propagate back to the OTLP
// client as errors, providing natural backpressure. The BridgeServer's own
// bounded pending queue handles buffering before the connection is ready.
type CMAdapterPublisher struct {
	cm *autopaho.ConnectionManager
}

// NewCMAdapterPublisher creates a new adapter for an autopaho connection manager.
func NewCMAdapterPublisher(cm *autopaho.ConnectionManager) *CMAdapterPublisher {
	return &CMAdapterPublisher{cm: cm}
}

// Publish sends the payload synchronously to the topic with QoS 0.
// Returns an error if the MQTT connection is down, allowing the caller
// to apply backpressure or retry rather than buffering unboundedly.
func (p *CMAdapterPublisher) Publish(ctx context.Context, topic string, payload []byte) error {
	_, err := p.cm.Publish(ctx, &paho.Publish{
		Topic:   topic,
		Payload: payload,
		QoS:     0,
		Retain:  false,
	})
	return err
}
