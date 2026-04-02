package otlpbridge

import (
	"context"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
)

// CMAdapterPublisher adapts autopaho.ConnectionManager to implement Publisher.
// It uses PublishViaQueue so that messages are buffered in memory during MQTT
// disconnects and drained automatically after reconnection — no data loss.
type CMAdapterPublisher struct {
	cm *autopaho.ConnectionManager
}

// NewCMAdapterPublisher creates a new adapter for an autopaho connection manager.
func NewCMAdapterPublisher(cm *autopaho.ConnectionManager) *CMAdapterPublisher {
	return &CMAdapterPublisher{cm: cm}
}

// Publish enqueues the payload for delivery to the topic with QoS 0.
// Returns an error only if the message could not be added to the local queue.
// Actual transmission happens asynchronously after the MQTT connection is up.
func (p *CMAdapterPublisher) Publish(ctx context.Context, topic string, payload []byte) error {
	return p.cm.PublishViaQueue(ctx, &autopaho.QueuePublish{
		Publish: &paho.Publish{
			Topic:   topic,
			Payload: payload,
			QoS:     0,
			Retain:  false,
		},
	})
}
