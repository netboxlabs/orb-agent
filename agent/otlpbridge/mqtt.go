package otlpbridge

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
)

// MQTTPublisher is a Publisher backed by an autopaho connection manager.
type MQTTPublisher struct {
	cm *autopaho.ConnectionManager
}

// NewMQTTPublisher connects to the MQTT broker and returns a Publisher.
// It awaits initial connection before returning. If tokenRefresher is non-nil,
// it is called before every CONNECT packet to supply a fresh JWT.
func NewMQTTPublisher(ctx context.Context, mqttURL, jwt string, tokenRefresher func(ctx context.Context) (string, error)) (*MQTTPublisher, error) {
	u, err := url.Parse(mqttURL)
	if err != nil {
		return nil, fmt.Errorf("invalid mqtt url: %w", err)
	}

	clientID := randomClientID()

	cfg := autopaho.ClientConfig{
		ServerUrls:                    []*url.URL{u},
		KeepAlive:                     30,
		CleanStartOnInitialConnection: true,
		ConnectTimeout:                10 * time.Second,
		ReconnectBackoff:              func(_ int) time.Duration { return 5 * time.Second },
		ClientConfig:                  paho.ClientConfig{ClientID: clientID},
	}

	if jwt != "" {
		cfg.ConnectUsername = clientID
		cfg.ConnectPassword = []byte(jwt)
	}

	if tokenRefresher != nil {
		cfg.ConnectPacketBuilder = func(cp *paho.Connect, _ *url.URL) (*paho.Connect, error) {
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			freshJWT, err := tokenRefresher(ctx)
			if err != nil {
				return cp, nil // fall through with existing token
			}
			cp.Password = []byte(freshJWT)
			return cp, nil
		}
	}

	cm, err := autopaho.NewConnection(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create mqtt connection: %w", err)
	}

	// Wait for the initial connection
	if err := cm.AwaitConnection(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to mqtt: %w", err)
	}

	return &MQTTPublisher{cm: cm}, nil
}

// Publish sends the payload to the topic with QoS 0.
func (p *MQTTPublisher) Publish(ctx context.Context, topic string, payload []byte) error {
	_, err := p.cm.Publish(ctx, &paho.Publish{
		Topic:   topic,
		Payload: payload,
		QoS:     0,
		Retain:  false,
	})
	return err
}

// Close disconnects from the broker.
func (p *MQTTPublisher) Close(ctx context.Context) error {
	return p.cm.Disconnect(ctx)
}

func randomClientID() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return "otlp-bridge-" + hex.EncodeToString(buf)
}
