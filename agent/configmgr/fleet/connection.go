package fleet

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// MQTTConnection manages the MQTT connection
type MQTTConnection struct {
	logger            *slog.Logger
	connectionManager *autopaho.ConnectionManager
	heartbeater       *heartbeater
	messaging         *Messaging
	resetChan         chan struct{}
}

// NewMQTTConnection creates a new MQTTConnection
func NewMQTTConnection(logger *slog.Logger, pMgr policymgr.PolicyManager, resetChan chan struct{}, backendState backend.BackendState) *MQTTConnection {
	return &MQTTConnection{
		connectionManager: nil,
		logger:            logger,
		heartbeater:       newHeartbeater(logger, backendState),
		messaging:         NewMessaging(logger, pMgr, resetChan),
		resetChan:         resetChan,
	}
}

// TopicActions are the actions to take on a topic
type TopicActions struct {
	Subscribe   func(topic string) error
	Publish     func(ctx context.Context, topic string, payload []byte) error
	Unsubscribe func(topic string) error
}

// Connect connects to the MQTT broker
func (connection *MQTTConnection) Connect(ctx context.Context, fleetMQTTURL, token, agentID string, topics TokenResponseTopics, backends map[string]backend.Backend, clientID, zone string, labels map[string]string) error {
	// Parse the ORB URL
	serverURL, err := url.Parse(fleetMQTTURL)
	if err != nil {
		connection.logger.Error("failed to parse MQTT URL", "url", fleetMQTTURL, "error", err)
		return err
	}

	cfg := autopaho.ClientConfig{
		ServerUrls:                    []*url.URL{serverURL},
		KeepAlive:                     30,
		CleanStartOnInitialConnection: true,
		ConnectTimeout:                10 * time.Second,
		ReconnectBackoff: func(_ int) time.Duration {
			return 10 * time.Second
		},
		OnConnectionUp: func(cm *autopaho.ConnectionManager, _ *paho.Connack) {
			connection.logger.Info("MQTT connection established", "server", serverURL.String())

			_, err := cm.Subscribe(context.Background(), &paho.Subscribe{
				Subscriptions: []paho.SubscribeOptions{
					{Topic: topics.Inbox, QoS: 1},
				},
			})
			if err != nil {
				connection.logger.Error("failed to subscribe", "topic", topics.Inbox, "error", err)
			} else {
				connection.logger.Info("successfully subscribed", "topic", topics.Inbox)
			}

			// start heartbeat loop bound to the same connection-level context
			go connection.heartbeater.sendHeartbeats(ctx, func() {}, topics.Heartbeat, clientID, connection.publishToTopic)

			connection.messaging.sendCapabilities(ctx, backends, labels, func(ctx context.Context, payload []byte) error {
				_, err := cm.Publish(ctx, &paho.Publish{
					Topic:   topics.Capabilities,
					Payload: payload,
					QoS:     1,
					Retain:  false,
				})
				if err != nil {
					// TODO: reconnect?
					connection.logger.Error("failed to publish capabilities", "error", err)
					return err
				}

				connection.logger.Debug("capabilities sent",
					"topic", topics.Capabilities,
					"payload", string(payload),
				)
				return nil
			})

			go connection.messaging.sendGroupMembershipsRequest(ctx, func(ctx context.Context, payload []byte) error {
				_, err := cm.Publish(ctx, &paho.Publish{
					Topic:   topics.Outbox,
					Payload: payload,
					QoS:     1,
					Retain:  false,
				})
				if err != nil {
					connection.logger.Error("failed to publish group memberships request", "error", err)
					return err
				}
				return nil
			})
		},
		OnConnectError: func(err error) {
			connection.logger.Error("MQTT connection error", "error", err)
		},
		ClientConfig: paho.ClientConfig{
			ClientID: clientID,
			OnPublishReceived: []func(paho.PublishReceived) (bool, error){
				func(pr paho.PublishReceived) (bool, error) {
					// Log any published messages to subscribed topics
					connection.logger.Info("received MQTT message", "topic", pr.Packet.Topic)

					orgID := strings.Split(pr.Packet.Topic, "/")[1]

					// Use a fresh context for async message handling, not the Connect() context
					// which may be canceled or have a short timeout
					err = connection.messaging.DispatchToHandlers(
						context.Background(),
						pr.Packet.Payload,
						orgID,
						agentID,
						TopicActions{
							Subscribe:   connection.subscribeToTopic,
							Publish:     connection.publishToTopic,
							Unsubscribe: connection.unsubscribeFromTopic,
						},
					)
					if err != nil {
						connection.logger.Error("failed to dispatch to handlers", "error", err)
					}

					return true, nil
				},
			},
		},
	}

	// Set authentication if token is provided
	if token != "" {
		connection.logger.Info("setting MQTT authentication", "client_id", clientID, "zone", zone)
		cfg.ConnectUsername = fmt.Sprintf("%s:%s", zone, clientID)
		cfg.ConnectPassword = []byte(token)
	}

	// Create and start the connection manager using the long-lived context.
	connection.connectionManager, err = autopaho.NewConnection(ctx, cfg)
	if err != nil {
		connection.logger.Error("failed to create MQTT connection", "error", err)
		return err
	}

	// Wait for the initial connection; bound this operation with a timeout that
	// is still cancellable from the parent.
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	err = connection.connectionManager.AwaitConnection(waitCtx)
	if err != nil {
		connection.logger.Error("failed to establish initial MQTT connection", "error", err)
		return err
	}

	connection.logger.Info("MQTT connection manager started successfully")
	return nil
}

// Disconnect disconnects from the MQTT broker
func (connection *MQTTConnection) Disconnect(ctx context.Context, heartbeatTopic string) error {
	connection.heartbeater.stop(heartbeatTopic, connection.publishToTopic)
	return connection.connectionManager.Disconnect(ctx)
}

func (connection *MQTTConnection) subscribeToTopic(topic string) error {
	_, err := connection.connectionManager.Subscribe(context.Background(), &paho.Subscribe{
		Subscriptions: []paho.SubscribeOptions{
			{Topic: topic, QoS: 1},
		},
	})
	return err
}

func (connection *MQTTConnection) unsubscribeFromTopic(topic string) error {
	_, err := connection.connectionManager.Unsubscribe(context.Background(), &paho.Unsubscribe{
		Topics: []string{topic},
	})
	return err
}

func (connection *MQTTConnection) publishToTopic(ctx context.Context, topic string, payload []byte) error {
	connection.logger.Debug("publishing to topic", "topic", topic, "payload", string(payload))
	_, err := connection.connectionManager.Publish(ctx, &paho.Publish{
		Topic:   topic,
		Payload: payload,
		QoS:     0,
		Retain:  false,
	})
	if err != nil {
		connection.logger.Error("failed to publish to topic", "topic", topic, "error", err)
		return err
	}
	return nil
}
