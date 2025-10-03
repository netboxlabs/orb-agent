package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
	"github.com/netboxlabs/orb-agent/agent/version"
)

// MQTTConnection manages the MQTT connection
type MQTTConnection struct {
	logger            *slog.Logger
	connectionManager *autopaho.ConnectionManager
	heartbeater       *heartbeater
}

// NewMQTTConnection creates a new MQTTConnection
func NewMQTTConnection(logger *slog.Logger) *MQTTConnection {
	return &MQTTConnection{
		connectionManager: nil,
		logger:            logger,
		heartbeater:       newHeartbeater(logger),
	}
}

// Connect connects to the MQTT broker
func (connection *MQTTConnection) Connect(ctx context.Context, fleetMQTTURL, token string, topics TokenResponseTopics, backends map[string]backend.Backend, clientID, zone string, labels map[string]string) error {
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
			go connection.heartbeater.sendHeartbeats(ctx, func() {}, func(ctx context.Context, payload []byte) error {
				publishResponse, err := cm.Publish(ctx, &paho.Publish{
					Topic:   topics.Heartbeat,
					Payload: payload,
					QoS:     0,
					Retain:  false,
				})
				if err != nil {
					connection.logger.Error("failed to publish heartbeat", "error", err)
					// TODO: reconnect?
					return err
				}
				if publishResponse.ReasonCode != 0 {
					connection.logger.Debug("failed to publish heartbeat", "reason_code", publishResponse.ReasonCode, "topic", topics.Heartbeat)
					return fmt.Errorf("reason code indicates failure: %d", publishResponse.ReasonCode)
				}
				connection.logger.Debug("heartbeat sent",
					"topic", topics.Heartbeat,
					"payload", string(payload),
				)
				return nil
			}, clientID)

			go connection.sendCapabilities(ctx, backends, labels, func(ctx context.Context, payload []byte) error {
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

			// TODO: this is a hack to work around the race condition of capabilities not being processed by the time we request group memberships
			time.Sleep(10 * time.Second)
			go connection.sendGroupMembershipsRequest(ctx, func(ctx context.Context, payload []byte) error {
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
					var rpc messages.RPC
					if err := json.Unmarshal(pr.Packet.Payload, &rpc); err != nil {
						connection.logger.Error("failed to unmarshal RPC", "error", err)
						return true, nil
					}

					connection.dispatchToHandlers(rpc.Func, rpc, orgID)

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
func (connection *MQTTConnection) Disconnect(ctx context.Context) error {
	connection.heartbeater.stop()
	return connection.connectionManager.Disconnect(ctx)
}

func (connection *MQTTConnection) sendGroupMembershipsRequest(ctx context.Context, publishFunc func(ctx context.Context, payload []byte) error) {
	body, err := json.Marshal(messages.RPC{
		// SchemaVersion: messages.CurrentRPCSchemaVersion, // TODO: add schema version check later
		Func:    "group_membership_req",
		Payload: messages.SendGroupMembershipsRequest{},
	})
	if err != nil {
		connection.logger.Error("backend failed to marshal capabilities, skipping", "error", err)
		return
	}

	connection.logger.Info("sending group memberships request", "value", string(body))
	err = publishFunc(ctx, body)
	if err != nil {
		connection.logger.Error("error sending group memberships request", "error", err)
	}
	connection.logger.Info("group memberships request sent", "value", string(body))
}

func (connection *MQTTConnection) sendCapabilities(ctx context.Context, backends map[string]backend.Backend, labels map[string]string, publishFunc func(ctx context.Context, payload []byte) error) {
	capabilities := messages.Capabilities{
		SchemaVersion: messages.CurrentCapabilitiesSchemaVersion,
		AgentLabels:   labels,
		OrbAgent: messages.OrbAgentInfo{
			Version: version.GetBuildVersion(),
		},
	}

	capabilities.Backends = make(map[string]messages.BackendInfo)
	for name, be := range backends {
		ver, err := be.Version()
		if err != nil {
			connection.logger.Error("backend failed to retrieve version, skipping", "backend", name, "error", err)
			continue
		}
		cp, err := be.GetCapabilities()
		if err != nil {
			connection.logger.Error("backend failed to retrieve capabilities, skipping", "backend", name, "error", err)
			continue
		}
		capabilities.Backends[name] = messages.BackendInfo{
			Version: ver,
			Data:    cp,
		}
	}

	body, err := json.Marshal(capabilities)
	if err != nil {
		connection.logger.Error("backend failed to marshal capabilities, skipping", "error", err)
		return
	}

	connection.logger.Info("sending capabilities", "value", string(body))
	err = publishFunc(ctx, body)
	if err != nil {
		connection.logger.Error("error sending capabilities", "error", err)
	}
}

func (connection *MQTTConnection) dispatchToHandlers(messageType string, rpc messages.RPC, orgID string) {
	switch messageType {
	case "group_membership":
		connection.handleGroupMemberships(rpc, orgID)
	default:
		connection.logger.Debug("unknown message type", "message_type", messageType)
	}
}

func (connection *MQTTConnection) handleGroupMemberships(rpc messages.RPC, orgID string) {
	connection.logger.Debug("handling group memberships", "payload", rpc.Payload)
	payloadJSON, err := json.Marshal(rpc.Payload)
	if err != nil {
		connection.logger.Error("failed to marshal payload", "error", err)
		return
	}
	groupMeberships := messages.GroupMemberships{}
	if err := json.Unmarshal(payloadJSON, &groupMeberships); err != nil {
		connection.logger.Error("failed to unmarshal payload", "error", err)
		return
	}

	for _, group := range groupMeberships.Groups {
		connection.logger.Info("subscribing to group", "group", group)
		_, err := connection.connectionManager.Subscribe(context.Background(), &paho.Subscribe{
			Subscriptions: []paho.SubscribeOptions{
				{Topic: groupTopic(orgID, group.GroupID), QoS: 1},
			},
		})
		if err != nil {
			connection.logger.Error("failed to subscribe to group", "error", err)
		}
		connection.logger.Info("subscribed to group topic for group ID", "group_id", group.GroupID)
	}
}
