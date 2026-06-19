package fleet

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// TopicMessageHandler handles messages for a specific topic
type TopicMessageHandler func(topic string, payload []byte) error

// dispatchJob represents a message to be processed by the dispatch worker
type dispatchJob struct {
	payload      []byte
	orgID        string
	agentID      string
	topicActions TopicActions
}

// MQTTConnection manages the MQTT connection
type MQTTConnection struct {
	logger                   *slog.Logger
	connectionManager        *autopaho.ConnectionManager
	heartbeater              *heartbeater
	messaging                *Messaging
	resetChan                chan struct{}
	onReadyHooks             []func(cm *autopaho.ConnectionManager, topics TokenResponseTopics)
	topicHandlers            map[string]TopicMessageHandler
	connectionTopics         TokenResponseTopics
	reconnectChan            chan struct{}
	dispatchQueue            chan dispatchJob
	dispatchWorkerDone       chan struct{}
	dispatchMu               sync.Mutex // guards shuttingDown + dispatchQueue close
	shuttingDown             bool
	capabilitiesFailCount    int
	groupMembershipFailCount int
	heartbeatFailCount       int
	mu                       sync.Mutex
}

// NewMQTTConnection creates a new MQTTConnection
func NewMQTTConnection(logger *slog.Logger, pMgr policymgr.PolicyManager, resetChan chan struct{}, reconnectChan chan struct{}, backendState backend.StateRetriever, filesManager filesmgr.Manager) *MQTTConnection {
	groupManager := newGroupManager()
	return &MQTTConnection{
		connectionManager:  nil,
		logger:             logger,
		heartbeater:        newHeartbeater(logger, backendState, pMgr, &groupManager),
		messaging:          NewMessaging(logger, pMgr, resetChan, &groupManager, filesManager),
		resetChan:          resetChan,
		onReadyHooks:       make([]func(cm *autopaho.ConnectionManager, topics TokenResponseTopics), 0),
		topicHandlers:      make(map[string]TopicMessageHandler),
		reconnectChan:      reconnectChan,
		dispatchQueue:      make(chan dispatchJob, 100), // Buffered channel to prevent blocking MQTT acks
		dispatchWorkerDone: make(chan struct{}),
	}
}

// AddOnReadyHook registers a callback to be invoked when MQTT connection is ready.
func (connection *MQTTConnection) AddOnReadyHook(fn func(cm *autopaho.ConnectionManager, topics TokenResponseTopics)) {
	connection.onReadyHooks = append(connection.onReadyHooks, fn)
}

// RegisterTopicHandler registers a handler for a specific topic
func (connection *MQTTConnection) RegisterTopicHandler(topic string, handler TopicMessageHandler) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	connection.topicHandlers[topic] = handler
}

// TopicActions are the actions to take on a topic
type TopicActions struct {
	Subscribe   func(topic string) error
	Publish     func(ctx context.Context, topic string, payload []byte) error
	Unsubscribe func(topic string) error
}

// ConnectionDetails contains the details needed to connect to the MQTT broker
type ConnectionDetails struct {
	MQTTURL  string
	Token    string
	AgentID  string
	Topics   TokenResponseTopics
	ClientID string
	Zone     string
}

// MQTTConnector defines the interface for MQTT connection operations.
//
// Connect and Reconnect take two distinct contexts:
//   - ctx (lifecycle): passed to autopaho.NewConnection; must remain live until
//     the connection is intentionally torn down (typically connCtx in fleet.go).
//   - waitCtx (wait): governs the AwaitConnection call and, for Reconnect, the
//     disconnect-before-reconnect timeout; should be cancellable by shutdown
//     (typically monitorCtx) so Stop() is not blocked by in-flight connect attempts.
type MQTTConnector interface {
	Connect(ctx context.Context, waitCtx context.Context, details ConnectionDetails, backends map[string]backend.Backend, labels map[string]string, configFile string) error
	Disconnect(ctx context.Context, heartbeatTopic string) error
	Reconnect(ctx context.Context, waitCtx context.Context, details ConnectionDetails, backends map[string]backend.Backend, labels map[string]string, configFile string, timeout time.Duration) error
	AddOnReadyHook(fn func(cm *autopaho.ConnectionManager, topics TokenResponseTopics))
	RegisterTopicHandler(topic string, handler TopicMessageHandler)
}

// startDispatchWorker starts the worker goroutine that processes dispatch jobs sequentially.
func (connection *MQTTConnection) startDispatchWorker() {
	go func() {
		defer close(connection.dispatchWorkerDone)
		for job := range connection.dispatchQueue {
			connection.processJob(job)
		}
	}()
}

// processJob dispatches a single job to message handlers.
func (connection *MQTTConnection) processJob(job dispatchJob) {
	err := connection.messaging.DispatchToHandlers(
		context.Background(),
		job.payload,
		job.orgID,
		job.agentID,
		job.topicActions,
	)
	if err != nil {
		connection.logger.Error("failed to dispatch to handlers", "error", err)
	}
}

// stopDispatchWorker stops the dispatch worker and waits for it to finish.
// All reads of dispatchWorkerDone and dispatchQueue are done under dispatchMu
// so that senders and concurrent stoppers cannot race with the queue close.
func (connection *MQTTConnection) stopDispatchWorker() {
	connection.dispatchMu.Lock()

	done := connection.dispatchWorkerDone
	select {
	case <-done:
		connection.dispatchMu.Unlock()
		return
	default:
	}

	if connection.shuttingDown {
		connection.dispatchMu.Unlock()
		<-done
		return
	}

	connection.shuttingDown = true
	close(connection.dispatchQueue)
	connection.dispatchMu.Unlock()

	<-done
}

// Connect connects to the MQTT broker. It is safe to call after a previous
// failed Connect (e.g. from a startup retry loop): any existing dispatch
// worker and connection manager are torn down before reinitializing.
func (connection *MQTTConnection) Connect(ctx context.Context, waitCtx context.Context, details ConnectionDetails, backends map[string]backend.Backend, labels map[string]string, configFile string) error {
	// Parse the ORB URL
	serverURL, err := url.Parse(details.MQTTURL)
	if err != nil {
		connection.logger.Error("failed to parse MQTT URL", "url", details.MQTTURL, "error", err)
		return err
	}

	// Tear down any prior state so repeated Connect calls don't leak goroutines.
	// Only needed when a previous Connect left a running connection manager.
	if connection.connectionManager != nil {
		teardownCtx, teardownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = connection.connectionManager.Disconnect(teardownCtx)
		teardownCancel()
		connection.connectionManager = nil
		connection.stopDispatchWorker()
	}

	// Reinitialize dispatch channels after validation and teardown.
	connection.dispatchMu.Lock()
	connection.dispatchQueue = make(chan dispatchJob, 100)
	connection.dispatchWorkerDone = make(chan struct{})
	connection.shuttingDown = false
	connection.dispatchMu.Unlock()

	// Store topics for hook callbacks
	connection.connectionTopics = details.Topics

	// Start the dispatch worker to process incoming messages sequentially
	connection.startDispatchWorker()

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
					{Topic: details.Topics.Inbox, QoS: 1},
				},
			})
			if err != nil {
				connection.logger.Error("failed to subscribe", "topic", details.Topics.Inbox, "error", err)
			} else {
				connection.logger.Info("successfully subscribed", "topic", details.Topics.Inbox)
			}

			// Call onReady hooks
			for _, hook := range connection.onReadyHooks {
				go func(h func(cm *autopaho.ConnectionManager, topics TokenResponseTopics)) {
					h(cm, connection.connectionTopics)
				}(hook)
			}

			// Start heartbeat session without blocking OnConnectionUp: StartHeartbeats
			// may wait for a prior session to drain on reconnect (OBS-2315 review).
			go connection.heartbeater.StartHeartbeats(ctx, details.Topics.Heartbeat, details.ClientID, connection.publishToTopic, func() {
				// Track heartbeat failures
				connection.heartbeatFailCount++
				connection.logger.Error("heartbeat publish failed",
					"fail_count", connection.heartbeatFailCount)

				// After 5 consecutive failures, trigger reconnect
				if connection.heartbeatFailCount >= 5 {
					connection.logger.Warn("heartbeat publish failed 5 times, triggering JWT refresh and reconnect")
					select {
					case connection.reconnectChan <- struct{}{}:
					default:
						connection.logger.Debug("reconnect already in progress")
					}
					connection.heartbeatFailCount = 0
				}
			})

			connection.messaging.sendCapabilities(ctx, backends, labels, configFile, func(ctx context.Context, payload []byte) error {
				_, err := cm.Publish(ctx, &paho.Publish{
					Topic:   details.Topics.Capabilities,
					Payload: payload,
					QoS:     1,
					Retain:  false,
				})
				if err != nil {
					connection.capabilitiesFailCount++
					connection.logger.Error("failed to publish capabilities",
						"error", err,
						"fail_count", connection.capabilitiesFailCount)

					// After 1 retry (2 failures), trigger reconnect
					if connection.capabilitiesFailCount >= 2 {
						connection.logger.Warn("capabilities publish failed twice, triggering JWT refresh and reconnect")
						select {
						case connection.reconnectChan <- struct{}{}:
						default:
							connection.logger.Debug("reconnect already in progress")
						}
						connection.capabilitiesFailCount = 0
					}
					return err
				}

				// Reset counter on success
				connection.capabilitiesFailCount = 0
				connection.logger.Debug("capabilities sent",
					"topic", details.Topics.Capabilities,
					"payload", string(payload),
				)
				return nil
			})

			// Wait for capabilities to be handled
			time.Sleep(10 * time.Second)
			go connection.messaging.sendGroupMembershipsRequest(ctx, func(ctx context.Context, payload []byte) error {
				_, err := cm.Publish(ctx, &paho.Publish{
					Topic:   details.Topics.Outbox,
					Payload: payload,
					QoS:     1,
					Retain:  false,
				})
				if err != nil {
					connection.groupMembershipFailCount++
					connection.logger.Error("failed to publish group memberships request",
						"error", err,
						"fail_count", connection.groupMembershipFailCount)

					// After 1 retry (2 failures), trigger reconnect
					if connection.groupMembershipFailCount >= 2 {
						connection.logger.Warn("group membership publish failed twice, triggering JWT refresh and reconnect")
						select {
						case connection.reconnectChan <- struct{}{}:
						default:
							connection.logger.Debug("reconnect already in progress")
						}
						connection.groupMembershipFailCount = 0
					}
					return err
				}

				// Reset counter on success
				connection.groupMembershipFailCount = 0
				return nil
			})
			// Catch-up: ask fleet to (re)deliver our current bundle set. Fires on
			// the initial connect and every reconnect; Ensure is idempotent, so a
			// redundant delivery is harmless. When files delivery is inactive
			// (nil files manager), warn once per connect instead — so a fleet
			// agent that never set files_manager.active does not silently drop
			// bundles even if the control plane stops auto-pushing.
			if connection.messaging.filesManager != nil {
				go connection.messaging.sendBundleListRequestIfActive(ctx, func(ctx context.Context, payload []byte) error {
					_, err := cm.Publish(ctx, &paho.Publish{
						Topic:   details.Topics.Outbox,
						Payload: payload,
						QoS:     1,
						Retain:  false,
					})
					if err != nil {
						connection.logger.Error("failed to publish bundle_list_req", "error", err)
						return err
					}
					connection.logger.Debug("bundle_list_req sent", "topic", details.Topics.Outbox)
					return nil
				})
			} else {
				connection.logger.Warn("files_manager.active != fleet while config_manager.active == fleet; fleet-delivered bundles will not be installed")
			}
		},
		OnConnectError: func(err error) {
			connection.logger.Error("MQTT connection error", "error", err)
		},
		ClientConfig: paho.ClientConfig{
			ClientID: details.ClientID,
			OnPublishReceived: []func(paho.PublishReceived) (bool, error){
				func(pr paho.PublishReceived) (bool, error) {
					// Log any published messages to subscribed topics
					connection.logger.Debug("received MQTT message", "topic", pr.Packet.Topic)

					// Check if there's a topic-specific handler
					connection.mu.Lock()
					handler, hasHandler := connection.topicHandlers[pr.Packet.Topic]
					connection.mu.Unlock()

					if hasHandler {
						// Process in goroutine to avoid blocking message acknowledgment
						go func() {
							if err := handler(pr.Packet.Topic, pr.Packet.Payload); err != nil {
								connection.logger.Error("topic handler failed", "topic", pr.Packet.Topic, "error", err)
							}
						}()
						return true, nil
					}

					// Enqueue the job for sequential processing by the dispatch worker
					// This preserves message ordering and prevents race conditions
					parts := strings.Split(pr.Packet.Topic, "/")
					if len(parts) < 2 {
						connection.logger.Error("received MQTT message with malformed topic; cannot extract orgID", "topic", pr.Packet.Topic)
						return true, nil
					}
					orgID := parts[1]

					// Hold dispatchMu while checking shuttingDown and sending on
					// dispatchQueue so stopDispatchWorker cannot close the queue
					// between the check and the send.
					connection.dispatchMu.Lock()
					if connection.shuttingDown {
						connection.dispatchMu.Unlock()
						connection.logger.Debug("ignoring message during shutdown", "topic", pr.Packet.Topic)
						return true, nil
					}

					select {
					case connection.dispatchQueue <- dispatchJob{
						payload: pr.Packet.Payload,
						orgID:   orgID,
						agentID: details.AgentID,
						topicActions: TopicActions{
							Subscribe:   connection.subscribeToTopic,
							Publish:     connection.publishToTopic,
							Unsubscribe: connection.unsubscribeFromTopic,
						},
					}:
						connection.dispatchMu.Unlock()
					default:
						connection.dispatchMu.Unlock()
						// Queue is full - log warning and process synchronously as fallback
						connection.logger.Warn("dispatch queue full, processing synchronously", "topic", pr.Packet.Topic)
						err := connection.messaging.DispatchToHandlers(
							context.Background(),
							pr.Packet.Payload,
							orgID,
							details.AgentID,
							TopicActions{
								Subscribe:   connection.subscribeToTopic,
								Publish:     connection.publishToTopic,
								Unsubscribe: connection.unsubscribeFromTopic,
							},
						)
						if err != nil {
							connection.logger.Error("failed to dispatch to handlers", "error", err)
						}
					}

					return true, nil
				},
			},
		},
	}

	// Set authentication if token is provided
	if details.Token != "" {
		connection.logger.Info("setting MQTT authentication", "client_id", details.ClientID, "zone", details.Zone)
		cfg.ConnectUsername = fmt.Sprintf("%s:%s", details.Zone, details.ClientID)
		cfg.ConnectPassword = []byte(details.Token)
	}

	// Create and start the connection manager using the long-lived context.
	connection.connectionManager, err = autopaho.NewConnection(ctx, cfg)
	if err != nil {
		connection.logger.Error("failed to create MQTT connection", "error", err)
		connection.stopDispatchWorker()
		return err
	}

	// Wait for the initial connection using waitCtx so the caller can interrupt
	// this wait independently of the connection's lifecycle context.
	awaitCtx, cancel := context.WithTimeout(waitCtx, 30*time.Second)
	defer cancel()

	err = connection.connectionManager.AwaitConnection(awaitCtx)
	if err != nil {
		connection.logger.Error("failed to establish initial MQTT connection", "error", err)
		connection.stopDispatchWorker()
		return err
	}

	connection.logger.Debug("MQTT connection manager started successfully")
	return nil
}

// Reconnect reconnects to the MQTT broker with new connection details (e.g., refreshed JWT)
func (connection *MQTTConnection) Reconnect(ctx context.Context, waitCtx context.Context, details ConnectionDetails, backends map[string]backend.Backend, labels map[string]string, configFile string, timeout time.Duration) error {
	connection.logger.Info("reconnecting to MQTT broker with refreshed credentials")

	// Disconnect the existing connection
	if connection.connectionManager != nil {
		// Use waitCtx for the disconnect timeout so shutdown can interrupt it.
		disconnectCtx, cancel := context.WithTimeout(waitCtx, timeout)
		connection.heartbeater.stop(details.Topics.Heartbeat, connection.publishToTopic)
		err := connection.connectionManager.Disconnect(disconnectCtx)
		cancel()
		if err != nil {
			connection.logger.Error("failed to disconnect during reconnect", "error", err)
			// Continue anyway to try to establish new connection
		}
		connection.stopDispatchWorker()
	}

	// Reset failure counters
	connection.capabilitiesFailCount = 0
	connection.groupMembershipFailCount = 0
	connection.heartbeatFailCount = 0

	// Connect with new details; thread both contexts through.
	err := connection.Connect(ctx, waitCtx, details, backends, labels, configFile)
	if err != nil {
		return fmt.Errorf("failed to connect during reconnect: %w", err)
	}

	connection.logger.Debug("successfully reconnected to MQTT broker")
	return nil
}

// Disconnect disconnects from the MQTT broker. It is nil-safe: calling
// Disconnect when no connection manager exists is a no-op.
func (connection *MQTTConnection) Disconnect(ctx context.Context, heartbeatTopic string) error {
	if connection.connectionManager == nil {
		return nil
	}

	// Only attempt the offline heartbeat if we have a real topic; callers like
	// the startup retry loop pass "" when no session was ever established.
	if heartbeatTopic != "" {
		connection.heartbeater.stop(heartbeatTopic, connection.publishToTopic)
	}
	// Disconnect first to stop receiving new messages, then stop the worker
	err := connection.connectionManager.Disconnect(ctx)
	connection.stopDispatchWorker()
	return err
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
	// Reset heartbeat failure counter on successful publish
	// (heartbeats use this function, so successful publish means connection is ok)
	connection.heartbeatFailCount = 0
	return nil
}
