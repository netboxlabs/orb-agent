package configmgr

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet"
	"github.com/netboxlabs/orb-agent/agent/otlpbridge"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
	"github.com/netboxlabs/orb-agent/agent/redact"
	"github.com/netboxlabs/orb-agent/agent/secretsmgr"
)

// Compile-time check to ensure FleetConfigManager implements Manager interface
var _ Manager = (*FleetConfigManager)(nil)

// FleetConfigManager implements the Manager interface for Fleet-based configuration
type FleetConfigManager struct {
	logger           *slog.Logger
	connection       fleet.MQTTConnector
	authTokenManager *fleet.AuthTokenManager
	resetChan        chan struct{}
	reconnectChan    chan struct{}
	backendState     backend.StateRetriever
	policyManager    policymgr.PolicyManager
	otlpBridge       *otlpbridge.BridgeServer
	config           config.Config
	backends         map[string]backend.Backend
	labels           map[string]string
	configYaml       string
	// connMu guards connectionDetails, which is written by refreshAndReconnect and read
	// concurrently by the reset goroutine and the reconnect worker.
	connMu            sync.RWMutex
	connectionDetails fleet.ConnectionDetails
	monitorCtx        context.Context
	monitorCancel     context.CancelFunc
	debug             *debugServer
}

func newFleetConfigManager(logger *slog.Logger, pMgr policymgr.PolicyManager, backendState backend.StateRetriever) *FleetConfigManager {
	resetChan := make(chan struct{}, 1)
	reconnectChan := make(chan struct{}, 1)
	return &FleetConfigManager{
		logger:           logger,
		connection:       fleet.NewMQTTConnection(logger, pMgr, resetChan, reconnectChan, backendState),
		authTokenManager: fleet.NewAuthTokenManager(logger),
		resetChan:        resetChan,
		reconnectChan:    reconnectChan,
		backendState:     backendState,
		policyManager:    pMgr,
	}
}

// newFleetConfigManagerWithConnection creates a FleetConfigManager with a custom connection (for testing)
func newFleetConfigManagerWithConnection(logger *slog.Logger, pMgr policymgr.PolicyManager, backendState backend.StateRetriever, conn fleet.MQTTConnector) *FleetConfigManager {
	resetChan := make(chan struct{}, 1)
	reconnectChan := make(chan struct{}, 1)
	return &FleetConfigManager{
		logger:           logger,
		connection:       conn, // Use provided connection instead of creating new one
		authTokenManager: fleet.NewAuthTokenManager(logger),
		resetChan:        resetChan,
		reconnectChan:    reconnectChan,
		backendState:     backendState,
		policyManager:    pMgr,
	}
}

// Start initializes and starts the Fleet configuration manager
func (fleetManager *FleetConfigManager) Start(cfg config.Config, backends map[string]backend.Backend) error {
	ctx := context.Background()

	var err error
	cfg.OrbAgent.ConfigManager.Sources.Fleet.TokenURL, err = config.ResolveEnv(cfg.OrbAgent.ConfigManager.Sources.Fleet.TokenURL)
	if err != nil {
		return err
	}
	cfg.OrbAgent.ConfigManager.Sources.Fleet.ClientID, err = config.ResolveEnv(cfg.OrbAgent.ConfigManager.Sources.Fleet.ClientID)
	if err != nil {
		return err
	}
	cfg.OrbAgent.ConfigManager.Sources.Fleet.ClientSecret, err = config.ResolveEnv(cfg.OrbAgent.ConfigManager.Sources.Fleet.ClientSecret)
	if err != nil {
		return err
	}

	fleetManager.logger.Info("starting fleet config manager",
		"token_url", cfg.OrbAgent.ConfigManager.Sources.Fleet.TokenURL,
		"client_id", cfg.OrbAgent.ConfigManager.Sources.Fleet.ClientID)

	// call the token url to get the token
	timeout := 30 * time.Second
	if cfg.OrbAgent.ConfigManager.Sources.Fleet.Timeout != nil && *cfg.OrbAgent.ConfigManager.Sources.Fleet.Timeout > 0 {
		timeout = time.Duration(*cfg.OrbAgent.ConfigManager.Sources.Fleet.Timeout) * time.Second
	}
	token, err := fleetManager.authTokenManager.GetToken(ctx,
		cfg.OrbAgent.ConfigManager.Sources.Fleet.TokenURL,
		cfg.OrbAgent.ConfigManager.Sources.Fleet.SkipTLS, timeout,
		cfg.OrbAgent.ConfigManager.Sources.Fleet.ClientID,
		cfg.OrbAgent.ConfigManager.Sources.Fleet.ClientSecret)
	if err != nil {
		return err
	}

	jwtClaims, err := fleet.ParseJWTClaims(token.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	// generate topics from JWT claims and config agent_id using hardcoded templates
	topics, err := fleet.GenerateTopicsFromTemplate(jwtClaims)
	if err != nil {
		return fmt.Errorf("failed to generate topics: %w", err)
	}

	fleetManager.logger.Info("generated topics from JWT",
		"heartbeat_topic", topics.Heartbeat,
		"capabilities_topic", topics.Capabilities,
		"inbox_topic", topics.Inbox,
		"outbox_topic", topics.Outbox,
		"otlp_topic", topics.Ingest,
		"telemetry_topic", topics.Telemetry)

	connectionDetails := fleet.ConnectionDetails{
		MQTTURL:  jwtClaims.MqttURL,
		Token:    token.AccessToken,
		AgentID:  jwtClaims.AgentID,
		Topics:   *topics,
		ClientID: cfg.OrbAgent.ConfigManager.Sources.Fleet.ClientID,
		Zone:     jwtClaims.Zone,
	}
	configYaml, err := fleetManager.configToSafeString(cfg)
	if err != nil {
		return fmt.Errorf("failed to convert config to safe string: %w", err)
	}

	// Store connection state for reconnection
	fleetManager.config = cfg
	fleetManager.backends = backends
	fleetManager.labels = cfg.OrbAgent.Labels
	fleetManager.configYaml = string(configYaml)
	fleetManager.connectionDetails = connectionDetails

	// Start OTLP bridge server early, before MQTT connection
	// This ensures port binding errors are detected immediately and propagate to fail the agent startup
	grpcPort := 4317
	if cfg.OrbAgent.ConfigManager.Sources.Fleet.OTLPBridgeGRPCPort != nil {
		grpcPort = *cfg.OrbAgent.ConfigManager.Sources.Fleet.OTLPBridgeGRPCPort
	}
	bridgeConfig := otlpbridge.BridgeConfig{
		ListenAddr: fmt.Sprintf(":%d", grpcPort),
		Encoding:   "json",
	}
	fleetManager.otlpBridge, err = otlpbridge.NewBridgeServer(bridgeConfig, fleetManager.policyManager.GetRepo(), fleetManager.logger)
	if err != nil {
		return fmt.Errorf("failed to create OTLP bridge: %w", err)
	}
	if err := fleetManager.otlpBridge.Start(context.Background()); err != nil {
		return fmt.Errorf("failed to start OTLP bridge on port %d: %w", grpcPort, err)
	}
	fleetManager.logger.Info("OTLP bridge server started", slog.Int("grpc_port", grpcPort))

	// Wire up token refresher so autopaho's ConnectPacketBuilder can fetch a fresh JWT
	// on every reconnect attempt, eliminating the stale-token race window.
	if mqttConn, ok := fleetManager.connection.(*fleet.MQTTConnection); ok {
		mqttConn.SetTokenRefresher(func(ctx context.Context) (string, error) {
			resp, err := fleetManager.authTokenManager.RefreshToken(ctx)
			if err != nil {
				return "", err
			}
			return resp.AccessToken, nil
		})
	}

	err = fleetManager.connection.Connect(ctx, connectionDetails, backends, cfg.OrbAgent.Labels, string(configYaml))
	if err != nil {
		return err
	}

	// Start goroutine to handle agent reset requests
	go func() {
		for range fleetManager.resetChan {
			fleetManager.logger.Info("agent reset requested, reconnecting MQTT connection")

			// Snapshot connection details under the read lock so we get a consistent view
			// even if the reconnect worker is concurrently writing after a token refresh.
			fleetManager.connMu.RLock()
			details := fleetManager.connectionDetails
			fleetManager.connMu.RUnlock()

			// Disconnect first
			disconnectCtx, cancel := context.WithTimeout(context.Background(), timeout)
			err := fleetManager.connection.Disconnect(disconnectCtx, details.Topics.Heartbeat)
			cancel()
			if err != nil {
				fleetManager.logger.Error("failed to disconnect during reset", "error", err)
			}

			// Reconnect using the latest connection details (updated by refreshAndReconnect after token refresh)
			connectCtx := context.Background()
			err = fleetManager.connection.Connect(connectCtx, details, fleetManager.backends, fleetManager.labels, fleetManager.configYaml)
			if err != nil {
				fleetManager.logger.Error("failed to reconnect during reset", "error", err)
			}
		}
	}()

	// On each (re)connect, bind the MQTT publisher and topics to the OTLP bridge.
	// The bridge buffers messages internally, so brief outages during reconnect don't drop data.
	fleetManager.connection.AddOnReadyHook(func(cm *autopaho.ConnectionManager, topics fleet.TokenResponseTopics) {
		if fleetManager.otlpBridge == nil {
			fleetManager.logger.Error("OTLP bridge not initialized, cannot bind to MQTT")
			return
		}

		pub := otlpbridge.NewCMAdapterPublisher(cm)
		fleetManager.otlpBridge.SetPublisher(pub)
		fleetManager.otlpBridge.SetIngestTopic(topics.Ingest)
		fleetManager.otlpBridge.SetTelemetryTopic(topics.Telemetry)
		fleetManager.logger.Info("OTLP bridge bound to Fleet MQTT",
			slog.String("ingest_topic", topics.Ingest),
			slog.String("telemetry_topic", topics.Telemetry))
	})

	// Create a shared cancellable context for both the reconnect worker and the token expiry
	// monitor so that Stop() can terminate both goroutines with a single monitorCancel() call.
	fleetManager.monitorCtx, fleetManager.monitorCancel = context.WithCancel(context.Background())

	// Start goroutine to handle reconnect requests (JWT refresh)
	go fleetManager.runReconnectWorker(fleetManager.monitorCtx, timeout, 5, 5*time.Second, 2*time.Minute, 30*time.Second)

	// Start background goroutine to monitor token expiry and trigger proactive reconnection
	go fleetManager.monitorTokenExpiry()

	// Start debug HTTP server (no-op unless built with -tags debug).
	// Port controlled via ORB_DEBUG_PORT env var (default 6166).
	fleetManager.debug, _ = startDebugServer(fleetManager.logger, debugServerOpts{
		reconnectChan: fleetManager.reconnectChan,
		tokenStatus: func() tokenStatusInfo {
			expiry := fleetManager.authTokenManager.GetTokenExpiryTime()
			return tokenStatusInfo{
				ExpiresAt:       expiry,
				TimeUntilExpiry: time.Until(expiry).Truncate(time.Second).String(),
				Expired:         fleetManager.authTokenManager.IsTokenExpired(),
				ExpiringSoon:    fleetManager.authTokenManager.IsTokenExpiringSoon(2 * time.Minute),
			}
		},
		tokenRotate: func() (old, fresh time.Time, err error) {
			old = fleetManager.authTokenManager.GetTokenExpiryTime()
			_, err = fleetManager.authTokenManager.RefreshToken(context.Background())
			if err != nil {
				return old, time.Time{}, err
			}
			fresh = fleetManager.authTokenManager.GetTokenExpiryTime()
			return old, fresh, nil
		},
	})
	if fleetManager.debug != nil {
		fleetManager.logger.Info("debug server available", "addr", fleetManager.debug.addr())
	}

	return nil
}

// runReconnectWorker processes signals from reconnectChan, retrying token refresh with exponential
// backoff. After all retries are exhausted it disconnects the MQTT connection (Fix 2) so the server
// sees the agent as Offline rather than Stale, then schedules a fast re-signal (Fix 3) so recovery
// does not have to wait for the next full monitor tick. Timing parameters are injected so tests can
// use millisecond-scale values without slowing the test suite.
func (fleetManager *FleetConfigManager) runReconnectWorker(ctx context.Context, timeout time.Duration, maxRetries int, baseBackoff, maxBackoff, retryDelay time.Duration) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-fleetManager.reconnectChan:
		}
		fleetManager.logger.Debug("JWT refresh and reconnection requested")

		backoff := baseBackoff
		var lastErr error

		for attempt := 1; attempt <= maxRetries; attempt++ {
			if lastErr = fleetManager.refreshAndReconnect(ctx, timeout); lastErr == nil {
				break
			}
			fleetManager.logger.Error("refresh and reconnect attempt failed",
				"attempt", attempt, "max_retries", maxRetries,
				"error", lastErr, "retry_in", backoff)
			if attempt < maxRetries {
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				if backoff*2 < maxBackoff {
					backoff *= 2
				} else {
					backoff = maxBackoff
				}
			}
		}

		if lastErr != nil {
			fleetManager.logger.Error("all refresh and reconnect attempts exhausted, disconnecting agent",
				"error", lastErr)
			// Use a dedicated timeout context for teardown so that a hung MQTT broker cannot
			// block the reconnect loop indefinitely; the worker's ctx is long-lived and would
			// never expire on its own.
			fleetManager.connMu.RLock()
			heartbeatTopic := fleetManager.connectionDetails.Topics.Heartbeat
			fleetManager.connMu.RUnlock()
			disconnectCtx, disconnectCancel := context.WithTimeout(context.Background(), timeout)
			if err := fleetManager.connection.Disconnect(disconnectCtx, heartbeatTopic); err != nil {
				fleetManager.logger.Error("failed to disconnect after exhausted retries", "error", err)
			}
			disconnectCancel()
			time.AfterFunc(retryDelay, func() {
				if ctx.Err() != nil {
					return
				}
				select {
				case fleetManager.reconnectChan <- struct{}{}:
					fleetManager.logger.Debug("scheduled retry signal sent after refresh failure")
				default:
				}
			})
		}
	}
}

// BindSecretsManager binds a fleet secrets manager to the MQTT connection
func (fleetManager *FleetConfigManager) BindSecretsManager(sm secretsmgr.Manager) error {
	// Check if it's a fleet secrets manager by type assertion
	fleetSM, ok := sm.(*secretsmgr.FleetSecretsManager)
	if !ok {
		// Try to get the underlying fleet secrets manager
		// This handles the case where the manager is wrapped
		return nil // Not a fleet secrets manager, nothing to bind
	}

	// Register OnReadyHook to bind secrets manager when MQTT connection is ready
	fleetManager.connection.AddOnReadyHook(func(cm *autopaho.ConnectionManager, topics fleet.TokenResponseTopics) {
		// Create publisher and subscriber adapters
		pub := secretsmgr.NewCMAdapterPublisher(cm)
		sub := secretsmgr.NewCMAdapterSubscriber(cm)

		// Bind the secrets manager to MQTT
		if err := fleetSM.BindMQTT(pub, sub, topics.SecretsRequest, topics.SecretsResponse, topics.SecretsUpdated); err != nil {
			fleetManager.logger.Error("failed to bind fleet secrets manager to MQTT", "error", err)
			return
		}

		// Register topic handlers for secrets topics
		// Note: These handlers will be called from OnPublishReceived in connection.go
		fleetManager.connection.RegisterTopicHandler(topics.SecretsResponse, func(topic string, payload []byte) error {
			return fleetSM.HandleMessage(topic, payload)
		})
		fleetManager.connection.RegisterTopicHandler(topics.SecretsUpdated, func(topic string, payload []byte) error {
			return fleetSM.HandleMessage(topic, payload)
		})

		fleetManager.logger.Info("Fleet secrets manager bound to MQTT",
			slog.String("request_topic", topics.SecretsRequest),
			slog.String("response_topic", topics.SecretsResponse),
			slog.String("updated_topic", topics.SecretsUpdated))
	})

	return nil
}

// refreshAndReconnect refreshes the JWT token and reconnects to MQTT
func (fleetManager *FleetConfigManager) refreshAndReconnect(ctx context.Context, timeout time.Duration) error {
	// Refresh JWT token
	token, err := fleetManager.authTokenManager.RefreshToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	// Parse new JWT claims
	jwtClaims, err := fleet.ParseJWTClaims(token.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	// Regenerate topics
	topics, err := fleet.GenerateTopicsFromTemplate(jwtClaims)
	if err != nil {
		return fmt.Errorf("failed to generate topics: %w", err)
	}

	fleetManager.logger.Debug("refreshed JWT and generated new topics",
		"heartbeat_topic", topics.Heartbeat,
		"capabilities_topic", topics.Capabilities,
		"inbox_topic", topics.Inbox,
		"outbox_topic", topics.Outbox)

	// Update connection details
	newConnectionDetails := fleet.ConnectionDetails{
		MQTTURL:  jwtClaims.MqttURL,
		Token:    token.AccessToken,
		AgentID:  jwtClaims.AgentID,
		Topics:   *topics,
		ClientID: fleetManager.config.OrbAgent.ConfigManager.Sources.Fleet.ClientID,
		Zone:     jwtClaims.Zone,
	}

	// Store updated connection details under write lock so the reset goroutine and
	// reconnect worker always observe a fully initialised value.
	fleetManager.connMu.Lock()
	fleetManager.connectionDetails = newConnectionDetails
	fleetManager.connMu.Unlock()

	// Reconnect with new token
	err = fleetManager.connection.Reconnect(ctx, newConnectionDetails, fleetManager.backends, fleetManager.labels, fleetManager.configYaml, timeout)
	if err != nil {
		return fmt.Errorf("failed to reconnect: %w", err)
	}

	fleetManager.logger.Info("successfully refreshed JWT and reconnected")
	return nil
}

func (fleetManager *FleetConfigManager) configToSafeString(cfg config.Config) (string, error) {
	redacted := redact.SensitiveData(cfg)
	configYaml, err := yaml.Marshal(redacted)
	if err != nil {
		return "", fmt.Errorf("failed to marshal agent config: %w", err)
	}
	return string(configYaml), nil
}

// GetContext returns the context for the Fleet configuration manager
func (fleetManager *FleetConfigManager) GetContext(ctx context.Context) context.Context {
	// Empty implementation for now - just return the context as-is
	return ctx
}

// monitorTokenExpiry periodically checks token expiry and triggers reconnection before token expires
func (fleetManager *FleetConfigManager) monitorTokenExpiry() {
	// Check interval: default 30 seconds, configurable via config
	checkInterval := 30 * time.Second
	if fleetManager.config.OrbAgent.ConfigManager.Sources.Fleet.TokenExpiryCheckInterval != nil && *fleetManager.config.OrbAgent.ConfigManager.Sources.Fleet.TokenExpiryCheckInterval > 0 {
		checkInterval = time.Duration(*fleetManager.config.OrbAgent.ConfigManager.Sources.Fleet.TokenExpiryCheckInterval) * time.Second
	}

	// Reconnect buffer: default 2 minutes before expiry, configurable via config
	reconnectBuffer := 2 * time.Minute
	if fleetManager.config.OrbAgent.ConfigManager.Sources.Fleet.TokenReconnectBuffer != nil && *fleetManager.config.OrbAgent.ConfigManager.Sources.Fleet.TokenReconnectBuffer > 0 {
		reconnectBuffer = time.Duration(*fleetManager.config.OrbAgent.ConfigManager.Sources.Fleet.TokenReconnectBuffer) * time.Second
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	fleetManager.logger.Info("starting token expiry monitor",
		"check_interval", checkInterval,
		"reconnect_buffer", reconnectBuffer)

	for {
		select {
		case <-fleetManager.monitorCtx.Done():
			fleetManager.logger.Info("token expiry monitor stopped")
			return
		case <-ticker.C:
			// Check if token is expired or expiring soon
			if fleetManager.authTokenManager.IsTokenExpired() {
				fleetManager.logger.Warn("JWT token has expired, triggering reconnection",
					"expiry_time", fleetManager.authTokenManager.GetTokenExpiryTime())
				select {
				case fleetManager.reconnectChan <- struct{}{}:
					fleetManager.logger.Debug("reconnection signal sent due to expired token")
				default:
					fleetManager.logger.Debug("reconnection already in progress, skipping duplicate trigger")
				}
			} else if fleetManager.authTokenManager.IsTokenExpiringSoon(reconnectBuffer) {
				fleetManager.logger.Warn("JWT token expiring soon, triggering proactive reconnection",
					"expiry_time", fleetManager.authTokenManager.GetTokenExpiryTime(),
					"reconnect_buffer", reconnectBuffer)
				select {
				case fleetManager.reconnectChan <- struct{}{}:
					fleetManager.logger.Debug("reconnection signal sent due to imminent token expiry")
				default:
					fleetManager.logger.Debug("reconnection already in progress, skipping duplicate trigger")
				}
			} else {
				expiryTime := fleetManager.authTokenManager.GetTokenExpiryTime()
				if !expiryTime.IsZero() {
					timeUntilExpiry := time.Until(expiryTime)
					fleetManager.logger.Debug("token expiry check passed",
						"expiry_time", expiryTime,
						"time_until_expiry", timeUntilExpiry)
				}
			}
		}
	}
}

// Stop gracefully shuts down the OTLP bridge and token expiry monitor.
func (fleetManager *FleetConfigManager) Stop(ctx context.Context) error {
	// Stop token expiry monitor
	if fleetManager.monitorCancel != nil {
		fleetManager.monitorCancel()
	}

	fleetManager.debug.stop()

	if fleetManager.otlpBridge != nil {
		if err := fleetManager.otlpBridge.Stop(ctx); err != nil {
			fleetManager.logger.Error("error while stopping OTLP bridge", slog.Any("error", err))
			return err
		}
	}
	return nil
}
