package configmgr

import (
	"context"
	"errors"
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
func (fleetManager *FleetConfigManager) Start(ctx context.Context, cfg config.Config, backends map[string]backend.Backend) error {
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

	timeout := 30 * time.Second
	if cfg.OrbAgent.ConfigManager.Sources.Fleet.Timeout != nil && *cfg.OrbAgent.ConfigManager.Sources.Fleet.Timeout > 0 {
		timeout = time.Duration(*cfg.OrbAgent.ConfigManager.Sources.Fleet.Timeout) * time.Second
	}

	// Start OTLP bridge server early, before MQTT connection.
	// Port binding errors are local/permanent so we fail immediately.
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

	// Retry loop for token fetch + MQTT connect. These depend on external services
	// (token endpoint, MQTT broker) that may not be up yet at agent startup.
	// AuthError (401/403) is permanent — bad credentials won't be fixed by retrying.
	const maxStartupRetries = 0 // 0 = unlimited; agent retries until ctx is cancelled
	startupBackoff := 5 * time.Second
	const maxStartupBackoff = 2 * time.Minute
	var attempt int
	for {
		attempt++
		startupErr := fleetManager.startConnection(ctx, cfg, backends, timeout)
		if startupErr == nil {
			break
		}

		// Non-retriable: bad credentials
		var authErr *fleet.AuthError
		if errors.As(startupErr, &authErr) {
			_ = fleetManager.otlpBridge.Stop(context.Background())
			return fmt.Errorf("startup aborted, credentials rejected: %w", startupErr)
		}

		if maxStartupRetries > 0 && attempt >= maxStartupRetries {
			_ = fleetManager.otlpBridge.Stop(context.Background())
			return fmt.Errorf("startup failed after %d attempts: %w", attempt, startupErr)
		}

		// Defense-in-depth: tear down any lingering connection manager from the
		// failed attempt before retrying. Connect() has its own guard, but an
		// explicit teardown here ensures no leaked manager can reconnect in the
		// background. Disconnect is nil-safe.
		disconnectCtx, disconnectCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = fleetManager.connection.Disconnect(disconnectCtx, "")
		disconnectCancel()

		fleetManager.logger.Warn("startup attempt failed, retrying",
			"attempt", attempt,
			"error", startupErr,
			"retry_in", startupBackoff)

		select {
		case <-ctx.Done():
			_ = fleetManager.otlpBridge.Stop(context.Background())
			return fmt.Errorf("startup cancelled: %w", ctx.Err())
		case <-time.After(startupBackoff):
		}

		startupBackoff = min(startupBackoff*2, maxStartupBackoff)
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

			// Clear OTLP bridge so it buffers during the reset window.
			if fleetManager.otlpBridge != nil {
				fleetManager.otlpBridge.ClearPublisher()
			}

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

	// Register MQTTOnReadyHook to bind publisher and topics to the OTLP bridge
	// The bridge server is already started earlier in Start(), so we only need to bind MQTT here
	fleetManager.connection.AddOnReadyHook(func(cm *autopaho.ConnectionManager, topics fleet.TokenResponseTopics) {
		if fleetManager.otlpBridge == nil {
			fleetManager.logger.Error("OTLP bridge not initialized, cannot bind to MQTT")
			return
		}

		// Create publisher adapter and bind to bridge
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

	// Start debug signal triggers (no-op unless built with -tags debug).
	// Uses monitorCtx so the goroutine dies with monitorCancel() in Stop().
	fleet.StartDebugTrigger(fleetManager.monitorCtx, fleetManager.logger, fleetManager)

	return nil
}

// startConnection performs the token fetch, JWT parse, topic generation, and MQTT connect.
// It is called by Start's retry loop. Transient failures (network, broker down) return a
// plain error that the caller retries; permanent failures (bad credentials) return an
// *fleet.AuthError that the caller surfaces immediately.
func (fleetManager *FleetConfigManager) startConnection(ctx context.Context, cfg config.Config, backends map[string]backend.Backend, timeout time.Duration) error {
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

	// Wire up token refresher so autopaho's ConnectPacketBuilder can fetch a fresh JWT
	// on any auto-reconnect. The broker does not re-validate the JWT after CONNECT, so
	// no proactive disconnect is needed — monitorTokenExpiry keeps the cached token
	// fresh for whenever a real reconnect occurs.
	if mqttConn, ok := fleetManager.connection.(*fleet.MQTTConnection); ok {
		mqttConn.SetTokenRefresher(fleetManager.authTokenManager.GetFreshToken)
	}

	return fleetManager.connection.Connect(ctx, connectionDetails, backends, cfg.OrbAgent.Labels, string(configYaml))
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
			// Auth failures (HTTP 401/403) mean bad credentials — retrying is pointless.
			var authErr *fleet.AuthError
			if errors.As(lastErr, &authErr) {
				fleetManager.logger.Error("authentication failed, not retrying",
					"status_code", authErr.StatusCode, "error", authErr)
				break
			}
			if attempt > 1 {
				fleetManager.logger.Warn("refresh and reconnect attempt failed",
					"attempt", attempt, "max_retries", maxRetries,
					"error", lastErr, "retry_in", backoff)
			}
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
			// Auth failures (401/403) are permanent — don't disconnect or schedule
			// further reconnect attempts; the credentials need to be fixed externally.
			var authErr *fleet.AuthError
			if errors.As(lastErr, &authErr) {
				fleetManager.logger.Error("authentication failed permanently, not scheduling further reconnects",
					"status_code", authErr.StatusCode, "error", authErr)
				continue
			}

			fleetManager.logger.Error("all refresh and reconnect attempts exhausted, disconnecting agent",
				"error", lastErr)
			// Clear OTLP bridge so it buffers while disconnected.
			if fleetManager.otlpBridge != nil {
				fleetManager.otlpBridge.ClearPublisher()
			}
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

// refreshAndReconnect refreshes the JWT token and reconnects to MQTT.
func (fleetManager *FleetConfigManager) refreshAndReconnect(ctx context.Context, timeout time.Duration) error {
	// Always do a fresh HTTP refresh — we need the absolute latest token
	// before tearing down and rebuilding the MQTT connection.
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

	// Clear OTLP bridge publisher so it buffers during the reconnect window.
	// The OnReadyHook will re-bind the publisher once the new connection is up.
	if fleetManager.otlpBridge != nil {
		fleetManager.otlpBridge.ClearPublisher()
	}

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

// RotateCredentials refreshes the JWT token. The refreshed token is cached so
// autopaho's ConnectPacketBuilder uses it on the next auto-reconnect.
// Implements fleet.DebugCredentials.
func (fleetManager *FleetConfigManager) RotateCredentials(ctx context.Context) error {
	oldExpiry := fleetManager.authTokenManager.GetTokenExpiryTime()
	_, err := fleetManager.authTokenManager.RefreshToken(ctx)
	if err != nil {
		return err
	}
	newExpiry := fleetManager.authTokenManager.GetTokenExpiryTime()
	fleetManager.logger.Warn("credentials rotated",
		"previous_expiry", oldExpiry,
		"new_expiry", newExpiry,
		"new_time_until_expiry", time.Until(newExpiry).Truncate(time.Second))
	return nil
}

// LogCredentials logs current token age and status.
// Implements fleet.DebugCredentials.
func (fleetManager *FleetConfigManager) LogCredentials() {
	expiry := fleetManager.authTokenManager.GetTokenExpiryTime()
	fleetManager.logger.Warn("token status",
		"expires_at", expiry,
		"time_until_expiry", time.Until(expiry).Truncate(time.Second),
		"expired", fleetManager.authTokenManager.IsTokenExpired(),
		"expiring_soon", fleetManager.authTokenManager.IsTokenExpiringSoon(2*time.Minute))
}

// GetContext returns the context for the Fleet configuration manager
func (fleetManager *FleetConfigManager) GetContext(ctx context.Context) context.Context {
	// Empty implementation for now - just return the context as-is
	return ctx
}

// monitorTokenExpiry periodically checks token expiry and proactively refreshes
// the JWT before it expires. The refreshed token is cached so that autopaho's
// ConnectPacketBuilder (set up in startConnection) can use it on the next
// auto-reconnect — no disruptive disconnect/reconnect cycle is needed.
//
// NOTE: topics are currently static for a given agent. If topics ever become
// dynamic (derived from the JWT and changing between refreshes), this function
// would need to signal reconnectChan to trigger a full reconnect with new
// subscription topics.
func (fleetManager *FleetConfigManager) monitorTokenExpiry() {
	checkInterval := 30 * time.Second
	if fleetManager.config.OrbAgent.ConfigManager.Sources.Fleet.TokenExpiryCheckInterval != nil && *fleetManager.config.OrbAgent.ConfigManager.Sources.Fleet.TokenExpiryCheckInterval > 0 {
		checkInterval = time.Duration(*fleetManager.config.OrbAgent.ConfigManager.Sources.Fleet.TokenExpiryCheckInterval) * time.Second
	}

	refreshBuffer := 2 * time.Minute
	if fleetManager.config.OrbAgent.ConfigManager.Sources.Fleet.TokenReconnectBuffer != nil && *fleetManager.config.OrbAgent.ConfigManager.Sources.Fleet.TokenReconnectBuffer > 0 {
		refreshBuffer = time.Duration(*fleetManager.config.OrbAgent.ConfigManager.Sources.Fleet.TokenReconnectBuffer) * time.Second
	}

	// Cap refresh buffer to half the token's effective lifetime so that
	// short TTLs (e.g. 2m) don't cause "always refreshing" on every tick.
	if tokenExpiry := fleetManager.authTokenManager.GetTokenExpiryTime(); !tokenExpiry.IsZero() {
		if ttl := time.Until(tokenExpiry); ttl > 0 && refreshBuffer > ttl/2 {
			refreshBuffer = ttl / 2
		}
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	fleetManager.logger.Info("starting token expiry monitor",
		"check_interval", checkInterval,
		"refresh_buffer", refreshBuffer)

	for {
		select {
		case <-fleetManager.monitorCtx.Done():
			fleetManager.logger.Info("token expiry monitor stopped")
			return
		case <-ticker.C:
			if fleetManager.authTokenManager.IsTokenExpired() || fleetManager.authTokenManager.IsTokenExpiringSoon(refreshBuffer) {
				fleetManager.logger.Info("token expiring, refreshing proactively",
					"expiry_time", fleetManager.authTokenManager.GetTokenExpiryTime(),
					"expired", fleetManager.authTokenManager.IsTokenExpired())
				ctx, cancel := context.WithTimeout(fleetManager.monitorCtx, 30*time.Second)
				if _, err := fleetManager.authTokenManager.RefreshToken(ctx); err != nil {
					fleetManager.logger.Warn("proactive token refresh failed", "error", err)
				} else {
					fleetManager.logger.Info("proactive token refresh succeeded",
						"new_expiry", fleetManager.authTokenManager.GetTokenExpiryTime())
				}
				cancel()
			} else {
				expiryTime := fleetManager.authTokenManager.GetTokenExpiryTime()
				if !expiryTime.IsZero() {
					fleetManager.logger.Debug("token expiry check passed",
						"expiry_time", expiryTime,
						"time_until_expiry", time.Until(expiryTime))
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

	if fleetManager.otlpBridge != nil {
		if err := fleetManager.otlpBridge.Stop(ctx); err != nil {
			fleetManager.logger.Error("error while stopping OTLP bridge", slog.Any("error", err))
			return err
		}
	}
	return nil
}
