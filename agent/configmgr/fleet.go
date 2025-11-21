package configmgr

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet"
	"github.com/netboxlabs/orb-agent/agent/otlpbridge"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// Compile-time check to ensure fleetConfigManager implements Manager interface
var _ Manager = (*fleetConfigManager)(nil)

type fleetConfigManager struct {
	logger            *slog.Logger
	connection        *fleet.MQTTConnection
	authTokenManager  *fleet.AuthTokenManager
	resetChan         chan struct{}
	reconnectChan     chan struct{}
	backendState      backend.StateRetriever
	policyManager     policymgr.PolicyManager
	otlpBridge        *otlpbridge.BridgeServer
	config            config.Config
	backends          map[string]backend.Backend
	labels            map[string]string
	configYaml        string
	connectionDetails fleet.ConnectionDetails
	monitorCtx        context.Context
	monitorCancel     context.CancelFunc
}

func newFleetConfigManager(logger *slog.Logger, pMgr policymgr.PolicyManager, backendState backend.StateRetriever) *fleetConfigManager {
	resetChan := make(chan struct{}, 1)
	reconnectChan := make(chan struct{}, 1)
	return &fleetConfigManager{
		logger:           logger,
		connection:       fleet.NewMQTTConnection(logger, pMgr, resetChan, reconnectChan, backendState),
		authTokenManager: fleet.NewAuthTokenManager(logger),
		resetChan:        resetChan,
		reconnectChan:    reconnectChan,
		backendState:     backendState,
		policyManager:    pMgr,
	}
}

func (fleetManager *fleetConfigManager) Start(cfg config.Config, backends map[string]backend.Backend) error {
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
		"otlp_topic", topics.Ingest)

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

	err = fleetManager.connection.Connect(ctx, connectionDetails, backends, cfg.OrbAgent.Labels, string(configYaml))
	if err != nil {
		return err
	}

	// Start goroutine to handle agent reset requests
	go func() {
		for range fleetManager.resetChan {
			fleetManager.logger.Info("agent reset requested, reconnecting MQTT connection")

			// Disconnect first
			disconnectCtx, cancel := context.WithTimeout(context.Background(), timeout)
			err := fleetManager.connection.Disconnect(disconnectCtx, topics.Heartbeat)
			cancel()
			if err != nil {
				fleetManager.logger.Error("failed to disconnect during reset", "error", err)
			}

			// Reconnect
			connectCtx := context.Background()
			err = fleetManager.connection.Connect(connectCtx, connectionDetails, backends, cfg.OrbAgent.Labels, string(configYaml))
			if err != nil {
				fleetManager.logger.Error("failed to reconnect during reset", "error", err)
			}
		}
	}()

	// Register MQTTOnReadyHook to initialize the OTLP bridge
	fleetManager.connection.AddOnReadyHook(func(cm *autopaho.ConnectionManager, topics fleet.TokenResponseTopics) {
		if fleetManager.otlpBridge == nil {
			fleetManager.logger.Info("MQTT connection ready, initializing OTLP bridge")
			bridgeConfig := otlpbridge.BridgeConfig{
				ListenAddr: ":4317",
				Encoding:   "protobuf",
			}
			var err error
			fleetManager.otlpBridge, err = otlpbridge.NewBridgeServer(bridgeConfig, fleetManager.policyManager.GetRepo(), fleetManager.logger)
			if err != nil {
				fleetManager.logger.Error("failed to create OTLP bridge", slog.Any("error", err))
				return
			}
			if err := fleetManager.otlpBridge.Start(context.Background()); err != nil {
				fleetManager.logger.Error("failed to start OTLP bridge", slog.Any("error", err))
				return
			}
		} else {
			fleetManager.logger.Info("OTLP bridge already initialized, skipping initialization")
		}

		// Create publisher adapter and bind to bridge
		pub := otlpbridge.NewCMAdapterPublisher(cm)
		fleetManager.otlpBridge.SetPublisher(pub)
		fleetManager.otlpBridge.SetIngestTopic(topics.Ingest)
		fleetManager.logger.Info("OTLP bridge bound to Fleet MQTT", slog.String("topic", topics.Ingest))
	})

	// Start goroutine to handle reconnect requests (JWT refresh)
	go func() {
		for range fleetManager.reconnectChan {
			fleetManager.logger.Info("JWT refresh and reconnection requested")
			if err := fleetManager.refreshAndReconnect(ctx, timeout); err != nil {
				fleetManager.logger.Error("failed to refresh and reconnect", "error", err)
			}
		}
	}()

	// Start background goroutine to monitor token expiry and trigger proactive reconnection
	fleetManager.monitorCtx, fleetManager.monitorCancel = context.WithCancel(context.Background())
	go fleetManager.monitorTokenExpiry()

	return nil
}

// refreshAndReconnect refreshes the JWT token and reconnects to MQTT
func (fleetManager *fleetConfigManager) refreshAndReconnect(ctx context.Context, timeout time.Duration) error {
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

	fleetManager.logger.Info("refreshed JWT and generated new topics",
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

	// Store updated connection details
	fleetManager.connectionDetails = newConnectionDetails

	// Reconnect with new token
	err = fleetManager.connection.Reconnect(ctx, newConnectionDetails, fleetManager.backends, fleetManager.labels, fleetManager.configYaml, timeout)
	if err != nil {
		return fmt.Errorf("failed to reconnect: %w", err)
	}

	fleetManager.logger.Info("successfully refreshed JWT and reconnected")
	return nil
}

func (fleetManager *fleetConfigManager) configToSafeString(cfg config.Config) (string, error) {
	if cfg.OrbAgent.ConfigManager.Sources.Fleet.ClientSecret != "" {
		cfg.OrbAgent.ConfigManager.Sources.Fleet.ClientSecret = "******"
	}

	configYaml, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("failed to marshal agent config: %w", err)
	}
	return string(configYaml), nil
}

func (fleetManager *fleetConfigManager) GetContext(ctx context.Context) context.Context {
	// Empty implementation for now - just return the context as-is
	return ctx
}

// monitorTokenExpiry periodically checks token expiry and triggers reconnection before token expires
func (fleetManager *fleetConfigManager) monitorTokenExpiry() {
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
func (fleetManager *fleetConfigManager) Stop(ctx context.Context) error {
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
