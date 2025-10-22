package configmgr

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// Compile-time check to ensure fleetConfigManager implements Manager interface
var _ Manager = (*fleetConfigManager)(nil)

type fleetConfigManager struct {
	logger           *slog.Logger
	connection       *fleet.MQTTConnection
	authTokenManager *fleet.AuthTokenManager
	resetChan        chan struct{}
	backendState     backend.StateRetriever
}

func newFleetConfigManager(logger *slog.Logger, pMgr policymgr.PolicyManager, backendState backend.StateRetriever) *fleetConfigManager {
	resetChan := make(chan struct{}, 1)
	return &fleetConfigManager{
		logger:           logger,
		connection:       fleet.NewMQTTConnection(logger, pMgr, resetChan, backendState),
		authTokenManager: fleet.NewAuthTokenManager(logger),
		resetChan:        resetChan,
		backendState:     backendState,
	}
}

func (fleetManager *fleetConfigManager) Start(cfg config.Config, backends map[string]backend.Backend) error {
	ctx := context.Background()

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
		"outbox_topic", topics.Outbox)

	connectionDetails := fleet.ConnectionDetails{
		MQTTURL:  jwtClaims.MqttURL,
		Token:    token.AccessToken,
		AgentID:  jwtClaims.AgentID,
		Topics:   *topics,
		ClientID: cfg.OrbAgent.ConfigManager.Sources.Fleet.ClientID,
		Zone:     jwtClaims.Zone,
	}
	configYaml, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal agent config: %w", err)
	}
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

	return nil
}

func (fleetManager *fleetConfigManager) GetContext(ctx context.Context) context.Context {
	// Empty implementation for now - just return the context as-is
	return ctx
}
