package configmgr

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// Compile-time check to ensure fleetConfigManager implements Manager interface
var _ Manager = (*fleetConfigManager)(nil)

type fleetConfigManager struct {
	logger           *slog.Logger
	pMgr             policymgr.PolicyManager
	connection       *fleet.MQTTConnection
	authTokenManager *fleet.AuthTokenManager
}

func newFleetConfigManager(logger *slog.Logger, pMgr policymgr.PolicyManager) *fleetConfigManager {
	return &fleetConfigManager{
		logger:           logger,
		pMgr:             pMgr,
		connection:       fleet.NewMQTTConnection(logger),
		authTokenManager: fleet.NewAuthTokenManager(logger),
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

	// use the generated topics to connect over MQTT v5
	err = fleetManager.connection.Connect(ctx, jwtClaims.MqttURL, token.AccessToken, *topics, backends, cfg.OrbAgent.ConfigManager.Sources.Fleet.ClientID, jwtClaims.Zone, cfg.OrbAgent.Labels)
	if err != nil {
		return err
	}
	return nil
}

func (fleetManager *fleetConfigManager) GetContext(ctx context.Context) context.Context {
	// Empty implementation for now - just return the context as-is
	return ctx
}
