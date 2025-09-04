package configmgr

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/messages"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
	"github.com/netboxlabs/orb-agent/agent/version"
)

// Compile-time check to ensure fleetConfigManager implements Manager interface
var _ Manager = (*fleetConfigManager)(nil)

type fleetConfigManager struct {
	logger      *slog.Logger
	pMgr        policymgr.PolicyManager
	heartbeater *heartbeater
}

const (
	heartbeatFreq              = 5 * time.Second
	messageTypeUserPropertyKey = "message_type"
)

type heartbeater struct {
	logger       *slog.Logger
	hbTicker     *time.Ticker
	heartbeatCtx context.Context
}

func (hb *heartbeater) sendSingleHeartbeat(ctx context.Context, publishFunc func(ctx context.Context, payload []byte) error, agentID string, _ time.Time, _ messages.HeartbeatState) {
	hbData := messages.Heartbeat{
		AgentID: agentID,
		Version: "1.0.0",
	}

	body, err := json.Marshal(hbData)
	if err != nil {
		hb.logger.Error("error marshalling heartbeat", "error", err)
		return
	}

	if err := publishFunc(ctx, body); err != nil {
		hb.logger.Error("error sending heartbeat", "error", err)
	} else {
		hb.logger.Debug("heartbeat sent", "payload", string(body))
	}
}

// sendHeartbeats starts a goroutine that periodically issues heartbeats until the
// supplied context is cancelled.  The cancelFunc parameter is ignored by the
// implementation but is accepted for backward-compatibility with unit tests
// that expect to pass it.
func (hb *heartbeater) sendHeartbeats(ctx context.Context, _ context.CancelFunc, publishFunc func(ctx context.Context, payload []byte) error, agentID string) {
	// Update our internal reference so other methods that read hb.heartbeatCtx
	// (if any) remain accurate.
	hb.heartbeatCtx = ctx

	hb.logger.Debug("start heartbeats routine", slog.Any("routine", ctx.Value("routine")))
	hb.sendSingleHeartbeat(ctx, publishFunc, agentID, time.Now(), messages.Online)

	for {
		select {
		case <-ctx.Done():
			hb.logger.Debug("context done, stopping heartbeats routine")
			hb.sendSingleHeartbeat(ctx, publishFunc, agentID, time.Now(), messages.Offline)
			hb.heartbeatCtx = nil
			return
		case t := <-hb.hbTicker.C:
			hb.sendSingleHeartbeat(ctx, publishFunc, agentID, t, messages.Online)
		}
	}
}

func newFleetConfigManager(ctx context.Context, logger *slog.Logger, pMgr policymgr.PolicyManager) *fleetConfigManager {
	// The passed ctx represents the lifecycle of the fleet configuration
	// manager.  All child goroutines (heartbeat, MQTT, etc.) inherit from it so
	// that a single cancellation propagates everywhere.
	return &fleetConfigManager{
		logger: logger,
		pMgr:   pMgr,
		heartbeater: &heartbeater{
			logger:       logger,
			hbTicker:     time.NewTicker(heartbeatFreq),
			heartbeatCtx: ctx,
		},
	}
}

func (fleetManager *fleetConfigManager) Start(cfg config.Config, backends map[string]backend.Backend) error {
	ctx, _ := context.WithCancel(context.Background())
	// defer cancel() TODO: I dont think this is correct but we're cancelling the context too early so can't publish. Maybe they need to run under a different context?

	fleetManager.logger.Info("starting fleet config manager", "token_url", cfg.OrbAgent.ConfigManager.Sources.Fleet.TokenURL, "client_id", cfg.OrbAgent.ConfigManager.Sources.Fleet.ClientID, "client_secret", cfg.OrbAgent.ConfigManager.Sources.Fleet.ClientSecret)
	// call the token url to get the token
	token, err := fleetManager.getToken(ctx, cfg.OrbAgent.ConfigManager.Sources.Fleet.TokenURL, cfg.OrbAgent.ConfigManager.Sources.Fleet.ClientID, cfg.OrbAgent.ConfigManager.Sources.Fleet.ClientSecret)
	if err != nil {
		return err
	}

	jwtClaims, err := parseJWTClaims(token.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	// generate topics from JWT claims and config agent_id using hardcoded templates
	topics, err := generateTopicsFromTemplate(token.AccessToken, cfg.OrbAgent.ConfigManager.Sources.Fleet.ClientID, jwtClaims)
	if err != nil {
		return fmt.Errorf("failed to generate topics: %w", err)
	}

	fleetManager.logger.Info("generated topics from JWT org_id and config agent_id",
		"heartbeat_topic", topics.Heartbeat,
		"capabilities_topic", topics.Capabilities,
		"inbox_topic", topics.Inbox,
		"outbox_topic", topics.Outbox)

	// use MQTT URL from token response or fallback to config
	mqttURL := token.MQTTURL
	if mqttURL == "" {
		mqttURL = cfg.OrbAgent.ConfigManager.Sources.Fleet.MQTTURL
	}

	// use the generated topics to connect over MQTT v5
	err = fleetManager.connect(ctx, mqttURL, token.AccessToken, *topics, backends, cfg.OrbAgent.ConfigManager.Sources.Fleet.AgentID, jwtClaims.Zone)
	if err != nil {
		return err
	}
	return nil
}

// parseJWTClaims extracts org_id claim from a JWT token
func parseJWTClaims(tokenString string) (*JWTClaims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("empty token string")
	}

	// Parse the JWT token without verification (since we already trust it from the token endpoint)
	// We accept common signature algorithms used in JWTs
	token, err := jwt.ParseSigned(tokenString, []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512, jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.ES512})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}

	var claims jwt.Claims
	var customClaims map[string]interface{}

	// Extract both standard and custom claims without verification
	if err := token.UnsafeClaimsWithoutVerification(&claims, &customClaims); err != nil {
		return nil, fmt.Errorf("failed to extract claims from JWT: %w", err)
	}

	// Extract org_id from custom claims
	jwtClaims := &JWTClaims{}

	if orgID, ok := customClaims["orb:org_id"].(string); ok {
		jwtClaims.OrgID = orgID
	} else {
		return nil, fmt.Errorf("orb:org_id claim not found or not a string in JWT token")
	}

	if zone, ok := customClaims["orb:zone"].(string); ok {
		jwtClaims.Zone = zone
	} else {
		return nil, fmt.Errorf("orb:zone claim not found or not a string in JWT token")
	}

	return jwtClaims, nil
}

func (fleetManager *fleetConfigManager) connect(ctx context.Context, fleetMQTTURL, token string, topics tokenResponseTopics, backends map[string]backend.Backend, agentID, zone string) error {
	// Parse the ORB URL
	serverURL, err := url.Parse(fleetMQTTURL)
	if err != nil {
		fleetManager.logger.Error("failed to parse ORB URL", "url", fleetMQTTURL, "error", err)
		return err
	}

	// Configure autopaho client
	clientID := agentID + time.Now().Format("20060102150405")

	cfg := autopaho.ClientConfig{
		ServerUrls:                    []*url.URL{serverURL},
		KeepAlive:                     30,
		CleanStartOnInitialConnection: true,
		ConnectTimeout:                10 * time.Second,
		ReconnectBackoff: func(_ int) time.Duration {
			return 10 * time.Second
		},
		OnConnectionUp: func(cm *autopaho.ConnectionManager, _ *paho.Connack) {
			fleetManager.logger.Info("MQTT connection established", "server", serverURL.String())

			// Subscribe to "mytopic" when connection is established
			// _, err := cm.Subscribe(context.Background(), &paho.Subscribe{
			// 	Subscriptions: []paho.SubscribeOptions{
			// 		{Topic: topics.Inbox, QoS: 1},
			// 	},
			// })
			// if err != nil {
			// 	fleetManager.logger.Error("failed to subscribe", "topic", topics.Inbox, "error", err)
			// } else {
			// 	fleetManager.logger.Info("successfully subscribed", "topic", topics.Inbox)
			// }

			// start heartbeat loop bound to the same connection-level context
			fleetManager.heartbeater.sendHeartbeats(ctx, func() {}, func(ctx context.Context, payload []byte) error {
				publishResponse, err := cm.Publish(ctx, &paho.Publish{
					Topic:   topics.Heartbeat,
					Payload: payload,
					QoS:     1,
					Retain:  false,
				})
				if err != nil {
					fleetManager.logger.Error("failed to publish heartbeat", "error", err)
					// TODO: reconnect?
					return err
				}
				if publishResponse.ReasonCode != 0 {
					fleetManager.logger.Debug("failed to publish heartbeat", "reason_code", publishResponse.ReasonCode, "topic", topics.Heartbeat)
					return fmt.Errorf("reason code indicates failure: %d", publishResponse.ReasonCode)
				}
				fleetManager.logger.Debug("heartbeat sent",
					"topic", topics.Heartbeat,
					"payload", string(payload),
				)
				return nil
			}, agentID)

			go fleetManager.sendCapabilities(ctx, backends, func(ctx context.Context, payload []byte) error {
				_, err := cm.Publish(ctx, &paho.Publish{
					Topic:   topics.Capabilities,
					Payload: payload,
					QoS:     1,
					Retain:  false,
				})
				if err != nil {
					// TODO: reconnect?
					return err
				}
				return nil
			})
		},
		OnConnectError: func(err error) {
			fleetManager.logger.Error("MQTT connection error", "error", err)
		},
		ClientConfig: paho.ClientConfig{
			ClientID: clientID,
			OnPublishReceived: []func(paho.PublishReceived) (bool, error){
				func(pr paho.PublishReceived) (bool, error) {
					messageType := pr.Packet.Properties.User.Get(messageTypeUserPropertyKey)
					// Log any published messages to subscribed topics
					fleetManager.logger.Info("received MQTT message",
						"topic", pr.Packet.Topic,
						"payload", string(pr.Packet.Payload),
						"message_type", messageType)

					fleetManager.dispatchToHandlers(messageType, pr.Packet.Payload)

					return true, nil
				},
			},
		},
	}

	// Set authentication if token is provided
	if token != "" {
		cfg.ConnectUsername = fmt.Sprintf("%s:%s", zone, clientID)
		cfg.ConnectPassword = []byte(token)
	}

	// Create and start the connection manager using the long-lived context.
	connectionManager, err := autopaho.NewConnection(ctx, cfg)
	if err != nil {
		fleetManager.logger.Error("failed to create MQTT connection", "error", err)
		return err
	}

	// Wait for the initial connection; bound this operation with a timeout that
	// is still cancellable from the parent.
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	err = connectionManager.AwaitConnection(waitCtx)
	if err != nil {
		fleetManager.logger.Error("failed to establish initial MQTT connection", "error", err)
		return err
	}

	fleetManager.logger.Info("MQTT connection manager started successfully")
	return nil
}

func (fleetManager *fleetConfigManager) sendCapabilities(ctx context.Context, backends map[string]backend.Backend, publishFunc func(ctx context.Context, payload []byte) error) {
	capabilities := messages.Capabilities{
		SchemaVersion: messages.CurrentCapabilitiesSchemaVersion,
		// AgentTags:     fleetManager.config.OrbAgent.Tags, // TODO: add tags
		OrbAgent: messages.OrbAgentInfo{
			Version: version.GetBuildVersion(),
		},
	}

	capabilities.Backends = make(map[string]messages.BackendInfo)
	for name, be := range backends {
		ver, err := be.Version()
		if err != nil {
			fleetManager.logger.Error("backend failed to retrieve version, skipping", "backend", name, "error", err)
			continue
		}
		cp, err := be.GetCapabilities()
		if err != nil {
			fleetManager.logger.Error("backend failed to retrieve capabilities, skipping", "backend", name, "error", err)
			continue
		}
		capabilities.Backends[name] = messages.BackendInfo{
			Version: ver,
			Data:    cp,
		}
	}

	body, err := json.Marshal(capabilities)
	if err != nil {
		fleetManager.logger.Error("backend failed to marshal capabilities, skipping", "error", err)
		return
	}

	fleetManager.logger.Info("sending capabilities", "value", string(body))
	err = publishFunc(ctx, body)
	if err != nil {
		fleetManager.logger.Error("error sending capabilities", "error", err)
	}
}

func (fleetManager *fleetConfigManager) dispatchToHandlers(_ string, _ []byte) {
	// TODO: dispatch to handlers
	// switch messageType {
	// case "config":
	// 	fleetManager.handleConfig(payload)
	// case "policy":
	// 	fleetManager.handlePolicy(payload)
	// }
}

type tokenResponseTopics struct {
	Heartbeat    string `json:"heartbeat"`
	Capabilities string `json:"capabilities"`
	Inbox        string `json:"inbox"`
	Outbox       string `json:"outbox"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	MQTTURL     string `json:"mqtt_url"`
	ExpiresIn   int    `json:"expires_in"`
}

func (fleetManager *fleetConfigManager) getToken(ctx context.Context, tokenURL string, clientID string, clientSecret string) (*tokenResponse, error) {
	// Input validation
	if tokenURL == "" {
		return nil, fmt.Errorf("token URL cannot be empty")
	}
	if clientID == "" {
		return nil, fmt.Errorf("client ID cannot be empty")
	}
	if clientSecret == "" {
		return nil, fmt.Errorf("client secret cannot be empty")
	}

	fleetManager.logger.Debug("requesting access token", "token_url", tokenURL, "client_id", clientID)

	scopes := []string{
		"orb.mqtt",
	}

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", strings.Join(scopes, " "))
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	fleetManager.logger.Debug("sending token request", "url", tokenURL, "data", data, "client_id", clientID) //, "client_secret", clientSecret)

	req, err := http.NewRequest("POST", tokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		fleetManager.logger.Error("failed to create token request", "error", err, "token_url", tokenURL)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// HTTP client with configurable timeout and TLS settings
	httpClient := &http.Client{
		Timeout: 30 * time.Second, // TODO: make configurable
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // TODO: make configurable
		},
	}

	fleetManager.logger.Debug("sending token request", "url", tokenURL)
	resp, err := httpClient.Do(req.WithContext(ctx))
	if err != nil {
		fleetManager.logger.Error("failed to send token request", "error", err, "token_url", tokenURL)
		return nil, fmt.Errorf("failed to send request to %s: %w", tokenURL, err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fleetManager.logger.Error("failed to close response body", "error", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fleetManager.logger.Error("failed to read response body", "error", err, "status_code", resp.StatusCode)
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != 200 {
		fleetManager.logger.Error("token request failed",
			"status_code", resp.StatusCode,
			"response", string(body),
			"token_url", tokenURL,
			"client_id", clientID)
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResponse tokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		fleetManager.logger.Error("failed to parse token response", "error", err, "response", string(body))
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Validate token response
	if tokenResponse.AccessToken == "" {
		fleetManager.logger.Error("received empty access token", "response", string(body))
		return nil, fmt.Errorf("received empty access token from server")
	}

	fleetManager.logger.Info("successfully obtained access token",
		"token_url", tokenURL,
		"expires_in", tokenResponse.ExpiresIn,
		"mqtt_url", tokenResponse.MQTTURL)

	return &tokenResponse, nil
}

func (fleetManager *fleetConfigManager) GetContext(ctx context.Context) context.Context {
	// Empty implementation for now - just return the context as-is
	return ctx
}
