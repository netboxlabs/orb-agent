package configmgr

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
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

func newFleetConfigManager(logger *slog.Logger, pMgr policymgr.PolicyManager) *fleetConfigManager {
	return &fleetConfigManager{
		logger: logger,
		pMgr:   pMgr,
		heartbeater: &heartbeater{
			logger:       logger,
			hbTicker:     time.NewTicker(heartbeatFreq),
			heartbeatCtx: context.Background(),
		},
	}
}

func (fleetManager *fleetConfigManager) Start(cfg config.Config, backends map[string]backend.Backend) error {
	// call the token url to get the token
	token, err := fleetManager.getToken(cfg.OrbAgent.ConfigManager.Sources.Fleet.TokenURL, cfg.OrbAgent.ConfigManager.Sources.Fleet.ClientID, cfg.OrbAgent.ConfigManager.Sources.Fleet.ClientSecret)
	if err != nil {
		return err
	}

	// use the token to connect over MQTT v5
	err = fleetManager.connect(token.MQTTURL, token.AccessToken, token.Topics, backends)
	if err != nil {
		return err
	}
	return nil
}

func (fleetManager *fleetConfigManager) connect(fleetMQTTURL, token string, topics tokenResponseTopics, backends map[string]backend.Backend) error {
	// Parse the ORB URL
	serverURL, err := url.Parse(fleetMQTTURL)
	if err != nil {
		fleetManager.logger.Error("failed to parse ORB URL", "url", fleetMQTTURL, "error", err)
		return err
	}

	// Configure autopaho client
	clientID := "orb-agent-" + time.Now().Format("20060102150405")

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

			fleetManager.heartbeater.sendHeartbeats(context.Background(), context.CancelFunc(nil), func(ctx context.Context, payload []byte) error {
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
			})

			// go fleetManager.sendCapabilities(context.Background(), backends, func(ctx context.Context, payload []byte) error {
			// 	_, err := cm.Publish(ctx, &paho.Publish{
			// 		Topic:   topics.Heartbeat,
			// 		Payload: payload,
			// 		QoS:     1,
			// 		Retain:  false,
			// 	})
			// 	if err != nil {
			// 		// TODO: reconnect?
			// 		return err
			// 	}
			// 	return nil
			// })
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
		cfg.ConnectUsername = "token" // Using token as username, adjust as needed for your auth scheme
		cfg.ConnectPassword = []byte(token)
	} else {
		// TODO: remove these temporary credentials
		cfg.ConnectUsername = "admin"
		cfg.ConnectPassword = []byte("admin")
	}

	// Create and start the connection manager
	ctx := context.Background()
	connectionManager, err := autopaho.NewConnection(ctx, cfg)
	if err != nil {
		fleetManager.logger.Error("failed to create MQTT connection", "error", err)
		return err
	}

	// Wait for initial connection (with timeout)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = connectionManager.AwaitConnection(ctx)
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

type heartbeater struct {
	logger       *slog.Logger
	hbTicker     *time.Ticker
	heartbeatCtx context.Context
}

func (hb *heartbeater) sendSingleHeartbeat(ctx context.Context, publishFunc func(ctx context.Context, payload []byte) error, _ time.Time, _ messages.HeartbeatState) {
	hbData := messages.Heartbeat{
		AgentID: "orb-agent",
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

func (hb *heartbeater) sendHeartbeats(ctx context.Context, cancelFunc context.CancelFunc, publishFunc func(ctx context.Context, payload []byte) error) {
	hb.logger.Debug("start heartbeats routine", slog.Any("routine", ctx.Value("routine")))
	hb.sendSingleHeartbeat(ctx, publishFunc, time.Now(), messages.Online)
	defer func() {
		cancelFunc()
	}()
	for {
		select {
		case <-ctx.Done():
			hb.logger.Debug("context done, stopping heartbeats routine")
			hb.sendSingleHeartbeat(ctx, publishFunc, time.Now(), messages.Offline)
			hb.heartbeatCtx = nil
			return
		case t := <-hb.hbTicker.C:
			hb.sendSingleHeartbeat(ctx, publishFunc, t, messages.Online)
		}
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
	Heartbeat string `json:"heartbeat"`
	Inbox     string `json:"inbox"`
	Outbox    string `json:"outbox"`
}

type tokenResponse struct {
	AccessToken string              `json:"access_token"`
	MQTTURL     string              `json:"mqtt_url"`
	Topics      tokenResponseTopics `json:"topics"`
	ExpiresIn   int                 `json:"expires_in"`
}

func (fleetManager *fleetConfigManager) getToken(tokenURL string, clientID string, clientSecret string) (*tokenResponse, error) {
	scopes := []string{
		"rabbitmq.read:*/*",
		"rabbitmq.write:*/*",
		"rabbitmq.configure:*/*",
	}

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", strings.Join(scopes, " "))

	// Encode credentials in Basic Auth header
	creds := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", clientID, clientSecret)))

	req, err := http.NewRequest("POST", tokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+creds)

	// HTTP client with TLS verification disabled
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // TODO: make configurable?
		},
	}

	resp, err := httpClient.Do(req.WithContext(context.Background()))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fleetManager.logger.Error("failed to close response body", "error", err)
		}
	}()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("token request failed: %s", body)
	}

	var tokenResponse tokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokenResponse, nil
}

func (fleetManager *fleetConfigManager) GetContext(ctx context.Context) context.Context {
	// Empty implementation for now - just return the context as-is
	return ctx
}
