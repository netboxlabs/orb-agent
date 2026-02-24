package secretsmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
	"github.com/google/uuid"

	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
)

var _ Manager = (*FleetSecretsManager)(nil)

// fleetRefRegex matches fleet secret references in the format ${fleet://path}
var fleetRefRegex = regexp.MustCompile(`\${fleet://([^}]+)}`)

const defaultSecretRequestTimeout = 30 * time.Second

// Publisher interface for MQTT publishing
type Publisher interface {
	Publish(ctx context.Context, topic string, payload []byte) error
}

// Subscriber interface for MQTT subscribing
type Subscriber interface {
	Subscribe(ctx context.Context, subscribe *paho.Subscribe) error
}

// FleetSecretsManager implements the Manager interface for Fleet-based secrets
type FleetSecretsManager struct {
	logger        *slog.Logger
	config        config.FleetSecretsManager
	ctx           context.Context
	usedVars      map[string]fleetCachedSecret
	callback      func(map[string]bool)
	publisher     Publisher
	subscriber    Subscriber
	requestTopic  string
	responseTopic string
	updatedTopic  string
	mu            sync.RWMutex
	pendingReqs   map[string]chan *messages.SecretResponseMsg
	timeout       time.Duration
}

type fleetCachedSecret struct {
	Value     string          // The actual secret value
	Version   int             // Version number from control plane
	policyIDs map[string]bool // The IDs of policies that have used this secret
}

// NewFleetSecretsManager creates a new Fleet secrets manager
func NewFleetSecretsManager(logger *slog.Logger, cfg config.FleetSecretsManager) *FleetSecretsManager {
	timeout := defaultSecretRequestTimeout
	if cfg.Timeout != nil && *cfg.Timeout > 0 {
		timeout = time.Duration(*cfg.Timeout) * time.Second
	}

	return &FleetSecretsManager{
		logger:      logger,
		config:      cfg,
		usedVars:    make(map[string]fleetCachedSecret),
		pendingReqs: make(map[string]chan *messages.SecretResponseMsg),
		timeout:     timeout,
	}
}

// BindMQTT binds the secrets manager to MQTT connection and topics
func (f *FleetSecretsManager) BindMQTT(publisher Publisher, subscriber Subscriber, requestTopic, responseTopic, updatedTopic string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.publisher = publisher
	f.subscriber = subscriber
	f.requestTopic = requestTopic
	f.responseTopic = responseTopic
	f.updatedTopic = updatedTopic

	// Subscribe to response and updated topics
	// Use the manager's context if available, otherwise use background context
	ctx := f.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := f.subscriber.Subscribe(ctx, &paho.Subscribe{
		Subscriptions: []paho.SubscribeOptions{
			{Topic: responseTopic, QoS: 1},
			{Topic: updatedTopic, QoS: 1},
		},
	}); err != nil {
		return fmt.Errorf("failed to subscribe to secrets topics: %w", err)
	}

	f.logger.Info("Fleet secrets manager bound to MQTT",
		"request_topic", requestTopic,
		"response_topic", responseTopic,
		"updated_topic", updatedTopic)

	return nil
}

// HandleMessage handles incoming MQTT messages on secrets topics
func (f *FleetSecretsManager) HandleMessage(topic string, payload []byte) error {
	switch topic {
	case f.responseTopic:
		return f.handleResponse(payload)
	case f.updatedTopic:
		return f.handleUpdateNotification(payload)
	default:
		f.logger.Info("received unknown message on topic", "topic", topic)
		return nil
	}
}

func (f *FleetSecretsManager) handleResponse(payload []byte) error {
	var response messages.SecretResponseMsg
	if err := json.Unmarshal(payload, &response); err != nil {
		f.logger.Error("failed to unmarshal secret response", "error", err)
		return err
	}
	f.logger.Debug("handling secret response", "request_id", response.RequestID, "status", response.Status, "secrets", len(response.Secrets))

	f.mu.Lock()
	ch, exists := f.pendingReqs[response.RequestID]
	f.mu.Unlock()

	if !exists {
		f.logger.Warn("received response for unknown request", "request_id", response.RequestID)
		return nil
	}

	// Send response to waiting goroutine
	select {
	case ch <- &response:
	default:
		f.logger.Warn("response channel full, dropping response", "request_id", response.RequestID)
	}

	return nil
}

func (f *FleetSecretsManager) handleUpdateNotification(payload []byte) error {
	var notification messages.SecretUpdateNotificationMsg
	if err := json.Unmarshal(payload, &notification); err != nil {
		f.logger.Error("failed to unmarshal secret update notification", "error", err)
		return err
	}

	changedPolicyIDs := make(map[string]bool)

	for _, update := range notification.Updates {
		// Copy data needed for the request while holding the lock
		f.mu.Lock()
		cached, exists := f.usedVars[update.Path]
		if !exists {
			f.mu.Unlock()
			continue
		}

		// Check if version changed
		if update.Version <= cached.Version {
			f.mu.Unlock()
			continue
		}

		f.logger.Info("secret version changed, requesting update",
			"path", update.Path,
			"old_version", cached.Version,
			"new_version", update.Version)

		// Deep-copy policy IDs so they can be safely used while the lock is released
		policyIDsCopy := make(map[string]bool, len(cached.policyIDs))
		for id := range cached.policyIDs {
			policyIDsCopy[id] = true
		}
		path := update.Path

		// Release the lock before performing the potentially long-running network request
		f.mu.Unlock()

		// Request updated secret
		ctx := f.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		secret, err := f.requestSecret(ctx, path, policyIDsCopy)

		// Re-acquire the lock before accessing or mutating shared state
		f.mu.Lock()
		if err != nil {
			f.logger.Error("failed to request updated secret", "path", path, "error", err)
			// Mark policies as needing update but with error
			for id := range policyIDsCopy {
				changedPolicyIDs[id] = false
			}
			f.mu.Unlock()
			continue
		}

		// Re-fetch the cached entry in case it changed while the lock was released
		cached, exists = f.usedVars[path]
		if !exists {
			// The secret was removed while we were requesting it; skip updating.
			f.mu.Unlock()
			continue
		}
		// If the version is already up-to-date or newer, skip overwriting.
		if cached.Version >= secret.Version {
			f.mu.Unlock()
			continue
		}

		// Update cache
		cached.Value = secret.Value
		cached.Version = secret.Version
		f.usedVars[path] = cached

		// Mark policies as needing update
		for id := range cached.policyIDs {
			changedPolicyIDs[id] = true
		}
		f.mu.Unlock()
	}

	// Call callback if secrets changed
	if len(changedPolicyIDs) > 0 && f.callback != nil {
		f.logger.Info("calling update callback for changed secrets", "policy_count", len(changedPolicyIDs))
		f.callback(changedPolicyIDs)
	}

	return nil
}

// Start initializes the Fleet secrets manager
func (f *FleetSecretsManager) Start(ctx context.Context) error {
	f.ctx = ctx
	f.usedVars = make(map[string]fleetCachedSecret)
	return nil
}

// RegisterUpdatePoliciesCallback registers a callback for policy updates when secrets change
func (f *FleetSecretsManager) RegisterUpdatePoliciesCallback(callback func(map[string]bool)) {
	f.callback = callback
}

// SolvePolicySecrets resolves fleet secret references in a policy payload
func (f *FleetSecretsManager) SolvePolicySecrets(payload config.PolicyPayload) (config.PolicyPayload, error) {
	// Create a copy of the payload
	newPayload := payload

	// Process the Data field
	// TODO: currently this will solve secrets sequentially - we should find all the secrets and then request them all at once
	processedData, err := f.processValue(payload.Data, payload.ID)
	if err != nil {
		return payload, err
	}

	newPayload.Data = processedData
	return newPayload, nil
}

// SolveConfigSecrets resolves fleet secret references in backend and config manager configurations
func (f *FleetSecretsManager) SolveConfigSecrets(backends map[string]any, configManager config.ManagerConfig) (map[string]any, config.ManagerConfig, error) {
	// Create a copy of the backends
	newBackends := backends
	processedBackends, err := f.processValue(newBackends, "_backends")
	if err != nil {
		return backends, configManager, fmt.Errorf("failed to process backends: %w", err)
	}
	newBackends, ok := processedBackends.(map[string]any)
	if !ok {
		return backends, configManager, fmt.Errorf("failed to cast processed backends to map[string]any")
	}

	// Convert configManager to map[string]any
	configManagerMap, err := structToMap(configManager)
	if err != nil {
		return backends, configManager, fmt.Errorf("failed to convert config manager to map: %w", err)
	}
	// Process the config manager map
	processedConfigManagerMap, err := f.processValue(configManagerMap, "_config_manager")
	if err != nil {
		return backends, configManager, fmt.Errorf("failed to process config manager: %w", err)
	}
	newConfigManager, err := mapToStruct[config.ManagerConfig](processedConfigManagerMap)
	if err != nil {
		return backends, configManager, fmt.Errorf("failed to convert processed map to config manager: %w", err)
	}

	// Do not track updates on config vars for now
	f.mu.Lock()
	f.usedVars = make(map[string]fleetCachedSecret)
	f.mu.Unlock()

	// Process the backends and config manager
	return newBackends, newConfigManager, nil
}

func (f *FleetSecretsManager) processValue(value any, id string) (any, error) {
	switch val := value.(type) {
	case string:
		return f.processString(val, id)
	case map[string]any:
		return f.processMap(val, id)
	case []any:
		return f.processSlice(val, id)
	default:
		return val, nil
	}
}

// processString processes a string and replaces fleet secret references
func (f *FleetSecretsManager) processString(s string, id string) (string, error) {
	if !fleetRefRegex.MatchString(s) {
		return s, nil
	}

	match := fleetRefRegex.FindStringSubmatchIndex(s)
	if len(match) < 4 {
		return "", fmt.Errorf("failed to find fleet secret reference in string: %s", s)
	}

	fleetPath := s[match[2]:match[3]]

	// Check if secret exists in cache and update policy tracking
	f.mu.Lock()
	cached, exists := f.usedVars[fleetPath]
	if exists {
		if cached.policyIDs == nil {
			cached.policyIDs = make(map[string]bool)
		}
		cached.policyIDs[id] = true
		f.usedVars[fleetPath] = cached
		value := cached.Value
		f.mu.Unlock()
		return value, nil
	}
	f.mu.Unlock()

	// Request secret from control plane
	ctx := f.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	policyIDs := map[string]bool{id: true}
	secret, err := f.requestSecret(ctx, fleetPath, policyIDs)
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s: %w", fleetPath, err)
	}

	f.logger.Info("got secret", "secret_path", fleetPath)

	// Cache the secret
	f.mu.Lock()
	f.usedVars[fleetPath] = fleetCachedSecret{
		Value:     secret.Value,
		Version:   secret.Version,
		policyIDs: policyIDs,
	}
	f.mu.Unlock()

	return secret.Value, nil
}

// processMap processes a map recursively and replaces fleet secret references in its values
func (f *FleetSecretsManager) processMap(m map[string]any, id string) (map[string]any, error) {
	result := make(map[string]any)
	for key, val := range m {
		processedVal, err := f.processValue(val, id)
		if err != nil {
			return nil, fmt.Errorf("failed to process value for key %s: %w", key, err)
		}
		result[key] = processedVal
	}
	return result, nil
}

// processSlice processes a slice recursively and replaces fleet secret references in its elements
func (f *FleetSecretsManager) processSlice(s []any, id string) ([]any, error) {
	result := make([]any, len(s))
	for i, val := range s {
		processedVal, err := f.processValue(val, id)
		if err != nil {
			return nil, fmt.Errorf("failed to process value at index %d: %w", i, err)
		}
		result[i] = processedVal
	}
	return result, nil
}

// requestSecret requests a secret from the control plane via MQTT
func (f *FleetSecretsManager) requestSecret(ctx context.Context, path string, policyIDs map[string]bool) (*messages.SecretValue, error) {
	f.logger.Info("requesting secret", "path", path, "policy_ids", policyIDs)
	if f.publisher == nil {
		return nil, fmt.Errorf("MQTT publisher not bound")
	}

	requestID := uuid.New().String()
	request := messages.SecretRequestMsg{
		SchemaVersion: messages.CurrentSecretsSchemaVersion,
		RequestID:     requestID,
		Timestamp:     time.Now(),
		Secrets: []messages.SecretRequest{
			{
				Path:    path,
				Context: getContextFromPolicyIDs(policyIDs),
			},
		},
	}

	payload, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal secret request: %w", err)
	}

	// Create response channel with buffer size 1 to prevent blocking handleResponse
	responseCh := make(chan *messages.SecretResponseMsg, 1)
	f.mu.Lock()
	f.pendingReqs[requestID] = responseCh
	f.mu.Unlock()

	// Cleanup pending request on exit
	// Note: The channel is intentionally not closed here to avoid a race condition where
	// handleResponse might already have a reference to the channel and attempt to send after
	// it's closed (which would panic). By removing the channel from pendingReqs, we ensure
	// no new sends will be attempted, and the buffered channel prevents blocking. The channel
	// will be garbage collected once this function returns and any in-flight sends complete.
	defer func() {
		f.mu.Lock()
		delete(f.pendingReqs, requestID)
		f.mu.Unlock()
	}()

	// Publish request
	if err := f.publisher.Publish(ctx, f.requestTopic, payload); err != nil {
		return nil, fmt.Errorf("failed to publish secret request: %w", err)
	}

	// Wait for response with timeout
	select {
	case response := <-responseCh:
		if response.Status == "error" {
			if len(response.Errors) > 0 {
				err := response.Errors[0]
				return nil, fmt.Errorf("secret request failed: %s (code: %s)", err.Error, err.Code)
			}
			return nil, fmt.Errorf("secret request failed with status: %s", response.Status)
		}

		if len(response.Secrets) == 0 {
			return nil, fmt.Errorf("no secrets in response")
		}

		// Log warning for partial responses (some secrets succeeded, some failed)
		if response.Status == "partial" && len(response.Errors) > 0 {
			for _, secretErr := range response.Errors {
				f.logger.Warn("partial secret response: some secrets failed",
					"path", secretErr.Path,
					"error", secretErr.Error,
					"code", secretErr.Code)
			}
		}

		return &response.Secrets[0], nil

	case <-ctx.Done():
		return nil, fmt.Errorf("context canceled while waiting for secret response")
	case <-time.After(f.timeout):
		return nil, fmt.Errorf("timeout waiting for secret response after %s", f.timeout)
	}
}

// getContextFromPolicyIDs extracts a context string from policy IDs
// For now, we use the first policy ID or "config" if it's a config secret
func getContextFromPolicyIDs(policyIDs map[string]bool) string {
	for id := range policyIDs {
		if id != "_backends" && id != "_config_manager" {
			return id
		}
	}
	return "config"
}

// CMAdapterPublisher adapts autopaho.ConnectionManager to implement Publisher
type CMAdapterPublisher struct {
	cm *autopaho.ConnectionManager
}

// NewCMAdapterPublisher creates a new adapter for an autopaho connection manager
func NewCMAdapterPublisher(cm *autopaho.ConnectionManager) *CMAdapterPublisher {
	return &CMAdapterPublisher{cm: cm}
}

// Publish sends the payload to the topic with QoS 0
func (p *CMAdapterPublisher) Publish(ctx context.Context, topic string, payload []byte) error {
	_, err := p.cm.Publish(ctx, &paho.Publish{
		Topic:   topic,
		Payload: payload,
		QoS:     0,
		Retain:  false,
	})
	return err
}

// CMAdapterSubscriber adapts autopaho.ConnectionManager to implement Subscriber
type CMAdapterSubscriber struct {
	cm *autopaho.ConnectionManager
}

// NewCMAdapterSubscriber creates a new adapter for an autopaho connection manager
func NewCMAdapterSubscriber(cm *autopaho.ConnectionManager) *CMAdapterSubscriber {
	return &CMAdapterSubscriber{cm: cm}
}

// Subscribe subscribes to topics
func (s *CMAdapterSubscriber) Subscribe(ctx context.Context, subscribe *paho.Subscribe) error {
	_, err := s.cm.Subscribe(ctx, subscribe)
	return err
}
