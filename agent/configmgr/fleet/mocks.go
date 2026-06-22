package fleet

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/stretchr/testify/mock"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// RawJWTWithClaims builds a raw JWT string with the given claims.
// Signature is a dummy value; ParseUnverified only inspects header/payload.
func RawJWTWithClaims(claims map[string]any) string {
	return RawJWTWithClaimsAlg(claims, "RS256")
}

// RawJWTWithClaimsAlg is like RawJWTWithClaims but sets the JWS "alg" header (for tests).
func RawJWTWithClaimsAlg(claims map[string]any, alg string) string {
	header := map[string]any{
		"alg": alg,
		"kid": "test-key",
		"typ": "JWT",
	}
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p) + ".sig"
}

// mockBackend implements the Backend interface for testing
type mockBackend struct {
	mock.Mock
}

func (m *mockBackend) Configure(logger *slog.Logger, repo policies.PolicyRepo, config map[string]any, commons config.BackendCommons, _ filesmgr.Manager) error {
	args := m.Called(logger, repo, config, commons)
	return args.Error(0)
}

func (m *mockBackend) Version() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *mockBackend) Start(ctx context.Context, cancelFunc context.CancelFunc) error {
	args := m.Called(ctx, cancelFunc)
	return args.Error(0)
}

func (m *mockBackend) Stop(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockBackend) FullReset(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockBackend) GetStartTime() time.Time {
	args := m.Called()
	return args.Get(0).(time.Time)
}

func (m *mockBackend) GetCapabilities() (map[string]any, error) {
	args := m.Called()
	return args.Get(0).(map[string]any), args.Error(1)
}

func (m *mockBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
	args := m.Called()
	return args.Get(0).(backend.RunningStatus), args.String(1), args.Error(2)
}

func (m *mockBackend) GetInitialState() backend.RunningStatus {
	args := m.Called()
	return args.Get(0).(backend.RunningStatus)
}

func (m *mockBackend) ApplyPolicy(data policies.PolicyData, updatePolicy bool) error {
	args := m.Called(data, updatePolicy)
	return args.Error(0)
}

func (m *mockBackend) RemovePolicy(data policies.PolicyData) error {
	args := m.Called(data)
	return args.Error(0)
}

// MockMQTTConnection is a mock implementation of MQTTConnector for testing
type MockMQTTConnection struct {
	mu sync.Mutex

	ConnectError    error
	DisconnectError error
	ReconnectError  error

	// guarded by mu — written from the goroutine under test, read from test goroutines
	connectCalled      bool
	disconnectCalled   bool
	lastConnectDetails ConnectionDetails

	hooks []func(cm *autopaho.ConnectionManager, topics TokenResponseTopics)
}

// ConnectCalled returns whether Connect has been called (safe for concurrent use).
func (m *MockMQTTConnection) ConnectCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connectCalled
}

// DisconnectCalled returns whether Disconnect has been called (safe for concurrent use).
func (m *MockMQTTConnection) DisconnectCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.disconnectCalled
}

// LastConnectDetails returns the details passed to the most recent Connect call (safe for concurrent use).
func (m *MockMQTTConnection) LastConnectDetails() ConnectionDetails {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastConnectDetails
}

// Connect connects to the MQTT broker
func (m *MockMQTTConnection) Connect(_ context.Context, _ context.Context, details ConnectionDetails, _ map[string]backend.Backend, _ map[string]string, _ string) error {
	m.mu.Lock()
	m.connectCalled = true
	m.lastConnectDetails = details
	m.mu.Unlock()
	return m.ConnectError
}

// Disconnect disconnects from the MQTT broker
func (m *MockMQTTConnection) Disconnect(_ context.Context, _ string) error {
	m.mu.Lock()
	m.disconnectCalled = true
	m.mu.Unlock()
	return m.DisconnectError
}

// Reconnect reconnects to the MQTT broker
func (m *MockMQTTConnection) Reconnect(_ context.Context, _ context.Context, _ ConnectionDetails, _ map[string]backend.Backend, _ map[string]string, _ string, _ time.Duration) error {
	return m.ReconnectError
}

// AddOnReadyHook registers a hook function to be called when the MQTT connection is ready.
func (m *MockMQTTConnection) AddOnReadyHook(fn func(cm *autopaho.ConnectionManager, topics TokenResponseTopics)) {
	m.hooks = append(m.hooks, fn)
}

// RegisterTopicHandler registers a handler for a specific topic (mock implementation)
func (m *MockMQTTConnection) RegisterTopicHandler(_ string, _ TopicMessageHandler) {
	// No-op for mock
}

// TriggerOnReadyHook triggers all registered onReady hooks (for testing)
func (m *MockMQTTConnection) TriggerOnReadyHook(cm *autopaho.ConnectionManager, topics TokenResponseTopics) {
	for _, hook := range m.hooks {
		hook(cm, topics)
	}
}

// HookCount returns the number of registered onReady hooks (for testing).
func (m *MockMQTTConnection) HookCount() int {
	return len(m.hooks)
}
