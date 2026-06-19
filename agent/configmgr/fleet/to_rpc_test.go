package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// mockPolicyManagerForToRPC implements the PolicyManager interface for to_rpc testing
type mockPolicyManagerForToRPC struct {
	mock.Mock
}

func (m *mockPolicyManagerForToRPC) ManagePolicy(payload config.PolicyPayload) {
	m.Called(payload)
}

func (m *mockPolicyManagerForToRPC) RemovePolicyDataset(policyID string, datasetID string, be backend.Backend) {
	m.Called(policyID, datasetID, be)
}

func (m *mockPolicyManagerForToRPC) GetPolicyState() ([]policies.PolicyData, error) {
	args := m.Called()
	return args.Get(0).([]policies.PolicyData), args.Error(1)
}

func (m *mockPolicyManagerForToRPC) GetRepo() policies.PolicyRepo {
	args := m.Called()
	return args.Get(0).(policies.PolicyRepo)
}

func (m *mockPolicyManagerForToRPC) ApplyBackendPolicies(be backend.Backend) error {
	args := m.Called(be)
	return args.Error(0)
}

func (m *mockPolicyManagerForToRPC) RemoveBackendPolicies(be backend.Backend, permanently bool) error {
	args := m.Called(be, permanently)
	return args.Error(0)
}

func (m *mockPolicyManagerForToRPC) RemovePolicy(policyID string, policyName string, beName string) error {
	args := m.Called(policyID, policyName, beName)
	return args.Error(0)
}

func TestMessaging_SendCapabilities_Success(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForToRPC{}
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	messaging := NewMessaging(logger, mockPMgr, resetChan, &groupManager, nil)

	// Create mock backends
	mockBackend1 := &mockBackend{}
	mockBackend2 := &mockBackend{}

	// Set up backend expectations
	mockBackend1.On("Version").Return("1.2.3", nil)
	mockBackend1.On("GetCapabilities").Return(map[string]any{
		"feature1": "enabled",
		"feature2": "disabled",
	}, nil)

	mockBackend2.On("Version").Return("2.0.0", nil)
	mockBackend2.On("GetCapabilities").Return(map[string]any{
		"protocol":   "mqtt",
		"encryption": "tls",
	}, nil)

	backends := map[string]backend.Backend{
		"backend1": mockBackend1,
		"backend2": mockBackend2,
	}

	// Mock publish function
	var capturedPayload []byte
	publishFunc := func(_ context.Context, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()
	labels := map[string]string{}
	config := `orb:
	config_manager:
	  active: local
	backends:
	  common:
		diode:
		  target: grpc://192.168.0.100:8080/diode
		  client_id: ${DIODE_CLIENT_ID}
		  client_secret: ${DIODE_CLIENT_SECRET}
		  agent_name: agent01
	  snmp_discovery:
	`

	// Act
	messaging.sendCapabilities(ctx, backends, labels, config, publishFunc)

	// Assert
	require.NotNil(t, capturedPayload)

	// Verify the published capabilities structure
	var capabilities messages.Capabilities
	err := json.Unmarshal(capturedPayload, &capabilities)
	require.NoError(t, err)

	assert.Equal(t, messages.CurrentCapabilitiesSchemaVersion, capabilities.SchemaVersion)
	assert.NotEmpty(t, capabilities.OrbAgent.Version)
	assert.Len(t, capabilities.Backends, 2)

	// Verify backend1 capabilities
	assert.Contains(t, capabilities.Backends, "backend1")
	backend1Info := capabilities.Backends["backend1"]
	assert.Equal(t, "1.2.3", backend1Info.Version)
	assert.Equal(t, "enabled", backend1Info.Data["feature1"])
	assert.Equal(t, "disabled", backend1Info.Data["feature2"])

	// Verify backend2 capabilities
	assert.Contains(t, capabilities.Backends, "backend2")
	backend2Info := capabilities.Backends["backend2"]
	assert.Equal(t, "2.0.0", backend2Info.Version)
	assert.Equal(t, "mqtt", backend2Info.Data["protocol"])
	assert.Equal(t, "tls", backend2Info.Data["encryption"])

	assert.Equal(t, config, capabilities.AgentConfig)

	// Verify all mock expectations were met
	mockBackend1.AssertExpectations(t)
	mockBackend2.AssertExpectations(t)
}

func TestMessaging_SendCapabilities_BackendVersionError(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForToRPC{}
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	messaging := NewMessaging(logger, mockPMgr, resetChan, &groupManager, nil)

	// Create mock backends - one succeeds, one fails on version
	mockBackend1 := &mockBackend{}
	mockBackend2 := &mockBackend{}

	mockBackend1.On("Version").Return("1.2.3", nil)
	mockBackend1.On("GetCapabilities").Return(map[string]any{"feature": "enabled"}, nil)

	mockBackend2.On("Version").Return("", errors.New("version retrieval failed"))

	backends := map[string]backend.Backend{
		"backend1": mockBackend1,
		"backend2": mockBackend2,
	}

	labels := map[string]string{}

	config := `orb:
	config_manager:
	  active: local
	backends:
	  common:
		diode:
		  target: grpc://192.168.0.100:8080/diode
		  client_id: ${DIODE_CLIENT_ID}
		  client_secret: ${DIODE_CLIENT_SECRET}
		  agent_name: agent01
	  snmp_discovery:
	`

	var capturedPayload []byte
	publishFunc := func(_ context.Context, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()

	// Act
	messaging.sendCapabilities(ctx, backends, labels, config, publishFunc)

	// Assert
	require.NotNil(t, capturedPayload)

	var capabilities messages.Capabilities
	err := json.Unmarshal(capturedPayload, &capabilities)
	require.NoError(t, err)

	// Only backend1 should be included, backend2 should be skipped
	assert.Len(t, capabilities.Backends, 1)
	assert.Contains(t, capabilities.Backends, "backend1")
	assert.NotContains(t, capabilities.Backends, "backend2")

	mockBackend1.AssertExpectations(t)
	mockBackend2.AssertExpectations(t)
}

func TestMessaging_SendCapabilities_BackendCapabilitiesError(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForToRPC{}
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	messaging := NewMessaging(logger, mockPMgr, resetChan, &groupManager, nil)

	// Create mock backends - one succeeds, one fails on capabilities
	mockBackend1 := &mockBackend{}
	mockBackend2 := &mockBackend{}

	mockBackend1.On("Version").Return("1.2.3", nil)
	mockBackend1.On("GetCapabilities").Return(map[string]any{"feature": "enabled"}, nil)

	mockBackend2.On("Version").Return("2.0.0", nil)
	mockBackend2.On("GetCapabilities").Return(map[string]any(nil), errors.New("capabilities retrieval failed"))

	backends := map[string]backend.Backend{
		"backend1": mockBackend1,
		"backend2": mockBackend2,
	}

	labels := map[string]string{}

	config := `orb:
	config_manager:
	  active: local
	backends:
	  common:
		diode:
		  target: grpc://192.168.0.100:8080/diode
		  client_id: ${DIODE_CLIENT_ID}
		  client_secret: ${DIODE_CLIENT_SECRET}
		  agent_name: agent01
	  snmp_discovery:
	`
	var capturedPayload []byte
	publishFunc := func(_ context.Context, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()

	// Act
	messaging.sendCapabilities(ctx, backends, labels, config, publishFunc)

	// Assert
	require.NotNil(t, capturedPayload)

	var capabilities messages.Capabilities
	err := json.Unmarshal(capturedPayload, &capabilities)
	require.NoError(t, err)

	// Only backend1 should be included, backend2 should be skipped
	assert.Len(t, capabilities.Backends, 1)
	assert.Contains(t, capabilities.Backends, "backend1")
	assert.NotContains(t, capabilities.Backends, "backend2")

	mockBackend1.AssertExpectations(t)
	mockBackend2.AssertExpectations(t)
}

func TestMessaging_SendCapabilities_PublishError(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForToRPC{}
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	messaging := NewMessaging(logger, mockPMgr, resetChan, &groupManager, nil)

	mockBackend1 := &mockBackend{}
	mockBackend1.On("Version").Return("1.0.0", nil)
	mockBackend1.On("GetCapabilities").Return(map[string]any{"test": "value"}, nil)

	backends := map[string]backend.Backend{
		"backend1": mockBackend1,
	}

	labels := map[string]string{}

	config := `orb:
	config_manager:
	  active: local
	backends:
	  common:
		diode:
		  target: grpc://192.168.0.100:8080/diode
		  client_id: ${DIODE_CLIENT_ID}
		  client_secret: ${DIODE_CLIENT_SECRET}
		  agent_name: agent01
	  snmp_discovery:
	`
	publishError := errors.New("publish failed")
	publishFunc := func(_ context.Context, _ []byte) error {
		return publishError
	}

	ctx := context.Background()

	// Act
	messaging.sendCapabilities(ctx, backends, labels, config, publishFunc)

	// Assert
	assert.Equal(t, publishError, publishFunc(ctx, []byte{}))

	mockBackend1.AssertExpectations(t)
}

func TestMessaging_SendCapabilities_EmptyBackends(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForToRPC{}
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	messaging := NewMessaging(logger, mockPMgr, resetChan, &groupManager, nil)

	backends := map[string]backend.Backend{} // Empty backends
	labels := map[string]string{}

	config := `orb:
	config_manager:
	  active: local
	backends:
	  common:
		diode:
		  target: grpc://192.168.0.100:8080/diode
		  client_id: ${DIODE_CLIENT_ID}
		  client_secret: ${DIODE_CLIENT_SECRET}
		  agent_name: agent01
	  snmp_discovery:
	`
	var capturedPayload []byte
	publishFunc := func(_ context.Context, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()

	// Act
	messaging.sendCapabilities(ctx, backends, labels, config, publishFunc)

	// Assert
	require.NotNil(t, capturedPayload)

	var capabilities messages.Capabilities
	err := json.Unmarshal(capturedPayload, &capabilities)
	require.NoError(t, err)

	assert.Equal(t, messages.CurrentCapabilitiesSchemaVersion, capabilities.SchemaVersion)
	assert.NotEmpty(t, capabilities.OrbAgent.Version)
	assert.Empty(t, capabilities.Backends)
}

func TestMessaging_SendCapabilities_AllBackendsFail(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForToRPC{}
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	messaging := NewMessaging(logger, mockPMgr, resetChan, &groupManager, nil)

	// All backends fail
	mockBackend1 := &mockBackend{}
	mockBackend2 := &mockBackend{}

	labels := map[string]string{}

	mockBackend1.On("Version").Return("", errors.New("version error"))
	mockBackend2.On("Version").Return("1.0.0", nil)
	mockBackend2.On("GetCapabilities").Return(map[string]any(nil), errors.New("capabilities error"))

	backends := map[string]backend.Backend{
		"backend1": mockBackend1,
		"backend2": mockBackend2,
	}

	config := ""
	var capturedPayload []byte
	publishFunc := func(_ context.Context, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()

	// Act
	messaging.sendCapabilities(ctx, backends, labels, config, publishFunc)

	// Assert
	require.NotNil(t, capturedPayload)

	var capabilities messages.Capabilities
	err := json.Unmarshal(capturedPayload, &capabilities)
	require.NoError(t, err)

	// No backends should be included
	assert.Empty(t, capabilities.Backends)

	mockBackend1.AssertExpectations(t)
	mockBackend2.AssertExpectations(t)
}

func TestMessaging_SendCapabilities_CapabilitiesStructure(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForToRPC{}
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	messaging := NewMessaging(logger, mockPMgr, resetChan, &groupManager, nil)

	mockBackend1 := &mockBackend{}
	mockBackend1.On("Version").Return("test-version", nil)
	mockBackend1.On("GetCapabilities").Return(map[string]any{
		"string_val":  "test",
		"number_val":  42,
		"boolean_val": true,
		"array_val":   []string{"a", "b", "c"},
		"object_val":  map[string]string{"nested": "value"},
	}, nil)

	backends := map[string]backend.Backend{
		"test_backend": mockBackend1,
	}

	labels := map[string]string{}

	config := ""
	var capturedPayload []byte
	publishFunc := func(_ context.Context, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()

	// Act
	messaging.sendCapabilities(ctx, backends, labels, config, publishFunc)

	// Assert
	require.NotNil(t, capturedPayload)

	// Verify JSON structure can be unmarshaled and contains expected data types
	var capabilities messages.Capabilities
	err := json.Unmarshal(capturedPayload, &capabilities)
	require.NoError(t, err)

	// Verify structure fields
	assert.Equal(t, messages.CurrentCapabilitiesSchemaVersion, capabilities.SchemaVersion)
	assert.NotEmpty(t, capabilities.OrbAgent.Version)

	// Verify backend data structure preservation
	backendInfo := capabilities.Backends["test_backend"]
	assert.Equal(t, "test-version", backendInfo.Version)

	// Verify all data types are preserved
	assert.Equal(t, "test", backendInfo.Data["string_val"])
	assert.Equal(t, float64(42), backendInfo.Data["number_val"]) // JSON numbers become float64
	assert.Equal(t, true, backendInfo.Data["boolean_val"])
	assert.IsType(t, []interface{}{}, backendInfo.Data["array_val"])
	assert.IsType(t, map[string]interface{}{}, backendInfo.Data["object_val"])

	mockBackend1.AssertExpectations(t)
}

func TestSendGroupMembershipsRequest_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	messaging := NewMessaging(logger, nil, resetChan, &groupManager, nil)

	var published []byte
	publishFunc := func(_ context.Context, payload []byte) error {
		published = payload
		return nil
	}

	messaging.sendGroupMembershipsRequest(context.Background(), publishFunc)
	assert.NotEmpty(t, published)

	var rpc map[string]any
	require.NoError(t, json.Unmarshal(published, &rpc))
	assert.Equal(t, "group_membership_req", rpc["func"])
}

func TestSendGroupMembershipsRequest_PublishError(_ *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	messaging := NewMessaging(logger, nil, resetChan, &groupManager, nil)

	publishFunc := func(_ context.Context, _ []byte) error {
		return errors.New("publish failed")
	}

	// Should log error but not panic
	messaging.sendGroupMembershipsRequest(context.Background(), publishFunc)
}

func TestSendBundleListRequest(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := &Messaging{logger: logger}

	var captured []byte
	m.sendBundleListRequest(context.Background(), func(_ context.Context, payload []byte) error {
		captured = payload
		return nil
	})

	require.NotNil(t, captured)

	// Assert the full envelope, including an empty-object payload (RPC.Payload is `any`,
	// so a nil/wrong payload would otherwise slip through).
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(captured, &raw))
	var fn, schema string
	require.NoError(t, json.Unmarshal(raw["func"], &fn))
	require.NoError(t, json.Unmarshal(raw["schema_version"], &schema))
	assert.Equal(t, messages.BundleListReqRPCFunc, fn)
	assert.Equal(t, messages.CurrentRPCSchemaVersion, schema)
	assert.JSONEq(t, "{}", string(raw["payload"]))
}

func TestSendBundleListRequestIfActive_Disabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := &Messaging{logger: logger} // filesManager nil => disabled

	called := false
	m.sendBundleListRequestIfActive(context.Background(), func(context.Context, []byte) error {
		called = true
		return nil
	})
	assert.False(t, called, "catch-up must not publish when files delivery is disabled")
}

func TestSendBundleListRequestIfActive_Enabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := &Messaging{logger: logger, filesManager: &mockFilesManager{}}

	called := false
	m.sendBundleListRequestIfActive(context.Background(), func(context.Context, []byte) error {
		called = true
		return nil
	})
	assert.True(t, called, "catch-up must publish when files delivery is active")
}
