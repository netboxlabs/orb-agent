package secretsmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/eclipse/paho.golang/paho"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
)

func TestFleetSecretsManager_processString(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("no fleet reference", func(t *testing.T) {
		fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{Timeout: intPtr(1)})
		fm.ctx = ctx

		result, err := fm.processString("plain text", "policy1")
		assert.NoError(t, err)
		assert.Equal(t, "plain text", result)
	})

	t.Run("valid fleet reference", func(t *testing.T) {
		fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{Timeout: intPtr(5)})
		fm.ctx = ctx
		fm.requestTopic = "test/request"
		fm.responseTopic = "test/response"
		fm.updatedTopic = "test/updated"

		mockPub := &asyncMockPublisher{fm: fm}
		fm.publisher = mockPub
		fm.subscriber = &mockSubscriber{}

		result, err := fm.processString("${fleet://orb/agents/database/password}", "policy1")
		assert.NoError(t, err)
		assert.Equal(t, "secretvalue", result)
	})

	t.Run("cached secret", func(t *testing.T) {
		fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{Timeout: intPtr(1)})
		fm.ctx = ctx
		// Pre-cache a secret
		fm.usedVars["orb/agents/cached/secret"] = fleetCachedSecret{
			Value:     "cachedvalue",
			Version:   1,
			policyIDs: map[string]bool{"policy1": true},
		}

		result, err := fm.processString("${fleet://orb/agents/cached/secret}", "policy1")
		assert.NoError(t, err)
		assert.Equal(t, "cachedvalue", result)
	})

	t.Run("malformed reference", func(t *testing.T) {
		fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{Timeout: intPtr(1)})
		fm.ctx = ctx

		result, err := fm.processString("${fleet:/malformed}", "policy1")
		assert.NoError(t, err)
		assert.Equal(t, "${fleet:/malformed}", result)
	})
}

func TestFleetSecretsManager_handleResponse(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{})
	fm.pendingReqs = make(map[string]chan *messages.SecretResponseMsg)

	requestID := uuid.New().String()
	responseCh := make(chan *messages.SecretResponseMsg, 1)
	fm.pendingReqs[requestID] = responseCh

	response := messages.SecretResponseMsg{
		SchemaVersion: messages.CurrentSecretsSchemaVersion,
		RequestID:     requestID,
		Timestamp:     time.Now(),
		Status:        "success",
		Secrets: []messages.SecretValue{
			{
				Path:    "test/path",
				Value:   "testvalue",
				Version: 1,
			},
		},
	}

	payload, err := json.Marshal(response)
	require.NoError(t, err)

	err = fm.handleResponse(payload)
	assert.NoError(t, err)

	// Check that response was sent to channel
	select {
	case received := <-responseCh:
		assert.Equal(t, requestID, received.RequestID)
		assert.Equal(t, "success", received.Status)
		assert.Len(t, received.Secrets, 1)
		assert.Equal(t, "testvalue", received.Secrets[0].Value)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for response")
	}
}

func TestFleetSecretsManager_handleUpdateNotification(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{})
	fm.usedVars = make(map[string]fleetCachedSecret)
	fm.usedVars["test/path"] = fleetCachedSecret{
		Value:     "oldvalue",
		Version:   1,
		policyIDs: map[string]bool{"policy1": true},
	}

	var callbackCalled bool
	var callbackPolicyIDs map[string]error
	fm.callback = func(policyIDs map[string]error) {
		callbackCalled = true
		callbackPolicyIDs = policyIDs
	}

	notification := messages.SecretUpdateNotificationMsg{
		SchemaVersion: messages.CurrentSecretsSchemaVersion,
		Timestamp:     time.Now(),
		Updates: []messages.SecretUpdate{
			{
				Path:     "test/path",
				Version:  2,
				Contexts: []string{"policy1"},
			},
		},
	}

	payload, err := json.Marshal(notification)
	require.NoError(t, err)

	// handleUpdateNotification has no publisher: fetch fails, callback reports the error.
	err = fm.handleUpdateNotification(payload)
	assert.NoError(t, err)

	assert.True(t, callbackCalled)
	assert.Contains(t, callbackPolicyIDs, "policy1")
	assert.ErrorContains(t, callbackPolicyIDs["policy1"], "MQTT publisher not bound")
}

func TestFleetSecretsManager_handleUpdateNotification_successUpdatesCacheAndCallbacks(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{Timeout: intPtr(5)})
	fm.ctx = ctx
	fm.requestTopic = "test/request"
	fm.responseTopic = "test/response"
	fm.updatedTopic = "test/updated"
	fm.usedVars = map[string]fleetCachedSecret{
		"test/path": {
			Value:     "oldvalue",
			Version:   1,
			policyIDs: map[string]bool{"policy1": true},
		},
	}

	var callbackPolicyIDs map[string]error
	var callbackCalled bool
	fm.callback = func(ids map[string]error) {
		callbackCalled = true
		callbackPolicyIDs = ids
	}

	fm.publisher = &asyncMockPublisher{
		fm: fm,
		customResponse: func(req messages.SecretRequestMsg) *messages.SecretResponseMsg {
			return &messages.SecretResponseMsg{
				SchemaVersion: messages.CurrentSecretsSchemaVersion,
				RequestID:     req.RequestID,
				Timestamp:     time.Now(),
				Status:        "success",
				Secrets: []messages.SecretValue{
					{Path: "test/path", Value: "newvalue", Version: 2},
				},
			}
		},
	}
	fm.subscriber = &mockSubscriber{}

	notification := messages.SecretUpdateNotificationMsg{
		SchemaVersion: messages.CurrentSecretsSchemaVersion,
		Timestamp:     time.Now(),
		Updates: []messages.SecretUpdate{
			{Path: "test/path", Version: 2, Contexts: []string{"policy1"}},
		},
	}
	payload, err := json.Marshal(notification)
	require.NoError(t, err)

	err = fm.handleUpdateNotification(payload)
	assert.NoError(t, err)

	assert.True(t, callbackCalled)
	require.Contains(t, callbackPolicyIDs, "policy1")
	assert.NoError(t, callbackPolicyIDs["policy1"], "policy callback should signal success after version bump")

	got := fm.usedVars["test/path"]
	assert.Equal(t, 2, got.Version)
	assert.Equal(t, "newvalue", got.Value)
}

func TestNewFleetSecretsManager(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	tests := []struct {
		name         string
		config       config.FleetSecretsManager
		expectedType string
	}{
		{
			name: "with timeout",
			config: config.FleetSecretsManager{
				Timeout: intPtr(60),
			},
			expectedType: "*secretsmgr.FleetSecretsManager",
		},
		{
			name:         "without timeout",
			config:       config.FleetSecretsManager{},
			expectedType: "*secretsmgr.FleetSecretsManager",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewFleetSecretsManager(logger, tt.config)
			assert.NotNil(t, manager)
			assert.Equal(t, tt.expectedType, fmt.Sprintf("%T", manager))
		})
	}
}

func TestFleetSecretsManager_RegisterUpdatePoliciesCallback(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{})

	called := false
	callback := func(_ map[string]error) {
		called = true
	}

	fm.RegisterUpdatePoliciesCallback(callback)
	assert.NotNil(t, fm.callback)

	// Manually call the callback to verify it works
	fm.callback(map[string]error{"policy1": nil})
	assert.True(t, called)
}

func TestFleetSecretsManager_SolvePolicySecrets_batchesUncachedPaths(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{Timeout: intPtr(5)})
	fm.ctx = ctx
	fm.requestTopic = "test/request"
	fm.responseTopic = "test/response"
	fm.updatedTopic = "test/updated"

	var publishCount int
	mockPub := &asyncMockPublisher{
		fm: fm,
		onPublish: func() {
			publishCount++
		},
	}
	fm.publisher = mockPub
	fm.subscriber = &mockSubscriber{}

	payload := config.PolicyPayload{
		ID: "policy-batch",
		Data: map[string]any{
			"a":    "${fleet://path/one}",
			"b":    []any{"${fleet://path/two}", map[string]any{"c": "${fleet://path/three}"}},
			"same": "${fleet://path/one}",
		},
	}

	out, err := fm.SolvePolicySecrets(payload)
	require.NoError(t, err)
	assert.Equal(t, 1, publishCount, "expected one batched MQTT request for multiple uncached paths")

	data, ok := out.Data.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "secretvalue", data["a"])
	assert.Equal(t, "secretvalue", data["same"])
	slc, ok := data["b"].([]any)
	require.True(t, ok)
	assert.Equal(t, "secretvalue", slc[0])
	nested, ok := slc[1].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "secretvalue", nested["c"])
}

// Multi-token strings use legacy first-match resolution in processString; prefetch must not
// request later tokens (they would be ignored and could spuriously fail the solve).
func TestFleetSecretsManager_SolvePolicySecrets_multiTokenStringPrefetchesFirstRefOnly(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{Timeout: intPtr(5)})
	fm.ctx = ctx
	fm.requestTopic = "test/request"
	fm.responseTopic = "test/response"
	fm.updatedTopic = "test/updated"

	fm.publisher = &asyncMockPublisher{
		fm: fm,
		customResponse: func(req messages.SecretRequestMsg) *messages.SecretResponseMsg {
			require.Len(t, req.Secrets, 1, "only first fleet ref in the string should be prefetched")
			assert.Equal(t, "path/first", req.Secrets[0].Path)
			return &messages.SecretResponseMsg{
				SchemaVersion: messages.CurrentSecretsSchemaVersion,
				RequestID:     req.RequestID,
				Timestamp:     time.Now(),
				Status:        "success",
				Secrets: []messages.SecretValue{
					{Path: "path/first", Value: "firstval", Version: 1},
				},
			}
		},
	}
	fm.subscriber = &mockSubscriber{}

	payload := config.PolicyPayload{
		ID: "policy-multi",
		Data: map[string]any{
			"k": "${fleet://path/first} ${fleet://path/second}",
		},
	}

	out, err := fm.SolvePolicySecrets(payload)
	require.NoError(t, err)
	data, ok := out.Data.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "firstval", data["k"])
}

// A refresh that fails after Fleet announced a new version leaves the cached
// value outdated: the next resolve of the path, as a re-delivery of the policy
// makes, asks Fleet again instead of applying the value it had.
func TestFleetSecretsManager_aFailedRefreshIsRequestedAgainOnResolve(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{Timeout: intPtr(5)})
	fm.ctx = ctx
	fm.requestTopic = "test/request"
	fm.responseTopic = "test/response"
	fm.updatedTopic = "test/updated"
	fm.usedVars = map[string]fleetCachedSecret{
		"test/path": {Value: "oldvalue", Version: 1, policyIDs: map[string]bool{"policy1": true}},
	}
	var reported map[string]error
	fm.callback = func(ids map[string]error) { reported = ids }

	notification, err := json.Marshal(messages.SecretUpdateNotificationMsg{
		SchemaVersion: messages.CurrentSecretsSchemaVersion,
		Timestamp:     time.Now(),
		Updates:       []messages.SecretUpdate{{Path: "test/path", Version: 2, Contexts: []string{"policy1"}}},
	})
	require.NoError(t, err)
	// No publisher bound yet: the refresh fails.
	require.NoError(t, fm.handleUpdateNotification(notification))
	require.Error(t, reported["policy1"])

	requests := 0
	fm.publisher = &asyncMockPublisher{
		fm:        fm,
		onPublish: func() { requests++ },
		customResponse: func(req messages.SecretRequestMsg) *messages.SecretResponseMsg {
			return &messages.SecretResponseMsg{
				SchemaVersion: messages.CurrentSecretsSchemaVersion,
				RequestID:     req.RequestID,
				Timestamp:     time.Now(),
				Status:        "success",
				Secrets:       []messages.SecretValue{{Path: "test/path", Value: "newvalue", Version: 2}},
			}
		},
	}
	fm.subscriber = &mockSubscriber{}

	out, err := fm.SolvePolicySecrets(config.PolicyPayload{ID: "policy1", Data: map[string]any{"c": "${fleet://test/path}"}})
	require.NoError(t, err)
	assert.Equal(t, 1, requests, "the path must be requested again")
	assert.Equal(t, "newvalue", out.Data.(map[string]any)["c"])

	_, err = fm.SolvePolicySecrets(config.PolicyPayload{ID: "policy1", Data: map[string]any{"c": "${fleet://test/path}"}})
	require.NoError(t, err)
	assert.Equal(t, 1, requests, "once requested again, the path is served from the cache")
}

func newFleetManagerForStaleTests(t *testing.T, respond func(req messages.SecretRequestMsg) *messages.SecretResponseMsg) (*FleetSecretsManager, *int) {
	t.Helper()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{Timeout: intPtr(5)})
	fm.ctx = ctx
	fm.requestTopic = "test/request"
	fm.responseTopic = "test/response"
	fm.updatedTopic = "test/updated"
	requests := 0
	fm.publisher = &asyncMockPublisher{fm: fm, onPublish: func() { requests++ }, customResponse: respond}
	fm.subscriber = &mockSubscriber{}
	return fm, &requests
}

func notify(t *testing.T, fm *FleetSecretsManager, updates ...messages.SecretUpdate) {
	t.Helper()
	payload, err := json.Marshal(messages.SecretUpdateNotificationMsg{
		SchemaVersion: messages.CurrentSecretsSchemaVersion,
		Timestamp:     time.Now(),
		Updates:       updates,
	})
	require.NoError(t, err)
	require.NoError(t, fm.handleUpdateNotification(payload))
}

// A notification that refreshes a path whose last refresh failed reports its
// policies to apply again, and the path is served from the cache from then on.
func TestFleetSecretsManager_aNotificationRefreshesAStalePath(t *testing.T) {
	fail := true
	fm, requests := newFleetManagerForStaleTests(t, func(req messages.SecretRequestMsg) *messages.SecretResponseMsg {
		resp := &messages.SecretResponseMsg{SchemaVersion: messages.CurrentSecretsSchemaVersion, RequestID: req.RequestID, Timestamp: time.Now(), Status: "success"}
		if fail {
			resp.Status = "error"
			resp.Errors = []messages.SecretError{{Path: "test/path", Error: "unavailable", Code: messages.ErrorCodeNotFound}}
			return resp
		}
		resp.Secrets = []messages.SecretValue{{Path: "test/path", Value: "v3", Version: 3}}
		return resp
	})
	fm.usedVars = map[string]fleetCachedSecret{
		"test/path": {Value: "v1", Version: 1, policyIDs: map[string]bool{"policy1": true}},
	}
	var reported map[string]error
	fm.callback = func(ids map[string]error) { reported = ids }

	notify(t, fm, messages.SecretUpdate{Path: "test/path", Version: 2})
	require.Error(t, reported["policy1"])

	fail = false
	notify(t, fm, messages.SecretUpdate{Path: "test/path", Version: 3})
	require.Equal(t, map[string]error{"policy1": nil}, reported)

	before := *requests
	out, err := fm.SolvePolicySecrets(config.PolicyPayload{ID: "policy1", Data: map[string]any{"c": "${fleet://test/path}"}})
	require.NoError(t, err)
	assert.Equal(t, before, *requests, "a refreshed path is served from the cache")
	assert.Equal(t, "v3", out.Data.(map[string]any)["c"])
}

// A policy whose paths change in one notification, one refreshed and one not,
// is reported failed, whichever comes first.
func TestFleetSecretsManager_aFailedPathOutweighsARefreshedOneForTheSamePolicy(t *testing.T) {
	for _, order := range [][]string{{"path/bad", "path/good"}, {"path/good", "path/bad"}} {
		fm, _ := newFleetManagerForStaleTests(t, func(req messages.SecretRequestMsg) *messages.SecretResponseMsg {
			resp := &messages.SecretResponseMsg{SchemaVersion: messages.CurrentSecretsSchemaVersion, RequestID: req.RequestID, Timestamp: time.Now(), Status: "success"}
			if req.Secrets[0].Path == "path/bad" {
				resp.Status = "error"
				resp.Errors = []messages.SecretError{{Path: "path/bad", Error: "gone", Code: messages.ErrorCodeNotFound}}
				return resp
			}
			resp.Secrets = []messages.SecretValue{{Path: "path/good", Value: "v2", Version: 2}}
			return resp
		})
		fm.usedVars = map[string]fleetCachedSecret{
			"path/bad":  {Value: "b1", Version: 1, policyIDs: map[string]bool{"policy1": true}},
			"path/good": {Value: "g1", Version: 1, policyIDs: map[string]bool{"policy1": true}},
		}
		var reported map[string]error
		fm.callback = func(ids map[string]error) { reported = ids }

		updates := make([]messages.SecretUpdate, 0, len(order))
		for _, p := range order {
			updates = append(updates, messages.SecretUpdate{Path: p, Version: 2})
		}
		notify(t, fm, updates...)
		require.Len(t, reported, 1, "order %v", order)
		assert.Error(t, reported["policy1"], "order %v", order)
	}
}

func TestFleetSecretsManager_SolvePolicySecrets_batchPartialDoesNotCache(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{Timeout: intPtr(5)})
	fm.ctx = ctx
	fm.requestTopic = "test/request"
	fm.responseTopic = "test/response"
	fm.updatedTopic = "test/updated"

	mockPub := &asyncMockPublisher{
		fm: fm,
		customResponse: func(req messages.SecretRequestMsg) *messages.SecretResponseMsg {
			require.Len(t, req.Secrets, 2)
			var goodPath, badPath string
			for _, s := range req.Secrets {
				switch s.Path {
				case "path/good":
					goodPath = s.Path
				case "path/bad":
					badPath = s.Path
				}
			}
			require.NotEmpty(t, goodPath)
			require.NotEmpty(t, badPath)
			return &messages.SecretResponseMsg{
				SchemaVersion: messages.CurrentSecretsSchemaVersion,
				RequestID:     req.RequestID,
				Timestamp:     time.Now(),
				Status:        "partial",
				Secrets: []messages.SecretValue{
					{Path: goodPath, Value: "ok", Version: 1},
				},
				Errors: []messages.SecretError{
					{Path: badPath, Error: "not found", Code: messages.ErrorCodeNotFound},
				},
			}
		},
	}
	fm.publisher = mockPub
	fm.subscriber = &mockSubscriber{}

	payload := config.PolicyPayload{
		ID: "policy-partial",
		Data: map[string]any{
			"x": "${fleet://path/good}",
			"y": "${fleet://path/bad}",
		},
	}

	_, err := fm.SolvePolicySecrets(payload)
	require.Error(t, err)
	assert.Empty(t, fm.usedVars, "failed batch must not populate cache")
}

// Helper functions and mocks

// asyncMockPublisher simulates async MQTT responses for testing
type asyncMockPublisher struct {
	fm             *FleetSecretsManager
	customResponse func(req messages.SecretRequestMsg) *messages.SecretResponseMsg
	onPublish      func()
}

func (m *asyncMockPublisher) Publish(_ context.Context, _ string, payload []byte) error {
	var req messages.SecretRequestMsg
	if err := json.Unmarshal(payload, &req); err != nil {
		return err
	}

	if m.onPublish != nil {
		m.onPublish()
	}

	go func() {
		time.Sleep(10 * time.Millisecond)

		var response messages.SecretResponseMsg
		if m.customResponse != nil {
			response = *m.customResponse(req)
		} else {
			secrets := make([]messages.SecretValue, len(req.Secrets))
			for i, sr := range req.Secrets {
				secrets[i] = messages.SecretValue{
					Path:    sr.Path,
					Value:   "secretvalue",
					Version: 1,
				}
			}
			response = messages.SecretResponseMsg{
				SchemaVersion: messages.CurrentSecretsSchemaVersion,
				RequestID:     req.RequestID,
				Timestamp:     time.Now(),
				Status:        "success",
				Secrets:       secrets,
			}
		}

		responsePayload, _ := json.Marshal(response)
		_ = m.fm.handleResponse(responsePayload)
	}()

	return nil
}

type mockSubscriber struct{}

func (m *mockSubscriber) Subscribe(_ context.Context, _ *paho.Subscribe) error {
	return nil
}

func intPtr(i int) *int {
	return &i
}
