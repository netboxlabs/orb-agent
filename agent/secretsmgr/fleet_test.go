package secretsmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
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

	t.Run("valid generic secret reference", func(t *testing.T) {
		fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{Timeout: intPtr(5)})
		fm.ctx = ctx
		fm.requestTopic = "test/request"
		fm.responseTopic = "test/response"
		fm.updatedTopic = "test/updated"

		mockPub := &asyncMockPublisher{fm: fm}
		fm.publisher = mockPub
		fm.subscriber = &mockSubscriber{}

		result, err := fm.processString("${secret://orb/agents/database/password}", "policy1")
		assert.NoError(t, err)
		assert.Equal(t, "secretvalue", result)
	})

	t.Run("empty body rejected", func(t *testing.T) {
		// An empty body must produce a clear error rather than leaking the
		// literal placeholder to the backend, for both reference forms.
		fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{Timeout: intPtr(1)})
		fm.ctx = ctx

		_, err := fm.processString("${fleet://}", "policy1")
		assert.ErrorContains(t, err, "empty body")

		_, err = fm.processString("${secret://}", "policy1")
		assert.ErrorContains(t, err, "empty body")
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
	for path, cached := range fm.usedVars {
		assert.Empty(t, cached.Value, "failed batch must not cache %s's value", path)
		assert.True(t, cached.stale, "%s is kept stale, to be requested again", path)
	}
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

// scriptedPublisher answers each request with what answer returns for its
// sequence number; a nil answer leaves the request unanswered, as a lost QoS 0
// publish. published is closed when the first request is published.
type scriptedPublisher struct {
	fm        *FleetSecretsManager
	mu        sync.Mutex
	n         int
	published chan struct{}
	answer    func(n int, req messages.SecretRequestMsg) (resp *messages.SecretResponseMsg, after <-chan struct{})
}

func (p *scriptedPublisher) Publish(_ context.Context, _ string, payload []byte) error {
	var req messages.SecretRequestMsg
	if err := json.Unmarshal(payload, &req); err != nil {
		return err
	}
	p.mu.Lock()
	p.n++
	n := p.n
	p.mu.Unlock()
	if n == 1 {
		close(p.published)
	}
	resp, after := p.answer(n, req)
	if resp == nil {
		return nil
	}
	go func() {
		if after != nil {
			<-after
		}
		b, _ := json.Marshal(resp)
		_ = p.fm.handleResponse(b)
	}()
	return nil
}

func fleetAnswer(req messages.SecretRequestMsg, value string, version int) *messages.SecretResponseMsg {
	return &messages.SecretResponseMsg{
		SchemaVersion: messages.CurrentSecretsSchemaVersion, RequestID: req.RequestID, Timestamp: time.Now(), Status: "success",
		Secrets: []messages.SecretValue{{Path: req.Secrets[0].Path, Value: value, Version: version}},
	}
}

func newScriptedFleetManager(t *testing.T, timeout int, answer func(int, messages.SecretRequestMsg) (*messages.SecretResponseMsg, <-chan struct{})) (*FleetSecretsManager, *scriptedPublisher) {
	t.Helper()
	fm := NewFleetSecretsManager(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})), config.FleetSecretsManager{Timeout: intPtr(timeout)})
	fm.ctx = context.Background()
	fm.requestTopic, fm.responseTopic, fm.updatedTopic = "test/request", "test/response", "test/updated"
	pub := &scriptedPublisher{fm: fm, published: make(chan struct{}), answer: answer}
	fm.publisher = pub
	fm.subscriber = &mockSubscriber{}
	return fm, pub
}

// Notifications are handled on goroutines of their own. A request for an
// older version that fails after a newer notification already refreshed the
// path neither marks the path stale nor reports its policies failed.
func TestFleetSecretsManager_aLateFailureLeavesANewerRefreshAlone(t *testing.T) {
	fm, pub := newScriptedFleetManager(t, 1, func(n int, req messages.SecretRequestMsg) (*messages.SecretResponseMsg, <-chan struct{}) {
		if n == 1 {
			return nil, nil // lost: it times out
		}
		return fleetAnswer(req, "v3", 3), nil
	})
	fm.usedVars = map[string]fleetCachedSecret{
		"snmp/community": {Value: "v1", Version: 1, policyIDs: map[string]bool{"policy1": true}},
	}
	var mu sync.Mutex
	var reports []map[string]error
	fm.callback = func(m map[string]error) {
		mu.Lock()
		defer mu.Unlock()
		reports = append(reports, m)
	}

	done := make(chan struct{})
	go func() { notify(t, fm, messages.SecretUpdate{Path: "snmp/community", Version: 2}); close(done) }()
	<-pub.published
	notify(t, fm, messages.SecretUpdate{Path: "snmp/community", Version: 3})
	<-done

	fm.mu.Lock()
	entry := fm.usedVars["snmp/community"]
	fm.mu.Unlock()
	assert.False(t, entry.stale)
	assert.Equal(t, 3, entry.Version)
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []map[string]error{{"policy1": nil}}, reports)
	assert.NoError(t, fm.Unresolved("policy1"))
}

// A stale path is requested again while it is cached. An answer handled late
// never replaces a newer version a notification stored meanwhile.
func TestFleetSecretsManager_aLateAnswerNeverReplacesANewerVersion(t *testing.T) {
	release := make(chan struct{})
	fm, pub := newScriptedFleetManager(t, 5, func(n int, req messages.SecretRequestMsg) (*messages.SecretResponseMsg, <-chan struct{}) {
		if n == 1 {
			return fleetAnswer(req, "v2", 2), release // the re-delivery's request, answered late
		}
		return fleetAnswer(req, "v3", 3), nil
	})
	fm.usedVars = map[string]fleetCachedSecret{
		"snmp/community": {Value: "v1", Version: 1, policyIDs: map[string]bool{"policy1": true}, stale: true},
	}
	fm.callback = func(map[string]error) {}

	done := make(chan error, 1)
	go func() {
		_, err := fm.SolvePolicySecrets(config.PolicyPayload{ID: "policy1", Data: map[string]any{"c": "${fleet://snmp/community}"}})
		done <- err
	}()
	<-pub.published
	notify(t, fm, messages.SecretUpdate{Path: "snmp/community", Version: 3})
	close(release)
	require.NoError(t, <-done)

	fm.mu.Lock()
	entry := fm.usedVars["snmp/community"]
	fm.mu.Unlock()
	assert.Equal(t, 3, entry.Version)
	assert.Equal(t, "v3", entry.Value)
	assert.False(t, entry.stale)
}

// Unresolved answers the failed refresh of a stale path the policy uses, and
// nil once the path is refreshed; a policy edited off a path or forgotten no
// longer counts among its users.
func TestFleetSecretsManager_unresolvedAndTheUsersOfAPath(t *testing.T) {
	fm, _ := newScriptedFleetManager(t, 5, func(_ int, req messages.SecretRequestMsg) (*messages.SecretResponseMsg, <-chan struct{}) {
		return fleetAnswer(req, "fresh", 9), nil
	})
	refreshErr := fmt.Errorf("secret request failed for path a: unavailable")
	fm.usedVars = map[string]fleetCachedSecret{
		"a": {Value: "v1", Version: 1, policyIDs: map[string]bool{"policy1": true, "policy2": true}, stale: true, err: refreshErr},
		"b": {Value: "v1", Version: 1, policyIDs: map[string]bool{"policy2": true}},
	}
	assert.ErrorIs(t, fm.Unresolved("policy1"), refreshErr)

	// policy2's edit off "a" is applied; policy1 is removed.
	v2 := map[string]any{"c": "${fleet://b}"}
	_, err := fm.SolvePolicySecrets(config.PolicyPayload{ID: "policy2", Data: v2})
	require.NoError(t, err)
	fm.PolicyApplied("policy2", v2)
	assert.NoError(t, fm.Unresolved("policy2"))
	fm.ForgetPolicy("policy1")

	fm.mu.Lock()
	defer fm.mu.Unlock()
	assert.NotContains(t, fm.usedVars, "a", "a path no policy uses is dropped")
	assert.Equal(t, map[string]bool{"policy2": true}, fm.usedVars["b"].policyIDs)
}

// Fleet answering, for a path whose refresh failed, the version the agent
// already holds means that value is current: a notification and a delivery
// alike clear the stale mark, and the notification re-applies the policies.
func TestFleetSecretsManager_anAnswerAtTheHeldVersionClearsAStalePath(t *testing.T) {
	for _, via := range []string{"notification", "delivery"} {
		t.Run(via, func(t *testing.T) {
			fm, _ := newScriptedFleetManager(t, 5, func(_ int, req messages.SecretRequestMsg) (*messages.SecretResponseMsg, <-chan struct{}) {
				return fleetAnswer(req, "v1", 1), nil
			})
			fm.usedVars = map[string]fleetCachedSecret{
				"snmp/community": {Value: "v1", Version: 1, policyIDs: map[string]bool{"policy1": true}, stale: true, err: fmt.Errorf("refresh failed")},
			}
			var reported map[string]error
			fm.callback = func(m map[string]error) { reported = m }

			if via == "notification" {
				notify(t, fm, messages.SecretUpdate{Path: "snmp/community", Version: 2})
				assert.Equal(t, map[string]error{"policy1": nil}, reported)
			} else {
				_, err := fm.SolvePolicySecrets(config.PolicyPayload{ID: "policy1", Data: map[string]any{"c": "${fleet://snmp/community}"}})
				require.NoError(t, err)
			}
			assert.NoError(t, fm.Unresolved("policy1"))
			fm.mu.Lock()
			defer fm.mu.Unlock()
			assert.False(t, fm.usedVars["snmp/community"].stale)
		})
	}
}

// A refresh that fails reports every policy using the path when it fails,
// including one that resolved the path while the request was in flight, and
// so runs with the value the failed refresh was to replace.
func TestFleetSecretsManager_aFailedRefreshReportsThePoliciesThatResolvedThePathMeanwhile(t *testing.T) {
	fm, pub := newScriptedFleetManager(t, 1, func(int, messages.SecretRequestMsg) (*messages.SecretResponseMsg, <-chan struct{}) {
		return nil, nil // lost: it times out
	})
	fm.usedVars = map[string]fleetCachedSecret{
		"snmp/community": {Value: "v1", Version: 1, policyIDs: map[string]bool{"policy1": true}},
	}
	var mu sync.Mutex
	var reported map[string]error
	fm.callback = func(m map[string]error) {
		mu.Lock()
		defer mu.Unlock()
		reported = m
	}

	done := make(chan struct{})
	go func() { notify(t, fm, messages.SecretUpdate{Path: "snmp/community", Version: 2}); close(done) }()
	<-pub.published
	_, err := fm.SolvePolicySecrets(config.PolicyPayload{ID: "policy2", Data: map[string]any{"c": "${fleet://snmp/community}"}})
	require.NoError(t, err)
	<-done

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, reported, 2)
	assert.Error(t, reported["policy1"])
	assert.Error(t, reported["policy2"])
}

// An answer to a request that started before a later refresh of the path
// failed is out of date: it does not clear the stale mark that failure set,
// through a notification or a delivery, and reports no policy to re-apply.
func TestFleetSecretsManager_anAnswerFromBeforeAFailedRefreshLeavesThePathStale(t *testing.T) {
	refused := func(req messages.SecretRequestMsg) *messages.SecretResponseMsg {
		return &messages.SecretResponseMsg{
			SchemaVersion: messages.CurrentSecretsSchemaVersion, RequestID: req.RequestID, Timestamp: time.Now(), Status: "error",
			Errors: []messages.SecretError{{Path: req.Secrets[0].Path, Error: "unavailable", Code: messages.ErrorCodeInternalError}},
		}
	}
	for _, via := range []string{"notification", "delivery"} {
		t.Run(via, func(t *testing.T) {
			release := make(chan struct{})
			fm, pub := newScriptedFleetManager(t, 5, func(n int, req messages.SecretRequestMsg) (*messages.SecretResponseMsg, <-chan struct{}) {
				if n == 1 {
					return fleetAnswer(req, "v2", 2), release // answered once the later refresh failed
				}
				return refused(req), nil
			})
			entry := fleetCachedSecret{Value: "v1", Version: 1, policyIDs: map[string]bool{"policy1": true}}
			if via == "delivery" {
				// A path whose refresh failed earlier: a delivery requests it.
				entry.stale, entry.err = true, fmt.Errorf("refresh of v2 failed")
			}
			fm.usedVars = map[string]fleetCachedSecret{"snmp/community": entry}
			var mu sync.Mutex
			var reports []map[string]error
			fm.callback = func(m map[string]error) {
				mu.Lock()
				defer mu.Unlock()
				reports = append(reports, m)
			}

			done := make(chan error, 1)
			go func() {
				if via == "notification" {
					notify(t, fm, messages.SecretUpdate{Path: "snmp/community", Version: 2})
					done <- nil
					return
				}
				_, err := fm.SolvePolicySecrets(config.PolicyPayload{ID: "policy1", Data: map[string]any{"c": "${fleet://snmp/community}"}})
				done <- err
			}()
			<-pub.published
			notify(t, fm, messages.SecretUpdate{Path: "snmp/community", Version: 3})
			close(release)
			if err := <-done; via == "delivery" {
				assert.Error(t, err, "the delivery is not served the stale value")
			}

			fm.mu.Lock()
			stale := fm.usedVars["snmp/community"].stale
			fm.mu.Unlock()
			assert.True(t, stale, "the refresh of v3 failed after the request answered with v2 started")
			assert.Error(t, fm.Unresolved("policy1"))
			mu.Lock()
			defer mu.Unlock()
			for _, r := range reports {
				assert.Error(t, r["policy1"], "no report re-applies the policy: %v", reports)
			}
		})
	}
}

// A path marked stale after ensureSecrets checked it, by a refresh that failed
// in between, is not served when the policy's data is substituted: the
// resolve fails with the refresh's error, and the policy counts among the
// path's users so its next report reaches it.
func TestFleetSecretsManager_aStalePathIsNotSubstituted(t *testing.T) {
	fm := NewFleetSecretsManager(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})), config.FleetSecretsManager{})
	refreshErr := fmt.Errorf("secret request failed for path snmp/community: unavailable")
	fm.usedVars = map[string]fleetCachedSecret{
		"snmp/community": {Value: "outdated", Version: 1, policyIDs: map[string]bool{"policy1": true}, stale: true, err: refreshErr},
	}

	v, err := fm.processString("${fleet://snmp/community}", "policy2")
	require.ErrorIs(t, err, refreshErr)
	assert.Empty(t, v)
	assert.True(t, fm.usedVars["snmp/community"].policyIDs["policy2"])
}

// A path that fails the first time a policy resolves it is kept, stale and
// with no value, as the poller keeps a failed reference: Unresolved answers
// its failure, so a new policy's manage does not take it for one that
// resolved meanwhile, and the next resolve requests it again.
func TestFleetSecretsManager_aPathThatFailsItsFirstResolveIsKeptStale(t *testing.T) {
	fm, pub := newScriptedFleetManager(t, 5, func(_ int, req messages.SecretRequestMsg) (*messages.SecretResponseMsg, <-chan struct{}) {
		return &messages.SecretResponseMsg{
			SchemaVersion: messages.CurrentSecretsSchemaVersion, RequestID: req.RequestID, Timestamp: time.Now(), Status: "error",
			Errors: []messages.SecretError{{Path: req.Secrets[0].Path, Error: "not found", Code: messages.ErrorCodeNotFound}},
		}, nil
	})
	payload := config.PolicyPayload{ID: "policy1", Data: map[string]any{"c": "${fleet://snmp/community}"}}

	_, err := fm.SolvePolicySecrets(payload)
	require.Error(t, err)
	assert.Error(t, fm.Unresolved("policy1"))
	fm.mu.Lock()
	entry := fm.usedVars["snmp/community"]
	fm.mu.Unlock()
	assert.True(t, entry.stale)
	assert.Empty(t, entry.Value)
	assert.True(t, entry.policyIDs["policy1"])

	_, err = fm.SolvePolicySecrets(payload)
	require.Error(t, err)
	pub.mu.Lock()
	defer pub.mu.Unlock()
	assert.Equal(t, 2, pub.n, "a stale path is requested again")
}

// A first resolve whose request fails after another policy's request for the
// same path succeeded leaves the path as that one stored it: the failure is
// older than the value.
func TestFleetSecretsManager_aFailedFirstResolveLeavesAPathRefreshedMeanwhile(t *testing.T) {
	release := make(chan struct{})
	fm, pub := newScriptedFleetManager(t, 5, func(n int, req messages.SecretRequestMsg) (*messages.SecretResponseMsg, <-chan struct{}) {
		if n == 1 {
			return &messages.SecretResponseMsg{
				SchemaVersion: messages.CurrentSecretsSchemaVersion, RequestID: req.RequestID, Timestamp: time.Now(), Status: "error",
				Errors: []messages.SecretError{{Path: req.Secrets[0].Path, Error: "timeout", Code: messages.ErrorCodeTimeout}},
			}, release
		}
		return fleetAnswer(req, "v1", 1), nil
	})
	done := make(chan error, 1)
	go func() {
		_, err := fm.SolvePolicySecrets(config.PolicyPayload{ID: "policy1", Data: map[string]any{"c": "${fleet://snmp/community}"}})
		done <- err
	}()
	<-pub.published
	_, err := fm.SolvePolicySecrets(config.PolicyPayload{ID: "policy2", Data: map[string]any{"c": "${fleet://snmp/community}"}})
	require.NoError(t, err)
	close(release)
	require.Error(t, <-done)

	fm.mu.Lock()
	entry := fm.usedVars["snmp/community"]
	fm.mu.Unlock()
	assert.False(t, entry.stale)
	assert.Equal(t, "v1", entry.Value)
	assert.True(t, entry.policyIDs["policy1"])
	assert.NoError(t, fm.Unresolved("policy1"))
}
