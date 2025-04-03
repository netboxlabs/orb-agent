package secretsmgr

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
	vaulthttp "github.com/hashicorp/vault/http"
	vaultsrv "github.com/hashicorp/vault/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

func TestVaultManager_getSecret(t *testing.T) {
	// Create test vault server
	ln, client := createTestVault(t)
	defer func() {
		if err := ln.Close(); err != nil {
			assert.NoError(t, err, "Failed to close test vault listener")
		}
	}()

	// Create the vault manager with the test client
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vm := &vaultManager{
		logger: logger,
		config: config.VaultManager{},
		ctx:    ctx,
		client: client,
	}

	tests := []struct {
		name          string
		path          string
		expectedValue string
		expectedError string
	}{
		{
			name:          "valid path and secret",
			path:          "testsecret/app/credentials/password",
			expectedValue: "secretvalue",
			expectedError: "",
		},
		{
			name:          "invalid path format",
			path:          "testsecret/password",
			expectedValue: "",
			expectedError: "invalid vault path format: testsecret/password",
		},
		{
			name:          "secret not found",
			path:          "testsecret/nonexistent/path/key",
			expectedValue: "",
			expectedError: "failed to get secret path testsecret/nonexistent/path/key:",
		},
		{
			name:          "key not found in data",
			path:          "testsecret/app/credentials/nonexistentkey",
			expectedValue: "",
			expectedError: "secret not found: testsecret/app/credentials/nonexistentkey",
		},
		{
			name:          "non-string value",
			path:          "testsecret/app/credentials/numeric",
			expectedValue: "",
			expectedError: "secret is not a string: testsecret/app/credentials/numeric",
		},
		{
			name:          "empty string value",
			path:          "testsecret/app/credentials/empty",
			expectedValue: "",
			expectedError: "secret is empty: testsecret/app/credentials/empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call the method under test
			value, err := vm.getSecret(tt.path)

			// Assertions
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedValue, value)
			}
		})
	}
}

func createTestVault(t *testing.T) (net.Listener, *vault.Client) {
	t.Helper()

	// Create an in-memory, unsealed core
	core, keyShares, rootToken := vaultsrv.TestCoreUnsealed(t)
	_ = keyShares

	// Start an HTTP server for the core
	ln, addr := vaulthttp.TestServer(t, core)

	// Create a client that talks to the server
	conf := vault.DefaultConfig()
	conf.Address = addr

	client, err := vault.NewClient(conf)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken(rootToken)

	// Enable KV v2 secret engine
	mountInput := &vault.MountInput{
		Type:    "kv",
		Options: map[string]string{"version": "2"},
	}
	err = client.Sys().Mount("testsecret", mountInput)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for KV v2 to become available
	time.Sleep(100 * time.Millisecond)

	// Setup various test secrets
	secrets := map[string]map[string]interface{}{
		"app/credentials": {
			"password": "secretvalue",
			"numeric":  12345,
			"empty":    "",
		},
	}

	for path, data := range secrets {
		_, err = client.KVv2("testsecret").Put(context.Background(), path, data)
		require.NoError(t, err, "Failed to set up secret at %s", path)
	}

	return ln, client
}

func TestVaultManager_processString(t *testing.T) {
	// Create test vault server
	ln, client := createTestVault(t)
	defer func() {
		if err := ln.Close(); err != nil {
			assert.NoError(t, err, "Failed to close test vault listener")
		}
	}()
	// Create the vault manager with the test client
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vm := &vaultManager{
		logger:   logger,
		config:   config.VaultManager{},
		ctx:      ctx,
		client:   client,
		usedVars: make(map[string]cachedSecret),
	}

	tests := []struct {
		name          string
		input         string
		policyID      string
		expectedValue string
		expectError   bool
	}{
		{
			name:          "no vault reference",
			input:         "plain text",
			policyID:      "policy1",
			expectedValue: "plain text",
			expectError:   false,
		},
		{
			name:          "valid vault reference",
			input:         "${vault://testsecret/app/credentials/password}",
			policyID:      "policy1",
			expectedValue: "secretvalue",
			expectError:   false,
		},
		{
			name:          "invalid vault path",
			input:         "${vault://testsecret/nonexistent/key}",
			policyID:      "policy1",
			expectedValue: "",
			expectError:   true,
		},
		{
			name:          "malformed reference",
			input:         "${vault:/malformed}",
			policyID:      "policy1",
			expectedValue: "${vault:/malformed}",
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := vm.processString(tt.input, tt.policyID)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedValue, result)

				// For valid vault references, verify they're cached properly
				if strings.Contains(tt.input, "${vault://") && !tt.expectError {
					path := strings.TrimPrefix(strings.TrimSuffix(tt.input, "}"), "${vault://")
					cached, exists := vm.usedVars[path]
					assert.True(t, exists, "Secret should be cached")
					assert.Equal(t, tt.expectedValue, cached.Value)
					assert.True(t, cached.policyIDs[tt.policyID])
				}
			}
		})
	}
}

func TestVaultManager_processMap(t *testing.T) {
	// Create test vault server
	ln, client := createTestVault(t)
	defer func() {
		if err := ln.Close(); err != nil {
			assert.NoError(t, err, "Failed to close test vault listener")
		}
	}()

	// Create the vault manager with the test client
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vm := &vaultManager{
		logger:   logger,
		config:   config.VaultManager{},
		ctx:      ctx,
		client:   client,
		usedVars: make(map[string]cachedSecret),
	}

	tests := []struct {
		name        string
		input       map[string]any
		policyID    string
		expected    map[string]any
		expectError bool
	}{
		{
			name: "map with no vault references",
			input: map[string]any{
				"key1": "value1",
				"key2": "value2",
			},
			policyID: "policy1",
			expected: map[string]any{
				"key1": "value1",
				"key2": "value2",
			},
			expectError: false,
		},
		{
			name: "map with vault references",
			input: map[string]any{
				"key1": "value1",
				"key2": "${vault://testsecret/app/credentials/password}",
			},
			policyID: "policy1",
			expected: map[string]any{
				"key1": "value1",
				"key2": "secretvalue",
			},
			expectError: false,
		},
		{
			name: "map with invalid vault reference",
			input: map[string]any{
				"key1": "value1",
				"key2": "${vault://testsecret/nonexistent/key}",
			},
			policyID:    "policy1",
			expected:    nil,
			expectError: true,
		},
		{
			name: "nested map",
			input: map[string]any{
				"key1": "value1",
				"nested": map[string]any{
					"subkey": "${vault://testsecret/app/credentials/password}",
				},
			},
			policyID: "policy1",
			expected: map[string]any{
				"key1": "value1",
				"nested": map[string]any{
					"subkey": "secretvalue",
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := vm.processMap(tt.input, tt.policyID)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestVaultManager_processSlice(t *testing.T) {
	// Create test vault server
	ln, client := createTestVault(t)
	defer func() {
		if err := ln.Close(); err != nil {
			assert.NoError(t, err, "Failed to close test vault listener")
		}
	}()

	// Create the vault manager with the test client
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vm := &vaultManager{
		logger:   logger,
		config:   config.VaultManager{},
		ctx:      ctx,
		client:   client,
		usedVars: make(map[string]cachedSecret),
	}

	tests := []struct {
		name        string
		input       []any
		policyID    string
		expected    []any
		expectError bool
	}{
		{
			name:     "slice with no vault references",
			input:    []any{"value1", "value2", 123},
			policyID: "policy1",
			expected: []any{"value1", "value2", 123},
		},
		{
			name:     "slice with vault references",
			input:    []any{"value1", "${vault://testsecret/app/credentials/password}", 123},
			policyID: "policy1",
			expected: []any{"value1", "secretvalue", 123},
		},
		{
			name:        "slice with invalid vault reference",
			input:       []any{"value1", "${vault://testsecret/nonexistent/key}"},
			policyID:    "policy1",
			expectError: true,
		},
		{
			name: "slice with nested map",
			input: []any{
				"value1",
				map[string]any{
					"subkey": "${vault://testsecret/app/credentials/password}",
				},
			},
			policyID: "policy1",
			expected: []any{
				"value1",
				map[string]any{
					"subkey": "secretvalue",
				},
			},
		},
		{
			name: "slice with nested slice",
			input: []any{
				"value1",
				[]any{"nested1", "${vault://testsecret/app/credentials/password}"},
			},
			policyID: "policy1",
			expected: []any{
				"value1",
				[]any{"nested1", "secretvalue"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := vm.processSlice(tt.input, tt.policyID)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestVaultManager_SolveSecrets(t *testing.T) {
	// Create test vault server
	ln, client := createTestVault(t)
	defer func() {
		if err := ln.Close(); err != nil {
			assert.NoError(t, err, "Failed to close test vault listener")
		}
	}()

	// Create the vault manager with the test client
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vm := &vaultManager{
		logger:   logger,
		config:   config.VaultManager{},
		ctx:      ctx,
		client:   client,
		usedVars: make(map[string]cachedSecret),
	}

	tests := []struct {
		name        string
		payload     config.PolicyPayload
		expected    config.PolicyPayload
		expectError bool
	}{
		{
			name: "payload with no secrets",
			payload: config.PolicyPayload{
				ID:   "policy1",
				Name: "test-policy",
				Data: map[string]any{
					"key1": "value1",
					"key2": "value2",
				},
			},
			expected: config.PolicyPayload{
				ID:   "policy1",
				Name: "test-policy",
				Data: map[string]any{
					"key1": "value1",
					"key2": "value2",
				},
			},
			expectError: false,
		},
		{
			name: "payload with vault references",
			payload: config.PolicyPayload{
				ID:   "policy2",
				Name: "test-policy-secrets",
				Data: map[string]any{
					"key1": "value1",
					"key2": "${vault://testsecret/app/credentials/password}",
					"nested": map[string]any{
						"subkey": "${vault://testsecret/app/credentials/password}",
					},
				},
			},
			expected: config.PolicyPayload{
				ID:   "policy2",
				Name: "test-policy-secrets",
				Data: map[string]any{
					"key1": "value1",
					"key2": "secretvalue",
					"nested": map[string]any{
						"subkey": "secretvalue",
					},
				},
			},
			expectError: false,
		},
		{
			name: "payload with invalid vault reference",
			payload: config.PolicyPayload{
				ID:   "policy3",
				Name: "test-policy-invalid",
				Data: map[string]any{
					"key1": "value1",
					"key2": "${vault://testsecret/nonexistent/key}",
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := vm.SolveSecrets(tt.payload)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestVaultManager_RegisterUpdateCallback(t *testing.T) {
	// Create the vault manager
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	vm := &vaultManager{
		logger: logger,
		config: config.VaultManager{},
	}

	// Test registering a callback
	called := false
	callback := func(_ map[string]bool) {
		called = true
	}

	vm.RegisterUpdateCallback(callback)
	assert.NotNil(t, vm.callback)

	// Manually call the callback to verify it works
	vm.callback(map[string]bool{"policy1": true})
	assert.True(t, called)
}

func TestVaultManager_pollSecrets(t *testing.T) {
	// Create test vault server
	ln, client := createTestVault(t)
	defer func() {
		if err := ln.Close(); err != nil {
			assert.NoError(t, err, "Failed to close test vault listener")
		}
	}()

	// Create the vault manager with the test client
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var callbackCalled bool
	var callbackPolicyIDs map[string]bool

	callback := func(policyIDs map[string]bool) {
		callbackCalled = true
		callbackPolicyIDs = policyIDs
	}

	vm := &vaultManager{
		logger:   logger,
		config:   config.VaultManager{},
		ctx:      ctx,
		client:   client,
		usedVars: make(map[string]cachedSecret),
		callback: callback,
	}

	// Setup initial secret state
	vm.usedVars["testsecret/app/credentials/password"] = cachedSecret{
		Value:     "secretvalue",
		policyIDs: map[string]bool{"policy1": true, "policy2": true},
	}

	// First poll with no changes
	callbackCalled = false
	callbackPolicyIDs = nil
	vm.pollSecrets()
	assert.False(t, callbackCalled)

	// Update the secret in vault
	_, err := client.KVv2("testsecret").Put(ctx, "app/credentials", map[string]interface{}{
		"password": "newsecretvalue",
		"numeric":  12345,
		"empty":    "",
	})
	require.NoError(t, err)

	// Poll again - should detect the change
	callbackCalled = false
	callbackPolicyIDs = nil
	vm.pollSecrets()

	assert.True(t, callbackCalled)
	assert.NotNil(t, callbackPolicyIDs)
	assert.Contains(t, callbackPolicyIDs, "policy1")
	assert.Contains(t, callbackPolicyIDs, "policy2")
	assert.True(t, callbackPolicyIDs["policy1"])
	assert.True(t, callbackPolicyIDs["policy2"])

	// Verify the cached value was updated
	assert.Equal(t, "newsecretvalue", vm.usedVars["testsecret/app/credentials/password"].Value)
}

func TestVaultManager_Start(t *testing.T) {
	// Create test vault server
	ln, client := createTestVault(t)
	defer func() {
		if err := ln.Close(); err != nil {
			assert.NoError(t, err, "Failed to close test vault listener")
		}
	}()

	addr := ln.Addr().String()
	token := client.Token()

	tests := []struct {
		name        string
		config      config.VaultManager
		expectError bool
	}{
		{
			name: "valid config with token auth",
			config: config.VaultManager{
				Address: "http://" + addr,
				Auth:    "token",
				AuthArgs: map[string]any{
					"token": token,
				},
			},
			expectError: false,
		},
		{
			name: "missing auth method",
			config: config.VaultManager{
				Address: "http://" + addr,
			},
			expectError: true,
		},
		{
			name: "invalid auth method",
			config: config.VaultManager{
				Address: "http://" + addr,
				Auth:    "invalid-method",
				AuthArgs: map[string]any{
					"token": token,
				},
			},
			expectError: true,
		},
		{
			name: "with timeout",
			config: config.VaultManager{
				Address: "http://" + addr,
				Auth:    "token",
				AuthArgs: map[string]any{
					"token": token,
				},
				Timeout: func() *int { i := 10; return &i }(),
			},
			expectError: false,
		},
		{
			name: "with namespace",
			config: config.VaultManager{
				Address:   "http://" + addr,
				Auth:      "token",
				Namespace: "test-namespace",
				AuthArgs: map[string]any{
					"token": token,
				},
			},
			expectError: false,
		},
		{
			name: "with schedule",
			config: config.VaultManager{
				Address: "http://" + addr,
				Auth:    "token",
				AuthArgs: map[string]any{
					"token": token,
				},
				Schedule: func() *string { s := "*/5 * * * *"; return &s }(),
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
			vm := &vaultManager{
				logger: logger,
				config: tt.config,
			}

			ctx, cancel := context.WithCancel(context.Background())
			err := vm.Start(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, vm.client)
				assert.NotNil(t, vm.token)
				assert.NotNil(t, vm.usedVars)

				if tt.config.Schedule != nil {
					assert.NotNil(t, vm.scheduler)
					err = vm.scheduler.Shutdown()
					assert.NoError(t, err)
				}
			}

			cancel()
		})
	}
}

func TestNew(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	tests := []struct {
		name         string
		config       config.ManagerSecrets
		expectedType string
	}{
		{
			name: "vault manager",
			config: config.ManagerSecrets{
				Active: "vault",
				Sources: config.SecretsSources{
					Vault: config.VaultManager{
						Address: "http://localhost:8200",
					},
				},
			},
			expectedType: "*secretsmgr.vaultManager",
		},
		{
			name: "dummy manager when active is empty",
			config: config.ManagerSecrets{
				Active: "",
			},
			expectedType: "*secretsmgr.dummyManager",
		},
		{
			name: "dummy manager when active is invalid",
			config: config.ManagerSecrets{
				Active: "invalid",
			},
			expectedType: "*secretsmgr.dummyManager",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := New(logger, tt.config)
			assert.NotNil(t, manager)
			assert.Equal(t, tt.expectedType, fmt.Sprintf("%T", manager))
		})
	}
}
