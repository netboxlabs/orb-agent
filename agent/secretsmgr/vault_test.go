package secretsmgr

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/testcluster"
	"github.com/hashicorp/vault/sdk/helper/testcluster/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

var (
	sharedVaultCluster *docker.DockerCluster
	sharedVaultClient  *vault.Client
	sharedVaultSetup   sync.Once
	sharedVaultCleanup sync.Once
)

func TestMain(m *testing.M) {
	// Run tests
	code := m.Run()

	// Cleanup: Clean up shared cluster once after all tests
	sharedVaultCleanup.Do(func() {
		if sharedVaultCluster != nil {
			sharedVaultCluster.Cleanup()
		}
	})

	os.Exit(code)
}

// setupSharedVault creates a shared Vault cluster once for all tests
func setupSharedVault(t *testing.T) {
	t.Helper()
	sharedVaultSetup.Do(func() {
		opts := &docker.DockerClusterOptions{
			ImageRepo:    "hashicorp/vault",
			ImageTag:     "1.19",
			DisableMlock: true,
			DisableTLS:   true,
			ClusterOptions: testcluster.ClusterOptions{
				NumCores: 1,
				VaultNodeConfig: &testcluster.VaultNodeConfig{
					LogLevel: "INFO",
					StorageOptions: map[string]string{
						"performance_multiplier": "1",
					},
				},
			},
		}

		// Create cluster (this is the slow part - only done once)
		sharedVaultCluster = docker.NewTestDockerCluster(t, opts)
		sharedVaultClient = sharedVaultCluster.Nodes()[0].APIClient()

		// Wait for Vault to be ready
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		for {
			_, err := sharedVaultClient.Logical().Read("sys/storage/raft/configuration")
			if err == nil {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatalf("Vault cluster failed to become ready: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
		}

		// Enable KV v2 secret engine
		mountInput := &vault.MountInput{
			Type:    "kv",
			Options: map[string]string{"version": "2"},
		}
		err := sharedVaultClient.Sys().Mount("testsecret", mountInput)
		if err != nil {
			// Mount might already exist, check if it's already mounted
			mounts, err2 := sharedVaultClient.Sys().ListMounts()
			if err2 != nil || mounts["testsecret/"] == nil {
				t.Fatalf("Failed to mount KV v2: %v", err)
			}
		}

		// Wait briefly for mount to be ready (reduced from 100ms to 10ms)
		time.Sleep(10 * time.Millisecond)

		// Setup initial test secrets
		secrets := map[string]map[string]any{
			"app/credentials": {
				"password": "secretvalue",
				"numeric":  12345,
				"empty":    "",
			},
		}

		for path, data := range secrets {
			_, err := sharedVaultClient.KVv2("testsecret").Put(context.Background(), path, data)
			if err != nil {
				t.Fatalf("Failed to set up secret at %s: %v", path, err)
			}
		}
	})
}

// getTestVaultClient returns a cloned Vault client for tests to avoid state interference
func getTestVaultClient(t *testing.T) *vault.Client {
	t.Helper()
	setupSharedVault(t)
	if sharedVaultClient == nil {
		t.Fatal("shared Vault client not initialized")
	}
	// Clone the client to avoid state interference between tests
	config := vault.DefaultConfig()
	config.Address = sharedVaultClient.Address()
	client, err := vault.NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client clone: %v", err)
	}
	// Copy the token from the shared client
	client.SetToken(sharedVaultClient.Token())
	// Copy namespace if set
	if ns := sharedVaultClient.Namespace(); ns != "" {
		client.SetNamespace(ns)
	}
	return client
}

// getTestVaultCluster returns the shared Vault cluster for tests that need cluster info
func getTestVaultCluster(t *testing.T) *docker.DockerCluster {
	t.Helper()
	setupSharedVault(t)
	if sharedVaultCluster == nil {
		t.Fatal("shared Vault cluster not initialized")
	}
	return sharedVaultCluster
}

// createTestVault is kept for backward compatibility but now returns the shared cluster/client
// This allows tests to continue using the same pattern
func createTestVault(t *testing.T) (*docker.DockerCluster, *vault.Client) {
	t.Helper()
	return getTestVaultCluster(t), getTestVaultClient(t)
}

// newTestVaultManager builds a vaultManager wired into pollingBase for tests
// that bypass Start (which is the normal initializer for the base).
func newTestVaultManager(ctx context.Context, logger *slog.Logger, client *vault.Client, callback func(map[string]bool)) *vaultManager {
	vm := &vaultManager{
		pollingBase: pollingBase{
			logger:   logger,
			scheme:   "vault",
			ctx:      ctx,
			usedVars: make(map[string]cachedSecret),
			callback: callback,
		},
		preLogger: logger,
		config:    config.VaultManager{},
		client:    client,
	}
	vm.pollingBase.fetch = vm.fetch
	return vm
}

func TestVaultManager_fetch(t *testing.T) {
	// Use shared test vault server
	_, client := createTestVault(t)

	// Create the vault manager with the test client
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vm := &vaultManager{
		pollingBase: pollingBase{
			logger:   logger,
			scheme:   "vault",
			ctx:      ctx,
			usedVars: make(map[string]cachedSecret),
		},
		preLogger: logger,
		config:    config.VaultManager{},
		client:    client,
	}
	vm.pollingBase.fetch = vm.fetch

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
			expectedError: `invalid vault reference "testsecret/password"`,
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
			value, err := vm.fetch(tt.path)

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

func TestVaultManager_processString(t *testing.T) {
	// Use shared test vault server
	_, client := createTestVault(t)
	// Create the vault manager with the test client
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vm := newTestVaultManager(ctx, logger, client, nil)

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
			result, err := processString(tt.input, "vault", tt.policyID, vm.resolveBody)

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
	// Use shared test vault server
	_, client := createTestVault(t)

	// Create the vault manager with the test client
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vm := newTestVaultManager(ctx, logger, client, nil)

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
			result, err := processMap(tt.input, "vault", tt.policyID, vm.resolveBody)

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
	// Use shared test vault server
	_, client := createTestVault(t)

	// Create the vault manager with the test client
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vm := newTestVaultManager(ctx, logger, client, nil)

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
			result, err := processSlice(tt.input, "vault", tt.policyID, vm.resolveBody)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestVaultManager_SolvePolicySecrets(t *testing.T) {
	// Use shared test vault server
	_, client := createTestVault(t)

	// Create the vault manager with the test client
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vm := newTestVaultManager(ctx, logger, client, nil)

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
			result, err := vm.SolvePolicySecrets(tt.payload)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestVaultManager_RegisterUpdatePoliciesCallback(t *testing.T) {
	// Create the vault manager
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	vm := &vaultManager{
		pollingBase: pollingBase{logger: logger, scheme: "vault"},
		preLogger:   logger,
		config:      config.VaultManager{},
	}

	// Test registering a callback
	called := false
	callback := func(_ map[string]bool) {
		called = true
	}

	vm.RegisterUpdatePoliciesCallback(callback)
	assert.NotNil(t, vm.callback)

	// Manually call the callback to verify it works
	vm.callback(map[string]bool{"policy1": true})
	assert.True(t, called)
}

func TestVaultManager_pollSecrets(t *testing.T) {
	// Use shared test vault server
	_, client := createTestVault(t)

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

	vm := newTestVaultManager(ctx, logger, client, callback)

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
	_, err := client.KVv2("testsecret").Put(ctx, "app/credentials", map[string]any{
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

// TestVaultManager_PollSecretsFailureEvictsAndSignalsFalse exercises the
// behavior Vault inherited from pollingBase via the Phase 2 refactor: a
// failed fetch during polling now evicts the cached entry and signals the
// affected policies as failed. The test bypasses Start (no Docker) by
// constructing a vaultManager directly and overriding the wired fetch with
// a stub that returns an error for the cached path.
func TestVaultManager_PollSecretsFailureEvictsAndSignalsFalse(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	gotCalls := make(chan map[string]bool, 1)
	callback := func(m map[string]bool) { gotCalls <- m }

	const path = "testsecret/app/credentials/password"
	vm := &vaultManager{
		pollingBase: pollingBase{
			logger:   logger,
			scheme:   "vault",
			ctx:      ctx,
			usedVars: make(map[string]cachedSecret),
			callback: callback,
		},
		preLogger: logger,
		config:    config.VaultManager{},
	}
	// Pre-seed the cache as if the secret had been resolved earlier.
	vm.usedVars[path] = cachedSecret{
		Value:     "stale",
		policyIDs: map[string]bool{"policy-1": true, "policy-2": true},
	}
	// Override fetch with a stub that simulates a fatal Vault read failure.
	vm.pollingBase.fetch = func(string) (string, error) {
		return "", fmt.Errorf("vault simulated read failure")
	}

	vm.pollSecrets()

	select {
	case m := <-gotCalls:
		require.Equal(t, map[string]bool{"policy-1": false, "policy-2": false}, m)
	case <-time.After(time.Second):
		t.Fatal("expected failure callback was not invoked")
	}

	vm.mu.Lock()
	_, present := vm.usedVars[path]
	vm.mu.Unlock()
	require.False(t, present, "failed entry must be evicted from the cache")
}

func TestVaultManager_Start(t *testing.T) {
	// Use shared test vault server
	cluster, _ := createTestVault(t)

	tests := []struct {
		name        string
		config      func() config.VaultManager
		expectError bool
	}{
		{
			name: "valid config with token auth",
			config: func() config.VaultManager {
				client := getTestVaultClient(t)
				addr := cluster.ClusterNodes[0].HostPort
				return config.VaultManager{
					Address: "http://" + addr,
					Auth:    "token",
					AuthArgs: map[string]any{
						"token": client.Token(),
					},
				}
			},
			expectError: false,
		},
		{
			name: "missing auth method",
			config: func() config.VaultManager {
				addr := cluster.ClusterNodes[0].HostPort
				return config.VaultManager{
					Address: "http://" + addr,
				}
			},
			expectError: true,
		},
		{
			name: "invalid auth method",
			config: func() config.VaultManager {
				client := getTestVaultClient(t)
				addr := cluster.ClusterNodes[0].HostPort
				return config.VaultManager{
					Address: "http://" + addr,
					Auth:    "invalid-method",
					AuthArgs: map[string]any{
						"token": client.Token(),
					},
				}
			},
			expectError: true,
		},
		{
			name: "with timeout",
			config: func() config.VaultManager {
				client := getTestVaultClient(t)
				addr := cluster.ClusterNodes[0].HostPort
				timeout := 10
				return config.VaultManager{
					Address: "http://" + addr,
					Auth:    "token",
					AuthArgs: map[string]any{
						"token": client.Token(),
					},
					Timeout: &timeout,
				}
			},
			expectError: false,
		},
		{
			name: "with namespace",
			config: func() config.VaultManager {
				client := getTestVaultClient(t)
				addr := cluster.ClusterNodes[0].HostPort
				return config.VaultManager{
					Address:   "http://" + addr,
					Auth:      "token",
					Namespace: "test-namespace",
					AuthArgs: map[string]any{
						"token": client.Token(),
					},
				}
			},
			expectError: false,
		},
		{
			name: "with schedule",
			config: func() config.VaultManager {
				client := getTestVaultClient(t)
				addr := cluster.ClusterNodes[0].HostPort
				schedule := "*/5 * * * *"
				return config.VaultManager{
					Address: "http://" + addr,
					Auth:    "token",
					AuthArgs: map[string]any{
						"token": client.Token(),
					},
					Schedule: &schedule,
				}
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get fresh config for this test case
			testConfig := tt.config()

			logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
			vm := &vaultManager{
				preLogger: logger,
				config:    testConfig,
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := vm.Start(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, vm.client)
				// Note: vm.token might be nil if token auth doesn't return a secret (e.g., root token)
				// This is acceptable for some auth methods
				assert.NotNil(t, vm.usedVars)

				// Clean up scheduler if it was created
				if testConfig.Schedule != nil && vm.scheduler != nil {
					err = vm.scheduler.Shutdown()
					assert.NoError(t, err)
				}
			}
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
		{
			name: "delinea manager",
			config: config.ManagerSecrets{
				Active: "delinea",
				Sources: config.SecretsSources{
					Delinea: config.DelineaManager{
						ServerURL: "https://example.com",
						Username:  "svc_orb",
						Password:  "p",
					},
				},
			},
			expectedType: "*secretsmgr.delineaManager",
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
