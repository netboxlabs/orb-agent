package secretsmgr

import (
	"context"
	"log/slog"
	"net"
	"os"
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
	time.Sleep(500 * time.Millisecond)

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
