package secretsmgr

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

// TestVaultManager_AddressPasswordIsSentButNeverQuoted starts the Vault
// manager with an address that carries a user and password, as one does for
// a proxy that asks for basic auth in front of Vault. Every request still
// carries them, but no log line or error quotes the password: the Vault
// client quotes the address it was given in the text of every error it
// returns (MON-880).
func TestVaultManager_AddressPasswordIsSentButNeverQuoted(t *testing.T) {
	var sawBasicAuth bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "proxyuser" || pass != "Pr0xy-pa55word" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		sawBasicAuth = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
	}))
	t.Cleanup(proxy.Close)

	logs := &bytes.Buffer{}
	vm := &vaultManager{
		preLogger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		config: config.VaultManager{
			Address:  strings.Replace(proxy.URL, "http://", "http://proxyuser:Pr0xy-pa55word@", 1),
			Auth:     "token",
			AuthArgs: map[string]any{"token": "not-a-token"},
		},
	}

	err := vm.Start(context.Background())
	require.Error(t, err, "the stand-in refuses the token")
	assert.True(t, sawBasicAuth, "the request reached Vault through the proxy's basic auth")
	assert.Contains(t, err.Error(), "permission denied")
	assert.NotContains(t, err.Error(), "Pr0xy-pa55word", "the error quotes no password")
	assert.NotContains(t, logs.String(), "Pr0xy-pa55word", "no log line quotes the password")
	assert.Contains(t, logs.String(), "proxyuser:********@", "the address is logged with its password masked")
}
