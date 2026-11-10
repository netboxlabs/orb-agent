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

// TestVaultManager_AddressCredentialsAreSentButNeverQuoted starts the Vault
// manager with an address that carries a user and password, as one does for
// a proxy that asks for basic auth in front of Vault. Every request still
// carries them, but no log line or error quotes the user or the password:
// the Vault client quotes the address it was given in the text of every
// error it returns.
func TestVaultManager_AddressCredentialsAreSentButNeverQuoted(t *testing.T) {
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
	assert.NotContains(t, err.Error(), "proxyuser", "the error quotes no user")
	assert.NotContains(t, logs.String(), "proxyuser", "no log line quotes the user")
	assert.Contains(t, logs.String(), "://********@", "the address is logged with its user and password masked")
}

// TestVaultManager_AnAddressNoParserReadsIsRefusedWithoutQuotingIt starts
// the Vault manager with an address whose user or password holds a / ? # or
// space that is not escaped. No URL parser reads it as one, and the parse
// error, or the Vault client's errors for the host it would then call, would
// quote the address, credential included: the agent refuses it without
// quoting it.
func TestVaultManager_AnAddressNoParserReadsIsRefusedWithoutQuotingIt(t *testing.T) {
	for _, address := range []string{
		"https://proxyuser:Pr0xy/pa55word@127.0.0.1:1",
		"https://proxyuser:Pr0xy?pa55word@127.0.0.1:1",
		"https://proxyuser:Pr0xy pa55word@127.0.0.1:1",
		// A token given as the user, which a parser reads as the host.
		"https://Pr0xy/pa55word@127.0.0.1:1",
		"https://Pr0xy?pa55word@127.0.0.1:1",
		"https://Pr0xy#pa55word@127.0.0.1:1",
		// An address written without //, or without a scheme.
		"https:Pr0xy:pa55word@127.0.0.1:1",
		"Pr0xy:pa55word@127.0.0.1:1",
		"Pr0xy-pa55word@127.0.0.1:1",
	} {
		logs := &bytes.Buffer{}
		vm := &vaultManager{
			preLogger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
			config:    config.VaultManager{Address: address, Auth: "token", AuthArgs: map[string]any{"token": "t"}},
		}
		err := vm.Start(context.Background())
		require.Error(t, err)
		for _, part := range []string{"Pr0xy", "pa55word"} {
			assert.NotContains(t, err.Error(), part, "the error quotes no part of the password")
			assert.NotContains(t, logs.String(), part, "no log line quotes a part of the password")
		}
	}
}
