package secretsmgr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

// The agent logs in to Vault when it starts, and the token it gets lasts until
// its max TTL. These tests have a Vault stand-in end a token, or refuse a
// login, and check the agent logs in again where its auth method can, and
// says so once where it cannot.

const communityRef = "secrets/snmp/community"

// TestVaultManager_LogsInAgainWhenItsTokenIsNoLongerValid has Vault stop
// accepting the agent's token. A read that Vault refuses for it logs in again
// and is read again, so the secret still resolves without a restart.
func TestVaultManager_LogsInAgainWhenItsTokenIsNoLongerValid(t *testing.T) {
	vault := newVaultStandIn(t)
	vm, logs := startVaultManager(t, vault, appRole)
	require.Equal(t, 1, vault.loginCount())

	vault.expire("tok-1")
	value, err := vm.fetch(communityRef)
	require.NoError(t, err, "the read logs in again and is retried")
	assert.Equal(t, "s3cret-community", value)
	assert.Equal(t, 2, vault.loginCount())
	assert.Contains(t, logs.String(), "logged in to Vault again")
}

// TestVaultManager_ReadsThatFailTogetherLogInOnce has many reads find the
// token ended at once: they log in once between them.
func TestVaultManager_ReadsThatFailTogetherLogInOnce(t *testing.T) {
	vault := newVaultStandIn(t)
	vm, _ := startVaultManager(t, vault, appRole)
	vault.expire("tok-1")

	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := vm.fetch(communityRef)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}
	assert.Equal(t, 2, vault.loginCount(), "one login at start and one for all the reads")
}

// TestVaultManager_AReadDeniedToAValidTokenLogsInNoAgain has Vault refuse a
// path to every token: the agent's token is still valid, so the read fails as
// it did, and the agent does not log in again for it at every read.
func TestVaultManager_AReadDeniedToAValidTokenLogsInNoAgain(t *testing.T) {
	vault := newVaultStandIn(t)
	vault.deny("snmp")
	vm, _ := startVaultManager(t, vault, appRole)

	for range 3 {
		_, err := vm.fetch(communityRef)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "permission denied")
	}
	assert.Equal(t, 1, vault.loginCount())
}

// TestVaultManager_LogsInAgainWhenItsTokenReachesItsMaxTTL has the agent's
// token reach its max TTL, past which Vault renews it no longer: the agent
// logs in again before a read fails.
func TestVaultManager_LogsInAgainWhenItsTokenReachesItsMaxTTL(t *testing.T) {
	vault := newVaultStandIn(t)
	vault.renewable(2, 3*time.Second)
	vm, logs := startVaultManager(t, vault, appRole)

	require.Eventually(t, func() bool { return vault.loginCount() >= 2 }, 15*time.Second, 50*time.Millisecond,
		"the agent logs in again when its token can be renewed no longer")
	assert.Contains(t, logs.String(), "can be renewed no longer")
	require.Eventually(t, func() bool { return vault.loginCount() >= 3 }, 15*time.Second, 50*time.Millisecond,
		"the token from the new login is renewed, and logged in again for, too")
	value, err := vm.fetch(communityRef)
	require.NoError(t, err)
	assert.Equal(t, "s3cret-community", value)
	assert.Zero(t, vault.refusedReads(), "no read was refused on the way")
}

// TestVaultManager_AWatcherWhoseTokenALoginReplacedLogsInNoAgain has a read
// log in again for a token Vault stopped accepting, while that token's watcher
// still runs. The watcher then finds its token renewed no longer, but the
// token it would log in again for was replaced already: the agent logs in no
// more.
func TestVaultManager_AWatcherWhoseTokenALoginReplacedLogsInNoAgain(t *testing.T) {
	vault := newVaultStandIn(t)
	vault.renewable(2, time.Hour)
	vm, logs := startVaultManager(t, vault, appRole)

	vault.expire("tok-1")
	_, err := vm.fetch(communityRef)
	require.NoError(t, err)
	require.Equal(t, 2, vault.loginCount())
	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "can be renewed no longer") },
		15*time.Second, 50*time.Millisecond, "the first token's watcher ends")
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, 2, vault.loginCount(), "the watcher of the token replaced logs in no more")
}

// TestVaultManager_TokenAuthSaysOnceThatItsTokenEnded has the token the agent
// was given end. Token auth cannot log in again: the reads fail, and the
// agent says why once, at ERROR, not at every read.
func TestVaultManager_TokenAuthSaysOnceThatItsTokenEnded(t *testing.T) {
	vault := newVaultStandIn(t)
	vm, logs := startVaultManager(t, vault, func(*vaultStandIn) (string, map[string]any) {
		return "token", map[string]any{"token": "static-tok"}
	})
	_, err := vm.fetch(communityRef)
	require.NoError(t, err)

	vault.expire("static-tok")
	for range 3 {
		_, err = vm.fetch(communityRef)
		require.Error(t, err)
	}
	assert.Zero(t, vault.loginCount())
	assert.Equal(t, 1, strings.Count(logs.String(), "level=ERROR"), logs.String())
	assert.Contains(t, logs.String(), "token auth cannot log in again")
}

// TestVaultManager_ALoginThatFailsIsSaidOnceAndTriedAgain has Vault refuse
// the agent's login once its token ended, as it does for a secret_id that
// expired: the reads fail, the agent says so once, at ERROR, and logs in at
// the next read once Vault accepts the login again.
func TestVaultManager_ALoginThatFailsIsSaidOnceAndTriedAgain(t *testing.T) {
	vault := newVaultStandIn(t)
	vm, logs := startVaultManager(t, vault, appRole)
	vault.expire("tok-1")
	vault.refuseLogins(true)

	for range 3 {
		_, err := vm.fetch(communityRef)
		require.Error(t, err)
	}
	assert.Equal(t, 1, strings.Count(logs.String(), "level=ERROR"), logs.String())
	assert.Contains(t, logs.String(), "failed to log in to Vault again")

	vault.refuseLogins(false)
	value, err := vm.fetch(communityRef)
	require.NoError(t, err)
	assert.Equal(t, "s3cret-community", value)
	assert.Contains(t, logs.String(), "logged in to Vault again")
}

// TestVaultManager_APollAfterTheTokenEndedStopsNoPolicy has a policy use a
// secret from Vault, then Vault stop accepting the agent's token before the
// scheduled poll reads it again: the poll logs in again and reads it, so no
// policy that uses it is stopped.
func TestVaultManager_APollAfterTheTokenEndedStopsNoPolicy(t *testing.T) {
	vault := newVaultStandIn(t)
	vm, _ := startVaultManager(t, vault, appRole)
	var reported []map[string]error
	vm.RegisterUpdatePoliciesCallback(func(changed map[string]error) { reported = append(reported, changed) })
	resolved, err := vm.SolvePolicySecrets(config.PolicyPayload{
		ID:   "policy-1",
		Data: map[string]any{"scope": map[string]any{"community": "${vault://" + communityRef + "}"}},
	})
	require.NoError(t, err)
	require.Equal(t, "s3cret-community", resolved.Data.(map[string]any)["scope"].(map[string]any)["community"])

	vault.expire("tok-1")
	vm.pollSecrets()
	for _, changed := range reported {
		assert.NoError(t, changed["policy-1"], "the poll stops no policy")
	}
	assert.Equal(t, 2, vault.loginCount())
}

// appRole configures an AppRole login.
func appRole(*vaultStandIn) (string, map[string]any) {
	return "approle", map[string]any{"role_id": "role", "secret_id": "secret"}
}

// startVaultManager starts a Vault manager against the stand-in, logging into
// the returned buffer.
func startVaultManager(t *testing.T, vault *vaultStandIn, login func(*vaultStandIn) (string, map[string]any)) (*vaultManager, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	auth, args := login(vault)
	vm := &vaultManager{
		preLogger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		config:    config.VaultManager{Address: vault.url, Auth: auth, AuthArgs: args},
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	require.NoError(t, vm.Start(ctx))
	return vm, logs
}

// vaultStandIn answers the Vault API calls the agent makes: AppRole logins,
// token renewals and lookups, and KV v2 reads of one secret.
type vaultStandIn struct {
	url string

	mu        sync.Mutex
	logins    int
	refuse    bool
	lease     int
	renew     bool
	maxTTL    time.Duration
	issued    map[string]time.Time
	ended     map[string]bool
	denied    map[string]bool
	refusedRd int
}

func newVaultStandIn(t *testing.T) *vaultStandIn {
	t.Helper()
	s := &vaultStandIn{
		lease:  3600,
		issued: map[string]time.Time{"static-tok": time.Now()},
		ended:  map[string]bool{},
		denied: map[string]bool{},
	}
	srv := httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(srv.Close)
	s.url = srv.URL
	return s
}

func (s *vaultStandIn) loginCount() int   { s.mu.Lock(); defer s.mu.Unlock(); return s.logins }
func (s *vaultStandIn) refusedReads() int { s.mu.Lock(); defer s.mu.Unlock(); return s.refusedRd }
func (s *vaultStandIn) expire(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ended[token] = true
}

func (s *vaultStandIn) deny(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denied[path] = true
}

func (s *vaultStandIn) refuseLogins(refuse bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refuse = refuse
}

// renewable has the tokens it issues last lease seconds, renewable up to
// maxTTL after they were issued.
func (s *vaultStandIn) renewable(lease int, maxTTL time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lease, s.renew, s.maxTTL = lease, true, maxTTL
}

// validLocked reports whether Vault accepts the token. The caller holds s.mu.
func (s *vaultStandIn) validLocked(token string) bool {
	issued, ok := s.issued[token]
	if !ok || s.ended[token] {
		return false
	}
	return s.maxTTL == 0 || time.Since(issued) < s.maxTTL
}

func (s *vaultStandIn) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token := r.Header.Get("X-Vault-Token")
	write := func(code int, body any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(body)
	}
	denied := map[string]any{"errors": []string{"permission denied"}}
	switch {
	case r.URL.Path == "/v1/auth/approle/login":
		if s.refuse {
			write(http.StatusBadRequest, map[string]any{"errors": []string{"invalid role or secret ID"}})
			return
		}
		s.logins++
		issued := fmt.Sprintf("tok-%d", s.logins)
		s.issued[issued] = time.Now()
		write(http.StatusOK, map[string]any{"auth": map[string]any{
			"client_token": issued, "lease_duration": s.lease, "renewable": s.renew, "policies": []string{"default"},
		}})
	case r.URL.Path == "/v1/auth/token/renew-self":
		if !s.validLocked(token) {
			write(http.StatusForbidden, denied)
			return
		}
		lease := s.lease
		if left := int((s.maxTTL - time.Since(s.issued[token])) / time.Second); s.maxTTL > 0 && left < lease {
			lease = left
		}
		write(http.StatusOK, map[string]any{"auth": map[string]any{
			"client_token": token, "lease_duration": lease, "renewable": true, "policies": []string{"default"},
		}})
	case r.URL.Path == "/v1/auth/token/lookup-self":
		if !s.validLocked(token) {
			write(http.StatusForbidden, denied)
			return
		}
		write(http.StatusOK, map[string]any{"data": map[string]any{"id": token, "ttl": s.lease}})
	case strings.HasPrefix(r.URL.Path, "/v1/secrets/data/"):
		if !s.validLocked(token) || s.denied[strings.TrimPrefix(r.URL.Path, "/v1/secrets/data/")] {
			s.refusedRd++
			write(http.StatusForbidden, denied)
			return
		}
		write(http.StatusOK, map[string]any{"data": map[string]any{
			"data":     map[string]any{"community": "s3cret-community"},
			"metadata": map[string]any{"version": 1},
		}})
	default:
		write(http.StatusNotFound, map[string]any{"errors": []string{}})
	}
}

// syncBuffer is a buffer the manager's goroutines can log into.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
