package secretsmgr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
// still runs. The watcher of the token replaced is stopped: it neither logs
// in again past the lease it would have waited out nor says it would.
func TestVaultManager_AWatcherWhoseTokenALoginReplacedLogsInNoAgain(t *testing.T) {
	vault := newVaultStandIn(t)
	vault.renewable(2, time.Hour)
	vm, logs := startVaultManager(t, vault, appRole)

	vault.expire("tok-1")
	_, err := vm.fetch(communityRef)
	require.NoError(t, err)
	require.Equal(t, 2, vault.loginCount())

	time.Sleep(3 * time.Second)
	assert.Equal(t, 2, vault.loginCount(), "the watcher of the token replaced logs in no more")
	assert.NotContains(t, logs.String(), "can be renewed no longer", "nor says it would")
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

// TestVaultManager_ALoginThatFailsIsSaidOnceAndTriedAgainAnIntervalLater has
// Vault refuse the agent's login once its token ended, as it does for a
// secret_id that expired or a password rotated: the reads fail, and the agent
// says so once, at ERROR. It tries to log in again at most once an interval, not
// at every read: a directory locks an account out after so many failed binds.
func TestVaultManager_ALoginThatFailsIsSaidOnceAndTriedAgainAnIntervalLater(t *testing.T) {
	vault := newVaultStandIn(t)
	clock := &fakeClock{t: time.Now()}
	vm, logs := startVaultManager(t, vault, appRole, withClock(clock))
	vault.expire("tok-1")
	vault.refuseLogins(true)

	for range 20 {
		_, err := vm.fetch(communityRef)
		require.Error(t, err)
	}
	assert.Equal(t, 2, vault.loginAttempts(), "one at start, one for the reads of the interval")
	assert.Equal(t, 1, strings.Count(logs.String(), "level=ERROR"), logs.String())
	assert.Contains(t, logs.String(), "failed to log in to Vault again")

	vault.refuseLogins(false)
	_, err := vm.fetch(communityRef)
	require.Error(t, err, "not tried again within the interval")
	assert.Equal(t, 2, vault.loginAttempts())

	clock.advance(loginInterval)
	value, err := vm.fetch(communityRef)
	require.NoError(t, err)
	assert.Equal(t, "s3cret-community", value)
	assert.Contains(t, logs.String(), "logged in to Vault again")
}

// TestVaultManager_ALoginRefusedAtTheMaxTTLIsTriedAgainAnIntervalLater has
// Vault refuse the login the agent tries when its token reaches its max TTL:
// the reads that then find the token ended do not try again within the
// interval.
func TestVaultManager_ALoginRefusedAtTheMaxTTLIsTriedAgainAnIntervalLater(t *testing.T) {
	vault := newVaultStandIn(t)
	vault.renewable(2, 3*time.Second)
	clock := &fakeClock{t: time.Now()}
	started := time.Now()
	vm, _ := startVaultManager(t, vault, appRole, withClock(clock))
	vault.refuseLogins(true)

	require.Eventually(t, func() bool { return vault.loginAttempts() >= 2 }, 15*time.Second, 50*time.Millisecond,
		"the agent tries to log in at the max TTL")
	time.Sleep(time.Until(started.Add(3500 * time.Millisecond)))
	for range 5 {
		_, err := vm.fetch(communityRef)
		require.Error(t, err)
	}
	assert.Equal(t, 2, vault.loginAttempts(), "the reads do not try again within the interval")

	vault.refuseLogins(false)
	clock.advance(loginInterval)
	_, err := vm.fetch(communityRef)
	require.NoError(t, err)
}

// TestVaultManager_AWatcherWaitsTheIntervalAfterALoginThatFailed has a read
// fail to log in again for a token Vault stopped accepting, whose watcher
// then finds it renewed no longer: the watcher does not try again within the
// interval either.
func TestVaultManager_AWatcherWaitsTheIntervalAfterALoginThatFailed(t *testing.T) {
	vault := newVaultStandIn(t)
	vault.renewable(2, time.Hour)
	clock := &fakeClock{t: time.Now()}
	vm, logs := startVaultManager(t, vault, appRole, withClock(clock))
	vault.expire("tok-1")
	vault.refuseLogins(true)

	_, err := vm.fetch(communityRef)
	require.Error(t, err)
	require.Equal(t, 2, vault.loginAttempts())
	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "can be renewed no longer") },
		15*time.Second, 50*time.Millisecond, "the token's watcher ends")
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, 2, vault.loginAttempts(), "the watcher waits out the interval")
}

// TestVaultManager_ATokenThatMayNotLookItselfUpLogsInAtMostOnceAnInterval has a
// token whose policy does not let it look itself up, as a role with
// token_no_default_policy gives, read a path it may not read. Vault refuses
// the lookup as it does for a token that ended, so the agent cannot tell the
// two apart: it logs in again at most once an interval for such reads, not at
// every one, and the token it replaced is renewed no more.
func TestVaultManager_ATokenThatMayNotLookItselfUpLogsInAtMostOnceAnInterval(t *testing.T) {
	vault := newVaultStandIn(t)
	vault.renewable(2, time.Hour)
	vault.lookupAnswers(http.StatusForbidden)
	vault.deny("snmp")
	clock := &fakeClock{t: time.Now()}
	vm, _ := startVaultManager(t, vault, appRole, withClock(clock))

	for range 50 {
		_, err := vm.fetch(communityRef)
		require.Error(t, err)
	}
	assert.Equal(t, 2, vault.loginCount(), "one at start, one for the reads of the interval")
	replacedAt := time.Now()

	clock.advance(loginInterval)
	_, err := vm.fetch(communityRef)
	require.Error(t, err)
	assert.Equal(t, 3, vault.loginCount())

	time.Sleep(3 * time.Second)
	assert.False(t, vault.renewedSince("tok-1", replacedAt), "the token replaced is renewed no more")
	assert.False(t, vault.renewedSince("tok-2", replacedAt.Add(500*time.Millisecond)), "nor the one replaced after it")
}

// TestVaultManager_StoppingCutsALookupOrALoginShortQuietly stops the agent
// while it asks Vault about its token, or logs in again, and Vault does not
// answer: the read returns as the agent stops, not when the request times
// out, and a login cut short is not logged as refused.
func TestVaultManager_StoppingCutsALookupOrALoginShortQuietly(t *testing.T) {
	for name, path := range map[string]string{"lookup": "/v1/auth/token/lookup-self", "login": "/v1/auth/approle/login"} {
		t.Run(name, func(t *testing.T) {
			vault := newVaultStandIn(t)
			logs := &syncBuffer{}
			vm := &vaultManager{
				preLogger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
				config:    config.VaultManager{Address: vault.url, Auth: "approle", AuthArgs: map[string]any{"role_id": "role", "secret_id": "secret"}},
			}
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			require.NoError(t, vm.Start(ctx))
			vault.expire("tok-1")
			vault.hangOn(path)

			done := make(chan error, 1)
			go func() {
				_, err := vm.fetch(communityRef)
				done <- err
			}()
			time.Sleep(100 * time.Millisecond)
			cancel()
			select {
			case err := <-done:
				require.Error(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("the read waits on Vault past the agent's stop")
			}
			assert.NotContains(t, logs.String(), "level=ERROR", "a login cut short is not logged as refused")
		})
	}
}

// TestVaultManager_ALookupThatFailsOtherwiseLogsInNoAgain has Vault fail the
// lookup of the token with another error than a 403: whether the token ended
// is unknown, so the read fails as it is, without a login.
func TestVaultManager_ALookupThatFailsOtherwiseLogsInNoAgain(t *testing.T) {
	vault := newVaultStandIn(t)
	vm, _ := startVaultManager(t, vault, appRole)
	vault.expire("tok-1")
	vault.lookupAnswers(http.StatusBadRequest)

	_, err := vm.fetch(communityRef)
	require.Error(t, err)
	assert.Equal(t, 1, vault.loginAttempts())
}

// TestVaultManager_AWrappedSecretIDSaysOnceItCannotLogInAgain logs in with a
// secret_id given wrapped, which Vault unwraps once: when the token ends, the
// agent cannot log in again with it, and says so once, at ERROR, without
// trying.
func TestVaultManager_AWrappedSecretIDSaysOnceItCannotLogInAgain(t *testing.T) {
	vault := newVaultStandIn(t)
	vm, logs := startVaultManager(t, vault, func(*vaultStandIn) (string, map[string]any) {
		return "approle", map[string]any{"role_id": "role", "secret_id": "wrapping-token", "wrapping_token": true}
	})
	require.Equal(t, 1, vault.loginCount())

	vault.expire("tok-1")
	for range 3 {
		_, err := vm.fetch(communityRef)
		require.Error(t, err)
	}
	assert.Equal(t, 1, vault.loginAttempts(), "no login is tried again")
	assert.Equal(t, 1, vault.unwrapCount(), "the wrapping token is not unwrapped again")
	assert.Equal(t, 1, strings.Count(logs.String(), "level=ERROR"), logs.String())
	assert.Contains(t, logs.String(), "a wrapped secret_id cannot log in again")
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

// withClock has the manager read the time from clock.
func withClock(clock *fakeClock) func(*vaultManager) {
	return func(vm *vaultManager) { vm.now = clock.now }
}

// fakeClock is a clock a test moves forward.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// appRole configures an AppRole login.
func appRole(*vaultStandIn) (string, map[string]any) {
	return "approle", map[string]any{"role_id": "role", "secret_id": "secret"}
}

// startVaultManager starts a Vault manager against the stand-in, logging into
// the returned buffer.
func startVaultManager(t *testing.T, vault *vaultStandIn, login func(*vaultStandIn) (string, map[string]any), opts ...func(*vaultManager)) (*vaultManager, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	auth, args := login(vault)
	vm := &vaultManager{
		preLogger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		config:    config.VaultManager{Address: vault.url, Auth: auth, AuthArgs: args},
	}
	for _, opt := range opts {
		opt(vm)
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
	attempts  int
	unwraps   int
	refuse    bool
	lease     int
	renew     bool
	maxTTL    time.Duration
	lookup    int
	hang      map[string]bool
	issued    map[string]time.Time
	renewed   map[string]time.Time
	ended     map[string]bool
	denied    map[string]bool
	refusedRd int
}

func newVaultStandIn(t *testing.T) *vaultStandIn {
	t.Helper()
	s := &vaultStandIn{
		lease:   3600,
		issued:  map[string]time.Time{"static-tok": time.Now()},
		renewed: map[string]time.Time{},
		hang:    map[string]bool{},
		ended:   map[string]bool{},
		denied:  map[string]bool{},
	}
	srv := httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(srv.Close)
	s.url = srv.URL
	return s
}

func (s *vaultStandIn) loginCount() int    { s.mu.Lock(); defer s.mu.Unlock(); return s.logins }
func (s *vaultStandIn) loginAttempts() int { s.mu.Lock(); defer s.mu.Unlock(); return s.attempts }
func (s *vaultStandIn) unwrapCount() int   { s.mu.Lock(); defer s.mu.Unlock(); return s.unwraps }

// renewedSince reports whether Vault renewed the token after at.
func (s *vaultStandIn) renewedSince(token string, at time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.renewed[token].After(at)
}

// hangOn has Vault answer no request to path until the agent gives up on it.
func (s *vaultStandIn) hangOn(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hang[path] = true
}

// lookupAnswers has Vault answer every token lookup with status.
func (s *vaultStandIn) lookupAnswers(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lookup = status
}
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
	if s.hang[r.URL.Path] {
		s.mu.Unlock()
		// The server notices the agent hang up only once the body is read.
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
		return
	}
	defer s.mu.Unlock()
	token := r.Header.Get("X-Vault-Token")
	write := func(code int, body any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(body)
	}
	denied := map[string]any{"errors": []string{"permission denied"}}
	switch {
	case r.URL.Path == "/v1/sys/wrapping/unwrap":
		s.unwraps++
		if s.unwraps > 1 {
			write(http.StatusBadRequest, map[string]any{"errors": []string{"wrapping token is not valid or does not exist"}})
			return
		}
		write(http.StatusOK, map[string]any{"data": map[string]any{"secret_id": "secret"}})
	case r.URL.Path == "/v1/auth/approle/login":
		s.attempts++
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
		s.renewed[token] = time.Now()
		write(http.StatusOK, map[string]any{"auth": map[string]any{
			"client_token": token, "lease_duration": lease, "renewable": true, "policies": []string{"default"},
		}})
	case r.URL.Path == "/v1/auth/token/lookup-self":
		if s.lookup != 0 {
			write(s.lookup, denied)
			return
		}
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
