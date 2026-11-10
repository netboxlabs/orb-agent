package secretsmgr

import (
	"bytes"
	"context"
	"encoding/base64"
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

	vaultapi "github.com/hashicorp/vault/api"
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

// TestVaultManager_ATokenThatMayNotLookItselfUpLogsInNoAgainForADeniedPath has
// a token whose policy does not let it look itself up or revoke itself, as a
// role with token_no_default_policy gives, read a path it may not read at
// every poll. Vault refuses the lookup as it does for a token that ended, so
// the agent cannot tell the two apart: it says so once, at WARN, and logs in
// again for none of the reads, so no token piles up in Vault.
func TestVaultManager_ATokenThatMayNotLookItselfUpLogsInNoAgainForADeniedPath(t *testing.T) {
	vault := newVaultStandIn(t)
	vault.withoutDefaultPolicy()
	vault.deny("snmp")
	clock := &fakeClock{t: time.Now()}
	vm, logs := startVaultManager(t, vault, appRole, withClock(clock))

	for range 6 {
		_, err := vm.fetch(communityRef)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "permission denied")
		clock.advance(loginInterval)
	}
	assert.Equal(t, 1, vault.loginCount(), "the login at start only")
	assert.Equal(t, 1, vault.validTokens(), "no token piles up in Vault")
	assert.NotContains(t, logs.String(), "logged in to Vault again")
	assert.Equal(t, 1, strings.Count(logs.String(), "level=WARN"), logs.String())
	assert.Contains(t, logs.String(), "auth/token/lookup-self")
}

// TestVaultManager_ATokenThatMayNotLookItselfUpLogsInAgainPastItsLease has a
// token that may not look itself up, and that no watcher renews (not
// renewable, or a batch token), reach the end of its lease. A read Vault
// refuses before that end logs in no more, and one past it does, at most once
// an interval: for each token the agent logs in with, until its lease ends.
// It says once that the token may not look itself up.
func TestVaultManager_ATokenThatMayNotLookItselfUpLogsInAgainPastItsLease(t *testing.T) {
	vault := newVaultStandIn(t)
	vault.withoutDefaultPolicy()
	vault.leaseOf(100)
	clock := &fakeClock{t: time.Now()}
	vm, logs := startVaultManager(t, vault, appRole, withClock(clock))

	for i, token := range []string{"tok-1", "tok-2", "tok-3"} {
		vault.expire(token)
		clock.advance(loginInterval)
		_, err := vm.fetch(communityRef)
		require.Error(t, err, "not logged in again for before the end of the lease")
		require.Equal(t, i+1, vault.loginCount())

		clock.advance(loginInterval + time.Second)
		value, err := vm.fetch(communityRef)
		require.NoError(t, err, "logged in again for past the end of the lease")
		assert.Equal(t, "s3cret-community", value)
		assert.Equal(t, i+2, vault.loginCount())
	}
	assert.Equal(t, 1, strings.Count(logs.String(), "level=WARN"), "said once, not at each login: "+logs.String())
}

// TestVaultManager_ALoginRefusedAtTheMaxTTLOfATokenThatMayNotLookItselfUpIsTriedAgain
// has the login the agent tries when a token that may not look itself up
// reaches its max TTL fail once. Nothing renews the token any more, so a read
// Vault refuses logs in again an interval later, once logins work.
func TestVaultManager_ALoginRefusedAtTheMaxTTLOfATokenThatMayNotLookItselfUpIsTriedAgain(t *testing.T) {
	vault := newVaultStandIn(t)
	vault.renewable(2, 3*time.Second)
	vault.withoutDefaultPolicy()
	clock := &fakeClock{t: time.Now()}
	started := time.Now()
	vm, _ := startVaultManager(t, vault, appRole, withClock(clock))
	vault.refuseLogins(true)

	require.Eventually(t, func() bool { return vault.loginAttempts() >= 2 }, 15*time.Second, 50*time.Millisecond,
		"the agent tries to log in at the max TTL")
	time.Sleep(time.Until(started.Add(3500 * time.Millisecond)))
	vault.refuseLogins(false)
	_, err := vm.fetch(communityRef)
	require.Error(t, err, "not tried again within the interval")

	clock.advance(loginInterval)
	value, err := vm.fetch(communityRef)
	require.NoError(t, err, "the agent logs in again once logins work")
	assert.Equal(t, "s3cret-community", value)
}

// TestVaultManager_ATokenGrantedLookupSelfLaterIsAskedAboutAtTheNextLogin has
// the token's policy let it look itself up only after the start, as when an
// operator grants it on the agent's warning. The agent notices at its next
// login, here past the end of the token's lease: from then on, a read Vault
// refuses for a token that ended logs in again, whenever it comes.
func TestVaultManager_ATokenGrantedLookupSelfLaterIsAskedAboutAtTheNextLogin(t *testing.T) {
	vault := newVaultStandIn(t)
	vault.lookupAnswers(http.StatusForbidden)
	vault.leaseOf(100)
	clock := &fakeClock{t: time.Now()}
	vm, _ := startVaultManager(t, vault, appRole, withClock(clock))
	vault.lookupAnswers(0)

	vault.expire("tok-1")
	var err error
	for range 3 {
		clock.advance(loginInterval)
		_, err = vm.fetch(communityRef)
	}
	require.NoError(t, err, "logged in again for past the end of the lease")
	require.Equal(t, 2, vault.loginCount())

	// tok-2 came from a login an interval ago, half a lease before its end.
	vault.expire("tok-2")
	value, err := vm.fetch(communityRef)
	require.NoError(t, err, "the token from the new login may look itself up: its end is told at once")
	assert.Equal(t, "s3cret-community", value)
	assert.Equal(t, 3, vault.loginCount())
}

// TestVaultManager_ARenewalMovesTheEndOfATokenThatMayNotLookItselfUp has the
// watcher renew a token that may not look itself up: the end the agent knows
// for it moves with each renewal, so a read Vault refuses past the end of the
// lease its login gave, but within the renewed one, logs in no more.
func TestVaultManager_ARenewalMovesTheEndOfATokenThatMayNotLookItselfUp(t *testing.T) {
	vault := newVaultStandIn(t)
	vault.renewable(2, time.Hour)
	vault.withoutDefaultPolicy()
	vault.deny("snmp")
	clock := &fakeClock{t: time.Now()}
	vm, _ := startVaultManager(t, vault, appRole, withClock(clock))

	// The login's lease ends 2s on the agent's clock. A renewal the agent
	// takes in a second later, usually the watcher's first, moves it to 3s.
	clock.advance(time.Second)
	require.Eventually(t, func() bool {
		vm.loginMu.Lock()
		defer vm.loginMu.Unlock()
		return vm.tokenEnd.After(clock.now().Add(1500 * time.Millisecond))
	}, 10*time.Second, 20*time.Millisecond, "the agent takes a renewal of the token in")
	clock.advance(1500 * time.Millisecond)
	_, err := vm.fetch(communityRef)
	require.Error(t, err)
	assert.Equal(t, 1, vault.loginCount(), "the token's renewed lease has not ended")
}

// TestVaultManager_ALateRenewalOfAReplacedTokenMovesNoEnd has the watcher of
// a token a login replaced report a renewal after the login, as one running
// when the login stopped it can: the end the agent knows for the new token
// stays the end of its own lease.
func TestVaultManager_ALateRenewalOfAReplacedTokenMovesNoEnd(t *testing.T) {
	vault := newVaultStandIn(t)
	vault.withoutDefaultPolicy()
	vault.leaseOf(100)
	clock := &fakeClock{t: time.Now()}
	vm, _ := startVaultManager(t, vault, appRole, withClock(clock))
	vault.expire("tok-1")
	clock.advance(101 * time.Second)
	_, err := vm.fetch(communityRef)
	require.NoError(t, err)
	require.Equal(t, 2, vault.loginCount())

	vm.renewed("tok-1", &vaultapi.Secret{Auth: &vaultapi.SecretAuth{ClientToken: "tok-1", LeaseDuration: 1}})
	vault.deny("snmp")
	clock.advance(loginInterval)
	_, err = vm.fetch(communityRef)
	require.Error(t, err)
	assert.Equal(t, 2, vault.loginCount(), "tok-2's lease has not ended")
}

// TestVaultManager_ATokenWithNoLeaseThatMayNotLookItselfUpIsTakenNotToEnd has
// a login give a token with no lease, which Vault does not end, and whose
// policy does not let it look itself up: a read Vault refuses is a path it
// may not read, and logs in no more, however long after the login it comes.
func TestVaultManager_ATokenWithNoLeaseThatMayNotLookItselfUpIsTakenNotToEnd(t *testing.T) {
	vault := newVaultStandIn(t)
	vault.withoutDefaultPolicy()
	vault.leaseOf(0)
	vault.deny("snmp")
	clock := &fakeClock{t: time.Now()}
	vm, _ := startVaultManager(t, vault, appRole, withClock(clock))

	for range 3 {
		clock.advance(24 * time.Hour)
		_, err := vm.fetch(communityRef)
		require.Error(t, err)
	}
	assert.Equal(t, 1, vault.loginCount())
}

// TestVaultManager_AWatcherThatEndsWithoutALoginEndsTheTokenThatMayNotLookItselfUp
// has the watcher of a token that may not look itself up end, and its login
// fail: nothing renews the token any more, so the agent takes it to have
// ended, and a read Vault refuses an interval later logs in, whatever the end
// of its lease.
func TestVaultManager_AWatcherThatEndsWithoutALoginEndsTheTokenThatMayNotLookItselfUp(t *testing.T) {
	vault := newVaultStandIn(t)
	vault.withoutDefaultPolicy()
	clock := &fakeClock{t: time.Now()}
	vm, _ := startVaultManager(t, vault, appRole, withClock(clock))

	vault.refuseLogins(true)
	require.False(t, vm.loginAgain("tok-1"), "the login the watcher tries when it ends fails")
	vault.refuseLogins(false)
	vault.expire("tok-1")

	clock.advance(loginInterval)
	value, err := vm.fetch(communityRef)
	require.NoError(t, err, "a read logs in again, long before the end of the token's lease")
	assert.Equal(t, "s3cret-community", value)
	assert.Equal(t, 2, vault.loginCount())
}

// TestVaultManager_EveryLoginIsAskedAbout has the token's policy stop letting
// it look itself up after the start: the agent learns it from the login a read
// makes once the token ended, and logs in no more for a path the new token may
// not read.
func TestVaultManager_EveryLoginIsAskedAbout(t *testing.T) {
	vault := newVaultStandIn(t)
	clock := &fakeClock{t: time.Now()}
	vm, logs := startVaultManager(t, vault, appRole, withClock(clock))
	vault.withoutDefaultPolicy()
	vault.expire("tok-1")
	_, err := vm.fetch(communityRef)
	require.NoError(t, err)
	require.Equal(t, 2, vault.loginCount())

	vault.deny("snmp")
	for range 3 {
		clock.advance(loginInterval)
		_, err := vm.fetch(communityRef)
		require.Error(t, err)
	}
	assert.Equal(t, 2, vault.loginCount())
	assert.Contains(t, logs.String(), "auth/token/lookup-self")
}

// TestVaultManager_ALookupThatFailsOtherwiseAfterALoginTellsNothing has Vault
// fail the question the agent asks about its token right after the login
// with another error than a 403: whether the token may look itself up is
// unknown, so a read Vault refuses for a token that ended logs in again, as
// before.
func TestVaultManager_ALookupThatFailsOtherwiseAfterALoginTellsNothing(t *testing.T) {
	vault := newVaultStandIn(t)
	vault.lookupAnswers(http.StatusServiceUnavailable)
	vm, logs := startVaultManager(t, vault, appRole)
	vault.lookupAnswers(0)

	vault.expire("tok-1")
	value, err := vm.fetch(communityRef)
	require.NoError(t, err)
	assert.Equal(t, "s3cret-community", value)
	assert.Equal(t, 2, vault.loginCount())
	assert.NotContains(t, logs.String(), "level=WARN")
}

// TestVaultManager_ALookupVaultDoesNotAnswerAfterALoginHoldsUpNoStart has
// Vault not answer the question the agent asks about its token right after
// the login: the agent starts after a short wait, not the client's timeout,
// and the token is treated as before.
func TestVaultManager_ALookupVaultDoesNotAnswerAfterALoginHoldsUpNoStart(t *testing.T) {
	vault := newVaultStandIn(t)
	vault.hangOn("/v1/auth/token/lookup-self")
	began := time.Now()
	_, logs := startVaultManager(t, vault, appRole)
	assert.Less(t, time.Since(began), lookupTimeout+3*time.Second, "the agent's start waits on the lookup no longer than its own timeout")
	assert.NotContains(t, logs.String(), "level=WARN")
}

// TestVaultManager_ALoginRevokesTheTokenItReplaces has the agent log in again
// in place of a token Vault still accepts: here its policy stops letting it
// look itself up after the start, so a path it may not read looks like the
// token's end. The token replaced is revoked, so it does not stay valid in
// Vault until its own TTL.
func TestVaultManager_ALoginRevokesTheTokenItReplaces(t *testing.T) {
	vault := newVaultStandIn(t)
	vault.deny("snmp")
	vm, _ := startVaultManager(t, vault, appRole)
	vault.lookupAnswers(http.StatusForbidden)

	_, err := vm.fetch(communityRef)
	require.Error(t, err)
	require.Equal(t, 2, vault.loginCount())
	require.Eventually(t, func() bool { return vault.revokedToken("tok-1") }, 5*time.Second, 20*time.Millisecond,
		"the token replaced is revoked")
	assert.Equal(t, 1, vault.validTokens())
}

// TestVaultManager_ATokenALoginReplacedIsRenewedNoMore has the agent log in
// again in place of a token Vault still accepts, and refuses to let revoke
// itself: the token replaced is renewed no more, so it ends at its TTL.
func TestVaultManager_ATokenALoginReplacedIsRenewedNoMore(t *testing.T) {
	vault := newVaultStandIn(t)
	vault.renewable(2, time.Hour)
	vault.deny("snmp")
	vm, _ := startVaultManager(t, vault, appRole)
	vault.withoutDefaultPolicy()

	_, err := vm.fetch(communityRef)
	require.Error(t, err)
	require.Equal(t, 2, vault.loginCount())
	replacedAt := time.Now()

	time.Sleep(3 * time.Second)
	assert.False(t, vault.revokedToken("tok-1"), "Vault refused the revoke")
	assert.False(t, vault.renewedSince("tok-1", replacedAt), "the token replaced is renewed no more")
	assert.True(t, vault.renewedSince("tok-2", replacedAt), "the token from the new login is")
}

// TestVaultManager_ARevokeThatFailsOrHangsHoldsUpNoRead has Vault refuse the
// revoke of the token a login replaced, as it does for a token that ended, or
// not answer it: the read that logged in again returns the secret at once,
// and a refused revoke is logged at DEBUG only.
func TestVaultManager_ARevokeThatFailsOrHangsHoldsUpNoRead(t *testing.T) {
	for name, hang := range map[string]bool{"refused": false, "hangs": true} {
		t.Run(name, func(t *testing.T) {
			vault := newVaultStandIn(t)
			vm, logs := startVaultManager(t, vault, appRole)
			vault.expire("tok-1")
			if hang {
				vault.hangOn("/v1/auth/token/revoke-self")
			}

			done := make(chan error, 1)
			go func() {
				_, err := vm.fetch(communityRef)
				done <- err
			}()
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("the read waits on the revoke of the token it replaced")
			}
			if !hang {
				require.Eventually(t, func() bool { return strings.Contains(logs.String(), "was not revoked") },
					5*time.Second, 20*time.Millisecond, "a revoke Vault refuses is logged")
				assert.Contains(t, logs.String(), "level=DEBUG msg=\"the Vault token a login replaced was not revoked\"")
			}
			assert.NotContains(t, logs.String(), "level=ERROR")
			assert.NotContains(t, logs.String(), "level=WARN")
		})
	}
}

// TestVaultManager_ARevokeCarriesTheNamespaceAndTheProxysLogin has the agent
// reach Vault in a namespace, through a proxy that asks for basic auth: the
// revoke of the token a login replaced is sent with both, as every other
// request is.
func TestVaultManager_ARevokeCarriesTheNamespaceAndTheProxysLogin(t *testing.T) {
	vault := newVaultStandIn(t)
	vault.deny("snmp")
	vm, _ := startVaultManager(t, vault, appRole, func(vm *vaultManager) {
		vm.config.Namespace = "team-a"
		vm.config.Address = strings.Replace(vault.url, "//", "//proxyuser:Pr0xy-pa55word@", 1)
	})
	vault.lookupAnswers(http.StatusForbidden)

	_, err := vm.fetch(communityRef)
	require.Error(t, err)
	require.Eventually(t, func() bool { return vault.revokedToken("tok-1") }, 5*time.Second, 20*time.Millisecond,
		"the token replaced is revoked")
	headers := vault.revokeHeaders()
	assert.Equal(t, "team-a", headers.Get("X-Vault-Namespace"))
	assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("proxyuser:Pr0xy-pa55word")), headers.Get("Authorization"))
}

// TestVaultManager_StoppingCutsARevokeShort stops the agent while Vault does
// not answer the revoke of the token a login replaced: the revoke ends as the
// agent stops, not when the client's request times out.
func TestVaultManager_StoppingCutsARevokeShort(t *testing.T) {
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
	vault.hangOn("/v1/auth/token/revoke-self")

	_, err := vm.fetch(communityRef)
	require.NoError(t, err)
	require.Eventually(t, func() bool { held, _ := vault.hangsOn("/v1/auth/token/revoke-self"); return held == 1 },
		5*time.Second, 20*time.Millisecond, "the agent asks Vault to revoke the token replaced")
	cancel()
	require.Eventually(t, func() bool { _, givenUp := vault.hangsOn("/v1/auth/token/revoke-self"); return givenUp == 1 },
		3*time.Second, 20*time.Millisecond, "the revoke ends as the agent stops")
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
// token renewals, lookups and revokes, and KV v2 reads of one secret.
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
	noDefault bool
	hang      map[string]bool
	hangs     map[string]int
	hangEnds  map[string]int
	revokeHdr http.Header
	issued    map[string]time.Time
	renewed   map[string]time.Time
	ended     map[string]bool
	revoked   map[string]bool
	denied    map[string]bool
	refusedRd int
}

func newVaultStandIn(t *testing.T) *vaultStandIn {
	t.Helper()
	s := &vaultStandIn{
		lease:    3600,
		issued:   map[string]time.Time{"static-tok": time.Now()},
		renewed:  map[string]time.Time{},
		hang:     map[string]bool{},
		hangs:    map[string]int{},
		hangEnds: map[string]int{},
		ended:    map[string]bool{},
		revoked:  map[string]bool{},
		denied:   map[string]bool{},
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

// hangsOn counts the requests to path Vault holds, and those of them the
// agent gave up on.
func (s *vaultStandIn) hangsOn(path string) (held, givenUp int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hangs[path], s.hangEnds[path]
}

// revokeHeaders returns the headers of the last revoke Vault was asked for.
func (s *vaultStandIn) revokeHeaders() http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revokeHdr
}

// leaseOf has the tokens it issues last seconds, and not be renewable.
func (s *vaultStandIn) leaseOf(seconds int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lease = seconds
}

// lookupAnswers has Vault answer every token lookup with status, 0 for its
// own answer.
func (s *vaultStandIn) lookupAnswers(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lookup = status
}

// withoutDefaultPolicy has the tokens Vault issues lack the default policy,
// as a role with token_no_default_policy gives: Vault refuses them a lookup
// or a revoke of themselves.
func (s *vaultStandIn) withoutDefaultPolicy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.noDefault = true
}

// revokedToken reports whether the token was revoked.
func (s *vaultStandIn) revokedToken(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revoked[token]
}

// validTokens counts the tokens from logins that Vault still accepts.
func (s *vaultStandIn) validTokens() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for token := range s.issued {
		if strings.HasPrefix(token, "tok-") && s.validLocked(token) {
			n++
		}
	}
	return n
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
	if r.URL.Path == "/v1/auth/token/revoke-self" {
		s.revokeHdr = r.Header.Clone()
	}
	if s.hang[r.URL.Path] {
		s.hangs[r.URL.Path]++
		s.mu.Unlock()
		// The server notices the agent hang up only once the body is read.
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
		s.mu.Lock()
		s.hangEnds[r.URL.Path]++
		s.mu.Unlock()
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
		if !s.validLocked(token) || s.noDefault {
			write(http.StatusForbidden, denied)
			return
		}
		write(http.StatusOK, map[string]any{"data": map[string]any{"id": token, "ttl": s.lease}})
	case r.URL.Path == "/v1/auth/token/revoke-self":
		if !s.validLocked(token) || s.noDefault {
			write(http.StatusForbidden, denied)
			return
		}
		s.ended[token] = true
		s.revoked[token] = true
		w.WriteHeader(http.StatusNoContent)
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
