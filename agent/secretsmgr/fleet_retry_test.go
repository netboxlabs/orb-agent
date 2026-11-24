package secretsmgr

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
)

// recordedReports collects what a manager reports to its callback.
type recordedReports struct {
	mu      sync.Mutex
	reports []map[string]error
}

func (r *recordedReports) record(m map[string]error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reports = append(r.reports, m)
}

func (r *recordedReports) all() []map[string]error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]map[string]error(nil), r.reports...)
}

// assertWait asserts that wait is delay, spread by up to a fifth either way.
func assertWait(t *testing.T, delay, wait time.Duration) {
	t.Helper()
	assert.GreaterOrEqual(t, wait, delay*4/5, "the wait for a %s delay", delay)
	assert.LessOrEqual(t, wait, delay*6/5, "the wait for a %s delay", delay)
}

// A refresh Fleet doesn't answer, can't be sent, or fails with a fault of its
// own leaves the policies running with the value they have, and the path is
// requested again a minute later: once Fleet answers, the policies are
// applied with the new value, with no delivery.
func TestFleetSecretsManager_aRefreshFleetDoesNotAnswerIsRequestedAgain(t *testing.T) {
	for _, tc := range []struct {
		name string
		// fail fails the first request.
		fail func(pub *scriptedPublisher)
	}{{
		name: "no answer",
		fail: func(*scriptedPublisher) {},
	}, {
		name: "a failed publish",
		fail: func(pub *scriptedPublisher) {
			pub.publishErr = func(n int) error {
				if n == 1 {
					return errors.New("connection lost")
				}
				return nil
			}
		},
	}, {
		name: "INTERNAL_ERROR",
	}, {
		name: "RATE_LIMITED",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			fm, pub := newScriptedFleetManager(t, 1, func(n int, req messages.SecretRequestMsg) (*messages.SecretResponseMsg, <-chan struct{}) {
				switch {
				case n > 1:
					return fleetAnswer(req, "v2", 2), nil
				case tc.name == "INTERNAL_ERROR":
					return fleetRefuses(req, messages.ErrorCodeInternalError), nil
				case tc.name == "RATE_LIMITED":
					return fleetRefuses(req, messages.ErrorCodeRateLimited), nil
				default:
					return nil, nil // lost: it times out
				}
			})
			if tc.fail != nil {
				tc.fail(pub)
			}
			timers := &fakeRetryTimers{}
			fm.afterFunc = timers.afterFunc
			fm.usedVars = map[string]fleetCachedSecret{
				"snmp/community": {Value: "v1", Version: 1, policyIDs: map[string]bool{"policy1": true}},
			}
			reports := &recordedReports{}
			fm.callback = reports.record

			notify(t, fm, messages.SecretUpdate{Path: "snmp/community", Version: 2})
			assert.Empty(t, reports.all(), "the policies keep running")
			assert.NoError(t, fm.Unresolved("policy1"))
			out, err := fm.SolvePolicySecrets(config.PolicyPayload{ID: "policy2", Data: map[string]any{"c": "${fleet://snmp/community}"}})
			require.NoError(t, err)
			assert.Equal(t, "v1", out.Data.(map[string]any)["c"], "the value held is served meanwhile")
			waits := timers.pending()
			require.Len(t, waits, 1)
			assertWait(t, time.Minute, waits[0])

			timers.fire(t)
			assert.Equal(t, []map[string]error{{"policy1": nil, "policy2": nil}}, reports.all(),
				"the policies are applied with the new value")
			fm.mu.Lock()
			entry := fm.usedVars["snmp/community"]
			retries := len(fm.retries)
			fm.mu.Unlock()
			assert.Equal(t, "v2", entry.Value)
			assert.Equal(t, 2, entry.Version)
			assert.Zero(t, retries)
			assert.Empty(t, timers.pending())
			pub.mu.Lock()
			defer pub.mu.Unlock()
			assert.Equal(t, 2, pub.n, "no request but the retry")
		})
	}
}

// A refresh Fleet refuses, because the secret doesn't exist, the agent may
// not read it or the path isn't valid, stops the policies. The path is
// requested again, after twice as long each time Fleet refuses again, up to
// ten minutes, and the policies are applied again once Fleet answers with the
// value.
func TestFleetSecretsManager_aRefusedRefreshStopsThePoliciesUntilARetryIsAnswered(t *testing.T) {
	for _, code := range []string{messages.ErrorCodeNotFound, messages.ErrorCodeForbidden, messages.ErrorCodeInvalidPath} {
		t.Run(code, func(t *testing.T) {
			const refusals = 6
			fm, _ := newScriptedFleetManager(t, 5, func(n int, req messages.SecretRequestMsg) (*messages.SecretResponseMsg, <-chan struct{}) {
				if n <= refusals {
					return fleetRefuses(req, code), nil
				}
				return fleetAnswer(req, "v2", 2), nil
			})
			timers := &fakeRetryTimers{}
			fm.afterFunc = timers.afterFunc
			fm.usedVars = map[string]fleetCachedSecret{
				"snmp/community": {Value: "v1", Version: 1, policyIDs: map[string]bool{"policy1": true}},
			}
			reports := &recordedReports{}
			fm.callback = reports.record

			notify(t, fm, messages.SecretUpdate{Path: "snmp/community", Version: 2})
			got := reports.all()
			require.Len(t, got, 1)
			require.ErrorContains(t, got[0]["policy1"], code, "the policy is stopped")
			require.ErrorContains(t, fm.Unresolved("policy1"), code)

			for _, delay := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 10 * time.Minute, 10 * time.Minute} {
				waits := timers.pending()
				require.Len(t, waits, 1)
				assertWait(t, delay, waits[0])
				timers.fire(t)
			}
			got = reports.all()
			require.Len(t, got, 2, "a refusal of a stopped policy's path reports nothing more: %v", got)
			assert.Equal(t, map[string]error{"policy1": nil}, got[1], "the policy is applied again")
			assert.NoError(t, fm.Unresolved("policy1"))
			assert.Empty(t, timers.pending())
			fm.mu.Lock()
			defer fm.mu.Unlock()
			assert.False(t, fm.usedVars["snmp/community"].stale)
			assert.Equal(t, "v2", fm.usedVars["snmp/community"].Value)
		})
	}
}

// A success answer that holds no value for the path is Fleet answering
// about the secret: it stops the policies, as a refusal does.
func TestFleetSecretsManager_anAnswerWithoutTheSecretStopsThePolicies(t *testing.T) {
	fm, _ := newScriptedFleetManager(t, 5, func(_ int, req messages.SecretRequestMsg) (*messages.SecretResponseMsg, <-chan struct{}) {
		return &messages.SecretResponseMsg{
			SchemaVersion: messages.CurrentSecretsSchemaVersion, RequestID: req.RequestID, Timestamp: time.Now(), Status: "success",
		}, nil
	})
	fm.usedVars = map[string]fleetCachedSecret{
		"snmp/community": {Value: "v1", Version: 1, policyIDs: map[string]bool{"policy1": true}},
	}
	reports := &recordedReports{}
	fm.callback = reports.record

	notify(t, fm, messages.SecretUpdate{Path: "snmp/community", Version: 2})
	got := reports.all()
	require.Len(t, got, 1)
	assert.Error(t, got[0]["policy1"])
}

// A delivery that fetches a refused path before the retry does applies its
// own policy only: the retry finds the path current, requests nothing, and
// applies the other policies stopped for it.
func TestFleetSecretsManager_aRetryAppliesThePoliciesStoppedForAPathADeliveryFetched(t *testing.T) {
	fm, pub := newScriptedFleetManager(t, 5, func(n int, req messages.SecretRequestMsg) (*messages.SecretResponseMsg, <-chan struct{}) {
		if n == 1 {
			return fleetRefuses(req, messages.ErrorCodeForbidden), nil
		}
		return fleetAnswer(req, "v2", 2), nil
	})
	timers := &fakeRetryTimers{}
	fm.afterFunc = timers.afterFunc
	fm.usedVars = map[string]fleetCachedSecret{
		"snmp/community": {Value: "v1", Version: 1, policyIDs: map[string]bool{"policy1": true, "policy2": true}},
	}
	reports := &recordedReports{}
	fm.callback = reports.record

	notify(t, fm, messages.SecretUpdate{Path: "snmp/community", Version: 2})
	out, err := fm.SolvePolicySecrets(config.PolicyPayload{ID: "policy2", Data: map[string]any{"c": "${fleet://snmp/community}"}})
	require.NoError(t, err)
	assert.Equal(t, "v2", out.Data.(map[string]any)["c"])

	timers.fire(t)
	got := reports.all()
	require.Len(t, got, 2)
	assert.Equal(t, map[string]error{"policy1": nil, "policy2": nil}, got[1])
	pub.mu.Lock()
	defer pub.mu.Unlock()
	assert.Equal(t, 2, pub.n, "the retry requests nothing")
}

// A delivery that fetches a refused path while the scheduled request for it
// is being made completes that request, whatever its own answer: a failure
// or the same version. The request ends, and the other policies stopped for
// the path are applied again, as when the delivery comes before the request.
func TestFleetSecretsManager_aDeliveryDuringTheScheduledRequestCompletesIt(t *testing.T) {
	for name, answer := range map[string]func(messages.SecretRequestMsg) *messages.SecretResponseMsg{
		"it fails": func(req messages.SecretRequestMsg) *messages.SecretResponseMsg {
			return fleetRefuses(req, messages.ErrorCodeInternalError)
		},
		"it answers": func(req messages.SecretRequestMsg) *messages.SecretResponseMsg {
			return fleetAnswer(req, "v2", 2)
		},
	} {
		t.Run(name, func(t *testing.T) {
			asked, release := make(chan struct{}), make(chan struct{})
			fm, pub := newScriptedFleetManager(t, 5, func(n int, req messages.SecretRequestMsg) (*messages.SecretResponseMsg, <-chan struct{}) {
				switch n {
				case 1:
					return fleetRefuses(req, messages.ErrorCodeNotFound), nil
				case 2:
					close(asked)
					return answer(req), release
				default:
					return fleetAnswer(req, "v2", 2), nil
				}
			})
			timers := &fakeRetryTimers{}
			fm.afterFunc = timers.afterFunc
			fm.usedVars = map[string]fleetCachedSecret{
				"snmp/community": {Value: "v1", Version: 1, policyIDs: map[string]bool{"policy1": true}},
			}
			reports := &recordedReports{}
			fm.callback = reports.record

			notify(t, fm, messages.SecretUpdate{Path: "snmp/community", Version: 2})
			require.Len(t, reports.all(), 1, "policy1 is stopped")
			done := make(chan struct{})
			go func() {
				defer close(done)
				timers.fire(t)
			}()
			<-asked
			out, err := fm.SolvePolicySecrets(config.PolicyPayload{ID: "policy2", Data: map[string]any{"c": "${fleet://snmp/community}"}})
			require.NoError(t, err)
			assert.Equal(t, "v2", out.Data.(map[string]any)["c"])
			close(release)
			<-done

			got := reports.all()
			require.Len(t, got, 2, "the scheduled request reports the policies stopped for the path")
			assert.Equal(t, map[string]error{"policy1": nil, "policy2": nil}, got[1])
			assert.NoError(t, fm.Unresolved("policy1"))
			assert.Empty(t, timers.pending())
			fm.mu.Lock()
			retries := len(fm.retries)
			fm.mu.Unlock()
			assert.Zero(t, retries, "the scheduled request ends")
			pub.mu.Lock()
			defer pub.mu.Unlock()
			assert.Equal(t, 3, pub.n)
		})
	}
}

// The answer to a request for an older version, handled after the refresh of
// a newer one failed, applies its value, and leaves the request for the newer
// version scheduled.
func TestFleetSecretsManager_aLateAnswerForAnOlderVersionKeepsTheRetry(t *testing.T) {
	release := make(chan struct{})
	fm, pub := newScriptedFleetManager(t, 5, func(n int, req messages.SecretRequestMsg) (*messages.SecretResponseMsg, <-chan struct{}) {
		switch n {
		case 1:
			return fleetAnswer(req, "v2", 2), release
		case 2:
			return fleetRefuses(req, messages.ErrorCodeInternalError), nil
		default:
			return fleetAnswer(req, "v3", 3), nil
		}
	})
	timers := &fakeRetryTimers{}
	fm.afterFunc = timers.afterFunc
	fm.usedVars = map[string]fleetCachedSecret{
		"snmp/community": {Value: "v1", Version: 1, policyIDs: map[string]bool{"policy1": true}},
	}
	reports := &recordedReports{}
	fm.callback = reports.record

	done := make(chan struct{})
	go func() { notify(t, fm, messages.SecretUpdate{Path: "snmp/community", Version: 2}); close(done) }()
	<-pub.published
	notify(t, fm, messages.SecretUpdate{Path: "snmp/community", Version: 3})
	close(release)
	<-done
	assert.Equal(t, []map[string]error{{"policy1": nil}}, reports.all(), "applied with v2")
	require.Len(t, timers.pending(), 1, "v3 is still to be requested")

	timers.fire(t)
	assert.Equal(t, []map[string]error{{"policy1": nil}, {"policy1": nil}}, reports.all(), "applied with v3")
	fm.mu.Lock()
	defer fm.mu.Unlock()
	assert.Equal(t, "v3", fm.usedVars["snmp/community"].Value)
}

// An answer with an older version than Fleet announced, as from a replica
// that lags, is applied when it is newer than the value held, and the
// announced version is requested again until Fleet answers with it.
func TestFleetSecretsManager_anAnswerOlderThanAnnouncedIsRequestedAgain(t *testing.T) {
	for _, tc := range []struct {
		name string
		// held is the version the agent holds; lagging, the one Fleet answers
		// first for the announced version 3.
		held, lagging int
		// applied are the reports of the first answer.
		applied []map[string]error
	}{
		{name: "newer than the one held", held: 1, lagging: 2, applied: []map[string]error{{"policy1": nil}}},
		{name: "older than the one held", held: 2, lagging: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fm, pub := newScriptedFleetManager(t, 5, func(n int, req messages.SecretRequestMsg) (*messages.SecretResponseMsg, <-chan struct{}) {
				switch n {
				case 1:
					return fleetAnswer(req, fmt.Sprintf("v%d", tc.lagging), tc.lagging), nil
				case 2:
					return fleetAnswer(req, "v1", 1), nil // still behind: requested again later
				default:
					return fleetAnswer(req, "v3", 3), nil
				}
			})
			timers := &fakeRetryTimers{}
			fm.afterFunc = timers.afterFunc
			fm.usedVars = map[string]fleetCachedSecret{
				"snmp/community": {Value: fmt.Sprintf("v%d", tc.held), Version: tc.held, policyIDs: map[string]bool{"policy1": true}},
			}
			reports := &recordedReports{}
			fm.callback = reports.record

			notify(t, fm, messages.SecretUpdate{Path: "snmp/community", Version: 3})
			assert.Equal(t, tc.applied, reports.all())
			waits := timers.pending()
			require.Len(t, waits, 1, "the announced version is requested again")
			assertWait(t, time.Minute, waits[0])

			timers.fire(t)
			waits = timers.pending()
			require.Len(t, waits, 1, "still behind")
			assertWait(t, 2*time.Minute, waits[0])

			timers.fire(t)
			assert.Equal(t, append(tc.applied, map[string]error{"policy1": nil}), reports.all(), "applied with the announced version")
			assert.Empty(t, timers.pending())
			fm.mu.Lock()
			defer fm.mu.Unlock()
			assert.Equal(t, "v3", fm.usedVars["snmp/community"].Value)
			assert.Zero(t, len(fm.retries))
			pub.mu.Lock()
			defer pub.mu.Unlock()
			assert.Equal(t, 3, pub.n)
		})
	}
}

// A path whose refresh Fleet refused stays stale, its policies stopped, when
// Fleet answers with the version the agent holds, older than the one it
// announced, as a replica that lags would: whether the scheduled request or a
// delivery gets that answer. The announced version is requested again, and
// the policies are applied once Fleet answers with it.
func TestFleetSecretsManager_anAnswerAtTheHeldVersionKeepsARefusedPathStopped(t *testing.T) {
	for _, tc := range []struct {
		via string
		// applied is what the answer with the announced version reports.
		applied map[string]error
	}{
		{via: "the scheduled request", applied: map[string]error{"policy1": nil}},
		{via: "a delivery", applied: map[string]error{"policy1": nil, "policy2": nil}},
	} {
		t.Run(tc.via, func(t *testing.T) {
			fm, pub := newScriptedFleetManager(t, 5, func(n int, req messages.SecretRequestMsg) (*messages.SecretResponseMsg, <-chan struct{}) {
				switch n {
				case 1:
					return fleetRefuses(req, messages.ErrorCodeNotFound), nil
				case 2:
					return fleetAnswer(req, "v1", 1), nil // behind the announced version
				default:
					return fleetAnswer(req, "v2", 2), nil
				}
			})
			timers := &fakeRetryTimers{}
			fm.afterFunc = timers.afterFunc
			fm.usedVars = map[string]fleetCachedSecret{
				"snmp/community": {Value: "v1", Version: 1, policyIDs: map[string]bool{"policy1": true}},
			}
			reports := &recordedReports{}
			fm.callback = reports.record

			notify(t, fm, messages.SecretUpdate{Path: "snmp/community", Version: 2})
			require.Len(t, reports.all(), 1, "the policy is stopped")

			if tc.via == "a delivery" {
				_, err := fm.SolvePolicySecrets(config.PolicyPayload{ID: "policy2", Data: map[string]any{"c": "${fleet://snmp/community}"}})
				require.ErrorContains(t, err, messages.ErrorCodeNotFound, "not applied with the value Fleet replaced")
				waits := timers.pending()
				require.Len(t, waits, 1, "the announced version is still to be requested")
				assertWait(t, time.Minute, waits[0])
			} else {
				timers.fire(t)
				waits := timers.pending()
				require.Len(t, waits, 1, "the announced version is requested again")
				assertWait(t, 2*time.Minute, waits[0])
			}
			assert.Len(t, reports.all(), 1, "the policy stays stopped")
			require.ErrorContains(t, fm.Unresolved("policy1"), messages.ErrorCodeNotFound)

			timers.fire(t)
			got := reports.all()
			require.Len(t, got, 2)
			assert.Equal(t, tc.applied, got[1], "applied with the announced version")
			assert.NoError(t, fm.Unresolved("policy1"))
			assert.Empty(t, timers.pending())
			fm.mu.Lock()
			entry, retries := fm.usedVars["snmp/community"], len(fm.retries)
			fm.mu.Unlock()
			assert.False(t, entry.stale)
			assert.Equal(t, "v2", entry.Value)
			assert.Zero(t, retries)
			pub.mu.Lock()
			defer pub.mu.Unlock()
			assert.Equal(t, 3, pub.n)
		})
	}
}

// The version a scheduled request is for, announced again, as a repeated
// delivery of the notification whose request failed is (the update topic is
// subscribed at QoS 1), waits for that request rather than skip its backoff.
// A newer version is still requested at once.
func TestFleetSecretsManager_aRepeatedAnnouncementWaitsForTheScheduledRequest(t *testing.T) {
	fm, pub := newScriptedFleetManager(t, 5, func(n int, req messages.SecretRequestMsg) (*messages.SecretResponseMsg, <-chan struct{}) {
		if n == 1 {
			return fleetRefuses(req, messages.ErrorCodeInternalError), nil
		}
		return fleetAnswer(req, "v3", 3), nil
	})
	timers := &fakeRetryTimers{}
	fm.afterFunc = timers.afterFunc
	fm.usedVars = map[string]fleetCachedSecret{
		"snmp/community": {Value: "v1", Version: 1, policyIDs: map[string]bool{"policy1": true}},
	}
	reports := &recordedReports{}
	fm.callback = reports.record
	requests := func() int {
		pub.mu.Lock()
		defer pub.mu.Unlock()
		return pub.n
	}

	notify(t, fm, messages.SecretUpdate{Path: "snmp/community", Version: 2})
	waits := timers.pending()
	require.Len(t, waits, 1)
	notify(t, fm, messages.SecretUpdate{Path: "snmp/community", Version: 2})
	assert.Equal(t, 1, requests(), "the repeated announcement requests nothing")
	assert.Equal(t, waits, timers.pending(), "and leaves the scheduled request as it was")
	assert.Empty(t, reports.all())

	notify(t, fm, messages.SecretUpdate{Path: "snmp/community", Version: 3})
	assert.Equal(t, 2, requests(), "a newer version is requested at once")
	assert.Equal(t, []map[string]error{{"policy1": nil}}, reports.all())
	assert.Empty(t, timers.pending(), "its answer ends the scheduled request")
	fm.mu.Lock()
	defer fm.mu.Unlock()
	assert.Equal(t, "v3", fm.usedVars["snmp/community"].Value)
	assert.Zero(t, len(fm.retries))
}

// A request scheduled for a path is cancelled, its timer stopped, once no
// policy uses the path, and makes none once the agent is stopping.
func TestFleetSecretsManager_aRetryIsDroppedWhenNotNeeded(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cancel func(fm *FleetSecretsManager, stop context.CancelFunc)
	}{{
		name:   "the policy is removed",
		cancel: func(fm *FleetSecretsManager, _ context.CancelFunc) { fm.ForgetPolicy("policy1") },
	}, {
		name: "the policy is edited off the path",
		cancel: func(fm *FleetSecretsManager, _ context.CancelFunc) {
			fm.PolicyApplied("policy1", map[string]any{"c": "plain"})
		},
	}, {
		name:   "the agent is stopping",
		cancel: func(_ *FleetSecretsManager, stop context.CancelFunc) { stop() },
	}} {
		t.Run(tc.name, func(t *testing.T) {
			fm, pub := newScriptedFleetManager(t, 5, func(_ int, req messages.SecretRequestMsg) (*messages.SecretResponseMsg, <-chan struct{}) {
				return fleetRefuses(req, messages.ErrorCodeInternalError), nil
			})
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			fm.ctx = ctx
			timers := &fakeRetryTimers{}
			fm.afterFunc = timers.afterFunc
			fm.usedVars = map[string]fleetCachedSecret{
				"snmp/community": {Value: "v1", Version: 1, policyIDs: map[string]bool{"policy1": true}},
			}
			fm.callback = func(map[string]error) {}

			notify(t, fm, messages.SecretUpdate{Path: "snmp/community", Version: 2})
			require.Len(t, timers.pending(), 1)
			tc.cancel(fm, stop)
			if tc.name == "the agent is stopping" {
				timers.fire(t)
			}

			assert.Empty(t, timers.pending())
			fm.mu.Lock()
			retries := len(fm.retries)
			fm.mu.Unlock()
			assert.Zero(t, retries)
			pub.mu.Lock()
			defer pub.mu.Unlock()
			assert.Equal(t, 1, pub.n, "no request is made again")
		})
	}
}
