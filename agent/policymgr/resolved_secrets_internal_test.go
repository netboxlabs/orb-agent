package policymgr

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/policies"
)

// TestRemovedPolicyKeepsItsResolvedValuesForAMinute removes a policy from the
// repo the policy manager hands out. What the backend printed about the
// policy before it was removed can still be waiting to be relayed, so its
// values mask the backend's output for a minute more; after that, the agent
// keeps none of them. Another policy's values are kept.
func TestRemovedPolicyKeepsItsResolvedValuesForAMinute(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	resolved, repo := newTestMaskingRepo(t, &now, "policy-1", "policy-2")
	resolved.remember("policy-1", "worker", []resolvedValue{{path: "scope.community", value: "c0mmun1ty-v4l"}})
	resolved.remember("policy-2", "worker", []resolvedValue{{path: "scope.password", value: "p4ssw0rd-v4l"}})
	const printed = "community c0mmun1ty-v4l, password p4ssw0rd-v4l"

	require.NoError(t, repo.Remove("policy-1"))
	now = now.Add(time.Minute)
	assert.Equal(t, "community ********, password ********", resolved.maskOutput("worker", printed),
		"a line relayed within a minute of the removal")

	now = now.Add(time.Second)
	assert.Equal(t, "community c0mmun1ty-v4l, password ********", resolved.maskOutput("worker", printed),
		"a line relayed later")
	assert.Empty(t, resolved.of("policy-1"), "the removed policy's values are dropped")
	assert.Empty(t, resolved.departed, "and the agent holds none of them")
}

// TestPolicyAddedAgainKeepsMaskingWhereItRan adds a removed policy again: on
// the backend it ran on, its values keep masking the backend's output past
// the minute after the removal, since the backend runs it again; on another
// backend, the one it ran on still masks with them for the minute, for the
// lines it printed before the removal.
func TestPolicyAddedAgainKeepsMaskingWhereItRan(t *testing.T) {
	values := []resolvedValue{{path: "scope.password", value: "p4ssw0rd-v4l"}}
	const printed = "auth failed with p4ssw0rd-v4l"

	t.Run("on the same backend", func(t *testing.T) {
		now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
		resolved, repo := newTestMaskingRepo(t, &now, "policy-1")
		resolved.remember("policy-1", "worker", values)
		require.NoError(t, repo.Remove("policy-1"))
		now = now.Add(5 * time.Second)
		resolved.remember("policy-1", "worker", values)

		now = now.Add(time.Hour)
		assert.Equal(t, "auth failed with ********", resolved.maskOutput("worker", printed))
	})

	t.Run("on another backend", func(t *testing.T) {
		now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
		resolved, repo := newTestMaskingRepo(t, &now, "policy-1")
		resolved.remember("policy-1", "worker", values)
		require.NoError(t, repo.Remove("policy-1"))
		now = now.Add(5 * time.Second)
		resolved.remember("policy-1", "device_discovery", values)

		assert.Equal(t, "auth failed with ********", resolved.maskOutput("worker", printed), "the backend it ran on, within the minute")
		assert.Equal(t, "auth failed with ********", resolved.maskOutput("device_discovery", printed), "the backend it runs on")
		now = now.Add(time.Minute)
		assert.Equal(t, printed, resolved.maskOutput("worker", printed), "the backend it ran on, later")
	})

	t.Run("moved to another backend without a removal", func(t *testing.T) {
		now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
		resolved, _ := newTestMaskingRepo(t, &now, "policy-1")
		resolved.remember("policy-1", "worker", values)
		resolved.remember("policy-1", "device_discovery", values)

		assert.Equal(t, "auth failed with ********", resolved.maskOutput("worker", printed), "the backend it ran on, within the minute")
		now = now.Add(time.Minute + time.Second)
		assert.Equal(t, printed, resolved.maskOutput("worker", printed), "the backend it ran on, later")
	})
}

// TestOutputIsMaskedWithThePreviousResolutionToo has a backend print the
// value a policy's reference resolved to before its last rotation, as a
// backend still finishing a run it started with it does, while the policy
// runs and within the minute after it is removed.
func TestOutputIsMaskedWithThePreviousResolutionToo(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	resolved, repo := newTestMaskingRepo(t, &now, "policy-1")
	resolved.remember("policy-1", "worker", []resolvedValue{{path: "scope.community", value: "b3fore-r0tation"}})
	resolved.remember("policy-1", "worker", []resolvedValue{{path: "scope.community", value: "aft3r-r0tation"}})
	const printed = "walk with b3fore-r0tation failed"

	assert.Equal(t, "walk with ******** failed", resolved.maskOutput("worker", printed), "while the policy runs")
	require.NoError(t, repo.Remove("policy-1"))
	// Another policy applied to the backend changes what masks its output.
	resolved.remember("policy-2", "worker", []resolvedValue{{path: "scope.password", value: "p4ssw0rd-v4l"}})
	assert.Equal(t, "walk with ******** failed", resolved.maskOutput("worker", printed), "within the minute after its removal")
}

// TestRunReasonNamesEachFieldOnce reports a run that quotes a value the
// policy's last two resolutions share: the note names its field once.
func TestRunReasonNamesEachFieldOnce(t *testing.T) {
	now := time.Now()
	resolved, repo := newTestMaskingRepo(t, &now, "policy-1")
	resolved.remember("policy-1", "worker", []resolvedValue{
		{path: "scope.community", value: "c0mmun1ty-v4l"}, {path: "scope.password", value: "p4ssw0rd-v1"},
	})
	resolved.remember("policy-1", "worker", []resolvedValue{
		{path: "scope.community", value: "c0mmun1ty-v4l"}, {path: "scope.password", value: "p4ssw0rd-v2"},
	})

	require.NoError(t, repo.UpdateRuns("policy-1", []policies.RunData{{ID: "run-1", Status: "failed", Reason: "auth failed for community c0mmun1ty-v4l"}}))
	stored, err := repo.Get("policy-1")
	require.NoError(t, err)
	require.Len(t, stored.Runs, 1)
	assert.Equal(t, "auth failed for community ******** (the error quotes the value of the secret reference at scope.community, masked as ********)",
		stored.Runs[0].Reason)
}

// TestRunReportsReuseWhatTheyAreMaskedWith stores, poll after poll, the runs
// of a policy holding a private key: what the runs' reasons are masked with
// is built when the policy's values change, not for every run of every poll,
// which would cost megabytes and milliseconds a poll for each such policy.
func TestRunReportsReuseWhatTheyAreMaskedWith(t *testing.T) {
	now := time.Now()
	resolved, repo := newTestMaskingRepo(t, &now, "policy-1")
	resolved.remember("policy-1", "worker", []resolvedValue{
		{path: "scope.key", value: privateKey(t, 1800)},
		{path: "scope.password", value: "p4ssw0rd-v4l"},
	})
	runs := make([]policies.RunData, 50)
	poll := func() {
		for i := range runs {
			runs[i] = policies.RunData{ID: fmt.Sprint("run-", i), Status: "failed", Reason: "timeout polling 192.0.2.10"}
		}
		require.NoError(t, repo.UpdateRuns("policy-1", runs))
	}
	poll()

	allocs := testing.AllocsPerRun(5, poll)
	assert.LessOrEqual(t, allocs, 10.0*float64(len(runs)), "allocations to store a poll's runs")
}

// TestBackendOutputIsMaskedWithItsOwnPoliciesValues leaves a line one
// backend prints as printed when only another backend's policy resolved the
// value in it: each backend's lines cost the masking of its own policies'
// values, not every policy's.
func TestBackendOutputIsMaskedWithItsOwnPoliciesValues(t *testing.T) {
	resolved := newResolvedSecrets()
	resolved.remember("policy-1", "worker", []resolvedValue{{path: "scope.password", value: "p4ssw0rd-v4l"}})
	assert.Equal(t, "echo p4ssw0rd-v4l", resolved.maskOutput("snmp_discovery", "echo p4ssw0rd-v4l"))
}

// TestPolicyKeepsTheValuesOfItsLastTwoResolutions resolves a policy's
// secret reference to a new value again and again, as a secret that rotates
// on every poll is. The agent keeps the values of the last two resolutions
// that differ, for a run reported before the last one, and no more: each
// value it keeps is one more it holds in memory and masks every relayed line
// with. A resolution to the same values, as a restart's replay makes, is not
// a new one.
func TestPolicyKeepsTheValuesOfItsLastTwoResolutions(t *testing.T) {
	resolved := newResolvedSecrets()
	rotation := func(n int) []resolvedValue {
		return []resolvedValue{{path: "scope.community", value: fmt.Sprintf("r0tat3d-v4lue-%03d", n)}}
	}
	for n := range 100 {
		resolved.remember("policy-1", "worker", rotation(n))
	}
	resolved.remember("policy-1", "worker", rotation(99))
	assert.ElementsMatch(t, append(rotation(98), rotation(99)...), resolved.of("policy-1"))

	t.Run("two references at the same path, one of them rotated", func(t *testing.T) {
		// A key named "a.b" and a key b under a: two references, one path.
		raw := map[string]any{"a.b": "${vault://s/x}", "a": map[string]any{"b": "${vault://s/y}"}}
		resolved := newResolvedSecrets()
		resolved.remember("policy-1", "worker", resolvedValues(raw, map[string]any{"a.b": "s4me-v4lue-1", "a": map[string]any{"b": "s4me-v4lue-1"}}))
		resolved.remember("policy-1", "worker", resolvedValues(raw, map[string]any{"a.b": "s4me-v4lue-1", "a": map[string]any{"b": "r0tat3d-v4lue-2"}}))
		assert.Equal(t, "line ********", resolved.maskOutput("worker", "line r0tat3d-v4lue-2"))
	})
}

// TestRunTargetIsMaskedOnlyWhenItIsAValue masks a run's target or driver
// that is a value one of the policy's secret references resolved to, as a
// backend that copies a host from the policy's scope reports it, and leaves
// any other whole: Fleet maps a run's target to a device by its exact name,
// and a short value such as a user name or a port is a word of many names.
func TestRunTargetIsMaskedOnlyWhenItIsAValue(t *testing.T) {
	now := time.Now()
	resolved, repo := newTestMaskingRepo(t, &now, "policy-1")
	resolved.remember("policy-1", "worker", []resolvedValue{
		{path: "scope.username", value: "admin"},
		{path: "scope.port", value: "22"},
		{path: "scope.hosts[0]", value: "s3cret-host.example.net"},
	})

	require.NoError(t, repo.UpdateRuns("policy-1", []policies.RunData{{
		ID:      "run-1",
		Status:  "completed",
		Targets: []string{"admin-sw1.example.net", "10.0.0.22", "rtr1.example.net", "s3cret-host.example.net"},
		Driver:  "ios",
	}, {ID: "run-2", Status: "completed", Driver: "admin"}}))
	stored, err := repo.Get("policy-1")
	require.NoError(t, err)
	require.Len(t, stored.Runs, 2)
	assert.Equal(t, []string{"admin-sw1.example.net", "10.0.0.22", "rtr1.example.net", "********"}, stored.Runs[0].Targets)
	assert.Equal(t, "ios", stored.Runs[0].Driver)
	assert.Equal(t, "********", stored.Runs[1].Driver)
}

// TestMaskingALineReusesWhatItMasksWith masks lines a backend prints while
// its policies hold large values, a private key each: what the values are
// masked with is built once, when they change, not for every line, which
// would allocate megabytes per line and stall a backend that prints much.
func TestMaskingALineReusesWhatItMasksWith(t *testing.T) {
	resolved := newResolvedSecrets()
	for i := range 100 {
		resolved.remember(fmt.Sprint("policy-", i), "worker", []resolvedValue{
			{path: "scope.key", value: privateKey(t, 1800)},
			{path: "scope.password", value: fmt.Sprintf("p4ssw0rd-%03d", i)},
		})
	}
	line := `{"level":"debug","msg":"polled 192.0.2.10 ifHCInOctets.1 = 123456789 in 12ms"}`
	resolved.maskOutput("worker", line)

	allocs := testing.AllocsPerRun(20, func() { resolved.maskOutput("worker", line) })
	assert.LessOrEqual(t, allocs, 10.0, "allocations to mask one line")
}

// TestRunsAreMaskedForThePolicyTheyAreStoredOn has the store change after
// the masking repo looked up the policy a poll reports runs for, before the
// runs are stored. The manager stores a policy it just applied only once the
// backend accepted it, it can store another policy under the name, and an
// apply changes the values a policy's references resolved to. The runs ride
// every heartbeat, so they are stored masked with the values of the policy
// they are stored on, whatever changed since the lookup.
func TestRunsAreMaskedForThePolicyTheyAreStoredOn(t *testing.T) {
	const secret = "Pl41n-credential"
	quoted := []resolvedValue{{path: "scope.community", value: secret}}
	for _, tc := range []struct {
		name string
		// stored are the IDs of the policies stored under the name before the
		// poll, values those the agent keeps for each.
		stored []string
		values map[string][]resolvedValue
		// meanwhile changes the store or the values right before the runs
		// are handed to the store.
		meanwhile func(t *testing.T, resolved *resolvedSecrets, repo policies.PolicyRepo)
		storedOn  string
	}{{
		name:   "the record of the policy the backend was just given lands",
		values: map[string][]resolvedValue{"policy-1": quoted},
		meanwhile: func(t *testing.T, _ *resolvedSecrets, repo policies.PolicyRepo) {
			require.NoError(t, repo.Update(policies.PolicyData{ID: "policy-1", Name: "shared", Backend: "worker"}))
		},
		storedOn: "policy-1",
	}, {
		name:   "another policy is stored under the name",
		stored: []string{"policy-1"},
		values: map[string][]resolvedValue{
			// A target of the run stored on policy-2 is one of policy-1's values.
			"policy-1": {{path: "scope.hosts[0]", value: "rtr1.example.net"}},
			"policy-2": quoted,
		},
		meanwhile: func(t *testing.T, _ *resolvedSecrets, repo policies.PolicyRepo) {
			require.NoError(t, repo.Update(policies.PolicyData{ID: "policy-2", Name: "shared", Backend: "worker"}))
		},
		storedOn: "policy-2",
	}, {
		name:   "the policy's values change",
		stored: []string{"policy-1"},
		meanwhile: func(_ *testing.T, resolved *resolvedSecrets, _ policies.PolicyRepo) {
			resolved.remember("policy-1", "worker", quoted)
		},
		storedOn: "policy-1",
	}, {
		// A policy whose secrets fail to resolve, or whose backend is not
		// ready, is stored again without an apply: the agent keeps no values
		// for it, but the runs were reported for the policy as it was.
		name:   "the policy is removed and stored again without values",
		stored: []string{"policy-1"},
		values: map[string][]resolvedValue{"policy-1": quoted},
		meanwhile: func(t *testing.T, resolved *resolvedSecrets, repo policies.PolicyRepo) {
			require.NoError(t, repo.Remove("policy-1"))
			resolved.removed("policy-1")
			require.NoError(t, repo.Update(policies.PolicyData{ID: "policy-1", Name: "shared", Backend: "worker"}))
		},
		storedOn: "policy-1",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			resolved, repo := newTestMaskingRepo(t, &now)
			for _, id := range tc.stored {
				require.NoError(t, repo.Update(policies.PolicyData{ID: id, Name: "shared", Backend: "worker"}))
			}
			for id, values := range tc.values {
				resolved.remember(id, "worker", values)
			}
			store := repo.PolicyRepo
			repo.PolicyRepo = &changedBeforeStore{PolicyRepo: store, change: func() { tc.meanwhile(t, resolved, store) }}

			reported := []policies.RunData{{
				ID: "run-1", Status: "failed", Reason: "auth of 192.0.2.10 failed with " + secret, Targets: []string{"rtr1.example.net"},
			}}
			require.NoError(t, repo.UpdateRuns("shared", reported))
			all, err := repo.GetAll()
			require.NoError(t, err)
			for _, pd := range all {
				for _, r := range pd.Runs {
					assert.NotContains(t, r.Reason, secret, "a run stored on %s", pd.ID)
				}
			}
			stored, err := repo.Get(tc.storedOn)
			require.NoError(t, err)
			require.Len(t, stored.Runs, 1)
			assert.Contains(t, stored.Runs[0].Reason, "auth of 192.0.2.10 failed with ********")
			assert.Equal(t, []string{"rtr1.example.net"}, stored.Runs[0].Targets, "a target that is no value of the policy it is stored on")
		})
	}
}

// TestRunsAreMaskedBeforeTheStoreLocksForThem has the store see the runs a
// poll reports as they are handed to it: they are masked already. The store
// holds its lock while it saves them, and the heartbeat and each export read
// the store, so masking a long reason with a large value under the lock
// would hold them up.
func TestRunsAreMaskedBeforeTheStoreLocksForThem(t *testing.T) {
	now := time.Now()
	resolved, repo := newTestMaskingRepo(t, &now, "policy-1")
	resolved.remember("policy-1", "worker", []resolvedValue{{path: "scope.community", value: "Pl41n-credential"}})
	seen := &handedRuns{PolicyRepo: repo.PolicyRepo}
	repo.PolicyRepo = seen

	require.NoError(t, repo.UpdateRuns("policy-1", []policies.RunData{{ID: "run-1", Status: "failed", Reason: "auth of 192.0.2.10 failed with Pl41n-credential"}}))
	require.Len(t, seen.reasons, 1)
	assert.Contains(t, seen.reasons[0], "auth of 192.0.2.10 failed with ********")
}

// TestRunsACallerPreparesAreMaskedToo stores runs through the masking repo's
// UpdateRunsWith, as a caller that rewrites them before they are stored
// would: what it writes is masked like what the backend reported.
func TestRunsACallerPreparesAreMaskedToo(t *testing.T) {
	now := time.Now()
	resolved, repo := newTestMaskingRepo(t, &now, "policy-1")
	resolved.remember("policy-1", "worker", []resolvedValue{{path: "scope.community", value: "Pl41n-credential"}})

	quote := func(_ string, runs []policies.RunData) {
		runs[0].Reason = "auth of 192.0.2.10 failed with Pl41n-credential"
	}
	require.NoError(t, repo.UpdateRunsWith("policy-1", []policies.RunData{{ID: "run-1", Status: "failed"}}, quote))
	stored, err := repo.Get("policy-1")
	require.NoError(t, err)
	require.Len(t, stored.Runs, 1)
	assert.Contains(t, stored.Runs[0].Reason, "auth of 192.0.2.10 failed with ********")
}

// changedBeforeStore is a store that change changes right before runs are
// handed to it: after whatever the masking repo looked up or masked before.
type changedBeforeStore struct {
	policies.PolicyRepo
	change func()
}

func (s *changedBeforeStore) UpdateRunsWith(name string, runs []policies.RunData, prepare func(string, []policies.RunData)) error {
	s.change()
	return s.PolicyRepo.UpdateRunsWith(name, runs, prepare)
}

// handedRuns is a store that records the reasons of the runs handed to it.
type handedRuns struct {
	policies.PolicyRepo
	reasons []string
}

func (s *handedRuns) UpdateRunsWith(name string, runs []policies.RunData, prepare func(string, []policies.RunData)) error {
	for _, r := range runs {
		s.reasons = append(s.reasons, r.Reason)
	}
	return s.PolicyRepo.UpdateRunsWith(name, runs, prepare)
}

// privateKey returns a PEM-armoured key of n random bytes, 64 base64
// characters a line.
func privateKey(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	body := base64.StdEncoding.EncodeToString(b)
	var lines []string
	for len(body) > 64 {
		lines, body = append(lines, body[:64]), body[64:]
	}
	lines = append(lines, body)
	return "-----BEGIN PRIVATE KEY-----\n" + strings.Join(lines, "\n") + "\n-----END PRIVATE KEY-----\n"
}

// newTestMaskingRepo returns the values kept by a masking repo on the clock
// *now, and the repo, holding a policy on the worker for each id.
func newTestMaskingRepo(t *testing.T, now *time.Time, ids ...string) (*resolvedSecrets, *maskingRepo) {
	t.Helper()
	mem, err := policies.NewMemRepo()
	require.NoError(t, err)
	resolved := newResolvedSecrets()
	resolved.now = func() time.Time { return *now }
	repo := &maskingRepo{PolicyRepo: mem, secrets: resolved}
	for _, id := range ids {
		require.NoError(t, repo.Update(policies.PolicyData{ID: id, Name: id, Backend: "worker"}))
	}
	return resolved, repo
}
