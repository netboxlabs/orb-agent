package configmgr

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gitv5 "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// policyRepo is a policy repository on disk that a test commits to. The git
// config manager reads it over file://, as it read the lab's.
type policyRepo struct {
	dir  string
	repo *gitv5.Repository
}

func newPolicyRepo(t *testing.T, files map[string]string) *policyRepo {
	t.Helper()
	dir := t.TempDir()
	repo, err := gitv5.PlainInit(dir, false)
	require.NoError(t, err)
	r := &policyRepo{dir: dir, repo: repo}
	r.commit(t, files)
	return r
}

func (r *policyRepo) url() string { return "file://" + r.dir }

// commit writes each file, deletes each one mapped to "", and commits.
func (r *policyRepo) commit(t *testing.T, files map[string]string) {
	t.Helper()
	worktree, err := r.repo.Worktree()
	require.NoError(t, err)
	for path, content := range files {
		if content == "" {
			_, err = worktree.Remove(path)
			require.NoError(t, err)
			continue
		}
		full := filepath.Join(r.dir, path)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
		_, err = worktree.Add(path)
		require.NoError(t, err)
	}
	_, err = worktree.Commit("change", &gitv5.CommitOptions{
		Author: &object.Signature{Name: "tester", Email: "tester@example.com", When: time.Now()},
	})
	require.NoError(t, err)
}

// selecting returns a selector.yaml that selects paths for the label env: test.
func selecting(paths ...string) string {
	var b strings.Builder
	b.WriteString("s:\n  selector:\n    env: test\n  policies:\n")
	for i, p := range paths {
		fmt.Fprintf(&b, "    p%d:\n      path: %s\n", i, p)
	}
	return b.String()
}

// policyFile returns a policy file for beName with each policy's key set to
// its value: policyFile("be", "edge_tcp", "v1") holds edge_tcp with key v1.
func policyFile(beName string, nameValues ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s:\n", beName)
	for i := 0; i+1 < len(nameValues); i += 2 {
		fmt.Fprintf(&b, "  %s:\n    key: %s\n", nameValues[i], nameValues[i+1])
	}
	return b.String()
}

// gitAgent is a git config manager over the agent's real policy manager and
// one recording backend.
type gitAgent struct {
	gc       *gitConfigManager
	pm       policymgr.PolicyManager
	cfg      config.Config
	backends map[string]backend.Backend
}

// startGitAgent starts a git config manager on repo; onDemand declares the
// backend on demand, as the image declares pktvisor, instead of running it
// from the start.
func startGitAgent(t *testing.T, repo *policyRepo, beName string, be *recordingBackend, onDemand bool) *gitAgent {
	t.Helper()
	logger := testOutputLogger(t)
	pm := newPolicyManager(t, logger)
	if onDemand {
		superviseOnDemand(t, logger, pm, beName)
	}
	a := &gitAgent{
		gc:       &gitConfigManager{logger: logger, pMgr: pm},
		pm:       pm,
		cfg:      gitConfig(repo.url()),
		backends: map[string]backend.Backend{beName: be},
	}
	require.NoError(t, a.gc.Start(t.Context(), a.cfg, a.backends))
	t.Cleanup(func() { _ = a.gc.Stop(t.Context()) })
	return a
}

// poll runs one scheduled poll of the repository.
func (a *gitAgent) poll() {
	a.gc.schedule(a.cfg, a.backends)
}

// The clone at startup is every policy's first apply: none of them is
// removed first, whether the backend runs from the start or is started by
// the first policy and handed the policies stored meanwhile once it runs.
func TestGitStartAppliesEachPolicyWithoutRemovingItFirst(t *testing.T) {
	for name, onDemand := range map[string]bool{"eager": false, "on demand": true} {
		t.Run(name, func(t *testing.T) {
			beName, be := registerRecordingBackend(t, !onDemand)
			repo := newPolicyRepo(t, map[string]string{
				"selector.yaml": selecting("a.yaml", "b.yaml"),
				"a.yaml":        policyFile(beName, "alpha", "v1", "edge_tcp", "v1"),
				"b.yaml":        policyFile(beName, "beta", "v1"),
			})

			startGitAgent(t, repo, beName, be, onDemand)

			awaitApplies(t, be, "alpha", "edge_tcp", "beta")
			for _, p := range []string{"alpha", "edge_tcp", "beta"} {
				requireAppliedOnce(t, be, p, 1)
			}
		})
	}
}

// A policy a commit adds reaches the backend once, as version 1, without
// being removed first, whether the commit adds a file for it or adds it to a
// file already applied. Policies in other files are not sent again.
func TestGitPollAppliesAPolicyAddedInACommitOnce(t *testing.T) {
	beName, be := registerRecordingBackend(t, true)
	repo := newPolicyRepo(t, map[string]string{
		"selector.yaml": selecting("a.yaml"),
		"a.yaml":        policyFile(beName, "alpha", "v1"),
	})
	agent := startGitAgent(t, repo, beName, be, false)

	t.Run("in a new file", func(t *testing.T) {
		be.reset()
		repo.commit(t, map[string]string{
			"selector.yaml": selecting("a.yaml", "b.yaml"),
			"b.yaml":        policyFile(beName, "edge_tcp", "v1"),
		})
		agent.poll()

		requireAppliedOnce(t, be, "edge_tcp", 1)
		assert.Empty(t, be.callsFor("alpha"), "a policy in a file the commit left alone is not sent again")
	})

	t.Run("in a second new file", func(t *testing.T) {
		be.reset()
		repo.commit(t, map[string]string{
			"selector.yaml": selecting("a.yaml", "b.yaml", "c.yaml"),
			"c.yaml":        policyFile(beName, "edge_dns", "v1"),
		})
		agent.poll()

		requireAppliedOnce(t, be, "edge_dns", 1)
		assert.Empty(t, be.callsFor("alpha"))
		assert.Empty(t, be.callsFor("edge_tcp"))
	})

	t.Run("in a file already applied", func(t *testing.T) {
		be.reset()
		repo.commit(t, map[string]string{
			"b.yaml": policyFile(beName, "edge_tcp", "v1", "edge_udp", "v1"),
		})
		agent.poll()

		requireAppliedOnce(t, be, "edge_udp", 1)
		// The commit changed the file, so its other policy is sent again,
		// once, as the next version: a change re-sends the whole file.
		requireUpdatedOnce(t, be, "edge_tcp", 2)
		assert.Empty(t, be.callsFor("alpha"))
		assert.Empty(t, be.callsFor("edge_dns"))
	})
}

// An edited policy is updated once: one removal and one apply of the next
// version, with the new data. Policies in the files the commit left alone
// are not sent again.
func TestGitPollUpdatesAnEditedPolicyOnce(t *testing.T) {
	beName, be := registerRecordingBackend(t, true)
	repo := newPolicyRepo(t, map[string]string{
		"selector.yaml": selecting("a.yaml", "b.yaml"),
		"a.yaml":        policyFile(beName, "alpha", "v1"),
		"b.yaml":        policyFile(beName, "beta", "v1"),
	})
	agent := startGitAgent(t, repo, beName, be, false)

	for _, edit := range []struct {
		value   string
		version int32
	}{{"v2", 2}, {"v3", 3}} {
		be.reset()
		repo.commit(t, map[string]string{"a.yaml": policyFile(beName, "alpha", edit.value)})
		agent.poll()

		requireUpdatedOnce(t, be, "alpha", edit.version)
		assert.Equal(t, map[string]any{"key": edit.value}, be.callsFor("alpha")[1].Data)
		assert.Empty(t, be.callsFor("beta"), "a policy in another file is not sent again")
	}
}

// A policy deleted from the repository is removed from the backend, whether
// it goes with its file or alone from a file that keeps others.
func TestGitPollRemovesADeletedPolicy(t *testing.T) {
	beName, be := registerRecordingBackend(t, true)
	repo := newPolicyRepo(t, map[string]string{
		"selector.yaml": selecting("a.yaml", "b.yaml"),
		"a.yaml":        policyFile(beName, "alpha", "v1", "edge_tcp", "v1"),
		"b.yaml":        policyFile(beName, "beta", "v1"),
	})
	agent := startGitAgent(t, repo, beName, be, false)

	be.reset()
	repo.commit(t, map[string]string{
		"selector.yaml": selecting("a.yaml"),
		"b.yaml":        "",
		"a.yaml":        policyFile(beName, "alpha", "v1"),
	})
	agent.poll()

	for _, p := range []string{"beta", "edge_tcp"} {
		calls := be.callsFor(p)
		require.Len(t, calls, 1, "policy %s: %+v", p, calls)
		assert.Equal(t, "remove", calls[0].Op, "policy %s", p)
	}
	all, err := agent.pm.GetRepo().GetAll()
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.Equal(t, "alpha", all[0].Name)
}
