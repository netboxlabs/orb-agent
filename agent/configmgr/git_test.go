package configmgr_test

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	gitv5 "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr"
)

// TestIsAzureDevOpsURL tests the IsAzureDevOpsURL helper function.
func TestIsAzureDevOpsURL(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://dev.azure.com/org/proj/_git/repo", true},
		{"git@ssh.dev.azure.com:v3/org/proj/repo", true},
		{"https://org.visualstudio.com/proj/_git/repo", true},
		{"org@vs-ssh.visualstudio.com:v3/org/proj/repo", true},
		{"https://github.com/org/repo.git", false},
		{"file:///tmp/repo", false},
		{"git@github.com:org/repo.git", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			require.Equal(t, tt.want, configmgr.IsAzureDevOpsURL(tt.url))
		})
	}
}

// TestGitStart tests the Start method of gitConfigManager.
func TestGitStart(t *testing.T) {
	// Create a temporary directory for the fake remote repository.
	remoteDir, err := os.MkdirTemp("", "fake-remote")
	require.NoError(t, err)

	defer func() {
		if err := os.RemoveAll(remoteDir); err != nil {
			require.NoError(t, err, "failed to remove temp dir")
		}
	}()

	// Initialize a new git repository in remoteDir.
	remoteRepo, err := gitv5.PlainInit(remoteDir, false)
	require.NoError(t, err)

	// Create a minimal selector.yaml file.
	selectorContent := `
test_selector:
  selector:
    env: test
  policies:
    test_policy:
      enabled: true
      path: "policy.yaml"
`
	selectorPath := filepath.Join(remoteDir, "selector.yaml")
	err = os.WriteFile(selectorPath, []byte(selectorContent), 0o644)
	require.NoError(t, err)

	// Create a minimal policy file.
	policyContent := `
backend1:
  test_policy:
    key: "value"
`
	policyPath := filepath.Join(remoteDir, "policy.yaml")
	err = os.WriteFile(policyPath, []byte(policyContent), 0o644)
	require.NoError(t, err)

	// Add and commit files.
	w, err := remoteRepo.Worktree()
	require.NoError(t, err)
	_, err = w.Add("selector.yaml")
	require.NoError(t, err)
	_, err = w.Add("policy.yaml")
	require.NoError(t, err)
	commitMsg := "initial commit"
	_, err = w.Commit(commitMsg, &gitv5.CommitOptions{
		Author: &object.Signature{
			Name:  "tester",
			Email: "tester@example.com",
			When:  time.Now(),
		},
	})
	require.NoError(t, err)

	// Build a file:// URL for the repository.
	repoURL := "file://" + remoteDir

	// Create a fake policy manager.
	pMgr := new(mockPolicyManager)

	// Build a minimal config for testing.
	schedule := "* * * * *"
	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			Labels: map[string]string{"env": "test"},
			ConfigManager: config.ManagerConfig{
				Active: "git",
				Sources: config.Sources{
					Git: config.GitManager{
						URL:      repoURL,
						Branch:   "",        // let it detect default branch
						Auth:     "",        // no auth for file:// protocol
						Schedule: &schedule, // every minute
					},
				},
			},
		},
	}

	// Create a logger.
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Instantiate the gitConfigManager.
	gc := configmgr.New(logger, pMgr, cfg.OrbAgent.ConfigManager.Active, &mockBackendState{}, nil)

	// Call Start
	backends := map[string]backend.Backend{
		"backend1": &mockBackend{name: "backend1"},
	}

	pMgr.On("ManagePolicy", mock.MatchedBy(func(payload config.PolicyPayload) bool {
		return payload.Backend == "backend1" &&
			payload.Action == "manage"
	})).Return()

	err = gc.Start(context.Background(), cfg, backends)
	require.NoError(t, err)
}

// TestGitStartNoMatchingPolicies ensures Start returns an error when no selector entries match agent labels.
func TestGitStartNoMatchingPolicies(t *testing.T) {
	remoteDir, err := os.MkdirTemp("", "fake-remote-nomatch")
	require.NoError(t, err)
	defer func() {
		if err := os.RemoveAll(remoteDir); err != nil {
			require.NoError(t, err, "failed to remove temp dir")
		}
	}()

	remoteRepo, err := gitv5.PlainInit(remoteDir, false)
	require.NoError(t, err)

	selectorContent := `
test_selector:
  selector:
    env: prod
  policies:
    test_policy:
      enabled: true
      path: "policy.yaml"
`
	require.NoError(t, os.WriteFile(filepath.Join(remoteDir, "selector.yaml"), []byte(selectorContent), 0o644))

	policyContent := `
backend1:
  test_policy:
    key: "value"
`
	require.NoError(t, os.WriteFile(filepath.Join(remoteDir, "policy.yaml"), []byte(policyContent), 0o644))

	worktree, err := remoteRepo.Worktree()
	require.NoError(t, err)
	_, err = worktree.Add("selector.yaml")
	require.NoError(t, err)
	_, err = worktree.Add("policy.yaml")
	require.NoError(t, err)
	_, err = worktree.Commit("initial commit", &gitv5.CommitOptions{
		Author: &object.Signature{
			Name:  "tester",
			Email: "tester@example.com",
			When:  time.Now(),
		},
	})
	require.NoError(t, err)

	repoURL := "file://" + remoteDir
	pMgr := new(mockPolicyManager)
	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			Labels: map[string]string{"env": "dev"},
			ConfigManager: config.ManagerConfig{
				Active: "git",
				Sources: config.Sources{
					Git: config.GitManager{
						URL:  repoURL,
						Auth: "", // no auth for file:// protocol
					},
				},
			},
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	gc := configmgr.New(logger, pMgr, cfg.OrbAgent.ConfigManager.Active, &mockBackendState{}, nil)

	backends := map[string]backend.Backend{
		"backend1": &mockBackend{name: "backend1"},
	}

	err = gc.Start(context.Background(), cfg, backends)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no policies match the selector")
	pMgr.AssertNotCalled(t, "ManagePolicy", mock.Anything)
}

// TestGitStartUnsupportedAuthMode verifies that a misspelled auth mode fails
// startup instead of silently falling back to unauthenticated access. Auth is
// resolved before any network I/O, so no repository is needed.
func TestGitStartUnsupportedAuthMode(t *testing.T) {
	for _, auth := range []string{"none", "bacsic", "github-app"} {
		t.Run(auth, func(t *testing.T) {
			pMgr := new(mockPolicyManager)
			cfg := config.Config{
				OrbAgent: config.OrbAgent{
					ConfigManager: config.ManagerConfig{
						Active: "git",
						Sources: config.Sources{
							Git: config.GitManager{
								URL:  "https://example.com/org/policyrepo.git",
								Auth: auth,
							},
						},
					},
				},
			}

			logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
			gc := configmgr.New(logger, pMgr, cfg.OrbAgent.ConfigManager.Active, &mockBackendState{}, nil)

			err := gc.Start(context.Background(), cfg, map[string]backend.Backend{})
			require.Error(t, err)
			require.Contains(t, err.Error(), "unsupported git auth mode")
			pMgr.AssertNotCalled(t, "ManagePolicy", mock.Anything)
		})
	}
}

// TestGitStartAzureDevOpsURLFallback verifies that an Azure DevOps URL triggers
// the system git fallback path.  A local bare repo is used as the "remote"; a
// git URL rewrite (via GIT_CONFIG_GLOBAL) redirects the dev.azure.com URL to
// the filesystem so the test runs without network access.
func TestGitStartAzureDevOpsURLFallback(t *testing.T) {
	// Skip if system git is not available.
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("system git not found, skipping ADO fallback test")
	}

	// Create a source repo with selector.yaml + policy.yaml.
	sourceDir, err := os.MkdirTemp("", "ado-source-*")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, os.RemoveAll(sourceDir))
	}()

	sourceRepo, err := gitv5.PlainInit(sourceDir, false)
	require.NoError(t, err)

	selectorContent := `
ado_selector:
  selector:
    env: test
  policies:
    ado_policy:
      enabled: true
      path: "policy.yaml"
`
	policyContent := `
backend1:
  ado_policy:
    key: value
`
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "selector.yaml"), []byte(selectorContent), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "policy.yaml"), []byte(policyContent), 0o644))

	wt, err := sourceRepo.Worktree()
	require.NoError(t, err)
	_, err = wt.Add("selector.yaml")
	require.NoError(t, err)
	_, err = wt.Add("policy.yaml")
	require.NoError(t, err)
	_, err = wt.Commit("initial commit", &gitv5.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@test.com", When: time.Now()},
	})
	require.NoError(t, err)

	// Create a bare clone to act as the remote.
	bareDir, err := os.MkdirTemp("", "ado-bare-*")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, os.RemoveAll(bareDir))
	}()

	bareRepoPath := filepath.Join(bareDir, "repo.git")
	out, err := exec.Command("git", "clone", "--bare", sourceDir, bareRepoPath).CombinedOutput()
	require.NoError(t, err, "bare clone failed: %s", out)

	// Write a gitconfig that rewrites the ADO URL to the local bare repo.
	adoURL := "https://dev.azure.com/test/org/_git/testrepo"
	localURL := "file://" + bareRepoPath
	gitconfigContent := "[url \"" + localURL + "\"]\n\tinsteadOf = " + adoURL + "\n"
	gitconfigPath := filepath.Join(t.TempDir(), "test-gitconfig")
	require.NoError(t, os.WriteFile(gitconfigPath, []byte(gitconfigContent), 0o644))

	// Point git at our test config so the URL rewrite takes effect.
	t.Setenv("GIT_CONFIG_GLOBAL", gitconfigPath)

	// Confirm URL detection.
	require.True(t, configmgr.IsAzureDevOpsURL(adoURL), "expected IsAzureDevOpsURL to return true")

	pMgr := new(mockPolicyManager)
	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			Labels: map[string]string{"env": "test"},
			ConfigManager: config.ManagerConfig{
				Active: "git",
				Sources: config.Sources{
					Git: config.GitManager{
						URL:    adoURL,
						Branch: "", // auto-detect
						Auth:   "", // no auth for file:// protocol
					},
				},
			},
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	gc := configmgr.New(logger, pMgr, "git", &mockBackendState{}, nil)

	backends := map[string]backend.Backend{
		"backend1": &mockBackend{name: "backend1"},
	}

	pMgr.On("ManagePolicy", mock.MatchedBy(func(p config.PolicyPayload) bool {
		return p.Backend == "backend1" && p.Action == "manage"
	})).Return()

	err = gc.Start(context.Background(), cfg, backends)
	require.NoError(t, err, "Start() via system git fallback should succeed")
	pMgr.AssertCalled(t, "ManagePolicy", mock.Anything)
}
