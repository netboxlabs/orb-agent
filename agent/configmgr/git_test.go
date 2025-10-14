package configmgr_test

import (
	"log/slog"
	"os"
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
						Auth:     "none",    // no auth for file:// protocol
						Schedule: &schedule, // every minute
					},
				},
			},
		},
	}

	// Create a logger.
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Instantiate the gitConfigManager.
	gc := configmgr.New(logger, pMgr, cfg.OrbAgent.ConfigManager.Active, &mockBackendState{})

	// Call Start
	backends := map[string]backend.Backend{
		"backend1": &mockBackend{name: "backend1"},
	}

	pMgr.On("ManagePolicy", mock.MatchedBy(func(payload config.PolicyPayload) bool {
		return payload.Backend == "backend1" &&
			payload.Action == "manage"
	})).Return()

	err = gc.Start(cfg, backends)
	require.NoError(t, err)
}
