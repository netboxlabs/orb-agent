package configmgr_test

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr"
)

// Test the localConfigManager implementation
func TestLocalConfigManager(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	pMgr := new(mockPolicyManager)

	t.Run("Start with policies", func(t *testing.T) {
		cfg := config.ManagerConfig{
			Active: "local",
		}

		// Create test configuration with policies
		testConfig := config.Config{
			OrbAgent: config.OrbAgent{
				Policies: map[string]any{
					"testbackend": map[string]any{
						"testpolicy": map[string]string{
							"key": "value",
						},
					},
				},
			},
		}

		// Create a mock backend
		mockBE := &mockBackend{name: "testbackend"}
		backends := map[string]backend.Backend{
			"testbackend": mockBE,
		}

		// Setup expectations
		pMgr.On("ManagePolicy", mock.MatchedBy(func(payload config.PolicyPayload) bool {
			return payload.Name == "testpolicy" &&
				payload.Backend == "testbackend" &&
				payload.Action == "manage"
		})).Return()

		// Create and start the manager
		mgr := configmgr.New(logger, pMgr, cfg)
		err := mgr.Start(testConfig, backends)

		// Verify
		assert.NoError(t, err)
		pMgr.AssertExpectations(t)
	})

	t.Run("Start with no policies", func(t *testing.T) {
		cfg := config.ManagerConfig{
			Active: "local",
		}

		// Create test configuration with no policies
		testConfig := config.Config{}

		backends := map[string]backend.Backend{}

		// Create the manager
		mgr := configmgr.New(logger, pMgr, cfg)
		err := mgr.Start(testConfig, backends)

		// Should return an error
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no policies specified")
	})

	t.Run("Start with missing backend", func(t *testing.T) {
		cfg := config.ManagerConfig{
			Active: "local",
		}

		// Create test configuration with policies for non-existent backend
		testConfig := config.Config{
			OrbAgent: config.OrbAgent{
				Policies: map[string]any{
					"nonexistentbackend": map[string]any{
						"testpolicy": map[string]string{
							"key": "value",
						},
					},
				},
			},
		}

		backends := map[string]backend.Backend{}

		// Create the manager
		mgr := configmgr.New(logger, pMgr, cfg)
		err := mgr.Start(testConfig, backends)

		// Should return an error
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "backend not found")
	})
}
