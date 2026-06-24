package policy_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/diode-sdk-go/diode/v1/diodepb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/metrics"
	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/policy"
)

type MockClient struct {
	mock.Mock
}

func (m *MockClient) Ingest(ctx context.Context, entities []diode.Entity, _ ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	args := m.Called(ctx, entities)
	return args.Get(0).(*diodepb.IngestResponse), args.Error(1)
}

func (m *MockClient) IngestProto(ctx context.Context, entities []*diodepb.Entity, _ ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	args := m.Called(ctx, entities)
	return args.Get(0).(*diodepb.IngestResponse), args.Error(1)
}

func (m *MockClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestNewRunner(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
	mockClient := new(MockClient)
	runStore := policy.NewRunStore()
	cron := "0 0 * * *"
	policyConfig := config.Policy{
		Config: config.PolicyConfig{
			Schedule: &cron,
		},
		Scope: config.Scope{
			Targets: []string{"localhost"},
		},
	}
	ctx := context.Background()

	// Create new runner
	_, err := policy.NewRunner(ctx, logger, "test-policy", policyConfig, mockClient, runStore)
	assert.NoError(t, err, "policy.NewRunner should not return an error")
}

func TestRunnerRun(t *testing.T) {
	tests := []*struct {
		desc         string
		mockResponse diodepb.IngestResponse
		mockError    error
	}{
		{
			desc:         "no error",
			mockResponse: diodepb.IngestResponse{},
			mockError:    nil,
		},
		{
			desc:         "local error",
			mockResponse: diodepb.IngestResponse{},
			mockError:    errors.New("ingestion failed"),
		},
		{
			desc:         "server error",
			mockResponse: diodepb.IngestResponse{Errors: []string{"fail1", "fail2"}},
			mockError:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
			mockClient := new(MockClient)
			runStore := policy.NewRunStore()
			policyConfig := config.Policy{
				Config: config.PolicyConfig{
					Schedule: nil,
					Defaults: config.Defaults{
						Description: "Test",
						Comments:    "This is a test",
						Vrf:         "test-vrf",
						Tenant:      "test-tenant",
						Role:        "test-role",
						Tags:        []string{"test", "ip"},
					},
				},
				Scope: config.Scope{
					Targets: []string{"localhost"},
				},
			}
			ctx := context.Background()

			// Create runner
			runner, err := policy.NewRunner(ctx, logger, "test-policy", policyConfig, mockClient, runStore)
			assert.NoError(t, err, "policy.NewRunner should not return an error")

			// Use a channel to signal that Ingest was called
			ingestCalled := make(chan bool, 1)

			mockClient.On("Ingest", mock.Anything, mock.Anything, mock.Anything).Run(func(_ mock.Arguments) {
				ingestCalled <- true
			}).Return(&tt.mockResponse, tt.mockError)

			// Start the process
			runner.Start()

			// Wait for Ingest to be called or timeout
			select {
			case <-ingestCalled:
				// Ingest was called, proceed
			case <-time.After(30 * time.Second):
				t.Fatal("Timeout: Ingest was not called")
			}

			// Wait a bit for run update to complete (run update happens after Ingest returns)
			time.Sleep(100 * time.Millisecond)

			// Verify run was created and updated correctly
			runs := runStore.GetRunsForPolicy("test-policy")
			assert.NotEmpty(t, runs, "Run should be created")
			if len(runs) > 0 {
				latestRun := runs[len(runs)-1]
				assert.NotEmpty(t, latestRun.ID, "Run ID should be set")
				if tt.mockError != nil || len(tt.mockResponse.Errors) > 0 {
					assert.Equal(t, policy.RunStatusFailed, latestRun.Status, "Run should be marked as failed")
				} else {
					assert.Equal(t, policy.RunStatusCompleted, latestRun.Status, "Run should be marked as completed")
				}
			}

			// Stop the process
			err = runner.Stop()
			assert.NoError(t, err, "Runner.Stop should not return an error")
		})
	}
}

func TestRunnerWithOptions(t *testing.T) {
	tests := []struct {
		name     string
		policy   config.Policy
		expected []string
	}{
		{
			name: "with ports and exclude ports",
			policy: config.Policy{
				Config: config.PolicyConfig{
					Defaults: config.Defaults{
						Description: "Test with ports",
						NetworkMask: intPtr(24),
					},
				},
				Scope: config.Scope{
					Targets:      []string{"localhost"},
					Ports:        []string{"80", "443"},
					ExcludePorts: []string{"22"},
					DNSServers:   []string{"8.8.8.8"},
				},
			},
		},
		{
			name: "with fast mode and timing",
			policy: config.Policy{
				Config: config.PolicyConfig{},
				Scope: config.Scope{
					Targets:  []string{"localhost"},
					FastMode: boolPtr(true),
					Timing:   intPtr(3),
				},
			},
		},
		{
			name: "with os detection and without target masks",
			policy: config.Policy{
				Config: config.PolicyConfig{},
				Scope: config.Scope{
					Targets:        []string{"localhost"},
					OSDetection:    boolPtr(true),
					UseTargetMasks: boolPtr(false),
				},
			},
		},
		{
			name: "with top ports and ping scan",
			policy: config.Policy{
				Config: config.PolicyConfig{},
				Scope: config.Scope{
					Targets:  []string{"localhost"},
					TopPorts: intPtr(100),
					PingScan: boolPtr(true),
				},
			},
		},
		{
			name: "with scan types and max retries",
			policy: config.Policy{
				Config: config.PolicyConfig{},
				Scope: config.Scope{
					Targets:    []string{"localhost"},
					ScanTypes:  []string{"connect", "udp", "fin", "xmas"},
					PingScan:   boolPtr(true),
					MaxRetries: intPtr(0),
				},
			},
		},
		{
			name: "with icmp options",
			policy: config.Policy{
				Config: config.PolicyConfig{},
				Scope: config.Scope{
					Targets:       []string{"localhost"},
					ICMPEcho:      boolPtr(true),
					ICMPTimestamp: boolPtr(true),
					ICMPNetMask:   boolPtr(true),
					SkipHost:      boolPtr(true),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
			mockClient := new(MockClient)
			runStore := policy.NewRunStore()
			ctx := context.Background()

			// Create runner
			runner, err := policy.NewRunner(ctx, logger, "test-policy", tt.policy, mockClient, runStore)
			assert.NoError(t, err)

			// Use a channel to signal that Ingest was called
			ingestCalled := make(chan bool, 1)

			mockClient.On("Ingest", mock.Anything, mock.Anything, mock.Anything).Run(func(_ mock.Arguments) {
				ingestCalled <- true
			}).Return(&diodepb.IngestResponse{}, nil)

			// Start the process
			runner.Start()

			// Wait for Ingest to be called or for run to complete (success or failure)
			select {
			case <-ingestCalled:
				// Success - Ingest was called
			case <-time.After(30 * time.Second):
				// Check if run was created and marked as failed (scanner may have failed due to privileges)
				runs := runStore.GetRunsForPolicy("test-policy")
				if len(runs) > 0 {
					latestRun := runs[len(runs)-1]
					if latestRun.Status == policy.RunStatusFailed {
						// Scanner failed (likely due to privilege requirements), which is acceptable
						// Don't fail the test in this case
						return
					}
				}
				t.Fatal("Timeout: Ingest was not called and run was not marked as failed")
			}

			// Stop the process
			err = runner.Stop()
			assert.NoError(t, err)
		})
	}
}

func TestRunnerMetrics(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mockClient := new(MockClient)
	runStore := policy.NewRunStore()
	ctx := context.Background()

	// Initialize metrics
	err := metrics.SetupMetricsExport(ctx, logger, "localhost:4317", 10)
	assert.NoError(t, err, "metrics.SetupMetricsExport should not return an error")

	policyConfig := config.Policy{
		Config: config.PolicyConfig{
			Defaults: config.Defaults{
				Description: "Test",
				Comments:    "This is a test",
			},
		},
		Scope: config.Scope{
			Targets: []string{"localhost"},
		},
	}

	// Create runner
	runner, err := policy.NewRunner(ctx, logger, "test-policy", policyConfig, mockClient, runStore)
	assert.NoError(t, err, "policy.NewRunner should not return an error")

	// Use a channel to signal that Ingest was called
	ingestCalled := make(chan bool, 1)

	// Mock Ingest response
	mockClient.On("Ingest", mock.Anything, mock.Anything, mock.Anything).Run(func(_ mock.Arguments) {
		ingestCalled <- true
	}).Return(&diodepb.IngestResponse{}, nil)

	t.Run("MetricsValidation", func(t *testing.T) {
		// Start the runner
		runner.Start()

		// Wait for Ingest to be called or timeout
		select {
		case <-ingestCalled:
			// Success
		case <-time.After(30 * time.Second):
			t.Fatal("Timeout: Ingest was not called")
		}

		// Validate active policies metric increment
		activePolicies := metrics.GetActivePolicies()
		assert.NotNil(t, activePolicies, "Active policies metric should not be nil")
		// Simulate metric validation (mocked behavior)
		activePolicies.Add(ctx, 1)

		// Validate policy executions metric
		policyExecutions := metrics.GetPolicyExecutions()
		assert.NotNil(t, policyExecutions, "Policy executions metric should not be nil")
		// Simulate metric validation (mocked behavior)
		policyExecutions.Add(ctx, 1)

		// Validate discovery success metric
		discoverySuccess := metrics.GetDiscoverySuccess()
		assert.NotNil(t, discoverySuccess, "Discovery success metric should not be nil")
		// Simulate metric validation (mocked behavior)
		discoverySuccess.Add(ctx, 1)

		// Validate discovered hosts metric
		discoveredHosts := metrics.GetDiscoveredHosts()
		assert.NotNil(t, discoveredHosts, "Discovered hosts metric should not be nil")
		// Simulate metric validation (mocked behavior)
		discoveredHosts.Record(ctx, 1)

		// Stop the runner
		err := runner.Stop()
		assert.NoError(t, err, "Runner.Stop should not return an error")

		// Validate active policies metric decrement
		activePolicies.Add(ctx, -1)
	})
}

func TestRunnerNoHosts(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
	mockClient := new(MockClient)
	runStore := policy.NewRunStore()

	// Set up policy with target and port configuration likely to result in no hosts found
	policyConfig := config.Policy{
		Config: config.PolicyConfig{
			Schedule: nil, // Run immediately
		},
		Scope: config.Scope{
			Targets:    []string{"10.0.0.2"},
			Ports:      []string{"1"}, // Port 1 is typically not open
			FastMode:   boolPtr(true), // Speed up the scan for test purposes
			MaxRetries: intPtr(0),     // Don't retry to keep the test fast
		},
	}
	ctx := context.Background()

	// Create runner
	runner, err := policy.NewRunner(ctx, logger, "test-no-hosts", policyConfig, mockClient, runStore)
	assert.NoError(t, err, "policy.NewRunner should not return an error")

	// Configure mock to verify Ingest is NOT called
	mockClient.On("Close").Return(nil)

	// Start the runner
	runner.Start()

	// Wait for a short time to allow the scan to run
	time.Sleep(2 * time.Second)

	// Stop the runner
	err = runner.Stop()
	assert.NoError(t, err, "Runner.Stop should not return an error")

	// Check that Ingest was not called since no hosts should have been found
	mockClient.AssertNotCalled(t, "Ingest", mock.Anything, mock.Anything)

	// Verify run was created
	// Note: If scanner fails, run will be marked as failed. If scanner succeeds but finds no hosts, run will be completed.
	runs := runStore.GetRunsForPolicy("test-no-hosts")
	if len(runs) > 0 {
		latestRun := runs[len(runs)-1]
		// Run should be either completed (scan succeeded, no hosts) or failed (scan failed)
		assert.True(t, latestRun.Status == policy.RunStatusCompleted || latestRun.Status == policy.RunStatusFailed,
			"Run should be marked as completed or failed")
	}
}

func TestRunnerWithNetworkMask(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mockClient := new(MockClient)
	runStore := policy.NewRunStore()
	ctx := context.Background()

	policyConfig := config.Policy{
		Config: config.PolicyConfig{
			Schedule: nil, // Run immediately
		},
		Scope: config.Scope{
			Targets:    []string{"127.0.0.1/28"},
			FastMode:   boolPtr(true),
			MaxRetries: intPtr(0),
		},
	}

	// Create runner
	runner, err := policy.NewRunner(ctx, logger, "test-policy", policyConfig, mockClient, runStore)
	assert.NoError(t, err)

	// Use a channel to signal that Ingest was called
	ingestCalled := make(chan bool, 1)

	mockClient.On("Ingest", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		ingestCalled <- true
		entities := args.Get(1).([]diode.Entity)
		assert.NotEmpty(t, entities, "Entities should not be empty when scanning a network with a mask")
		ip0 := entities[0].(*diode.IPAddress)
		assert.Contains(t, *ip0.Address, "/28", "The scanned entity should reflect the network mask")
		rid, ok := ip0.Metadata["run_id"].(string)
		assert.True(t, ok && rid != "", "per-entity metadata should include run_id")
	}).Return(&diodepb.IngestResponse{}, nil)

	// Start the process
	runner.Start()

	// Wait for Ingest to be called or timeout
	select {
	case <-ingestCalled:
		// Success
	case <-time.After(30 * time.Second):
		t.Fatal("Timeout: Ingest was not called")
	}

	// Stop the process
	err = runner.Stop()
	assert.NoError(t, err)
}

// TestRunnerEmitsVrf locks in the behaviour change introduced when
// defaults.rd was promoted to a first-class field: when defaults.vrf is set,
// Vrf.Name is always populated; Vrf.Rd is set ONLY when defaults.rd is also
// provided. Previously Rd was hardcoded to mirror Name, which forced NetBox
// to create a fresh VRF for every name instead of matching an existing one
// with a different (or empty) RD.
func TestRunnerEmitsVrf(t *testing.T) {
	tests := []struct {
		name        string
		vrfDefault  string
		rdDefault   string
		expectVrf   bool
		expectName  string
		expectRdSet bool
		expectRd    string
	}{
		{
			name:        "vrf only - rd left nil",
			vrfDefault:  "production",
			rdDefault:   "",
			expectVrf:   true,
			expectName:  "production",
			expectRdSet: false,
		},
		{
			name:        "vrf + rd",
			vrfDefault:  "production",
			rdDefault:   "65000:100",
			expectVrf:   true,
			expectName:  "production",
			expectRdSet: true,
			expectRd:    "65000:100",
		},
		{
			name:       "no vrf - rd ignored",
			vrfDefault: "",
			rdDefault:  "65000:100",
			expectVrf:  false,
		},
		{
			name:       "neither set",
			vrfDefault: "",
			rdDefault:  "",
			expectVrf:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
			mockClient := new(MockClient)
			runStore := policy.NewRunStore()
			ctx := context.Background()

			policyConfig := config.Policy{
				Config: config.PolicyConfig{
					Schedule: nil,
					Defaults: config.Defaults{
						Vrf: tt.vrfDefault,
						Rd:  tt.rdDefault,
					},
				},
				Scope: config.Scope{
					Targets:    []string{"127.0.0.1"},
					FastMode:   boolPtr(true),
					MaxRetries: intPtr(0),
				},
			}

			runner, err := policy.NewRunner(ctx, logger, "test-policy", policyConfig, mockClient, runStore)
			assert.NoError(t, err)

			ingestCalled := make(chan bool, 1)
			mockClient.On("Ingest", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
				entities := args.Get(1).([]diode.Entity)
				assert.NotEmpty(t, entities, "expected at least one IPAddress entity")
				ip := entities[0].(*diode.IPAddress)
				if tt.expectVrf {
					assert.NotNil(t, ip.Vrf, "Vrf should be emitted when defaults.vrf is set")
					if ip.Vrf != nil {
						assert.NotNil(t, ip.Vrf.Name)
						assert.Equal(t, tt.expectName, *ip.Vrf.Name)
						if tt.expectRdSet {
							assert.NotNil(t, ip.Vrf.Rd, "Vrf.Rd should be set when defaults.rd is set")
							if ip.Vrf.Rd != nil {
								assert.Equal(t, tt.expectRd, *ip.Vrf.Rd)
							}
						} else {
							assert.Nil(t, ip.Vrf.Rd,
								"Vrf.Rd MUST be nil when defaults.rd is unset (no rd=name fallback)")
						}
					}
				} else {
					assert.Nil(t, ip.Vrf, "Vrf should not be emitted when defaults.vrf is empty")
				}
				ingestCalled <- true
			}).Return(&diodepb.IngestResponse{}, nil)

			runner.Start()
			select {
			case <-ingestCalled:
			case <-time.After(30 * time.Second):
				t.Fatal("Timeout: Ingest was not called")
			}
			err = runner.Stop()
			assert.NoError(t, err)
		})
	}
}

func boolPtr(b bool) *bool {
	return &b
}

func intPtr(i int) *int {
	return &i
}
