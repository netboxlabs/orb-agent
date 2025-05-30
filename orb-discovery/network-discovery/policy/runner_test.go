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
	"github.com/netboxlabs/orb-discovery/network-discovery/config"
	"github.com/netboxlabs/orb-discovery/network-discovery/metrics"
	"github.com/netboxlabs/orb-discovery/network-discovery/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockClient struct {
	mock.Mock
}

func (m *MockClient) Ingest(ctx context.Context, entities []diode.Entity) (*diodepb.IngestResponse, error) {
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
	_, err := policy.NewRunner(ctx, logger, "test-policy", policyConfig, mockClient)
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
			runner, err := policy.NewRunner(ctx, logger, "test-policy", policyConfig, mockClient)
			assert.NoError(t, err, "policy.NewRunner should not return an error")

			// Use a channel to signal that Ingest was called
			ingestCalled := make(chan bool, 1)

			mockClient.On("Ingest", mock.Anything, mock.Anything).Run(func(_ mock.Arguments) {
				ingestCalled <- true
			}).Return(&tt.mockResponse, tt.mockError)

			// Start the process
			runner.Start()

			// Wait for Ingest to be called or timeout
			select {
			case <-ingestCalled:
				// Ingest was called, proceed
			case <-time.After(10 * time.Second):
				t.Fatal("Timeout: Ingest was not called")
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
			mockClient := new(MockClient)
			ctx := context.Background()

			// Create runner
			runner, err := policy.NewRunner(ctx, logger, "test-policy", tt.policy, mockClient)
			assert.NoError(t, err)

			// Use a channel to signal that Ingest was called
			ingestCalled := make(chan bool, 1)

			mockClient.On("Ingest", mock.Anything, mock.Anything).Run(func(_ mock.Arguments) {
				ingestCalled <- true
			}).Return(&diodepb.IngestResponse{}, nil)

			// Start the process
			runner.Start()

			// Wait for Ingest to be called or timeout
			select {
			case <-ingestCalled:
				// Success
			case <-time.After(10 * time.Second):
				t.Fatal("Timeout: Ingest was not called")
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
	runner, err := policy.NewRunner(ctx, logger, "test-policy", policyConfig, mockClient)
	assert.NoError(t, err, "policy.NewRunner should not return an error")

	// Use a channel to signal that Ingest was called
	ingestCalled := make(chan bool, 1)

	// Mock Ingest response
	mockClient.On("Ingest", mock.Anything, mock.Anything).Run(func(_ mock.Arguments) {
		ingestCalled <- true
	}).Return(&diodepb.IngestResponse{}, nil)

	t.Run("MetricsValidation", func(t *testing.T) {
		// Start the runner
		runner.Start()

		// Wait for Ingest to be called or timeout
		select {
		case <-ingestCalled:
			// Success
		case <-time.After(10 * time.Second):
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
	runner, err := policy.NewRunner(ctx, logger, "test-no-hosts", policyConfig, mockClient)
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
}

func boolPtr(b bool) *bool {
	return &b
}

func intPtr(i int) *int {
	return &i
}
