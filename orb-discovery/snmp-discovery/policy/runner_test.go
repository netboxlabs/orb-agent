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

	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/policy"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/snmp"
)

type MockDiodeClient struct {
	mock.Mock
}

func (m *MockDiodeClient) Ingest(ctx context.Context, entities []diode.Entity) (*diodepb.IngestResponse, error) {
	args := m.Called(ctx, entities)
	return args.Get(0).(*diodepb.IngestResponse), args.Error(1)
}

func (m *MockDiodeClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestNewRunner(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
	mockClient := new(MockDiodeClient)
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
	_, err := policy.NewRunner(ctx, logger, "test-policy", policyConfig, mockClient, snmp.NewFakeSNMPWalker)
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
			mockClient := new(MockDiodeClient)
			policyConfig := config.Policy{
				Config: config.PolicyConfig{
					Schedule: nil,
					Defaults: config.Defaults{
						Description: "Test",
						Comments:    "This is a test",
						Tags:        []string{"test", "snmp"},
					},
				},
				Scope: config.Scope{
					Targets: []string{"localhost"},
				},
			}
			ctx := context.Background()

			// Create runner
			runner, err := policy.NewRunner(ctx, logger, "test-policy", policyConfig, mockClient, snmp.NewFakeSNMPWalker)
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
			name: "with SNMP version and community",
			policy: config.Policy{
				Config: config.PolicyConfig{},
				Scope: config.Scope{
					Targets: []string{"localhost"},
				},
			},
		},
		{
			name: "with SNMPv3 credentials",
			policy: config.Policy{
				Config: config.PolicyConfig{},
				Scope: config.Scope{
					Targets: []string{"localhost"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
			mockClient := new(MockDiodeClient)
			ctx := context.Background()

			// Create runner
			runner, err := policy.NewRunner(ctx, logger, "test-policy", tt.policy, mockClient, snmp.NewFakeSNMPWalker)
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

// func TestSNMPDataMappingAndIngestion(t *testing.T) {
// 	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
// 	mockClient := new(MockDiodeClient)
// 	ctx := context.Background()

// 	// Map SNMP data to entities
// 	expectedEntities := []diode.Entity{
// 		&diode.IPAddress{
// 			Address: diode.String("192.168.1.1"),
// 		},
// 	}

// 	// Setup mock client expectations
// 	mockClient.On("Ingest", mock.Anything, mock.Anything).Return(&diodepb.IngestResponse{}, nil)

// 	// Create runner
// 	runner, err := policy.NewRunner(ctx, logger, "test-successful-ingestion-policy", config.Policy{
// 		Config: config.PolicyConfig{},
// 		Scope: config.Scope{
// 			Targets: []string{"192.168.1.1"},
// 		},
// 	}, mockClient, snmp.NewFakeSNMPWalker)
// 	assert.NoError(t, err)

// 	// Start the process
// 	runner.Start()

// 	time.Sleep(3 * time.Second)

// 	// Stop the process
// 	err = runner.Stop()
// 	assert.NoError(t, err)

// 	// Verify that Ingest was called with the expected entities
// 	mockClient.AssertCalled(t, "Ingest", mock.Anything, expectedEntities)
// }
