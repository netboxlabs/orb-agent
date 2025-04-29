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

// MockHost is a mock implementation of the snmp.Walker interface
// to simulate errors during the Walk method.
type MockHost struct {
	mock.Mock
}

func (m *MockHost) Walk(objectID string) (snmp.ObjectIDValueMap, error) {
	args := m.Called(objectID)
	return nil, args.Error(1)
}

func (m *MockHost) Connect() error {
	return nil
}

func (m *MockHost) Close() error {
	return nil
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
			Targets: []config.Target{
				{
					Host: "localhost",
					Port: 161,
				},
			},
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
					Targets: []config.Target{
						{
							Host: "localhost",
							Port: 161,
						},
					},
					Authentication: config.Authentication{
						ProtocolVersion: snmp.ProtocolVersion2c,
						Community:       "public",
					},
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
					Targets: []config.Target{
						{
							Host: "localhost",
							Port: 161,
						},
					},
					Authentication: config.Authentication{
						ProtocolVersion: snmp.ProtocolVersion2c,
						Community:       "public",
					},
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

func TestRunnerIngestCalledWithCorrectValues(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mockClient := new(MockDiodeClient)
	ctx := context.Background()

	policyConfig := config.Policy{
		Config: config.PolicyConfig{},
		Scope: config.Scope{
			Targets: []config.Target{
				{
					Host: "192.168.1.1",
				},
			},
		},
	}

	// Create runner
	runner, err := policy.NewRunner(ctx, logger, "test-policy", policyConfig, mockClient, snmp.NewFakeSNMPWalker)
	assert.NoError(t, err)

	// Use a channel to signal that Ingest was called
	ingestCalled := make(chan bool, 1)

	expectedEntities := []diode.Entity{&diode.IPAddress{Address: diode.String("192.168.1.1/32")}}

	mockClient.On("Ingest", mock.Anything, expectedEntities).Run(func(args mock.Arguments) {
		ingestCalled <- true
		entities := args.Get(1).([]diode.Entity)
		assert.Equal(t, expectedEntities, entities, "Ingest should be called with the correct entities")
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
}

func TestRunnerWalkError(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mockClient := new(MockDiodeClient)
	ctx := context.Background()

	policyConfig := config.Policy{
		Config: config.PolicyConfig{},
		Scope: config.Scope{
			Targets: []config.Target{
				{
					Host: "localhost",
					Port: 161,
				},
			},
			Authentication: config.Authentication{
				ProtocolVersion: snmp.ProtocolVersion2c,
				Community:       "public",
			},
		},
	}

	// Create a mock host that returns an error on Walk
	mockHost := new(MockHost)
	mockHost.On("Walk", mock.Anything).Return(nil, errors.New("walk error"))

	// Create a mock client factory that returns the mock host
	mockClientFactory := func(host string, port uint16, retries int, authentication *config.Authentication) (snmp.Walker, error) {
		return mockHost, nil
	}

	// Create runner with the mock client factory
	runner, err := policy.NewRunner(ctx, logger, "test-policy", policyConfig, mockClient, mockClientFactory)
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
		// Ingest was called, proceed
	case <-time.After(10 * time.Second):
		t.Fatal("Timeout: Ingest was not called")
	}

	// Stop the process
	err = runner.Stop()
	assert.NoError(t, err, "Runner.Stop should not return an error")

	// Verify that the logger captured the error
	// This part depends on how you want to verify the log output
}
