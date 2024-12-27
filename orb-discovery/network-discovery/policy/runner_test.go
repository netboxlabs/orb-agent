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

	"github.com/netboxlabs/orb-discovery/network-discovery/config"
	"github.com/netboxlabs/orb-discovery/network-discovery/policy"
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
