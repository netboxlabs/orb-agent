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
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/metrics"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/policy"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/snmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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

func (m *MockHost) Walk(objectID string, identifierSize int) (map[string]snmp.PDU, error) {
	args := m.Called(objectID, identifierSize)
	return args.Get(0).(map[string]snmp.PDU), args.Error(1)
}

func (m *MockHost) Connect() error {
	return nil
}

func (m *MockHost) Close() error {
	return nil
}

func setupTestMetrics(t *testing.T) {
	err := metrics.SetupMetricsExport(context.Background(), slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})), "http://localhost:4317", 10)
	require.NoError(t, err)
}

func TestNewRunner(t *testing.T) {
	setupTestMetrics(t)
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
			Mappings: []config.MappingEntry{
				{
					OID:    "iso.3.6.1.2.1.2.2.1",
					Entity: "interface",
					Field:  "_id",
					MappingEntries: []config.MappingEntry{
						{
							OID:    "iso.3.6.1.2.1.2.2.1.2",
							Entity: "interface",
							Field:  "name",
						},
					},
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
	setupTestMetrics(t)
	tests := []*struct {
		desc          string
		mockResponse  diodepb.IngestResponse
		mockError     error
		expectSuccess bool
		expectFailure bool
	}{
		{
			desc:          "no error",
			mockResponse:  diodepb.IngestResponse{},
			mockError:     nil,
			expectSuccess: true,
			expectFailure: false,
		},
		{
			desc:          "local error",
			mockResponse:  diodepb.IngestResponse{},
			mockError:     errors.New("ingestion failed"),
			expectSuccess: false,
			expectFailure: true,
		},
		{
			desc:          "server error",
			mockResponse:  diodepb.IngestResponse{Errors: []string{"fail1", "fail2"}},
			mockError:     nil,
			expectSuccess: false,
			expectFailure: true,
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
						Tags: []string{"test", "snmp"},
						IPAddress: config.IPAddressDefaults{
							Description: "IP Address Default",
							Comments:    "IP Address Comment",
							Tags:        []string{"ip", "default"},
						},
						Interface: config.InterfaceDefaults{
							Description: "Interface Default",
							Tags:        []string{"interface", "default"},
							Type:        "unknown",
						},
						Device: config.DeviceDefaults{
							Description: "Device Default",
							Tags:        []string{"device", "default"},
						},
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
					Mappings: []config.MappingEntry{
						{
							OID:    "iso.3.6.1.2.1.2.2.1",
							Entity: "interface",
							Field:  "_id",
							MappingEntries: []config.MappingEntry{
								{
									OID:    "iso.3.6.1.2.1.2.2.1.2",
									Entity: "interface",
									Field:  "name",
								},
							},
						},
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

			// Verify metrics were recorded
			if tt.expectSuccess {
				assert.NotNil(t, metrics.GetDiscoverySuccess())
			}
			if tt.expectFailure {
				assert.NotNil(t, metrics.GetDiscoveryFailure())
			}
			assert.NotNil(t, metrics.GetDiscoveryAttempts())
			assert.NotNil(t, metrics.GetDiscoveryLatency())
		})
	}
}

func TestRunnerIngestCalledWithCorrectValues(t *testing.T) {
	setupTestMetrics(t)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mockClient := new(MockDiodeClient)
	ctx := context.Background()

	policyConfig := config.Policy{
		Config: config.PolicyConfig{
			Defaults: config.Defaults{
				Tags: []string{"test", "snmp"},
				IPAddress: config.IPAddressDefaults{
					Description: "IP Address Default",
					Comments:    "IP Address Comment",
					Tags:        []string{"ip", "default"},
				},
				Interface: config.InterfaceDefaults{
					Description: "Interface Default",
					Tags:        []string{"interface", "default"},
					Type:        "virtual",
				},
				Device: config.DeviceDefaults{
					Description: "Device Default",
					Tags:        []string{"device", "default"},
				},
			},
		},
		Scope: config.Scope{
			Targets: []config.Target{
				{
					Host: "192.168.1.1",
				},
			},
			Mappings: []config.MappingEntry{
				{
					OID:    "iso.3.6.1.2.1.2.2.1",
					Entity: "interface",
					Field:  "_id",
					MappingEntries: []config.MappingEntry{
						{
							OID:    "iso.3.6.1.2.1.2.2.1.2",
							Entity: "interface",
							Field:  "name",
						},
					},
				},
			},
		},
	}

	// Create runner
	runner, err := policy.NewRunner(ctx, logger, "test-policy", policyConfig, mockClient, snmp.NewFakeSNMPWalker)
	assert.NoError(t, err)

	// Use a channel to signal that Ingest was called
	ingestCalled := make(chan bool, 1)

	expectedEntities := []diode.Entity{
		&diode.Interface{
			Name:        diode.String("GigabitEthernet1/0/1"),
			Description: diode.String("Interface Default"),
			Tags: []*diode.Tag{
				{Name: diode.String("interface")},
				{Name: diode.String("default")},
				{Name: diode.String("test")},
				{Name: diode.String("snmp")},
			},
			Type: diode.String("virtual"),
		},
	}

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
		// Ingest was called, proceed
	case <-time.After(10 * time.Second):
		t.Fatal("Timeout: Ingest was not called")
	}

	// Stop the process
	err = runner.Stop()
	assert.NoError(t, err, "Runner.Stop should not return an error")
}

func TestRunnerWalkError(t *testing.T) {
	setupTestMetrics(t)
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
	mockHost.On("Walk", mock.Anything, mock.Anything).Return(nil, errors.New("walk error"))

	// Create a mock client factory that returns the mock host
	mockClientFactory := func(_ string, _ uint16, _ int, _ *config.Authentication) (snmp.Walker, error) {
		return mockHost, nil
	}

	// Create runner with the mock client factory
	runner, err := policy.NewRunner(ctx, logger, "test-policy", policyConfig, mockClient, mockClientFactory)
	assert.NoError(t, err)

	// Set up a channel to detect if Ingest is called (it shouldn't be)
	ingestCalled := make(chan bool, 1)
	mockClient.On("Ingest", mock.Anything, mock.Anything).Run(func(_ mock.Arguments) {
		ingestCalled <- true
	}).Return(&diodepb.IngestResponse{}, nil)

	// Start the process
	runner.Start()

	// Wait to verify that Ingest is NOT called
	select {
	case <-ingestCalled:
		t.Fatal("Ingest was called when it should not have been")
	case <-time.After(2 * time.Second):
		// Success - Ingest was not called
	}

	// Stop the process
	err = runner.Stop()
	assert.NoError(t, err, "Runner.Stop should not return an error")
}
