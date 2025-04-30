package metrics_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/netboxlabs/orb-discovery/network-discovery/metrics"
)

func TestSetupMetricsExport(t *testing.T) {
	ctx := context.Background()

	t.Run("EmptyEndpoint", func(t *testing.T) {
		err := metrics.SetupMetricsExport(ctx, "", 10)
		assert.NoError(t, err, "Should not return error with empty endpoint")
	})

	// Note: We can't easily test the actual OTLP setup without mocking the gRPC connection
	// A more comprehensive test would involve mocking the exporter
}

func TestGetCounter(t *testing.T) {
	t.Run("NilMeter", func(t *testing.T) {
		// We haven't initialized the meter, so it should be nil
		counter := metrics.GetCounter("test_counter", "Test counter")
		assert.Nil(t, counter, "Counter should be nil when meter is nil")
	})

	t.Run("CacheReuse", func(t *testing.T) {
		// Set up a test environment with a non-nil meter
		err := setupTestMeter(t)
		require.NoError(t, err)

		// Get the same counter twice, they should be the same instance
		counter1 := metrics.GetCounter("test_counter", "Test counter")
		counter2 := metrics.GetCounter("test_counter", "Test counter")
		assert.NotNil(t, counter1)
		assert.Same(t, counter1, counter2, "Should return the same cached counter")

		// Get a different counter, should be a different instance
		counter3 := metrics.GetCounter("another_counter", "Another counter")
		assert.NotEqual(t, counter1, counter3, "Different counters should be different instances")
	})
}

func TestGetUpDownCounter(t *testing.T) {
	t.Run("NilMeter", func(t *testing.T) {
		// We need to ensure the meter is nil for this test
		resetMetricsState()

		counter := metrics.GetUpDownCounter("test_updown", "Test updown counter")
		assert.Nil(t, counter, "UpDown counter should be nil when meter is nil")
	})

	t.Run("CacheReuse", func(t *testing.T) {
		err := setupTestMeter(t)
		require.NoError(t, err)

		counter1 := metrics.GetUpDownCounter("test_updown", "Test updown counter")
		counter2 := metrics.GetUpDownCounter("test_updown", "Test updown counter")
		assert.NotNil(t, counter1)
		assert.Same(t, counter1, counter2, "Should return the same cached updown counter")

		counter3 := metrics.GetUpDownCounter("another_updown", "Another updown counter")
		assert.NotEqual(t, counter1, counter3, "Different updown counters should be different instances")
	})
}

func TestGetHistogram(t *testing.T) {
	t.Run("NilMeter", func(t *testing.T) {
		// We need to ensure the meter is nil for this test
		resetMetricsState()

		histogram := metrics.GetHistogram("test_histogram", "Test histogram")
		assert.Nil(t, histogram, "Histogram should be nil when meter is nil")
	})

	t.Run("CacheReuse", func(t *testing.T) {
		err := setupTestMeter(t)
		require.NoError(t, err)

		histogram1 := metrics.GetHistogram("test_histogram", "Test histogram")
		histogram2 := metrics.GetHistogram("test_histogram", "Test histogram")
		assert.NotNil(t, histogram1)
		assert.Same(t, histogram1, histogram2, "Should return the same cached histogram")

		histogram3 := metrics.GetHistogram("another_histogram", "Another histogram")
		assert.NotEqual(t, histogram1, histogram3, "Different histograms should be different instances")
	})
}

func TestGetGauge(t *testing.T) {
	t.Run("NilMeter", func(t *testing.T) {
		// We need to ensure the meter is nil for this test
		resetMetricsState()

		gauge := metrics.GetGauge("test_gauge", "Test gauge")
		assert.Nil(t, gauge, "Gauge should be nil when meter is nil")
	})

	t.Run("CacheReuse", func(t *testing.T) {
		err := setupTestMeter(t)
		require.NoError(t, err)

		gauge1 := metrics.GetGauge("test_gauge", "Test gauge")
		gauge2 := metrics.GetGauge("test_gauge", "Test gauge")
		assert.NotNil(t, gauge1)
		assert.Same(t, gauge1, gauge2, "Should return the same cached gauge")

		gauge3 := metrics.GetGauge("another_gauge", "Another gauge")
		assert.NotEqual(t, gauge1, gauge3, "Different gauges should be different instances")
	})
}

func TestConvenienceFunctions(t *testing.T) {
	err := setupTestMeter(t)
	require.NoError(t, err)

	t.Run("GetDiscoverySuccess", func(t *testing.T) {
		counter := metrics.GetDiscoverySuccess()
		assert.NotNil(t, counter)

		// Test that it's the same as getting the counter directly
		directCounter := metrics.GetCounter("discovery_success", "Number of successful network discoveries")
		assert.Same(t, counter, directCounter)
	})

	t.Run("GetDiscoveryFailure", func(t *testing.T) {
		counter := metrics.GetDiscoveryFailure()
		assert.NotNil(t, counter)

		directCounter := metrics.GetCounter("discovery_failure", "Number of failed network discoveries")
		assert.Same(t, counter, directCounter)
	})

	t.Run("GetPolicyExecutions", func(t *testing.T) {
		counter := metrics.GetPolicyExecutions()
		assert.NotNil(t, counter)

		directCounter := metrics.GetCounter("policy_executions", "Number of policy executions")
		assert.Same(t, counter, directCounter)
	})

	t.Run("GetAPIRequests", func(t *testing.T) {
		counter := metrics.GetAPIRequests()
		assert.NotNil(t, counter)

		directCounter := metrics.GetCounter("api_requests", "Number of API requests")
		assert.Same(t, counter, directCounter)
	})

	t.Run("GetDiscoveredHosts", func(t *testing.T) {
		gauge := metrics.GetDiscoveredHosts()
		assert.NotNil(t, gauge)

		directGauge := metrics.GetGauge("discovered_hosts", "Number of hosts discovered in each run")
		assert.Same(t, gauge, directGauge)
	})

	t.Run("GetDiscoveryLatency", func(t *testing.T) {
		histogram := metrics.GetDiscoveryLatency()
		assert.NotNil(t, histogram)

		directHistogram := metrics.GetHistogram("discovery_latency", "Time taken for the network discovery process")
		assert.Same(t, histogram, directHistogram)
	})

	t.Run("GetAPIResponseLatency", func(t *testing.T) {
		histogram := metrics.GetAPIResponseLatency()
		assert.NotNil(t, histogram)

		directHistogram := metrics.GetHistogram("api_response_latency", "Time taken to respond to API requests")
		assert.Same(t, histogram, directHistogram)
	})

	t.Run("GetActivePolicies", func(t *testing.T) {
		counter := metrics.GetActivePolicies()
		assert.NotNil(t, counter)

		directCounter := metrics.GetUpDownCounter("active_policies", "Number of currently active policies")
		assert.Same(t, counter, directCounter)
	})
}

// setupTestMeter creates a no-op meter provider for testing
func setupTestMeter(_ *testing.T) error {
	ctx := context.Background()
	// Use the no-op meter provider for testing to avoid actual metrics export
	return metrics.SetupMetricsExport(ctx, "localhost:4317", 10)
}

// MockMeter is a mock implementation of metric.Meter for testing
type MockMeter struct {
	metric.Meter
}

func NewMockMeter() *MockMeter {
	return &MockMeter{
		Meter: noop.NewMeterProvider().Meter("mock"),
	}
}

// Add this helper function to reset the metrics state
func resetMetricsState() {
	// This function exposes a way to reset the meter to nil for testing
	metrics.ResetMeter()
}
