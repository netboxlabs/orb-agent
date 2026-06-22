#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""NetBox Labs - Metrics Unit Tests."""

from unittest.mock import MagicMock, patch

import pytest

from device_discovery.metrics import get_metric, setup_metrics_export


@pytest.fixture
def mock_opentelemetry():
    """Mock the OpenTelemetry SDK imports and components."""
    with patch("device_discovery.metrics.OTLPMetricExporter") as mock_exporter, patch(
        "device_discovery.metrics.PeriodicExportingMetricReader"
    ) as mock_reader, patch("opentelemetry.sdk.metrics.Meter") as mock_meter, patch(
        "device_discovery.metrics.MeterProvider"
    ) as mock_provider:
        # Setup return values
        mock_provider.return_value.get_meter.return_value = mock_meter

        yield {
            "exporter": mock_exporter,
            "reader": mock_reader,
            "meter": mock_meter,
            "provider": mock_provider,
        }


@pytest.fixture
def reset_metrics_cache():
    """Reset the metrics cache before test."""
    with patch("device_discovery.metrics._metrics_cache", {}), \
         patch("device_discovery.metrics._metric_factories", {}), \
         patch("device_discovery.metrics._metrics_enabled", True):
        yield


def test_setup_metrics_export(mock_opentelemetry):
    """Test that metrics export setup creates the correct OpenTelemetry components."""
    endpoint = "http://localhost:4317"
    export_period = 30

    setup_metrics_export(endpoint, export_period)

    # Verify exporter was created with correct endpoint
    mock_opentelemetry["exporter"].assert_called_once()
    args, kwargs = mock_opentelemetry["exporter"].call_args
    assert kwargs["endpoint"] == endpoint

    # Verify reader was created with correct exporter and export interval
    mock_opentelemetry["reader"].assert_called_once()
    args, kwargs = mock_opentelemetry["reader"].call_args
    assert kwargs["export_interval_millis"] == export_period * 1000

    # Verify meter provider was configured
    mock_opentelemetry["provider"].assert_called_once()

    # Verify meter was created
    mock_opentelemetry["provider"].return_value.get_meter.assert_called_once_with(
        "device-discovery", "0.0.0"
    )


def test_setup_metrics_export_no_endpoint(mock_opentelemetry, reset_metrics_cache):
    """Test that metrics export setup is properly disabled when no endpoint is provided."""
    with patch("device_discovery.metrics.logger") as mock_logger:
        # Call with None endpoint
        setup_metrics_export(None, 30)

        # Verify logger message
        mock_logger.info.assert_called_once_with(
            "No metrics endpoint provided, metrics collection is disabled"
        )

        # Verify no OpenTelemetry components were created
        mock_opentelemetry["exporter"].assert_not_called()
        mock_opentelemetry["reader"].assert_not_called()
        mock_opentelemetry["provider"].assert_not_called()

        # Verify get_metric returns None after setup with no endpoint
        metric = get_metric("api_requests")
        assert metric is None


def test_get_metric_returns_counter(reset_metrics_cache):
    """Test that get_metric returns a counter for counter-type metrics."""
    mock_counter = MagicMock()
    mock_meter = MagicMock()
    mock_meter.create_counter.return_value = mock_counter

    with patch("device_discovery.metrics._meter", mock_meter):
        # Test accessing a counter metric
        metric = get_metric("api_requests")

        # Verify counter was created with correct name and description
        mock_meter.create_counter.assert_called_once()
        args, kwargs = mock_meter.create_counter.call_args
        assert kwargs["name"] == "api_requests"
        assert "description" in kwargs

        # Should return the mock counter
        assert metric == mock_counter


def test_get_metric_returns_histogram(reset_metrics_cache):
    """Test that get_metric returns a histogram for latency-type metrics."""
    mock_histogram = MagicMock()
    mock_meter = MagicMock()
    mock_meter.create_histogram.return_value = mock_histogram

    with patch("device_discovery.metrics._meter", mock_meter):
        # Test accessing a histogram metric
        metric = get_metric("api_response_latency")

        # Verify histogram was created with correct name and description
        mock_meter.create_histogram.assert_called_once()
        args, kwargs = mock_meter.create_histogram.call_args
        assert kwargs["name"] == "api_response_latency"
        assert "description" in kwargs

        # Should return the mock histogram
        assert metric == mock_histogram


def test_get_metric_returns_none_when_not_initialized():
    """Test that get_metric returns None when metrics are not initialized."""
    with patch("device_discovery.metrics._meter", None):
        metric = get_metric("api_requests")
        assert metric is None


def test_get_metric_creates_metric_only_once(reset_metrics_cache):
    """Test that get_metric only creates a metric once and returns cached value."""
    mock_counter = MagicMock()
    mock_meter = MagicMock()
    mock_meter.create_counter.return_value = mock_counter

    with patch("device_discovery.metrics._meter", mock_meter), patch(
        "device_discovery.metrics._metrics_cache", {}
    ):

        # First call should create the metric
        metric1 = get_metric("api_requests")
        assert metric1 == mock_counter
        mock_meter.create_counter.assert_called_once()

        # Reset the mock to check if it's called again
        mock_meter.create_counter.reset_mock()

        # Second call should return cached metric without creating it again
        metric2 = get_metric("api_requests")
        assert metric2 == mock_counter
        mock_meter.create_counter.assert_not_called()


def test_all_expected_metrics_exist(reset_metrics_cache):
    """Test that all expected metrics can be retrieved."""
    expected_metrics = [
        "api_requests",
        "api_response_latency",
        "active_policies",
        "policy_executions",
        "discovery_attempts",
        "discovery_success",
        "discovery_failure",
        "discovery_latency",
        "device_connection_latency",
    ]

    mock_meter = MagicMock()
    mock_meter.create_counter.return_value = MagicMock()
    mock_meter.create_histogram.return_value = MagicMock()

    with patch("device_discovery.metrics._meter", mock_meter), patch(
        "device_discovery.metrics._metrics_cache", {}
    ):

        for metric_name in expected_metrics:
            metric = get_metric(metric_name)
            assert metric is not None, f"Expected metric {metric_name} to exist"


def test_setup_metrics_export_meter_provider_error(mock_opentelemetry, reset_metrics_cache):
    """Test handling of errors when setting the meter provider."""
    endpoint = "http://localhost:4317"
    export_period = 30

    # Mock set_meter_provider to raise an exception
    with patch("device_discovery.metrics.otlp_metrics.set_meter_provider",
              side_effect=Exception("Provider error")), \
         patch("device_discovery.metrics.logger") as mock_logger:

        # Call function
        setup_metrics_export(endpoint, export_period)

        # Verify components were created but meter provider wasn't set
        mock_opentelemetry["exporter"].assert_called_once()
        mock_opentelemetry["reader"].assert_called_once()
        mock_opentelemetry["provider"].assert_called_once()

        # Verify warning was logged
        mock_logger.warning.assert_called_once()
        warning_message = mock_logger.warning.call_args[0][0]
        assert "Could not set meter provider" in warning_message

        # Verify meter was not created
        mock_opentelemetry["provider"].return_value.get_meter.assert_not_called()

        # Verify metrics are not enabled and get_metric returns None
        metric = get_metric("api_requests")
        assert metric is None
