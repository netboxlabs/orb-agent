#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""NetBox Labs - Metrics Unit Tests."""

import logging
from unittest.mock import MagicMock, patch

import pytest
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.metrics.export import MetricsData

from worker.metrics import get_metric, mask_login, setup_metrics_export


@pytest.fixture
def mock_opentelemetry():
    """Mock the OpenTelemetry SDK imports and components."""
    with patch("worker.metrics.OTLPMetricExporter") as mock_exporter, patch(
        "worker.metrics.PeriodicExportingMetricReader"
    ) as mock_reader, patch("opentelemetry.sdk.metrics.Meter") as mock_meter, patch(
        "worker.metrics.MeterProvider"
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
    with patch("worker.metrics._metrics_cache", {}), \
         patch("worker.metrics._metric_factories", {}), \
         patch("worker.metrics._metrics_enabled", True):
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
    with patch("worker.metrics.logger") as mock_logger:
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

    with patch("worker.metrics._meter", mock_meter):
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

    with patch("worker.metrics._meter", mock_meter):
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
    with patch("worker.metrics._meter", None):
        metric = get_metric("api_requests")
        assert metric is None


def test_get_metric_creates_metric_only_once(reset_metrics_cache):
    """Test that get_metric only creates a metric once and returns cached value."""
    mock_counter = MagicMock()
    mock_meter = MagicMock()
    mock_meter.create_counter.return_value = mock_counter

    with patch("worker.metrics._meter", mock_meter), patch(
        "worker.metrics._metrics_cache", {}
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
        "backend_execution_success",
        "backend_execution_failure",
        "backend_execution_latency",
    ]

    mock_meter = MagicMock()
    mock_meter.create_counter.return_value = MagicMock()
    mock_meter.create_histogram.return_value = MagicMock()

    with patch("worker.metrics._meter", mock_meter), patch(
        "worker.metrics._metrics_cache", {}
    ):

        for metric_name in expected_metrics:
            metric = get_metric(metric_name)
            assert metric is not None, f"Expected metric {metric_name} to exist"


def test_setup_metrics_export_meter_provider_error(mock_opentelemetry, reset_metrics_cache):
    """Test handling of errors when setting the meter provider."""
    endpoint = "http://localhost:4317"
    export_period = 30

    # Mock set_meter_provider to raise an exception
    with patch("worker.metrics.otlp_metrics.set_meter_provider",
              side_effect=Exception("Provider error")), \
         patch("worker.metrics.logger") as mock_logger:

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


@pytest.mark.parametrize(
    ("text", "endpoint", "want"),
    [
        (
            "grpc://canary-user:canary-pass@127.0.0.1:4317",
            "grpc://canary-user:canary-pass@127.0.0.1:4317",
            "grpc://********@127.0.0.1:4317",
        ),
        (
            "canary-user:canary-pass@127.0.0.1:4317",
            "canary-user:canary-pass@127.0.0.1:4317",
            "********@127.0.0.1:4317",
        ),
        ("dns:///Canary-T0ken@collector:4317", "dns:///Canary-T0ken@collector:4317", "dns:///********@collector:4317"),
        (
            "exporting to canary-user:canary-pass@127.0.0.1:4317 failed",
            "grpc://canary-user:canary-pass@127.0.0.1:4317",
            "exporting to ********@127.0.0.1:4317 failed",
        ),
        ("grpc://127.0.0.1:4317", "grpc://127.0.0.1:4317", "grpc://127.0.0.1:4317"),
        ("", "", ""),
    ],
)
def test_mask_login(text, endpoint, want):
    """The login a collector URL carries is masked wherever a text writes it before an @."""
    assert mask_login(text, endpoint) == want


@pytest.mark.parametrize(
    "endpoint",
    ["grpc://canary-user:canary-pass@127.0.0.1:4317", "canary-user:canary-pass@127.0.0.1:4317"],
)
def test_setup_metrics_export_masks_the_collector_login(mock_opentelemetry, reset_metrics_cache, caplog, endpoint):
    """The exporter is given a collector URL as written, and the log writes its login masked."""
    with caplog.at_level(logging.DEBUG, logger="worker.metrics"):
        setup_metrics_export(endpoint, 30)

    _, kwargs = mock_opentelemetry["exporter"].call_args
    assert kwargs["endpoint"] == endpoint
    masked = endpoint.replace("canary-user:canary-pass@", "********@")
    assert f"OTLP metrics exporter configured with endpoint: {masked}" in caplog.messages
    for message in caplog.messages:
        assert "canary-user" not in message
        assert "canary-pass" not in message


def test_setup_metrics_export_masks_the_collector_login_in_its_error(mock_opentelemetry, reset_metrics_cache, caplog):
    """An error building the exporter that writes the collector's address writes its login masked."""
    endpoint = "grpc://canary-user:canary-pass@127.0.0.1:4317"
    mock_opentelemetry["exporter"].side_effect = ValueError("cannot dial canary-user:canary-pass@127.0.0.1:4317")

    with caplog.at_level(logging.DEBUG, logger="worker.metrics"):
        setup_metrics_export(endpoint, 30)

    assert "Failed to setup metrics export: cannot dial ********@127.0.0.1:4317" in caplog.messages
    for message in caplog.messages:
        assert "canary-user" not in message
        assert "canary-pass" not in message


@pytest.mark.parametrize(
    ("text", "endpoint", "want"),
    [
        # A login written without a scheme that holds a // or a :// is still
        # everything before the last @.
        ("user:pa//ss@collector:4317", "user:pa//ss@collector:4317", "********@collector:4317"),
        ("user:pa://ss@h:4317", "user:pa://ss@h:4317", "********@h:4317"),
        ("user:pass@collector:4317//x", "user:pass@collector:4317//x", "********@collector:4317//x"),
        # With a scheme, the login ends at the last @ of the authority.
        ("grpc://u:p@h:4317?x=y@z", "grpc://u:p@h:4317?x=y@z", "grpc://********@h:4317?x=y@z"),
        # A value written with spaces around it, as a URL parser trims it.
        (
            " grpc://canary-user:canary-pass@127.0.0.1:4317 ",
            " grpc://canary-user:canary-pass@127.0.0.1:4317 ",
            " grpc://********@127.0.0.1:4317 ",
        ),
        # A user alone is masked only where it starts a word.
        (
            "device contact noc-ops@example.com, ssh ops@10.0.0.1",
            "grpc://ops@collector:4317",
            "device contact noc-ops@example.com, ssh ********@10.0.0.1",
        ),
        # Percent-decoded, as the gRPC client writes the address, and escaped.
        (
            "errors resolving canary-user:canary@pass@127.0.0.1:1",
            "grpc://canary-user:canary%40pass@127.0.0.1:1",
            "errors resolving ********@127.0.0.1:1",
        ),
        (
            '{"error": "dial canary-user:canary\\"pass@h:4317"}',
            'canary-user:canary"pass@h:4317',
            '{"error": "dial ********@h:4317"}',
        ),
    ],
)
def test_mask_login_reads_the_login_as_the_agent_does(text, endpoint, want):
    """The login is read and masked as the agent reads and masks it."""
    assert mask_login(text, endpoint) == want


def test_mask_login_masks_what_the_exporter_writes_for_a_percent_encoded_login(caplog):
    """
    The real exporter writes the login as written and percent-decoded.

    A password holding an @ is percent-encoded in a URL. The gRPC client
    decodes the address it is given and writes it decoded in the error the
    exporter logs for every export it fails.
    """
    endpoint = "grpc://canary-user:canary%40pass@127.0.0.1:1"
    exporter = OTLPMetricExporter(endpoint=endpoint, timeout=1, insecure=True)
    try:
        with caplog.at_level(logging.WARNING):
            exporter.export(MetricsData(resource_metrics=[]))
    finally:
        exporter.shutdown()

    messages = [r.getMessage() for r in caplog.records if r.name.startswith("opentelemetry")]
    assert any("canary-user:canary@pass@127.0.0.1:1" in m for m in messages)
    for message in messages:
        masked = mask_login(message, endpoint)
        assert "canary" not in masked
        assert "********@127.0.0.1:1" in masked


@pytest.mark.parametrize(
    ("text", "endpoint"),
    [
        # A user and a password are masked wherever they come before an @.
        ("INFO:device_discovery.client:user:pass@h:4317 unreachable", "grpc://user:pass@h:4317"),
        ("target:user:pass@h:4317", "grpc://user:pass@h:4317"),
        ("x-user:pass@h", "grpc://user:pass@h:4317"),
        ("1user:pass@h", "grpc://user:pass@h:4317"),
        ("\x1b[31muser:pass@h:4317\x1b[0m", "grpc://user:pass@h:4317"),
        # gRPC strips a resolver's scheme written without //.
        ("invalid target address user:pass@127.0.0.1:1", "dns:user:pass@127.0.0.1:1"),
        # The login is read from the authority, whatever follows it.
        ("dial user:pass@h", "grpc://user:pass@h:4317/%zz@x"),
        ("dial user:pass@h", "grpc://user:pass@h:4317/x/a:b@c"),
        # Decoded leniently, an invalid escape kept.
        ("errors resolving user:pass%zz@x@127.0.0.1:1", "grpc://user:pass%zz%40x@127.0.0.1:1"),
    ],
)
def test_mask_login_masks_a_user_and_a_password_wherever_they_are(text, endpoint):
    """A user and a password are masked wherever a text writes them before an @."""
    masked = mask_login(text, endpoint)
    assert "user:pass" not in masked
    assert "********@" in masked


def test_mask_login_masks_what_the_exporter_writes_for_a_login_decoding_to_bytes_that_are_not_utf8():
    """
    The exporter writes a login decoding to bytes that are not UTF-8 as Latin-1.

    A password written with a raw %, as canary%F3pass, decodes to a byte that
    is not UTF-8: Python's gRPC writes the error that holds it as Latin-1.
    The line below is one the real exporter logged for this endpoint. gRPC
    does not always log it, as it can fail an export before the exporter
    gets the error, so it was captured rather than awaited.
    """
    endpoint = "grpc://canary-user:canary%F3pass@127.0.0.1:1"
    line = (
        "Failed to export metrics to canary-user:canary%F3pass@127.0.0.1:1, error code: StatusCode.UNAVAILABLE,"
        " error details: errors resolving canary-user:canary\xf3pass@127.0.0.1:1: [field:hostname lookup error:"
        "address lookup failed for canary-user:canary\xf3pass@127.0.0.1:1: Misformatted domain name]"
    )
    masked = mask_login(line, endpoint)
    assert "canary" not in masked
    assert masked.count("********@127.0.0.1:1") == 3
