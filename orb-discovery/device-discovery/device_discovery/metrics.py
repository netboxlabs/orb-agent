#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""Device Discovery Metrics."""

import logging
from typing import Any

from opentelemetry import metrics as otlp_metrics
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    PeriodicExportingMetricReader,
)

from device_discovery.version import version_semver

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variables to store the provider and meter
_meter_provider = None
_meter = None
_metrics_cache = {}
_metrics_enabled = False
_metric_factories = {}


def _init_metric_factories(meter):
    """Initialize the metric factory dictionary."""
    global _metric_factories

    _metric_factories = {
        "discovery_attempts": lambda: meter.create_counter(
            name="discovery_attempts",
            description="Number of device discovery attempts",
            unit="1",
        ),
        "discovery_success": lambda: meter.create_counter(
            name="discovery_success",
            description="Number of successful device discoveries",
            unit="1",
        ),
        "discovery_failure": lambda: meter.create_counter(
            name="discovery_failure",
            description="Number of failed device discoveries",
            unit="1",
        ),
        "policy_executions": lambda: meter.create_counter(
            name="policy_executions",
            description="Number of policy executions",
            unit="1",
        ),
        "api_requests": lambda: meter.create_counter(
            name="api_requests",
            description="Number of API requests",
            unit="1",
        ),
        "discovery_latency": lambda: meter.create_histogram(
            name="discovery_latency",
            description="Time taken for the discovery process",
            unit="ms",
        ),
        "device_connection_latency": lambda: meter.create_histogram(
            name="device_connection_latency",
            description="Time taken to connect to devices",
            unit="ms",
        ),
        "api_response_latency": lambda: meter.create_histogram(
            name="api_response_latency",
            description="Time taken to respond to API requests",
            unit="ms",
        ),
        "active_policies": lambda: meter.create_up_down_counter(
            name="active_policies",
            description="Number of currently active policies",
            unit="1",
        ),
    }


def get_metric(metric_name: str) -> Any:
    """
    Get a metric by name, lazily initializing it if needed.

    Args:
    ----
        metric_name: Name of the metric to retrieve

    Returns:
    -------
        The requested metric object or None if metrics are not configured

    """
    global _metrics_enabled, _meter, _metric_factories

    if not _metrics_enabled or _meter is None:
        # Metrics not configured, return a no-op implementation
        return None

    # Initialize the factories if not done already
    if not _metric_factories:
        _init_metric_factories(_meter)

    # Return cached metric if available
    if metric_name in _metrics_cache:
        return _metrics_cache[metric_name]

    # Create and cache the metric if the factory exists
    if metric_name in _metric_factories:
        _metrics_cache[metric_name] = _metric_factories[metric_name]()
        return _metrics_cache[metric_name]

    raise ValueError(f"Unknown metric: {metric_name}")


def setup_metrics_export(endpoint: str | None, export_period_seconds: int) -> None:
    """
    Setup metrics exporter with the proper endpoint.

    Args:
    ----
        endpoint (str, optional): OTLP endpoint for metrics export.
        export_period_seconds (int): Period in seconds between exports.

    """
    global _meter_provider, _meter, _metrics_enabled

    # Clear any existing metrics configuration
    _meter_provider = None
    _meter = None
    _metrics_cache.clear()
    _metrics_enabled = False

    if not endpoint:
        logger.info("No metrics endpoint provided, metrics collection is disabled")
        return

    try:
        # Set up the exporter with the provided endpoint and timeouts
        exporter = OTLPMetricExporter(
            endpoint=endpoint,
            timeout=10,  # Add timeout to prevent hangs on connection issues
            insecure=True if endpoint.startswith("grpc://") else False,
        )
        logger.info(f"OTLP metrics exporter configured with endpoint: {endpoint}")

        export_period_millis = export_period_seconds * 1000
        reader = PeriodicExportingMetricReader(
            exporter=exporter, export_interval_millis=export_period_millis
        )

        # Create a new MeterProvider with the updated reader
        _meter_provider = MeterProvider(metric_readers=[reader])
        try:
            otlp_metrics.set_meter_provider(_meter_provider)
            # Create the meter with the new provider
            _meter = _meter_provider.get_meter("device-discovery", version_semver())
            _metrics_enabled = True
            logger.info(
                f"Metrics export configured with period: {export_period_seconds} seconds"
            )
        except Exception as e:
            logger.warning(f"Could not set meter provider: {e}")
            return
    except Exception as e:
        logger.error(f"Failed to setup metrics export: {e}")
        return
