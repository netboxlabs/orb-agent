#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""Orb Worker Metrics."""

import json
import logging
import re
import string
from typing import Any
from urllib.parse import unquote, unquote_plus

from opentelemetry import metrics as otlp_metrics
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    PeriodicExportingMetricReader,
)

from worker.version import version_semver

logger = logging.getLogger(__name__)

# MASKED replaces the login of a collector URL where a log line writes it.
MASKED = "********"

# _SCHEME matches a URL's scheme and its ://.
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")

# _GRPC_RESOLVERS are the schemes of the gRPC resolvers a target can name
# without //, as dns:host:port: gRPC strips the scheme before it writes the
# address.
_GRPC_RESOLVERS = ("dns:", "unix:", "unix-abstract:", "vsock:", "ipv4:", "ipv6:", "passthrough:")

# _LOGIN_CHARS are the characters a user or a password can hold as an address
# writes it: RFC 3986 lets a user info hold them, and ' ( ) , = too, which
# also separate words in a text.
_LOGIN_CHARS = frozenset(string.ascii_letters + string.digits + "%-._~!$&*+;:")

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
        "backend_execution_success": lambda: meter.create_counter(
            name="backend_execution_success",
            description="Number of successful backend executions",
            unit="1",
        ),
        "backend_execution_failure": lambda: meter.create_counter(
            name="backend_execution_failure",
            description="Number of failed backend executions",
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
        "backend_execution_latency": lambda: meter.create_histogram(
            name="backend_execution_latency",
            description="Time taken for the backend execution process",
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


def _login(endpoint: str) -> str:
    """
    Return the login a collector URL carries, as written, or an empty string.

    The URL is read trimmed, as a URL parser reads it. Written from a scheme's
    :// or from //, its login is what its authority holds before its last @,
    after the third / of an empty authority, as gRPC's dns:/// writes one; or,
    when the authority holds no @, as when a password holds an unescaped /,
    what comes before the URL's last @. Written without //, as in
    user:password@host:port, it is everything before the last @, a // or a
    :// in the password included.
    """
    if not isinstance(endpoint, str):
        return ""
    endpoint = endpoint.strip()
    start = 0
    scheme = _SCHEME.match(endpoint)
    if scheme:
        start = scheme.end()
    elif endpoint.startswith("//"):
        start = 2
    if start:
        while endpoint.startswith("/", start):
            start += 1
        authority = re.split(r"[/?#]", endpoint[start:], maxsplit=1)[0]
        if "@" in authority:
            return authority[: authority.rfind("@")]
    at = endpoint.rfind("@")
    return endpoint[start:at] if at > start else ""


def _written_logins(endpoint: str) -> list[str]:
    """
    Return the login a collector URL carries as written, or none.

    When the URL is written without // after a gRPC resolver's scheme, as
    dns:user:password@host:port, the login without that scheme comes too:
    gRPC strips it before it writes the address.
    """
    login = _login(endpoint)
    if not login:
        return []
    logins = [login]
    endpoint = endpoint.strip()
    if not _SCHEME.match(endpoint) and not endpoint.startswith("//"):
        logins += [login[len(s) :] for s in _GRPC_RESOLVERS if len(login) > len(s) and login[: len(s)].lower() == s]
    return logins


def _login_forms(endpoint: str) -> list[str]:
    """
    Return the forms in which a text can write a collector URL's login.

    They are the login as written; percent-decoded, whole and its user and
    password each, leniently, an invalid %XX kept, as the gRPC client decodes
    the address it is given before it writes it in an error, a byte that is
    not UTF-8 read as Latin-1, as Python's gRPC writes it, or replaced by
    U+FFFD; and each of those escaped as JSON escapes a string. The longest
    come first.
    """
    plain = []
    for login in _written_logins(endpoint):
        user, colon, password = login.partition(":")
        plain.append(login)
        for unescape in (unquote, unquote_plus, _unquote_latin1):
            plain += [unescape(login), unescape(user) + colon + unescape(password)]
    forms = plain + [json.dumps(p)[1:-1] for p in plain] + [json.dumps(p, ensure_ascii=False)[1:-1] for p in plain]
    return sorted(dict.fromkeys(f for f in forms if f), key=len, reverse=True)


def _unquote_latin1(s: str) -> str:
    """Return s percent-decoded, its bytes read as Latin-1."""
    return unquote(s, encoding="latin-1")


def _starts_word(text: str, i: int) -> bool:
    """Return whether a login found at i in text starts a word, as an address does."""
    if i == 0 or text[i - 1] not in _LOGIN_CHARS:
        return True
    return i >= 2 and text[i - 2] == "\\" and text[i - 1] in "nrt"


def _mask_form(text: str, form: str) -> str:
    """
    Return text with form masked where it comes before an @.

    A user alone, a form without a :, is masked only where it also starts a
    word.
    """
    needle = form + "@"
    anywhere = ":" in form
    parts = []
    last = 0
    i = text.find(needle)
    while i >= 0:
        if anywhere or _starts_word(text, i):
            parts += [text[last:i], MASKED]
            last = i + len(form)
            i = text.find(needle, i + len(needle))
        else:
            i = text.find(needle, i + 1)
    if not parts:
        return text
    return "".join(parts) + text[last:]


def mask_login(text: str, endpoint: str) -> str:
    """
    Return text with the login a collector URL carries masked as ********.

    A collector URL can carry a login, as grpc://user:password@host:port or
    user:password@host:port, which the exporter is given as written. The
    login is masked wherever text writes it before an @: as written,
    percent-decoded, as the gRPC client writes it in its errors, or escaped
    as JSON escapes it. A user and a password are masked wherever they come;
    a user alone only at the start of a word, so it is not masked inside a
    longer user, as ops is in noc-ops@host. The longest form is masked first,
    so no part of one is left.

    Args:
    ----
        text (str): the text to mask, such as a log message or an error.
        endpoint (str): the collector URL.

    Returns:
    -------
        str: text with the login masked.

    """
    for form in _login_forms(endpoint):
        text = _mask_form(text, form)
    return text


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
        insecure = True if endpoint.startswith("grpc://") else None
        exporter = OTLPMetricExporter(endpoint=endpoint, timeout=10, insecure=insecure)
        logger.info(f"OTLP metrics exporter configured with endpoint: {mask_login(endpoint, endpoint)}")

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
        logger.error(f"Failed to setup metrics export: {mask_login(str(e), endpoint)}")
        return
