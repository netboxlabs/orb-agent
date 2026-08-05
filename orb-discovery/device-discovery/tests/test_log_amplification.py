#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
NetBox Labs - Log amplification regression tests.

Measured in PHYSICAL STDERR LINES, not log records, and that is the point.
The agent's go-cmd stream splits stderr on every newline and assigns ERROR by
pipe rather than by content (agent/backend/process.go:83-103 and
devicediscovery/device_discovery.go:172-176). That amplifier is deliberately
out of scope for #494, so the Python side has to hold the one-record ==
one-line invariant permanently. Record-count assertions alone would not catch
a regression that reintroduces embedded newlines.
"""

import io
import logging

import pytest
from napalm.base.exceptions import ConnectionException
from netmiko.exceptions import NetmikoAuthenticationException

from device_discovery.log_config import LOG_FORMAT
from device_discovery.policy.run import RunStore
from device_discovery.policy.runner import PolicyRunner

AUTH_MESSAGE = """Authentication to device failed.

Common causes of this problem are:
1. Invalid username and password
2. Incorrect SSH-key file
3. Connecting to the wrong device

Device settings: cisco_ios 10.0.0.5:22

Authentication failed."""


@pytest.fixture
def stderr_capture():
    """Attach a formatted stream handler to the runner logger, as the backend does."""
    buffer = io.StringIO()
    logger = logging.getLogger("device_discovery.policy.runner")
    handler = logging.StreamHandler(buffer)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))

    saved_handlers = logger.handlers[:]
    saved_propagate = logger.propagate
    saved_level = logger.level

    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)

    yield buffer, logger

    logger.handlers = saved_handlers
    logger.propagate = saved_propagate
    logger.setLevel(saved_level)


def _emit(logger, error):
    runner = PolicyRunner()
    runner.name = "test_policy"
    runner.run_store = RunStore()
    runner._log_target_failure("10.0.0.5", error)


@pytest.mark.parametrize(
    "error",
    [
        ConnectionException("Cannot connect to 10.0.0.5"),
        NetmikoAuthenticationException(AUTH_MESSAGE),
    ],
)
def test_expected_failure_is_exactly_one_physical_line(stderr_capture, error):
    """
    The headline of #494: one line per unreachable target, not ~63.

    The auth case is the one that matters most -- dropping exc_info without
    flattening leaves ten lines, nine of which the agent labels ERROR.
    """
    buffer, logger = stderr_capture
    _emit(logger, error)
    output = buffer.getvalue()
    assert output.count("\n") == 1
    assert "Traceback" not in output


def test_a_sweep_emits_one_line_per_host(stderr_capture):
    """The reported symptom, at the reported scale: a /24 of unreachable hosts."""
    buffer, logger = stderr_capture
    for octet in range(1, 255):
        _emit(logger, ConnectionException(f"Cannot connect to 10.0.0.{octet}"))
    assert buffer.getvalue().count("\n") == 254


def test_debug_adds_exactly_one_more_line(stderr_capture):
    """The escaped traceback is recoverable at DEBUG and still one line."""
    buffer, logger = stderr_capture
    logger.setLevel(logging.DEBUG)
    try:
        raise ConnectionException("Cannot connect to 10.0.0.5")
    except ConnectionException as error:
        _emit(logger, error)
    output = buffer.getvalue()
    assert output.count("\n") == 2
    assert "Traceback" in output


def test_unexpected_failure_still_gets_a_real_traceback(stderr_capture):
    """Quiet must not have been bought by destroying diagnosability."""
    buffer, logger = stderr_capture
    try:
        raise ValueError("boom")
    except ValueError as error:
        _emit(logger, error)
    output = buffer.getvalue()
    assert "Traceback" in output
    assert output.count("\n") > 1


def test_emitted_line_matches_the_shape_the_agent_parses(stderr_capture):
    """
    The format is a wire contract.

    normalizeDeviceDiscoveryLine (device_discovery.go:325-368) splits on the
    first two colons to recover LEVEL and module. If this shape changes, the
    agent silently falls back to assigning level by pipe.
    """
    buffer, logger = stderr_capture
    _emit(logger, ConnectionException("Cannot connect to 10.0.0.5"))
    line = buffer.getvalue().rstrip("\n")
    level, module, _ = line.split(":", 2)
    assert level == "WARNING"
    assert module == "device_discovery.policy.runner"
