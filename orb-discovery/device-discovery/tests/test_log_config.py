#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""NetBox Labs - Log configuration unit tests."""

import logging
from unittest.mock import MagicMock

import pytest

from device_discovery.log_config import (
    _LEVEL_ALIASES,
    LOG_FORMAT,
    configure_logging,
    flatten_message,
    resolve_log_level,
)


def test_log_format_is_logging_basic_format():
    """The emitted shape is a wire contract with the Go-side normalizer."""
    assert LOG_FORMAT == logging.BASIC_FORMAT


def test_alias_vocabulary_matches_the_go_side():
    """
    Mirrors parseDeviceDiscoveryLevel in device_discovery.go.

    If the Go switch gains a token, this assertion is the thing that notices.
    """
    assert set(_LEVEL_ALIASES) == {
        "trace",
        "debug",
        "info",
        "warn",
        "warning",
        "error",
        "err",
        "exception",
        "critical",
        "fatal",
    }


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("trace", logging.DEBUG),
        ("debug", logging.DEBUG),
        ("DEBUG", logging.DEBUG),
        ("  Debug  ", logging.DEBUG),
        ("info", logging.INFO),
        ("warn", logging.WARNING),
        ("warning", logging.WARNING),
        ("WARNING", logging.WARNING),
        ("error", logging.ERROR),
        ("err", logging.ERROR),
        ("exception", logging.ERROR),
        ("critical", logging.CRITICAL),
        ("fatal", logging.CRITICAL),
    ],
)
def test_resolve_known_levels(value, expected):
    """Every accepted token resolves without a warning."""
    level, warning = resolve_log_level(value)
    assert level == expected
    assert warning is None


@pytest.mark.parametrize("value", [None, "", "verbose", 3, MagicMock()])
def test_resolve_unknown_levels_fall_back_and_warn(value):
    """
    An unusable value degrades to INFO and says so.

    Must never raise: argparse has no choices= (a YAML typo would exit(2) and
    crash-loop the backend), and every existing main() test patches parse_args
    to return a MagicMock.
    """
    level, warning = resolve_log_level(value)
    assert level == logging.INFO
    assert warning is not None
    assert "falling back to INFO" in warning


def test_configure_logging_overrides_import_time_basicconfig(preserve_root_logging):
    """
    The load-bearing test: this FAILS on pre-#494 code.

    Importing device_discovery.client runs the import-time basicConfig, after
    which a plain basicConfig is a silent no-op. Without force=True the root
    level stays INFO and --log-level is accepted and ignored -- the exact
    defect this work exists to kill.
    """
    import device_discovery.client  # noqa: F401 - imported for its import-time side effect

    configure_logging("debug")

    root = logging.getLogger()
    assert root.level == logging.DEBUG
    assert root.handlers
    assert any(
        handler.formatter is not None and handler.formatter._fmt == LOG_FORMAT
        for handler in root.handlers
    )


def test_configure_logging_returns_applied_level(preserve_root_logging):
    """configure_logging reports what it applied."""
    assert configure_logging("error") == logging.ERROR
    assert logging.getLogger().level == logging.ERROR


def test_flatten_message_collapses_multiline_exceptions():
    """Netmiko messages are ten physical lines; one record must be one line."""
    error = ValueError("line one\n\nline two\n   line three")
    flattened = flatten_message(error)
    assert "\n" not in flattened
    assert flattened == "line one line two line three"
