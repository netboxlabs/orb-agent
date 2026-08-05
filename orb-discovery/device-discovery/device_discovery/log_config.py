#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
Logging configuration for the device-discovery backend.

Centralises the root-logger setup that used to be five independent
``logging.basicConfig`` calls, and provides the ``--log-level`` plumbing.

Two things here are load-bearing and easy to undo by accident:

1. ``LOG_FORMAT`` is byte-identical to ``logging.BASIC_FORMAT``. The emitted
   shape is a wire contract with ``normalizeDeviceDiscoveryLine`` in
   ``agent/backend/devicediscovery/device_discovery.go``, which parses
   ``LEVEL:module:message``, and with operator grep habits. Changing it buys
   nothing and breaks both.
2. ``configure_logging`` passes ``force=True``. Every module in this package
   configures logging at import time, so by the time ``main()`` runs a root
   handler already exists and a plain ``basicConfig`` is a silent no-op --
   which is exactly the "accepted and ignored" defect ``--log-level`` exists
   to fix. Prior art: ``orb-discovery/worker/worker/main.py``.
"""

import logging

# Byte-identical to logging.BASIC_FORMAT. See the module docstring.
LOG_FORMAT = "%(levelname)s:%(name)s:%(message)s"

DEFAULT_LEVEL = logging.INFO

# Mirrors parseDeviceDiscoveryLevel in
# agent/backend/devicediscovery/device_discovery.go so that every token the
# agent can forward resolves here instead of silently falling back to INFO.
#
# Deliberately an explicit dict rather than logging.getLevelNamesMapping()
# (3.11+, while pyproject declares requires-python = ">=3.10") or
# logging.getLevelName(), which returns the string "Level TRACE" for trace,
# err and exception -- setLevel raises on those.
_LEVEL_ALIASES = {
    "trace": logging.DEBUG,
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warn": logging.WARNING,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "err": logging.ERROR,
    "exception": logging.ERROR,
    "critical": logging.CRITICAL,
    "fatal": logging.CRITICAL,
}


def flatten_message(value: object) -> str:
    """
    Collapse a value's string form onto a single physical line.

    Not cosmetic. netmiko builds its timeout and authentication messages as
    ten-line f-strings, and the agent splits the backend's stderr on every
    newline and assigns ERROR by pipe rather than by content
    (agent/backend/process.go and device_discovery.go). An unflattened
    message therefore becomes one WARNING plus nine ERROR records.
    """
    return " ".join(str(value).split())


def resolve_log_level(value: object) -> tuple[int, str | None]:
    """
    Resolve a log-level value to a logging level, never raising.

    Tolerates non-str input on purpose: the argparse namespace is a MagicMock
    under test, and a YAML ``log_level: 3`` reaches us as an int.

    Args:
    ----
        value: the raw log-level value, of any type.

    Returns:
    -------
        tuple[int, str | None]: the resolved level, and a warning message when
        the value was unrecognised (so a degraded setting is visible rather
        than silent) or None when it was understood.

    """
    normalized = str(value).strip().lower()
    level = _LEVEL_ALIASES.get(normalized)
    if level is None:
        return DEFAULT_LEVEL, f"unrecognised log level {value!r}, falling back to INFO"
    return level, None


def configure_logging(value: object) -> int:
    """
    Configure root logging from a --log-level value, replacing any existing setup.

    ``force=True`` is required: the import-time ``configure_default_logging``
    calls have already installed a root handler by the time this runs, and
    ``basicConfig`` without ``force`` would be a silent no-op.

    Args:
    ----
        value: the raw --log-level value.

    Returns:
    -------
        int: the logging level that was applied.

    """
    level, warning = resolve_log_level(value)
    logging.basicConfig(level=level, format=LOG_FORMAT, force=True)
    if warning:
        logging.getLogger(__name__).warning(warning)
    return level


def configure_default_logging() -> None:
    """
    Configure root logging at the package default of INFO, if not already configured.

    Called at import time by the modules that used to call ``basicConfig``
    directly. Behaviour is unchanged -- the first call still wins and it is
    still INFO -- but the format is now stated once instead of being five
    implicit copies of an unchecked wire contract.

    Not removable: these modules are imported standalone by the test suite and
    by the FastAPI app, and without this the root logger is left unconfigured
    and INFO records vanish under ``logging.lastResort``.
    """
    logging.basicConfig(level=DEFAULT_LEVEL, format=LOG_FORMAT)
