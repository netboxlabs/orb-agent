#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Shared fixtures for the device-discovery test suite."""

import logging

import pytest

_LIBRARY_LOGGERS = ("napalm", "ncclient", "paramiko", "pyeapi")


@pytest.fixture
def preserve_root_logging():
    """
    Snapshot and restore process-global logging state.

    ``basicConfig(force=True)`` and ``set_napalm_logs_level`` both mutate
    process-global state, so without this the "exactly one record" and
    "exactly one line" assertions become order-dependent flakes.
    """
    root = logging.getLogger()
    saved_level = root.level
    saved_handlers = root.handlers[:]
    saved_library = {name: logging.getLogger(name).level for name in _LIBRARY_LOGGERS}

    yield

    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)
    for name, level in saved_library.items():
        logging.getLogger(name).setLevel(level)
