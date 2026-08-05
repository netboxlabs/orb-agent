#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
NetBox Labs - Structural guard against reintroducing ERROR-level tracebacks.

The generic Go stderr amplifier stays in place by decision, so nothing
downstream will ever catch a reintroduced ``exc_info=True`` on a routine
condition. This test is the backstop.
"""

import ast
import pathlib

RUNNER = (
    pathlib.Path(__file__).resolve().parents[1]
    / "device_discovery"
    / "policy"
    / "runner.py"
)


def _calls(tree):
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call)]


def _emitter_line_range(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_log_target_failure":
            return range(node.lineno, (node.end_lineno or node.lineno) + 1)
    return range(0)


def _attribute_path(func):
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


def test_no_logger_error_carries_exc_info():
    """
    logger.error(..., exc_info=...) belongs only inside _log_target_failure.

    Anywhere else it means a routine per-target condition is emitting a full
    chained traceback again, which the agent fans out into ~63 ERROR records.
    """
    tree = ast.parse(RUNNER.read_text())
    offenders = []
    for call in _calls(tree):
        if _attribute_path(call.func) != "logger.error":
            continue
        if any(keyword.arg == "exc_info" for keyword in call.keywords):
            offenders.append(call.lineno)

    allowed = _emitter_line_range(tree)
    unexpected = [line for line in offenders if line not in allowed]
    assert unexpected == [], (
        f"logger.error(..., exc_info=...) outside _log_target_failure at lines {unexpected}"
    )


def test_the_emitter_exists_so_this_cannot_pass_vacuously():
    """A guard that passes because the thing it guards was deleted is not a guard."""
    tree = ast.parse(RUNNER.read_text())
    names = {
        node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
    }
    assert "_log_target_failure" in names

    source = RUNNER.read_text()
    assert source.count("self._log_target_failure(") == 2, (
        "expected exactly two call sites: run() and run_with_parent()"
    )
