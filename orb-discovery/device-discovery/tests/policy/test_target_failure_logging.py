#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""NetBox Labs - Per-target failure logging behaviour unit tests."""

import logging
from unittest.mock import patch

import pytest
from napalm.base.exceptions import ConnectionException
from netmiko.exceptions import NetmikoAuthenticationException

from device_discovery.policy.models import Config, Defaults, Napalm, Status
from device_discovery.policy.run import RunStatus, RunStore
from device_discovery.policy.runner import PolicyRunner

RUNNER_LOGGER = "device_discovery.policy.runner"

# The real ten-line message netmiko builds for a rejected credential.
AUTH_MESSAGE = """Authentication to device failed.

Common causes of this problem are:
1. Invalid username and password
2. Incorrect SSH-key file
3. Connecting to the wrong device

Device settings: cisco_ios 10.0.0.5:22

Authentication failed."""


@pytest.fixture
def runner():
    """A PolicyRunner wired to a real RunStore."""
    instance = PolicyRunner()
    instance.name = "test_policy"
    instance.run_store = RunStore()
    return instance


@pytest.fixture
def scope():
    """A scope with the driver pinned, so driver discovery is skipped."""
    return Napalm(
        driver="ios", hostname="10.0.0.5", username="admin", password="password"
    )


@pytest.fixture
def config():
    """A minimal policy config."""
    return Config(schedule="0 * * * *", defaults=Defaults(site="Lab"))


def _invoke(runner, entry_point, scope, config):
    if entry_point == "run":
        runner.run("test_id", scope, config)
    else:
        runner.run_with_parent("test_id", scope, config, "10.0.0.0/24")


ENTRY_POINTS = ["run", "run_with_parent"]


@pytest.mark.parametrize("entry_point", ENTRY_POINTS)
@pytest.mark.parametrize(
    "error",
    [
        ConnectionException("Cannot connect to 10.0.0.5"),
        NetmikoAuthenticationException(AUTH_MESSAGE),
    ],
)
def test_expected_failure_is_one_flat_warning(
    runner, scope, config, entry_point, error, caplog
):
    """One WARNING, no traceback, no embedded newline -- on both entry points."""
    with (
        patch.object(PolicyRunner, "_collect_device_data", side_effect=error),
        caplog.at_level(logging.INFO, logger=RUNNER_LOGGER),
    ):
        _invoke(runner, entry_point, scope, config)

    records = [r for r in caplog.records if r.name == RUNNER_LOGGER and r.levelno >= logging.WARNING]
    assert len(records) == 1
    record = records[0]
    assert record.levelno == logging.WARNING
    assert record.exc_info is None
    assert record.exc_text is None
    assert "\n" not in record.getMessage()
    assert "10.0.0.5" in record.getMessage()


@pytest.mark.parametrize("entry_point", ENTRY_POINTS)
def test_expected_failure_keeps_traceback_at_debug(
    runner, scope, config, entry_point, caplog
):
    """At DEBUG the traceback is recoverable, still on a single physical line."""
    error = ConnectionException("Cannot connect to 10.0.0.5")
    with (
        patch.object(PolicyRunner, "_collect_device_data", side_effect=error),
        caplog.at_level(logging.DEBUG, logger=RUNNER_LOGGER),
    ):
        _invoke(runner, entry_point, scope, config)

    relevant = [
        r
        for r in caplog.records
        if r.name == RUNNER_LOGGER and r.levelno in (logging.WARNING, logging.DEBUG)
    ]
    assert [r.levelno for r in relevant] == [logging.WARNING, logging.DEBUG]
    debug_message = relevant[1].getMessage()
    assert "Traceback" in debug_message
    assert "\n" not in debug_message


@pytest.mark.parametrize("entry_point", ENTRY_POINTS)
def test_unexpected_failure_keeps_error_and_exc_info(
    runner, scope, config, entry_point, caplog
):
    """The decision-3 guard: real bugs must not lose their traceback."""
    error = RuntimeError("boom")
    with (
        patch.object(PolicyRunner, "_collect_device_data", side_effect=error),
        caplog.at_level(logging.INFO, logger=RUNNER_LOGGER),
    ):
        _invoke(runner, entry_point, scope, config)

    errors = [r for r in caplog.records if r.name == RUNNER_LOGGER and r.levelno == logging.ERROR]
    warnings = [r for r in caplog.records if r.name == RUNNER_LOGGER and r.levelno == logging.WARNING]
    assert len(errors) == 1
    assert errors[0].exc_info is not None
    assert errors[0].exc_info[1] is error
    assert warnings == []


@pytest.mark.parametrize("entry_point", ENTRY_POINTS)
def test_non_log_behaviour_is_unchanged(runner, scope, config, entry_point):
    """Run status, reason, and the failure metrics must be untouched."""
    error = NetmikoAuthenticationException(AUTH_MESSAGE)
    with patch.object(PolicyRunner, "_collect_device_data", side_effect=error):
        _invoke(runner, entry_point, scope, config)

    runs = runner.run_store.get_runs_for_policy("test_policy")
    assert runs
    run = runs[0]
    assert run.status is RunStatus.FAILED
    # run.reason is flattened too -- a multi-line string inside the JSON
    # /api/v1/status response is a defect on its own.
    assert "\n" not in run.reason
    assert "Authentication to device failed." in run.reason


@pytest.mark.parametrize("entry_point", ENTRY_POINTS)
def test_both_entry_points_route_through_the_shared_emitter(
    runner, scope, config, entry_point
):
    """The failure rule must not be able to drift between run and run_with_parent."""
    error = ConnectionException("Cannot connect to 10.0.0.5")
    with (
        patch.object(PolicyRunner, "_collect_device_data", side_effect=error),
        patch.object(PolicyRunner, "_log_target_failure") as emitter,
    ):
        _invoke(runner, entry_point, scope, config)

    assert emitter.call_count == 1


def test_driver_discovery_failure_warns_rather_than_errors(runner, scope, config, caplog):
    """
    runner.py:207 is the same expected-failure class on the auto-discovery path.

    Status.FAILED is deliberately left alone -- see the follow-up issue.
    """
    scope.driver = None
    with (
        patch("device_discovery.policy.runner.discover_device_driver", return_value=None),
        caplog.at_level(logging.INFO, logger=RUNNER_LOGGER),
    ):
        runner.run("test_id", scope, config)

    matching = [
        r
        for r in caplog.records
        if "Not able to discover device driver" in r.getMessage()
    ]
    assert len(matching) == 1
    assert matching[0].levelno == logging.WARNING
    assert runner.status == Status.FAILED
