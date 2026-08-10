#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""NetBox Labs - Per-target failure classification unit tests."""

import pytest
from napalm.base.exceptions import (
    CommandErrorException,
    CommandTimeoutException,
    ConnectAuthError,
    ConnectionClosedException,
    ConnectionException,
    ConnectTimeoutError,
    NapalmException,
    UnsupportedVersion,
    ValidationException,
)
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from device_discovery.policy.runner import (
    _EXPECTED_TARGET_FAILURES,
    _is_expected_target_failure,
)


def test_tuple_membership_is_a_conscious_choice():
    """
    Pin the tuple so widening or narrowing it must be a deliberate test edit.

    Collapsing it to the ConnectionException anchor alone restores the full
    traceback wall for rejected credentials, which is the reported case.
    """
    assert _EXPECTED_TARGET_FAILURES == (
        ConnectionException,
        NetmikoAuthenticationException,
    )


def test_netmiko_auth_is_not_reachable_via_the_anchor():
    """
    The reason the second entry exists.

    netmiko roots NetmikoAuthenticationException in paramiko, not napalm, so a
    rejected credential propagates past napalm's timeout-only except clause.
    """
    assert not issubclass(NetmikoAuthenticationException, ConnectionException)
    assert not issubclass(NetmikoAuthenticationException, NapalmException)


@pytest.mark.parametrize(
    "error",
    [
        ConnectionException("Cannot connect to 10.0.0.5"),
        ConnectAuthError("auth"),
        ConnectTimeoutError("timeout"),
        ConnectionClosedException("closed"),
        UnsupportedVersion("version"),
        NetmikoAuthenticationException("Authentication to device failed."),
    ],
)
def test_expected_failures(error):
    """Routine unreachable/unauthenticated hosts classify as expected."""
    assert _is_expected_target_failure(error) is True


@pytest.mark.parametrize(
    "error",
    [
        NapalmException("bare napalm"),
        CommandErrorException("bad command"),
        CommandTimeoutException("command timed out"),
        ValidationException("invalid"),
        NetmikoTimeoutException("normalized upstream, should not be listed"),
        KeyError("missing"),
        ValueError("bad value"),
        NotImplementedError("driver gap"),
        # Stand-in for a diode transport failure: Client().ingest runs inside
        # the same catch-all, and a dead ingest endpoint must NOT be reported
        # as a per-host connection failure.
        ConnectionResetError("diode endpoint reset"),
        TimeoutError("builtin timeout"),
        OSError("dns"),
    ],
)
def test_unexpected_failures(error):
    """Everything else keeps ERROR and its traceback."""
    assert _is_expected_target_failure(error) is False


def test_the_exception_chain_is_deliberately_not_walked():
    """
    A driver bug raised while handling a connection error stays UNEXPECTED.

    Proves the chain exists and is ignored on purpose, rather than the test
    passing because no chain was built.
    """
    try:
        try:
            raise ConnectionException("Cannot connect to 10.0.0.5")
        except ConnectionException:
            raise KeyError("driver bug")
    except KeyError as error:
        assert _is_expected_target_failure(error) is False
        assert isinstance(error.__context__, ConnectionException)
