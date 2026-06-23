#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""NetBox Labs - worker.exceptions hierarchy tests."""

import pytest

from worker.exceptions import IngestError, IngestRejected, IngestUnavailable


def test_unavailable_is_ingest_error():
    """IngestUnavailable is a subclass of IngestError."""
    assert issubclass(IngestUnavailable, IngestError)


def test_rejected_is_ingest_error():
    """IngestRejected is a subclass of IngestError."""
    assert issubclass(IngestRejected, IngestError)


def test_ingest_error_chain_catchable_as_base():
    """Subclasses can be caught as the base IngestError."""
    with pytest.raises(IngestError):
        raise IngestUnavailable("transient")
    with pytest.raises(IngestError):
        raise IngestRejected("bad payload")


@pytest.mark.parametrize(
    "exc_cls,msg",
    [
        pytest.param(IngestError, "base", id="base"),
        pytest.param(IngestUnavailable, "transient", id="unavailable"),
        pytest.param(IngestRejected, "permanent", id="rejected"),
    ],
)
def test_exceptions_carry_message(exc_cls, msg):
    """Each exception carries its constructor message via str()."""
    exc = exc_cls(msg)
    assert str(exc) == msg
