#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Device Discovery - unscoped-VLAN warning gate tests."""

import logging

import pytest
from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb

from device_discovery.client import Client


@pytest.fixture(autouse=True)
def _fresh_singleton():
    """
    Give each test its own Client.

    The Client is a process-wide singleton and the warned-policy set lives on
    it, so without this the gate under test would leak between tests and the
    results would depend on ordering.
    """
    Client._instance = None
    yield
    Client._instance = None


class _StubDiodeClient:
    """Accepts everything; the warning fires before ingestion is attempted."""

    def ingest(self, *args, **kwargs):
        class _Response:
            errors = None

        return _Response()


def _unscoped_vlan_entities():
    return [pb.Entity(vlan=pb.VLAN(vid=101, name="Voice"))]


def _ingest(client, policy, monkeypatch, instance="run-1"):
    monkeypatch.setattr(
        "device_discovery.client.translate_data",
        lambda data: _unscoped_vlan_entities(),
    )
    client.ingest(
        {"policy_name": policy, "policy_instance": instance, "hostname": "h1"},
        {},
        None,
    )


def _warnings(caplog):
    return [r for r in caplog.records if r.levelno == logging.WARNING
            and "VLAN group" in r.getMessage()]


def test_warns_once_per_policy_not_once_per_device(caplog, monkeypatch):
    """Repeated devices in one policy produce one warning, not thousands."""
    client = Client()
    client.diode_client = _StubDiodeClient()
    monkeypatch.setattr("device_discovery.client.prune_nested_refs", lambda e: None)
    with caplog.at_level(logging.WARNING):
        for _ in range(3):
            _ingest(client, "site-a", monkeypatch)
    assert len(_warnings(caplog)) == 1


def test_a_second_policy_is_still_warned(caplog, monkeypatch):
    """One Client serves every policy, so the gate must not silence the rest."""
    client = Client()
    client.diode_client = _StubDiodeClient()
    monkeypatch.setattr("device_discovery.client.prune_nested_refs", lambda e: None)
    with caplog.at_level(logging.WARNING):
        _ingest(client, "site-a", monkeypatch, instance="run-a")
        _ingest(client, "site-b", monkeypatch, instance="run-b")
    messages = [r.getMessage() for r in _warnings(caplog)]
    assert len(messages) == 2
    assert "site-a" in messages[0]
    assert "site-b" in messages[1]


def test_a_new_runner_for_the_same_policy_warns_again(caplog, monkeypatch):
    """
    Recreating a policy must warn again, without depending on a cleanup step.

    The key is the runner, not the policy name, so a job still in flight from
    the deleted runner writes its own dead key. Keying on the name instead let
    that late job silence the replacement for the life of the process, because
    PolicyRunner.stop() shuts the scheduler down with wait=False.
    """
    client = Client()
    client.diode_client = _StubDiodeClient()
    monkeypatch.setattr("device_discovery.client.prune_nested_refs", lambda e: None)

    with caplog.at_level(logging.WARNING):
        _ingest(client, "site-a", monkeypatch, instance="run-1")
        # The deleted runner's in-flight job lands after the policy was removed.
        _ingest(client, "site-a", monkeypatch, instance="run-1")
        # Its replacement is a different runner.
        _ingest(client, "site-a", monkeypatch, instance="run-2")

    assert len(_warnings(caplog)) == 2


def test_the_runner_supplies_a_distinct_instance_id(monkeypatch):
    """The key only works if each runner really is distinct."""
    from device_discovery.policy.runner import PolicyRunner

    assert PolicyRunner().instance_id != PolicyRunner().instance_id
