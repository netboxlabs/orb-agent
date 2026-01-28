#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Tests for RunStore."""

import threading
import time

from device_discovery.policy.run import Run, RunStatus, RunStore


def test_run_creation():
    """Test basic run creation."""
    run = Run(
        policy_id="test-policy",
        status=RunStatus.RUNNING,
        metadata={"target": "router1.example.com"},
    )

    assert run.id  # UUID should be generated
    assert run.policy_id == "test-policy"
    assert run.status == RunStatus.RUNNING
    assert run.reason == ""
    assert run.entity_count == 0
    assert run.metadata["target"] == "router1.example.com"
    assert run.created_at
    assert run.updated_at


def test_run_with_parent():
    """Test run creation with parent tracking."""
    run = Run(
        policy_id="test-policy",
        status=RunStatus.RUNNING,
        metadata={
            "target": "192.168.1.5",
            "parent_target": "192.168.1.0/24",
        },
    )

    assert run.metadata["target"] == "192.168.1.5"
    assert run.metadata["parent_target"] == "192.168.1.0/24"


def test_create_run_basic():
    """Test basic run creation."""
    store = RunStore()
    run = store.create_run("policy1", "192.168.1.1", "")

    assert run.policy_id == "policy1"
    assert run.status == RunStatus.RUNNING
    assert run.metadata["target"] == "192.168.1.1"
    assert "parent_target" not in run.metadata


def test_create_run_with_parent():
    """Test run creation with parent tracking."""
    store = RunStore()
    run = store.create_run("policy1", "192.168.1.5", "192.168.1.0/24")

    assert run.metadata["target"] == "192.168.1.5"
    assert run.metadata["parent_target"] == "192.168.1.0/24"


def test_update_run_success():
    """Test updating run to completed status."""
    store = RunStore()
    run = store.create_run("policy1", "router1.example.com", "")

    store.update_run(
        "policy1", "router1.example.com", run.id, RunStatus.COMPLETED, None, 42
    )

    updated = store.get_runs_for_target("policy1", "router1.example.com")[0]
    assert updated.status == RunStatus.COMPLETED
    assert updated.entity_count == 42
    assert updated.reason == ""


def test_update_run_failure():
    """Test updating run to failed status with error."""
    store = RunStore()
    run = store.create_run("policy1", "router1.example.com", "")

    error = Exception("Connection timeout")
    store.update_run(
        "policy1", "router1.example.com", run.id, RunStatus.FAILED, error, 0
    )

    updated = store.get_runs_for_target("policy1", "router1.example.com")[0]
    assert updated.status == RunStatus.FAILED
    assert updated.entity_count == 0
    assert "Connection timeout" in updated.reason


def test_normalize_target_ip():
    """Test IP address normalization."""
    store = RunStore()

    # Create runs with different IP formats (Python's ipaddress module normalizes them)
    store.create_run("policy1", "192.168.1.1", "")
    store.create_run("policy1", "192.168.1.1", "")

    # Should be stored under same normalized key
    runs = store.get_runs_for_target("policy1", "192.168.1.1")
    assert len(runs) == 2


def test_normalize_target_hostname():
    """Test hostname normalization (case-insensitive)."""
    store = RunStore()

    store.create_run("policy1", "Router1.Example.COM", "")
    store.create_run("policy1", "router1.example.com", "")

    # Should be stored under same normalized key (lowercase)
    runs = store.get_runs_for_target("policy1", "ROUTER1.EXAMPLE.COM")
    assert len(runs) == 2


def test_normalize_target_cidr():
    """Test CIDR range normalization."""
    store = RunStore()

    store.create_run("policy1", "192.168.1.0/24", "")
    store.create_run("policy1", "192.168.1.0/24", "")

    # Should be stored under same normalized key
    runs = store.get_runs_for_target("policy1", "192.168.1.0/24")
    assert len(runs) == 2


def test_get_runs_for_policy_sorted():
    """Test runs are returned newest first."""
    store = RunStore()

    run1 = store.create_run("policy1", "192.168.1.1", "")
    time.sleep(0.01)
    run2 = store.create_run("policy1", "192.168.1.2", "")
    time.sleep(0.01)
    run3 = store.create_run("policy1", "192.168.1.3", "")

    runs = store.get_runs_for_policy("policy1")
    assert len(runs) == 3
    assert runs[0].id == run3.id  # Newest first
    assert runs[1].id == run2.id
    assert runs[2].id == run1.id


def test_get_runs_for_nonexistent_policy():
    """Test getting runs for policy that doesn't exist."""
    store = RunStore()

    runs = store.get_runs_for_policy("nonexistent")
    assert runs == []


def test_get_runs_for_nonexistent_target():
    """Test getting runs for target that doesn't exist."""
    store = RunStore()
    store.create_run("policy1", "192.168.1.1", "")

    runs = store.get_runs_for_target("policy1", "192.168.1.2")
    assert runs == []


def test_get_all_policies_with_runs():
    """Test getting all policies with their runs."""
    store = RunStore()

    # Create runs for multiple policies
    store.create_run("policy1", "192.168.1.1", "")
    store.create_run("policy1", "192.168.1.2", "")
    store.create_run("policy2", "192.168.2.1", "")

    all_runs = store.get_all_policies_with_runs()

    assert len(all_runs) == 2
    assert "policy1" in all_runs
    assert "policy2" in all_runs
    assert len(all_runs["policy1"]) == 2
    assert len(all_runs["policy2"]) == 1


def test_deep_copy_returned():
    """Test that returned runs are deep copies."""
    store = RunStore()
    store.create_run("policy1", "192.168.1.1", "")

    # Get the run
    retrieved = store.get_runs_for_target("policy1", "192.168.1.1")[0]

    # Modify the retrieved run
    retrieved.status = RunStatus.FAILED
    retrieved.reason = "Modified"

    # Original should be unchanged
    original = store.get_runs_for_target("policy1", "192.168.1.1")[0]
    assert original.status == RunStatus.RUNNING
    assert original.reason == ""


def test_thread_safety_create():
    """Test concurrent run creation from multiple threads."""
    store = RunStore()
    errors = []
    run_count = 50

    def create_runs():
        try:
            for i in range(run_count):
                store.create_run("policy1", f"192.168.1.{i % 10}", "")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=create_runs) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    runs = store.get_runs_for_policy("policy1")
    assert len(runs) > 0


def test_thread_safety_update():
    """Test concurrent run updates from multiple threads."""
    store = RunStore()
    errors = []

    # Create initial runs
    run_ids = []
    for i in range(10):
        run = store.create_run("policy1", f"192.168.1.{i}", "")
        run_ids.append((f"192.168.1.{i}", run.id))

    def update_runs():
        try:
            for target, run_id in run_ids:
                store.update_run(
                    "policy1", target, run_id, RunStatus.COMPLETED, None, 1
                )
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=update_runs) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors

    # Verify all runs were updated
    for target, run_id in run_ids:
        runs = store.get_runs_for_target("policy1", target)
        assert len(runs) == 1
        assert runs[0].status == RunStatus.COMPLETED
        assert runs[0].entity_count == 1


def test_multiple_policies_isolated():
    """Test that runs for different policies are isolated."""
    store = RunStore()

    run1 = store.create_run("policy1", "192.168.1.1", "")
    run2 = store.create_run("policy2", "192.168.1.1", "")

    # Each policy should have its own run
    policy1_runs = store.get_runs_for_policy("policy1")
    policy2_runs = store.get_runs_for_policy("policy2")

    assert len(policy1_runs) == 1
    assert len(policy2_runs) == 1
    assert policy1_runs[0].id == run1.id
    assert policy2_runs[0].id == run2.id


def test_update_nonexistent_run():
    """Test updating a run that doesn't exist (should not raise error)."""
    store = RunStore()

    # Should not raise an error
    store.update_run(
        "policy1",
        "192.168.1.1",
        "nonexistent-id",
        RunStatus.COMPLETED,
        None,
        1,
    )


def test_parent_child_relationship():
    """Test parent-child relationship tracking."""
    store = RunStore()

    # Create parent run (scan)
    store.create_run("policy1", "192.168.1.0/24", "")

    # Create child runs
    store.create_run("policy1", "192.168.1.5", "192.168.1.0/24")
    store.create_run("policy1", "192.168.1.10", "192.168.1.0/24")

    # Verify parent run
    parent_runs = store.get_runs_for_target("policy1", "192.168.1.0/24")
    assert len(parent_runs) == 1
    assert parent_runs[0].metadata["target"] == "192.168.1.0/24"
    assert "parent_target" not in parent_runs[0].metadata

    # Verify child runs have parent reference
    child1_runs = store.get_runs_for_target("policy1", "192.168.1.5")
    assert len(child1_runs) == 1
    assert child1_runs[0].metadata["target"] == "192.168.1.5"
    assert child1_runs[0].metadata["parent_target"] == "192.168.1.0/24"

    child2_runs = store.get_runs_for_target("policy1", "192.168.1.10")
    assert len(child2_runs) == 1
    assert child2_runs[0].metadata["target"] == "192.168.1.10"
    assert child2_runs[0].metadata["parent_target"] == "192.168.1.0/24"


def test_metadata_preserved():
    """Test that original target is preserved in metadata."""
    store = RunStore()

    # Create run with IP that will be normalized
    store.create_run("policy1", "Router1.Example.COM", "")

    # Verify metadata contains original (not normalized)
    retrieved = store.get_runs_for_target("policy1", "router1.example.com")[0]
    assert retrieved.metadata["target"] == "Router1.Example.COM"
