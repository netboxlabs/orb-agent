#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""NetBox Labs - Worker Run Store Unit Tests."""

import threading
import time
from datetime import datetime

import pytest

from worker.policy.run import MAX_RUNS_PER_POLICY, RunStatus, RunStore


@pytest.fixture
def run_store():
    """Fixture to create a RunStore instance."""
    return RunStore()


def test_create_run_basic(run_store):
    """Test creating a basic run."""
    policy_name = "test-policy"

    run = run_store.create_run(policy_name)

    # Verify run properties
    assert run.id is not None
    assert run.policy_id == policy_name
    assert run.status == RunStatus.RUNNING
    assert run.reason == ""
    assert run.entity_count == 0
    assert run.metadata == {}
    assert isinstance(run.created_at, int)
    assert isinstance(run.updated_at, int)
    # created_at and updated_at should be very close (within 1 second in nanoseconds)
    time_diff_ns = abs(run.updated_at - run.created_at)
    assert time_diff_ns < 1_000_000_000  # 1 second in nanoseconds

    # Verify run is stored
    runs = run_store.get_runs_for_policy(policy_name)
    assert len(runs) == 1
    assert runs[0].id == run.id
    assert runs[0].policy_id == policy_name


def test_create_run_with_metadata(run_store):
    """Test creating a run with metadata."""
    policy_name = "test-policy"
    metadata = {
        "name": "test_backend",
        "app_name": "test_app",
        "app_version": "1.0.0",
    }

    run = run_store.create_run(policy_name, metadata=metadata)

    # Verify metadata is stored
    assert run.metadata == metadata

    # Verify run is stored with metadata
    runs = run_store.get_runs_for_policy(policy_name)
    assert len(runs) == 1
    assert runs[0].metadata == metadata


def test_update_run_to_completed(run_store):
    """Test updating a run to completed status."""
    policy_name = "test-policy"

    run = run_store.create_run(policy_name)
    run_id = run.id

    # Update to completed
    entity_count = 5
    run_store.update_run(
        policy_name=policy_name,
        run_id=run_id,
        status=RunStatus.COMPLETED,
        error=None,
        entity_count=entity_count,
    )

    runs = run_store.get_runs_for_policy(policy_name)
    assert len(runs) == 1
    assert runs[0].status == RunStatus.COMPLETED
    assert runs[0].reason == ""
    assert runs[0].entity_count == entity_count
    assert runs[0].updated_at > runs[0].created_at


def test_update_run_to_failed(run_store):
    """Test updating a run to failed status with error."""
    policy_name = "test-policy"

    run = run_store.create_run(policy_name)
    run_id = run.id

    # Update to failed with error
    test_error = Exception("test error")
    entity_count = 10
    run_store.update_run(
        policy_name=policy_name,
        run_id=run_id,
        status=RunStatus.FAILED,
        error=test_error,
        entity_count=entity_count,
    )

    runs = run_store.get_runs_for_policy(policy_name)
    assert len(runs) == 1
    assert runs[0].status == RunStatus.FAILED
    assert runs[0].reason == str(test_error)
    assert runs[0].entity_count == entity_count


def test_max_runs_per_policy(run_store):
    """Test that only the last MAX_RUNS_PER_POLICY runs are retained per policy."""
    policy_name = "test-policy"

    # Create 7 runs (more than MAX_RUNS_PER_POLICY which is 5)
    run_ids = []
    for i in range(7):
        run = run_store.create_run(policy_name)
        run_ids.append(run.id)
        time.sleep(0.01)  # Small delay to ensure different timestamps

    # Verify only last 5 runs are retained
    runs = run_store.get_runs_for_policy(policy_name)
    assert len(runs) == MAX_RUNS_PER_POLICY

    # Verify the last 5 runs are the ones retained (sorted newest first)
    expected_ids = run_ids[2:]  # Last 5 runs
    expected_ids.reverse()  # Newest first
    actual_ids = [run.id for run in runs]
    assert actual_ids == expected_ids


def test_multiple_policies(run_store):
    """Test storing runs for multiple policies."""
    policy1 = "policy-1"
    policy2 = "policy-2"

    # Create runs for policy 1
    run_store.create_run(policy1)
    run_store.create_run(policy1)

    # Create run for policy 2
    run_store.create_run(policy2)

    # Verify runs are stored separately
    runs1 = run_store.get_runs_for_policy(policy1)
    runs2 = run_store.get_runs_for_policy(policy2)

    assert len(runs1) == 2
    assert len(runs2) == 1
    assert all(run.policy_id == policy1 for run in runs1)
    assert all(run.policy_id == policy2 for run in runs2)


def test_get_all_policies_with_runs(run_store):
    """Test getting all policies with their runs."""
    policy1 = "policy-1"
    policy2 = "policy-2"

    # Create runs for multiple policies
    run_store.create_run(policy1)
    run_store.create_run(policy1)
    run_store.create_run(policy2)

    all_runs = run_store.get_all_policies_with_runs()

    assert len(all_runs) == 2
    assert len(all_runs[policy1]) == 2
    assert len(all_runs[policy2]) == 1

    # Verify policy_id is set correctly for each run
    for run in all_runs[policy1]:
        assert run.policy_id == policy1
    for run in all_runs[policy2]:
        assert run.policy_id == policy2


def test_get_runs_for_policy_empty(run_store):
    """Test getting runs for a non-existent policy."""
    runs = run_store.get_runs_for_policy("non-existent-policy")
    assert runs == []


def test_update_run_non_existent(run_store):
    """Test updating a non-existent run does not cause errors."""
    # Should not panic or raise an error
    run_store.update_run(
        policy_name="non-existent-policy",
        run_id="non-existent-id",
        status=RunStatus.FAILED,
        error=Exception("test"),
        entity_count=0,
    )

    # Verify no runs were created
    runs = run_store.get_runs_for_policy("non-existent-policy")
    assert runs == []


def test_run_deep_copy(run_store):
    """Test that runs are deep copied to prevent race conditions."""
    policy_name = "test-policy"
    metadata = {"key": "value"}

    run = run_store.create_run(policy_name, metadata=metadata)

    # Modify the returned run
    run.status = RunStatus.COMPLETED
    run.metadata["key"] = "modified"

    # Verify stored run is unchanged
    stored_runs = run_store.get_runs_for_policy(policy_name)
    assert stored_runs[0].status == RunStatus.RUNNING
    assert stored_runs[0].metadata["key"] == "value"


def test_runs_sorted_newest_first(run_store):
    """Test that runs are returned sorted by created_at descending (newest first)."""
    policy_name = "test-policy"

    # Create multiple runs with delays
    runs_created = []
    for i in range(3):
        run = run_store.create_run(policy_name)
        runs_created.append(run)
        time.sleep(0.01)  # Ensure different timestamps

    # Get runs
    runs = run_store.get_runs_for_policy(policy_name)

    # Verify they are in reverse order (newest first)
    assert len(runs) == 3
    assert runs[0].id == runs_created[2].id
    assert runs[1].id == runs_created[1].id
    assert runs[2].id == runs_created[0].id


def test_concurrency_create_runs(run_store):
    """Test concurrent run creation is thread-safe."""
    policy_name = "test-policy"
    num_threads = 10
    runs_per_thread = 5

    def create_runs():
        for _ in range(runs_per_thread):
            run_store.create_run(policy_name)

    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=create_runs)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Verify we have at most MAX_RUNS_PER_POLICY runs
    runs = run_store.get_runs_for_policy(policy_name)
    assert len(runs) <= MAX_RUNS_PER_POLICY


def test_concurrency_update_runs(run_store):
    """Test concurrent run updates are thread-safe."""
    policy_name = "test-policy"
    run = run_store.create_run(policy_name)
    run_id = run.id

    num_threads = 10
    entity_count = 3

    def update_run():
        run_store.update_run(
            policy_name=policy_name,
            run_id=run_id,
            status=RunStatus.COMPLETED,
            error=None,
            entity_count=entity_count,
        )

    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=update_run)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Verify run was updated
    runs = run_store.get_runs_for_policy(policy_name)
    assert len(runs) == 1
    assert runs[0].id == run_id
    assert runs[0].status == RunStatus.COMPLETED
    assert runs[0].entity_count == entity_count
