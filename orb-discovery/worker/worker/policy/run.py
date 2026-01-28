#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Worker Run Store."""

import threading
import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class RunStatus(str, Enum):
    """Run status enumeration."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Run(BaseModel):
    """Model for a single run execution."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    policy_id: str
    status: RunStatus
    reason: str = ""
    entity_count: int = 0
    metadata: dict[str, str] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now())
    updated_at: datetime = Field(default_factory=lambda: datetime.now())


# Maximum number of runs to keep per policy
MAX_RUNS_PER_POLICY = 5


class RunStore:
    """
    Thread-safe store for managing policy run history.

    Tracks up to MAX_RUNS_PER_POLICY runs per policy.
    Uses a dictionary: policy_name -> list of runs.
    """

    def __init__(self):
        """Initialize the RunStore with thread-safe storage."""
        self._lock = threading.RLock()
        self._runs: dict[str, list[Run]] = {}

    def _copy_run(self, run: Run) -> Run:
        """
        Create deep copy of run to prevent race conditions.

        Args:
        ----
            run: Run object to copy.

        Returns:
        -------
            Run: Deep copy of the run.

        """
        return run.model_copy(deep=True)

    def create_run(
        self, policy_name: str, metadata: dict[str, str] | None = None
    ) -> Run:
        """
        Create a new run for the given policy.

        Args:
        ----
            policy_name: Name of the policy.
            metadata: Optional metadata to attach to the run (e.g., app_name, app_version).

        Returns:
        -------
            Run: The created Run object (deep copy).

        """
        with self._lock:
            # Create run with running status
            run = Run(
                policy_id=policy_name,
                status=RunStatus.RUNNING,
                metadata=metadata or {},
            )

            # Initialize list if needed
            if policy_name not in self._runs:
                self._runs[policy_name] = []

            # Add run to the policy's run list
            runs = self._runs[policy_name]
            runs.append(run)

            # Keep only the last MAX_RUNS_PER_POLICY runs
            if len(runs) > MAX_RUNS_PER_POLICY:
                runs[:] = runs[-MAX_RUNS_PER_POLICY:]

            return self._copy_run(run)

    def update_run(
        self,
        policy_name: str,
        run_id: str,
        status: RunStatus,
        error: Exception | None,
        entity_count: int,
    ) -> None:
        """
        Update an existing run's status.

        Args:
        ----
            policy_name: Name of the policy.
            run_id: Run ID to update.
            status: New status.
            error: Error if failed, None otherwise.
            entity_count: Number of entities discovered.

        """
        with self._lock:
            if policy_name not in self._runs:
                return

            runs = self._runs[policy_name]
            for run in runs:
                if run.id == run_id:
                    run.status = status
                    run.entity_count = entity_count
                    run.updated_at = datetime.now()

                    if error:
                        run.reason = str(error)
                    else:
                        run.reason = ""  # Clear reason when no error

                    return

    def get_runs_for_policy(self, policy_name: str) -> list[Run]:
        """
        Get all runs for a specific policy.

        Args:
        ----
            policy_name: Name of the policy.

        Returns:
        -------
            List[Run]: List of runs sorted by created_at descending (deep copies).

        """
        with self._lock:
            if policy_name not in self._runs:
                return []

            runs = self._runs[policy_name]
            result = [self._copy_run(run) for run in runs]

            # Sort newest first
            result.sort(key=lambda r: r.created_at, reverse=True)

            return result

    def get_all_policies_with_runs(self) -> dict[str, list[Run]]:
        """
        Get all policies with their runs.

        Returns
        -------
            Dict[str, List[Run]]: Dict mapping policy name to list of runs (deep copies).

        """
        with self._lock:
            result = {}

            for policy_name, runs in self._runs.items():
                # Copy runs
                runs_copy = [self._copy_run(run) for run in runs]

                # Sort newest first
                runs_copy.sort(key=lambda r: r.created_at, reverse=True)

                result[policy_name] = runs_copy

            return result
