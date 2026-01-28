#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Device Discovery Run Store."""

import ipaddress
import threading
from datetime import datetime

from device_discovery.policy.models import Run, RunStatus

# Maximum number of runs to keep per target
MAX_RUNS_PER_TARGET = 3


class RunStore:
    """
    Thread-safe store for managing policy run history.

    Tracks up to MAX_RUNS_PER_TARGET runs per target, per policy.
    Uses nested dictionaries: policy_name -> normalized_target -> list of runs.
    """

    def __init__(self):
        """Initialize the RunStore with thread-safe storage."""
        self._lock = threading.RLock()
        self._runs: dict[str, dict[str, list[Run]]] = {}

    def _normalize_target(self, target: str) -> str:
        """
        Normalize target to canonical form for consistent storage.

        Args:
        ----
            target: Target hostname, IP address, or CIDR range.

        Returns:
        -------
            str: Normalized target string.

        """
        target = target.strip()

        # Try to parse as IP address
        try:
            addr = ipaddress.ip_address(target)
            return str(addr)
        except ValueError:
            pass

        # Try to parse as IP network (CIDR)
        try:
            network = ipaddress.ip_network(target, strict=False)
            return str(network)
        except ValueError:
            pass

        # For hostnames or other formats, normalize to lowercase
        return target.lower()

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

    def create_run(self, policy_name: str, target: str, parent_target: str = "") -> Run:
        """
        Create a new run for the given policy and target.

        Args:
        ----
            policy_name: Name of the policy.
            target: Target hostname or IP.
            parent_target: Parent target if this was expanded from a range (optional).

        Returns:
        -------
            Run: The created Run object (deep copy).

        """
        with self._lock:
            normalized_target = self._normalize_target(target)

            # Build metadata with target information
            metadata = {"target": target}  # Store original, not normalized
            if parent_target:
                metadata["parent_target"] = parent_target

            # Create run with running status
            run = Run(
                policy_id=policy_name,
                status=RunStatus.RUNNING,
                metadata=metadata,
            )

            # Initialize nested dicts if needed
            if policy_name not in self._runs:
                self._runs[policy_name] = {}

            if normalized_target not in self._runs[policy_name]:
                self._runs[policy_name][normalized_target] = []

            # Add run to the target's run list
            runs = self._runs[policy_name][normalized_target]
            runs.append(run)

            # Keep only the last MAX_RUNS_PER_TARGET runs
            if len(runs) > MAX_RUNS_PER_TARGET:
                runs[:] = runs[-MAX_RUNS_PER_TARGET:]

            return self._copy_run(run)

    def update_run(
        self,
        policy_name: str,
        target: str,
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
            target: Target hostname or IP.
            run_id: Run ID to update.
            status: New status.
            error: Error if failed, None otherwise.
            entity_count: Number of entities discovered.

        """
        with self._lock:
            if policy_name not in self._runs:
                return

            normalized_target = self._normalize_target(target)
            if normalized_target not in self._runs[policy_name]:
                return

            runs = self._runs[policy_name][normalized_target]
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

    def get_runs_for_target(self, policy_name: str, target: str) -> list[Run]:
        """
        Get all runs for a specific policy and target.

        Args:
        ----
            policy_name: Name of the policy.
            target: Target hostname or IP.

        Returns:
        -------
            List[Run]: List of runs (deep copies).

        """
        with self._lock:
            if policy_name not in self._runs:
                return []

            normalized_target = self._normalize_target(target)
            runs = self._runs[policy_name].get(normalized_target, [])

            return [self._copy_run(run) for run in runs]

    def get_runs_for_policy(self, policy_name: str) -> list[Run]:
        """
        Get all runs for a policy, flattened across all targets.

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

            # Flatten runs from all targets
            result = []
            for target_runs in self._runs[policy_name].values():
                result.extend(self._copy_run(run) for run in target_runs)

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

            for policy_name, targets in self._runs.items():
                # Flatten all target runs
                runs = []
                for target_runs in targets.values():
                    runs.extend(self._copy_run(run) for run in target_runs)

                # Sort newest first
                runs.sort(key=lambda r: r.created_at, reverse=True)

                result[policy_name] = runs

            return result
