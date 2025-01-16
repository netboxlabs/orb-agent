#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""NetBox Labs - Orb Worker Backend."""

import importlib
import inspect
from collections.abc import Iterable

from netboxlabs.diode.sdk.ingester import Entity

from worker.models import Metadata, Policy


class Backend:
    """Backend Class."""

    def setup(self) -> Metadata:
        """
        Set up the backend.

        Returns
        -------
            Metadata: The metadata for the backend.

        """
        raise NotImplementedError("The 'setup' method must be implemented.")

    def run(self, policy_name: str, policy: Policy) -> Iterable[Entity]:
        """
        Run the backend.

        Args:
        ----
            policy_name (str): The name of the policy.
            policy (Policy): The policy to run.

        Returns:
        -------
            Iterable[Entity]: The entities produced by the backend

        """
        raise NotImplementedError("The 'run' method must be implemented.")


def load_class(module_name: str) -> type[Backend]:
    """
    Dynamically load a class from a given module and ensure it conforms to Backend.

    Args:
    ----
        module_name (str): The module name.

    """
    try:
        module = importlib.import_module(module_name)
        for _, obj in inspect.getmembers(module):
            if inspect.isclass(obj) and issubclass(obj, Backend):
                return obj
        raise ImportError("No class inheriting 'Backend'")
    except (ImportError, AttributeError) as e:
        raise RuntimeError(
            f"Failed to load a class inheriting from 'Backend' in module '{module_name}': {e}"
        )
