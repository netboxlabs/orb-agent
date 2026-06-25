#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""NetBox Labs - Orb Worker Backend."""

import importlib
import inspect
import warnings
from collections.abc import Iterable
from typing import Protocol, runtime_checkable

from netboxlabs.diode.sdk.ingester import Entity
from typing_extensions import deprecated

from worker.models import Metadata, Policy


@runtime_checkable
class IngestSink(Protocol):
    """
    How a backend hands run outcomes to the worker outside the scheduled run() cycle.

    The worker passes an implementation to ``Backend.__init__``; an integration
    that ships entities outside ``run()`` (e.g. an HTTP-triggered sync) calls
    these methods. See ``worker.exceptions`` for the failure hierarchy.
    """

    def ingest(self, entities: Iterable[Entity], **kwargs) -> None:
        """
        Ingest ``entities`` as one worker-tracked run.

        Creates a run, chunks and sends the entities to Diode, and records the
        run COMPLETED. An empty iterable is a valid no-op (recorded COMPLETED,
        nothing sent). Raises ``IngestRejected`` (permanent) or ``IngestError``
        (other failures); the run is recorded FAILED before the exception
        propagates. ``**kwargs`` is a forward-compat door (e.g. a future
        ``run_id``).
        """
        ...

    def record_failure(self, error: Exception, **kwargs) -> None:
        """
        Record a FAILED run for a collection that produced no entities.

        Never raises. ``**kwargs`` is a forward-compat door.
        """
        ...


class Backend:
    """Backend Class."""

    def __init__(
        self,
        *,
        ingest_sink: "IngestSink | None" = None,
        **kwargs,
    ) -> None:
        """
        Construct the Backend.

        Args:
        ----
            ingest_sink: Optional :class:`IngestSink` the worker supplies so the
                backend can ingest entities or record failures outside the
                scheduled ``run()`` cycle. ``None`` when the worker predates
                this contract. Usable once policy setup completes — do not call
                it from ``__init__``.
            **kwargs: Forward-compat door for resources future worker versions
                may pass; ignored by default.

        """
        self.ingest_sink = ingest_sink

    def __init_subclass__(cls, **kwargs) -> None:
        """At class-definition time, flag deprecated setup() use and a non-classmethod describe()."""
        super().__init_subclass__(**kwargs)
        describe_member = next(
            (
                klass.__dict__["describe"]
                for klass in cls.__mro__[:-1]
                if klass is not Backend and "describe" in klass.__dict__
            ),
            None,
        )
        if describe_member is not None and not isinstance(describe_member, classmethod):
            warnings.warn(
                f"{cls.__module__}.{cls.__qualname__} defines describe() but not as a "
                "@classmethod; the worker reads metadata via the describe() classmethod, "
                "so add @classmethod.",
                RuntimeWarning,
                stacklevel=2,
            )
        overrides_setup = any(
            "setup" in klass.__dict__ for klass in cls.__mro__[:-1] if klass is not Backend
        )
        if overrides_setup and not _implements_describe(cls):
            warnings.warn(
                f"{cls.__module__}.{cls.__qualname__} overrides Backend.setup(), which is "
                "deprecated — implement the describe() classmethod instead "
                "(the setup() fallback will be removed in worker v2.0).",
                DeprecationWarning,
                stacklevel=2,
            )

    @classmethod
    def describe(cls) -> Metadata:
        """
        Return the backend's metadata without constructing an instance.

        Preferred over setup(): lets the worker read the backend's identity
        (name/app_name/app_version) before constructing it, so the ingest
        callback can be built and passed at construction time. Integrations
        that only implement the instance setup() are still supported — the
        worker falls back to a throwaway instance to read their metadata.
        """
        raise NotImplementedError("The 'describe' classmethod must be implemented.")

    @deprecated(
        "Implement the describe() classmethod instead; "
        "the setup() fallback will be removed in worker v2.0."
    )
    def setup(self) -> Metadata:
        """
        Set up the backend.

        .. deprecated::
            Implement the :meth:`describe` classmethod instead. The worker reads
            metadata via ``describe()`` and only falls back to a throwaway
            instance's ``setup()`` for legacy backends; that fallback is
            scheduled for removal in worker v2.0.

        Returns
        -------
            Metadata: The metadata for the backend.

        """
        raise NotImplementedError("The 'setup' method must be implemented.")

    def run(
        self,
        policy_name: str,
        policy: Policy,
        **kwargs,
    ) -> Iterable[Entity]:
        """
        Run the backend.

        Args:
        ----
            policy_name (str): The name of the policy.
            policy (Policy): The policy to run.
            **kwargs: Passive forward-compat door. The worker passes nothing
                through it in v1; future minor releases may add per-tick
                context (e.g. ``source="scheduled"|"trigger"``, ``run_id``).
                Concrete backends are encouraged to declare ``**kwargs`` so
                additive kwargs ride into the contract without a coordinated
                upgrade.

        Returns:
        -------
            Iterable[Entity]: The entities produced by the backend.

        """
        raise NotImplementedError("The 'run' method must be implemented.")


def _implements_describe(cls: type) -> bool:
    """
    Return True if ``cls`` overrides ``Backend.describe`` with a classmethod.

    Walks the MRO statically — it never *calls* describe(), so a describe() that
    raises ``NotImplementedError`` internally is not misread as "not
    implemented", and a describe() defined without ``@classmethod`` is reported
    as not-implemented (and separately warned about) rather than crashing
    attribute access.
    """
    for klass in cls.__mro__:
        if klass is Backend:
            return False
        member = klass.__dict__.get("describe")
        if member is not None:
            return isinstance(member, classmethod)
    return False


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
