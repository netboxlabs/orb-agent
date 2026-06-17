#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""Orb Worker Policy Runner."""

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta

import grpc
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from netboxlabs.diode.sdk import (
    DiodeClient,
    DiodeDryRunClient,
    DiodeOTLPClient,
    create_message_chunks,
)
from netboxlabs.diode.sdk.exceptions import OTLPClientError

from worker.backend import Backend, _implements_describe, load_class
from worker.entity_metadata import apply_run_id_to_entities
from worker.exceptions import IngestError, IngestRejected, IngestUnavailable
from worker.metrics import get_metric
from worker.models import DiodeConfig, Policy, Status
from worker.package_finder import maybe_evict
from worker.policy.run import RunStatus, RunStore

logger = logging.getLogger(__name__)

# gRPC status codes that signal a transient ingest failure worth retrying.
_TRANSIENT_GRPC_CODES = frozenset(
    {
        grpc.StatusCode.UNAVAILABLE,
        grpc.StatusCode.RESOURCE_EXHAUSTED,
        grpc.StatusCode.DEADLINE_EXCEEDED,
    }
)


def _grpc_status_code(exc) -> grpc.StatusCode | None:
    """
    Best-effort extract of a grpc.StatusCode from a raw or SDK-wrapped ingest error.

    The SDK clients do not surface raw ``grpc.RpcError`` from ``ingest()``: the
    credentialed ``DiodeClient`` wraps it as ``DiodeClientError`` and the
    ``DiodeOTLPClient`` as ``OTLPClientError``, both exposing the code via a
    ``status_code`` attribute. A bare ``grpc.RpcError`` (e.g. in tests) exposes
    it via ``code()``. Returns None when no code can be determined.
    """
    code = getattr(exc, "status_code", None)
    if code is None:
        getter = getattr(exc, "code", None)
        if callable(getter):
            try:
                code = getter()
            except Exception:
                code = None
    return code


@dataclass
class _RunOutcome:
    """What _execute_run reports back to its caller."""

    entity_count: int
    produce_seconds: float


class _PolicyRunnerIngestSink:
    """
    IngestSink bound to a PolicyRunner; reads runner state at call time.

    The binding is lazy: ``ingest`` / ``record_failure`` resolve ``run_store``,
    ``metadata`` and ``_diode_client`` off the runner when called, so the sink
    is valid the moment it is constructed even though the runner may finish
    wiring those fields afterwards. It must not be invoked before setup() ends.
    """

    def __init__(self, runner: "PolicyRunner") -> None:
        self._runner = runner

    def ingest(self, entities, **kwargs) -> None:
        runner = self._runner
        try:
            runner._execute_run(runner._diode_client, lambda: entities)
        except IngestError:
            raise
        except Exception as exc:
            raise IngestError(str(exc)) from exc

    def record_failure(self, error: Exception, **kwargs) -> None:
        runner = self._runner
        run = runner.run_store.create_run(
            policy_name=runner.name,
            metadata=runner._run_metadata(),
        )
        runner.run_store.update_run(
            policy_name=runner.name,
            run_id=run.id,
            status=RunStatus.FAILED,
            error=error,
            entity_count=0,
        )


class PolicyRunner:
    """Policy Runner class."""

    def __init__(self):
        """Initialize the PolicyRunner."""
        self.name = ""
        self.metadata = None
        self.policy = None
        self.status = Status.NEW
        self.scheduler = BackgroundScheduler()
        self.run_store = None
        self._diode_client = None

    def setup(
        self, name: str, diode_config: DiodeConfig, policy: Policy, run_store: RunStore
    ):
        """
        Set up the policy runner.

        Args:
        ----
            name: Policy name.
            diode_config: Diode configuration data.
            policy: Policy configuration data.
            run_store: RunStore instance for tracking runs.

        """
        self.name = name.replace("\r\n", "").replace("\n", "")
        policy.config.package = policy.config.package.replace("\r\n", "").replace(
            "\n", ""
        )

        # Evict stale cached modules if the bundle's `current` symlink has been
        # updated to a newer version since we last imported this package.
        maybe_evict(policy.config.package)

        # Debug logging for backend loading
        logger.debug(f"Loading backend class: {policy.config.package}")
        backend_class = load_class(policy.config.package)
        logger.debug(f"Backend class loaded successfully: {backend_class.__name__}")

        # Read the backend's metadata. Modern backends expose it via the
        # describe() classmethod (no instance needed). Legacy setup()-only
        # backends are constructed bare HERE and set up on that same instance —
        # the one that gets scheduled — so any state setup() initialises is live
        # when run() reads it.
        if _implements_describe(backend_class):
            legacy_backend = None
            metadata = backend_class.describe()
        else:
            logger.warning(
                "%s does not implement describe(); reading metadata via the "
                "deprecated setup() fallback (scheduled for removal in worker "
                "v2.0) — implement the describe() classmethod.",
                backend_class.__name__,
            )
            legacy_backend = backend_class()
            metadata = legacy_backend.setup()

        app_name = (
            f"{diode_config.prefix}/{metadata.app_name}"
            if diode_config.prefix
            else metadata.app_name
        )
        if diode_config.dry_run:
            client = DiodeDryRunClient(
                app_name=app_name,
                output_dir=diode_config.dry_run_output_dir,
            )
        elif (
            diode_config.client_id is not None
            and diode_config.client_secret is not None
        ):
            client = DiodeClient(
                target=diode_config.target,
                app_name=app_name,
                app_version=metadata.app_version,
                client_id=diode_config.client_id,
                client_secret=diode_config.client_secret,
            )
        else:
            logger.debug("Initializing Diode OTLP client")
            client = DiodeOTLPClient(
                target=diode_config.target,
                app_name=app_name,
                app_version=metadata.app_version,
            )

        self.metadata = metadata
        self.policy = policy
        self.run_store = run_store
        self._diode_client = client

        if legacy_backend is None:
            # Modern backends opt into the ingest sink — and thus API-triggered
            # sync — by implementing describe(); construct once with it.
            backend = backend_class(ingest_sink=_PolicyRunnerIngestSink(self))
        else:
            # Legacy setup()-only backends get scheduled runs only; the trigger
            # API requires migrating to describe(). No sink is attached.
            backend = legacy_backend

        self.scheduler.start()

        if self.policy.config.schedule is not None:
            logger.info(
                f"Policy {self.name}, Package {self.policy.config.package}: Scheduled to run with '{self.policy.config.schedule}'"
            )
            trigger = CronTrigger.from_crontab(self.policy.config.schedule)
        else:
            logger.info(
                f"Policy {self.name}, Package {self.policy.config.package}: One-time run"
            )
            trigger = DateTrigger(run_date=datetime.now() + timedelta(seconds=1))

        self.scheduler.add_job(
            self.run,
            trigger=trigger,
            args=[client, backend, self.policy],
        )

        self.status = Status.RUNNING

        active_policies = get_metric("active_policies")
        if active_policies:
            active_policies.add(1, {"policy": self.name})

    def _run_metadata(self) -> dict:
        """
        Build the metadata stored on a run record.

        TODO: consider recording the run's origin (scheduled vs ingest-sink)
        here once a consumer exists for it (e.g. the planned runs API over
        RunStore); a `source` key was carried earlier but nothing read it.
        """
        return {
            "name": self.metadata.name,
            "app_name": self.metadata.app_name,
            "app_version": self.metadata.app_version,
        }

    def _execute_run(self, client, produce_entities) -> _RunOutcome:
        """
        Create a run, produce + ingest entities through it, record COMPLETED/FAILED.

        ``produce_entities`` is a zero-arg callable invoked INSIDE the run's
        try-block — after ``create_run`` — so a failure while producing the
        entities (e.g. the backend's ``run()`` raising) is still recorded as a
        FAILED run rather than vanishing before the run is created. Re-raises on
        failure.

        The returned ``_RunOutcome.produce_seconds`` covers the producer call
        only — not chunking, ingest, or run-store writes — so callers can
        report truthful production timing.
        """
        run = self.run_store.create_run(
            policy_name=self.name, metadata=self._run_metadata()
        )
        entity_count = 0
        try:
            produce_start = time.perf_counter()
            entities_list = list(produce_entities())
            produce_seconds = time.perf_counter() - produce_start
            entity_count = len(entities_list)
            apply_run_id_to_entities(entities_list, run.id)
            metadata = {
                "policy_name": self.name,
                "worker_backend": self.metadata.name,
                "run_id": run.id,
            }
            self._send_entities(client, entities_list, metadata)
            self.run_store.update_run(
                policy_name=self.name,
                run_id=run.id,
                status=RunStatus.COMPLETED,
                error=None,
                entity_count=entity_count,
            )
            return _RunOutcome(entity_count, produce_seconds)
        except Exception as exc:
            self.run_store.update_run(
                policy_name=self.name,
                run_id=run.id,
                status=RunStatus.FAILED,
                error=exc,
                entity_count=entity_count,
            )
            raise

    def _send_entities(self, client, entities_list: list, metadata: dict) -> None:
        """
        Send entities to the Diode client.

        An empty entity list is a valid no-op (e.g. an incremental run that
        found no changes since its watermark) — Diode's ingester rejects an
        empty batch with ``entities is empty`` — so nothing is sent.

        Delegates chunking to the SDK's ``create_message_chunks``, which owns
        the gRPC message-size threshold (3 MB default, a safe margin below the
        4 MB ceiling) and returns a single chunk when the payload already fits.
        Transient gRPC failures are raised as ``IngestUnavailable``, other gRPC
        errors as ``IngestError``, and Diode-reported errors as ``IngestRejected``.
        """
        if not entities_list:
            return
        chunks = create_message_chunks(entities_list)
        for chunk in chunks:
            try:
                response = client.ingest(entities=chunk, metadata=metadata)
            except (grpc.RpcError, OTLPClientError) as exc:
                # DiodeClient wraps as DiodeClientError (a grpc.RpcError subclass)
                # and DiodeOTLPClient as OTLPClientError; both carry the status on
                # .status_code. A bare grpc.RpcError exposes it via .code().
                code = _grpc_status_code(exc)
                if code in _TRANSIENT_GRPC_CODES:
                    raise IngestUnavailable(
                        f"Transient ingest failure ({code.name}): {exc}"
                    ) from exc
                raise IngestError(f"Ingest transport error: {exc}") from exc
            if response.errors:
                raise IngestRejected(f"Chunk ingestion failed: {response.errors}")

    def run(
        self,
        client: DiodeClient | DiodeDryRunClient | DiodeOTLPClient,
        backend: Backend,
        policy: Policy,
    ):
        """
        Run the custom backend code for the specified scope.

        Args:
        ----
            client: Diode client.
            backend: Backend class.
            policy: Policy configuration.

        """
        policy_executions = get_metric("policy_executions")
        if policy_executions:
            policy_executions.add(1, {"policy": self.name})

        exec_start_time = time.perf_counter()
        try:
            logger.debug(f"Policy {self.name}: Starting backend execution")
            outcome = self._execute_run(
                client, lambda: backend.run(self.name, policy)
            )
            logger.debug(
                f"Policy {self.name}: Backend execution completed in {outcome.produce_seconds:.3f} seconds"
            )
            logger.info(
                f"Policy {self.name}: Successfully ingested {outcome.entity_count} entities"
            )

            run_success = get_metric("backend_execution_success")
            if run_success:
                run_success.add(
                    1,
                    {
                        "policy": self.name,
                        "backend": self.metadata.name,
                        "app_name": self.metadata.app_name,
                        "app_version": self.metadata.app_version,
                    },
                )
        except Exception as e:
            logger.error(f"Policy {self.name}: {e}")

            run_failure = get_metric("backend_execution_failure")
            if run_failure:
                run_failure.add(
                    1,
                    {
                        "policy": self.name,
                        "backend": self.metadata.name,
                        "app_name": self.metadata.app_name,
                        "app_version": self.metadata.app_version,
                    },
                )

        backend_execution_latency = get_metric("backend_execution_latency")
        if backend_execution_latency:
            exec_duration = (time.perf_counter() - exec_start_time) * 1000
            backend_execution_latency.record(
                exec_duration,
                {
                    "policy": self.name,
                    "backend": self.metadata.name,
                    "app_name": self.metadata.app_name,
                    "app_version": self.metadata.app_version,
                },
            )

    def stop(self):
        """Stop the policy runner."""
        self.scheduler.shutdown(wait=False)
        self.status = Status.FINISHED
        active_policies = get_metric("active_policies")
        if active_policies:
            active_policies.add(-1, {"policy": self.name})
