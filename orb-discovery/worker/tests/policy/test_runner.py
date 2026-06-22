#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""NetBox Labs - Policy Manager Unit Tests."""

from unittest.mock import MagicMock, patch

import grpc
import pytest
from apscheduler.triggers.date import DateTrigger
from netboxlabs.diode.sdk.diode.v1 import ingester_pb2
from netboxlabs.diode.sdk.exceptions import DiodeClientError, OTLPClientError

from worker.backend import Backend
from worker.exceptions import IngestError, IngestRejected, IngestUnavailable
from worker.models import Config, DiodeConfig, Metadata, Policy, Status
from worker.policy.run import RunStatus, RunStore
from worker.policy.runner import PolicyRunner, _PolicyRunnerIngestSink


@pytest.fixture
def policy_runner():
    """Fixture to create a PolicyRunner instance."""
    runner = PolicyRunner()
    runner.metadata = Metadata(
        name="test_backend", app_name="test_app", app_version="1.0"
    )
    return runner


@pytest.fixture
def sample_policy():
    """Fixture for a sample policy object."""
    return Policy(
        config=Config(schedule="0 * * * *", package="custom"), scope={"custom": "value"}
    )


@pytest.fixture
def sample_diode_config():
    """Fixture for a sample DiodeConfig object."""
    return DiodeConfig(
        target="http://localhost:8080",
        client_id="abc",
        client_secret="def",
        prefix="test",
    )


@pytest.fixture
def mock_run_store():
    """Fixture for a mock RunStore."""
    store = MagicMock(spec=RunStore)
    run = MagicMock()
    run.id = "11111111-1111-1111-1111-111111111111"
    store.create_run.return_value = run
    return store


@pytest.fixture
def sample_diode_dry_run_config():
    """Fixture for a sample DiodeConfig object."""
    return DiodeConfig(
        target="",
        prefix="test",
        dry_run=True,
        dry_run_output_dir="/tmp/dry_run",
    )


@pytest.fixture
def mock_load_class():
    """
    Patch load_class to return a real modern Backend subclass that records its instances.

    A real class (not a MagicMock) is required because the runner now decides
    the modern-vs-legacy path by statically inspecting the class for a
    describe() classmethod. ``mock_load_class.return_value`` is the class;
    ``._instances`` holds every instance constructed during the test.
    """
    instances: list = []

    class _FakeBackend(Backend):
        @classmethod
        def describe(cls) -> Metadata:
            return Metadata(name="mock_backend", app_name="mock_app", app_version="1.0.0")

        def __init__(self, **kwargs) -> None:
            super().__init__(**kwargs)
            instances.append(self)

        def run(self, policy_name, policy, **kwargs):
            return []

    _FakeBackend._instances = instances
    with patch("worker.policy.runner.load_class", return_value=_FakeBackend) as mock_load:
        yield mock_load


@pytest.fixture
def mock_diode_client():
    """Fixture to mock the DiodeClient constructor."""
    with patch("worker.policy.runner.DiodeClient") as mock_diode_client:
        mock_instance = MagicMock()
        mock_diode_client.return_value = mock_instance
        yield mock_diode_client


@pytest.fixture
def mock_diode_otlp_client():
    """Fixture to mock the DiodeOTLPClient constructor."""
    with patch("worker.policy.runner.DiodeOTLPClient") as mock_diode_otlp_client:
        mock_instance = MagicMock()
        mock_diode_otlp_client.return_value = mock_instance
        yield mock_diode_otlp_client


@pytest.fixture
def mock_diode_dry_run_client():
    """Fixture to mock the DiodeDryRunClient constructor."""
    with patch("worker.policy.runner.DiodeDryRunClient") as mock_diode_dry_run_client:
        mock_instance = MagicMock()
        mock_diode_dry_run_client.return_value = mock_instance
        yield mock_diode_dry_run_client


@pytest.fixture
def mock_backend():
    """Fixture to mock a backend."""
    backend = MagicMock()
    backend.run.return_value = ["entity1", "entity2"]  # Mock returned entities
    return backend


def _extract_sink(backend_class):
    """Recover the IngestSink PolicyRunner.setup attached to the constructed backend."""
    return backend_class._instances[-1].ingest_sink


def test_initial_status(policy_runner):
    """Test initial status of PolicyRunner."""
    assert policy_runner.status == Status.NEW


def test_setup_policy_runner_with_cron(
    policy_runner,
    sample_policy,
    sample_diode_config,
    mock_load_class,
    mock_diode_client,
    mock_run_store,
):
    """Test setting up the PolicyRunner with a cron schedule."""
    with patch.object(policy_runner.scheduler, "start") as mock_start, patch.object(
        policy_runner.scheduler, "add_job"
    ) as mock_add_job:

        policy_runner.setup(
            "policy1", sample_diode_config, sample_policy, mock_run_store
        )

        # Ensure scheduler starts and job is added
        mock_start.assert_called_once()
        mock_add_job.assert_called_once()
        mock_load_class.assert_called_once()
        mock_diode_client.assert_called_once()
        assert policy_runner.status == Status.RUNNING


def test_setup_policy_runner_with_one_time_run(
    policy_runner,
    sample_diode_config,
    sample_policy,
    mock_load_class,
    mock_diode_client,
    mock_run_store,
):
    """Test setting up the PolicyRunner with a one-time schedule."""
    one_time_config = Config(package="custom")
    with patch.object(policy_runner.scheduler, "start") as mock_start, patch.object(
        policy_runner.scheduler, "add_job"
    ) as mock_add_job:
        sample_policy.config = one_time_config
        policy_runner.setup(
            "policy1", sample_diode_config, sample_policy, mock_run_store
        )

        # Verify that DateTrigger is used for one-time scheduling
        trigger = mock_add_job.call_args[1]["trigger"]
        mock_load_class.assert_called_once()
        mock_diode_client.assert_called_once()
        assert isinstance(trigger, DateTrigger)
        assert mock_start.called
        assert policy_runner.status == Status.RUNNING


def test_setup_policy_runner_uses_otlp_client(
    policy_runner,
    sample_policy,
    mock_load_class,
    mock_diode_client,
    mock_diode_otlp_client,
    mock_run_store,
):
    """Ensure setup falls back to DiodeOTLPClient when credentials are missing."""
    otlp_config = DiodeConfig(target="http://localhost:8080", prefix="test-prefix")
    with patch.object(policy_runner.scheduler, "start") as mock_start, patch.object(
        policy_runner.scheduler, "add_job"
    ) as mock_add_job:
        policy_runner.setup("policy1", otlp_config, sample_policy, mock_run_store)

        mock_start.assert_called_once()
        mock_add_job.assert_called_once()

    mock_load_class.assert_called_once()
    assert not mock_diode_client.called
    mock_diode_otlp_client.assert_called_once()


def test_setup_policy_runner_dry_run(
    policy_runner,
    sample_diode_dry_run_config,
    sample_policy,
    mock_load_class,
    mock_diode_dry_run_client,
    mock_run_store,
):
    """Test setting up the PolicyRunner with dry run configuration."""
    with patch.object(policy_runner.scheduler, "start") as mock_start, patch.object(
        policy_runner.scheduler, "add_job"
    ) as mock_add_job:

        policy_runner.setup(
            "policy1", sample_diode_dry_run_config, sample_policy, mock_run_store
        )

        # Ensure scheduler starts and job is added
        mock_start.assert_called_once()
        mock_add_job.assert_called_once()
        mock_load_class.assert_called_once()
        mock_diode_dry_run_client.assert_called_once()
        assert policy_runner.status == Status.RUNNING


def test_run_success(
    policy_runner, sample_policy, mock_diode_client, mock_backend, mock_run_store
):
    """Test the run function for a successful execution."""
    policy_runner.name = "test_policy"
    policy_runner.run_store = mock_run_store

    # Create mock entities
    entities = []
    for i in range(3):
        entity = ingester_pb2.Entity()
        entity.device.name = f"test_device_{i}"
        entities.append(entity)

    mock_backend.run.return_value = entities
    mock_diode_client.ingest.return_value.errors = []

    # Call the run method
    policy_runner.run(mock_diode_client, mock_backend, sample_policy)

    # Assertions
    mock_backend.run.assert_called_once_with(policy_runner.name, sample_policy)
    # Should call ingest once for the single chunk
    mock_diode_client.ingest.assert_called_once()
    # Check that entities were passed correctly
    call_args = mock_diode_client.ingest.call_args[1]["entities"]
    assert len(call_args) == 3


def test_run_with_empty_delta_is_noop_completed(
    policy_runner, sample_policy, mock_diode_client, mock_backend, mock_run_store
):
    """A run producing zero entities (empty delta) records a COMPLETED no-op, no ingest call."""
    policy_runner.name = "test_policy"
    policy_runner.run_store = mock_run_store

    mock_backend.run.return_value = []

    policy_runner.run(mock_diode_client, mock_backend, sample_policy)

    mock_diode_client.ingest.assert_not_called()
    mock_run_store.update_run.assert_called_once()
    update_kwargs = mock_run_store.update_run.call_args.kwargs
    assert update_kwargs["status"] == RunStatus.COMPLETED
    assert update_kwargs["entity_count"] == 0


def test_run_passes_metadata_to_ingest(
    policy_runner, sample_policy, mock_diode_client, mock_backend, mock_run_store
):
    """Ensure run forwards policy/backend metadata to the Diode client."""
    policy_runner.name = "policy-meta"
    policy_runner.metadata = Metadata(
        name="custom_backend", app_name="custom", app_version="0.1"
    )
    policy_runner.run_store = mock_run_store

    entity = ingester_pb2.Entity()
    entity.device.name = "device-1"
    mock_backend.run.return_value = [entity]
    mock_diode_client.ingest.return_value.errors = []

    policy_runner.run(mock_diode_client, mock_backend, sample_policy)

    _, kwargs = mock_diode_client.ingest.call_args
    assert kwargs["metadata"] == {
        "policy_name": "policy-meta",
        "worker_backend": "custom_backend",
        "run_id": "11111111-1111-1111-1111-111111111111",
    }
    ingested = kwargs["entities"][0]
    assert ingested.device.metadata["run_id"] == "11111111-1111-1111-1111-111111111111"


def test_apply_run_id_to_entities_skips_non_protobuf_entries():
    """apply_run_id_to_entities ignores non-Entity entries (e.g. test doubles)."""
    from worker.entity_metadata import apply_run_id_to_entities

    apply_run_id_to_entities(["not-an-entity"], "run-id")


def test_run_ingestion_errors(
    policy_runner,
    sample_policy,
    mock_diode_client,
    mock_backend,
    caplog,
    mock_run_store,
):
    """Test the run function when ingestion has errors."""
    policy_runner.name = "test_policy"
    policy_runner.run_store = mock_run_store

    # Create mock entities
    entities = []
    for i in range(2):
        entity = ingester_pb2.Entity()
        entity.device.name = f"test_device_{i}"
        entities.append(entity)

    mock_backend.run.return_value = entities

    # Simulate ingestion errors
    mock_diode_client.ingest.return_value.errors = ["error1", "error2"]

    with caplog.at_level("ERROR"):
        policy_runner.run(mock_diode_client, mock_backend, sample_policy)

    # Assertions
    mock_backend.run.assert_called_once_with(policy_runner.name, sample_policy)
    mock_diode_client.ingest.assert_called_once()
    assert (
        "Policy test_policy: Chunk ingestion failed: ['error1', 'error2']"
        in caplog.text
    )


def test_run_backend_exception(
    policy_runner,
    sample_policy,
    mock_diode_client,
    mock_backend,
    caplog,
    mock_run_store,
):
    """Test the run function when an exception is raised by the backend."""
    policy_runner.name = "test_policy"
    policy_runner.run_store = mock_run_store

    # Simulate backend throwing an exception
    mock_backend.run.side_effect = Exception("Backend error")

    # Call the run method
    with caplog.at_level("ERROR"):
        policy_runner.run(mock_diode_client, mock_backend, sample_policy)

    # Assertions
    mock_backend.run.assert_called_once_with(policy_runner.name, sample_policy)
    mock_diode_client.ingest.assert_not_called()  # Client ingestion should not be called
    assert "Policy test_policy: Backend error" in caplog.text

    # Regression guard: a crashing scheduled backend must still be recorded as a
    # FAILED run — the run is created before the backend executes.
    mock_run_store.create_run.assert_called_once()
    failed_updates = [
        c
        for c in mock_run_store.update_run.call_args_list
        if c.kwargs.get("status") == RunStatus.FAILED
    ]
    assert failed_updates, "backend crash must record a FAILED run"


def test_stop_policy_runner(policy_runner):
    """Test stopping the PolicyRunner."""
    with patch.object(policy_runner.scheduler, "shutdown") as mock_shutdown:
        policy_runner.stop()

        # Ensure scheduler shutdown is called and status is updated
        mock_shutdown.assert_called_once()
        assert policy_runner.status == Status.FINISHED


def test_metrics_during_policy_lifecycle(
    policy_runner, sample_policy, mock_diode_client, mock_backend, mock_run_store
):
    """Test that metrics are properly updated during the policy lifecycle."""
    # Create mock metrics
    mock_active_policies = MagicMock()
    mock_policy_executions = MagicMock()
    mock_backend_execution_success = MagicMock()
    mock_backend_execution_failure = MagicMock()
    mock_backend_execution_latency = MagicMock()

    # Map of metric names to mock objects
    mock_metrics = {
        "active_policies": mock_active_policies,
        "policy_executions": mock_policy_executions,
        "backend_execution_success": mock_backend_execution_success,
        "backend_execution_failure": mock_backend_execution_failure,
        "backend_execution_latency": mock_backend_execution_latency,
    }

    policy_runner.name = "test_policy"
    policy_runner.metadata = Metadata(
        name="my_backend",
        app_name="test_app",
        app_version="1.0",
    )
    policy_runner.run_store = mock_run_store

    # Create mock entities
    entities = []
    for i in range(2):
        entity = ingester_pb2.Entity()
        entity.device.name = f"test_device_{i}"
        entities.append(entity)

    mock_backend.run.return_value = entities

    # Setup mock for get_metric function
    def mock_get_metric(name):
        return mock_metrics.get(name)

    with patch("worker.policy.runner.get_metric", side_effect=mock_get_metric):

        mock_diode_client.ingest.return_value.errors = []

        policy_runner.run(mock_diode_client, mock_backend, sample_policy)

        mock_backend.run.assert_called_once_with(policy_runner.name, sample_policy)
        mock_diode_client.ingest.assert_called_once()

        mock_policy_executions.add.assert_called_once_with(1, {"policy": "test_policy"})
        mock_backend_execution_success.add.assert_called_once_with(
            1,
            {
                "policy": "test_policy",
                "backend": "my_backend",
                "app_name": "test_app",
                "app_version": "1.0",
            },
        )

        # Test stop - should decrement active_policies
        with patch.object(policy_runner.scheduler, "shutdown") as mock_shutdown:
            policy_runner.stop()
            mock_shutdown.assert_called_once()
            mock_active_policies.add.assert_called_with(-1, {"policy": "test_policy"})


def test_metrics_during_failed_discovery(
    policy_runner, sample_policy, mock_diode_client, mock_backend, mock_run_store
):
    """Test that metrics are properly updated when discovery fails."""
    mock_backend_execution_failure = MagicMock()
    mock_backend_execution_latency = MagicMock()

    mock_metrics = {
        "backend_execution_failure": mock_backend_execution_failure,
        "backend_execution_latency": mock_backend_execution_latency,
    }

    policy_runner.name = "test_policy"
    policy_runner.metadata = Metadata(
        name="my_backend",
        app_name="test_app",
        app_version="1.0",
    )
    policy_runner.run_store = mock_run_store

    def mock_get_metric(name):
        return mock_metrics.get(name)

    # Simulate backend throwing an exception
    mock_backend.run.side_effect = Exception("Backend error")

    with patch("worker.policy.runner.get_metric", side_effect=mock_get_metric):
        mock_diode_client = MagicMock(name="MockDiodeClient")
        policy_runner.run(mock_diode_client, mock_backend, sample_policy)
        # Verify failure metric was called
        mock_backend_execution_failure.add.assert_called_once_with(
            1,
            {
                "policy": "test_policy",
                "backend": "my_backend",
                "app_name": "test_app",
                "app_version": "1.0",
            },
        )

        # Verify backend execution latency recorded with failure status
        mock_backend_execution_latency.record.assert_called_once()
        latency_args = mock_backend_execution_latency.record.call_args[0][0]
        latency_kwargs = mock_backend_execution_latency.record.call_args[0][1]
        assert latency_args > 0
        assert latency_kwargs["backend"] == "my_backend"


def test_run_with_small_entities_no_chunking(
    policy_runner, sample_policy, mock_diode_client, mock_backend, mock_run_store
):
    """Test the run function with small entities that don't require chunking."""
    policy_runner.name = "test_policy"
    policy_runner.run_store = mock_run_store

    # Create mock entities
    entities = []
    for i in range(5):
        entity = ingester_pb2.Entity()
        entity.device.name = f"test_device_{i}"
        entities.append(entity)

    mock_backend.run.return_value = entities
    mock_diode_client.ingest.return_value.errors = []

    # Small real entities fit in a single chunk, so the SDK returns one chunk.
    policy_runner.run(mock_diode_client, mock_backend, sample_policy)

    # Should call ingest once (no chunking)
    mock_diode_client.ingest.assert_called_once()

    # Verify all entities were passed in single call
    call_args = mock_diode_client.ingest.call_args[1]["entities"]
    assert len(call_args) == 5


def test_run_with_multiple_chunks(
    policy_runner,
    sample_policy,
    mock_diode_client,
    mock_backend,
    caplog,
    mock_run_store,
):
    """Test the run function with entities that require multiple chunks."""
    policy_runner.name = "test_policy"
    policy_runner.run_store = mock_run_store

    # Create many mock entities to trigger chunking
    entities = []
    for i in range(10):
        entity = ingester_pb2.Entity()
        entity.device.name = f"test_device_{i}"
        entities.append(entity)

    mock_backend.run.return_value = entities
    mock_diode_client.ingest.return_value.errors = []

    # Force the SDK to split into two chunks.
    with patch(
        "worker.policy.runner.create_message_chunks",
        return_value=[entities[:5], entities[5:]],
    ) as mock_chunks:

        with caplog.at_level("INFO"):
            policy_runner.run(mock_diode_client, mock_backend, sample_policy)

        # Should call chunking method
        mock_chunks.assert_called_once_with(entities)

        # Should call ingest twice (once per chunk)
        assert mock_diode_client.ingest.call_count == 2

        # Verify log messages for successful ingestion
        assert "Successfully ingested 10 entities" in caplog.text


def test_run_chunk_ingestion_error(
    policy_runner,
    sample_policy,
    mock_diode_client,
    mock_backend,
    caplog,
    mock_run_store,
):
    """Test the run function when a chunk ingestion fails."""
    policy_runner.name = "test_policy"
    policy_runner.run_store = mock_run_store

    # Create mock entities
    entities = []
    for i in range(6):
        entity = ingester_pb2.Entity()
        entity.device.name = f"test_device_{i}"
        entities.append(entity)

    mock_backend.run.return_value = entities

    # Mock first chunk succeeds, second chunk fails
    responses = [MagicMock(), MagicMock()]
    responses[0].errors = []  # First chunk succeeds
    responses[1].errors = ["Chunk error"]  # Second chunk fails

    mock_diode_client.ingest.side_effect = responses

    # Force two chunks; the second one fails.
    with patch(
        "worker.policy.runner.create_message_chunks",
        return_value=[entities[:3], entities[3:]],
    ):

        with caplog.at_level("ERROR"):
            policy_runner.run(mock_diode_client, mock_backend, sample_policy)

        # Both chunks are sent; the second chunk's response carries errors, raising
        # IngestRejected — so ingest is called twice.
        assert mock_diode_client.ingest.call_count == 2

        # Should log the error
        assert "Chunk ingestion failed" in caplog.text


# ---------------------------------------------------------------------------
# New tests: backend construction + IngestSink
# ---------------------------------------------------------------------------


def test_setup_modern_backend_reads_describe_and_constructs_once_with_sink(
    policy_runner,
    sample_policy,
    sample_diode_config,
    mock_diode_client,
    mock_run_store,
):
    """Modern backend: metadata via describe(); constructed once with an IngestSink; setup() untouched."""
    calls: list[str] = []

    class _ModernBackend(Backend):
        @classmethod
        def describe(cls) -> Metadata:
            calls.append("describe")
            return Metadata(name="mock_backend", app_name="mock_app", app_version="1.0.0")

        def setup(self) -> Metadata:
            calls.append("setup")
            return self.describe()

        def __init__(self, **kwargs) -> None:
            super().__init__(**kwargs)
            calls.append("init")

        def run(self, policy_name, policy, **kwargs):
            return []

    with patch("worker.policy.runner.load_class", return_value=_ModernBackend), patch.object(
        policy_runner.scheduler, "start"
    ), patch.object(policy_runner.scheduler, "add_job") as mock_add_job:
        policy_runner.setup("policy1", sample_diode_config, sample_policy, mock_run_store)

    # Metadata read off the class via describe(); the legacy setup() is never touched.
    assert "describe" in calls and "setup" not in calls
    # Constructed exactly once, and the scheduled instance carries the sink.
    assert calls.count("init") == 1
    scheduled_backend = mock_add_job.call_args.kwargs["args"][1]
    assert isinstance(scheduled_backend.ingest_sink, _PolicyRunnerIngestSink)


def test_setup_legacy_backend_sets_up_the_scheduled_instance(
    policy_runner,
    sample_policy,
    sample_diode_config,
    mock_diode_client,
    mock_run_store,
    caplog,
):
    """
    Legacy setup()-only backend with a custom no-kwargs __init__.

    Regression for two faults: (1) the worker must construct the legacy instance
    bare — passing ingest_sink= to a __init__ that doesn't accept it would crash
    policy startup; (2) the instance that gets scheduled must be the one whose
    setup() ran, so state initialised in setup() is live when run() reads it.
    """

    class _LegacyBackend(Backend):
        def __init__(self) -> None:  # NO **kwargs — must be constructed bare
            super().__init__()
            self.connected = False

        def setup(self) -> Metadata:
            self.connected = True  # state run() will rely on
            return Metadata(name="legacy_backend", app_name="legacy_app", app_version="2.0.0")

        def run(self, policy_name, policy):
            return []

    with patch("worker.policy.runner.load_class", return_value=_LegacyBackend), patch.object(
        policy_runner.scheduler, "start"
    ), patch.object(policy_runner.scheduler, "add_job") as mock_add_job, caplog.at_level(
        "WARNING"
    ):
        policy_runner.setup("policy1", sample_diode_config, sample_policy, mock_run_store)

    assert "deprecated setup() fallback" in caplog.text
    assert policy_runner.metadata.name == "legacy_backend"
    scheduled_backend = mock_add_job.call_args.kwargs["args"][1]
    # The scheduled instance is the one whose setup() ran (not a throwaway).
    assert scheduled_backend.connected is True
    # No sink: API-triggered sync requires the modern describe() contract, so a
    # legacy backend gets scheduled runs only.
    assert getattr(scheduled_backend, "ingest_sink", None) is None


def test_ingest_sink_ingest_happy_path(
    policy_runner,
    sample_policy,
    sample_diode_config,
    mock_load_class,
    mock_diode_client,
    mock_run_store,
):
    """sink.ingest(entities) sends them and records a COMPLETED run."""
    with patch.object(policy_runner.scheduler, "start"), patch.object(
        policy_runner.scheduler, "add_job"
    ):
        policy_runner.setup("policy1", sample_diode_config, sample_policy, mock_run_store)

    sink = _extract_sink(mock_load_class.return_value)

    client_instance = mock_diode_client.return_value
    client_instance.ingest.return_value.errors = []

    entity1 = ingester_pb2.Entity()
    entity1.device.name = "dev1"
    entity2 = ingester_pb2.Entity()
    entity2.device.name = "dev2"

    with patch("worker.policy.runner.apply_run_id_to_entities"):
        result = sink.ingest([entity1, entity2])

    assert result is None
    mock_run_store.create_run.assert_called_once()
    client_instance.ingest.assert_called_once()
    call_kwargs = client_instance.ingest.call_args.kwargs
    assert len(call_kwargs["entities"]) == 2
    mock_run_store.update_run.assert_called_once()
    update_kwargs = mock_run_store.update_run.call_args.kwargs
    assert update_kwargs["status"] == RunStatus.COMPLETED


def test_ingest_sink_ingest_empty_entities_is_noop_completed(
    policy_runner,
    sample_policy,
    sample_diode_config,
    mock_load_class,
    mock_diode_client,
    mock_run_store,
):
    """sink.ingest([]) records a COMPLETED no-op run, no ingest call."""
    with patch.object(policy_runner.scheduler, "start"), patch.object(
        policy_runner.scheduler, "add_job"
    ):
        policy_runner.setup("policy1", sample_diode_config, sample_policy, mock_run_store)

    sink = _extract_sink(mock_load_class.return_value)
    client_instance = mock_diode_client.return_value

    result = sink.ingest([])

    assert result is None
    client_instance.ingest.assert_not_called()
    mock_run_store.update_run.assert_called_once()
    update_kwargs = mock_run_store.update_run.call_args.kwargs
    assert update_kwargs["status"] == RunStatus.COMPLETED
    assert update_kwargs["entity_count"] == 0


def test_ingest_sink_record_failure(
    policy_runner,
    sample_policy,
    sample_diode_config,
    mock_load_class,
    mock_diode_client,
    mock_run_store,
):
    """sink.record_failure(error) records a FAILED run and skips client.ingest."""
    with patch.object(policy_runner.scheduler, "start"), patch.object(
        policy_runner.scheduler, "add_job"
    ):
        policy_runner.setup("policy1", sample_diode_config, sample_policy, mock_run_store)

    sink = _extract_sink(mock_load_class.return_value)
    client_instance = mock_diode_client.return_value

    err = Exception("vendor unreachable")
    result = sink.record_failure(err)

    assert result is None
    client_instance.ingest.assert_not_called()
    mock_run_store.update_run.assert_called_once()
    update_kwargs = mock_run_store.update_run.call_args.kwargs
    assert update_kwargs["status"] == RunStatus.FAILED
    assert update_kwargs["error"] is err


def test_ingest_sink_translates_transport_errors_to_ingest_error(
    policy_runner,
    sample_policy,
    sample_diode_config,
    mock_load_class,
    mock_diode_client,
    mock_run_store,
):
    """Non-IngestError transport exceptions are wrapped as the base IngestError."""
    with patch.object(policy_runner.scheduler, "start"), patch.object(
        policy_runner.scheduler, "add_job"
    ):
        policy_runner.setup("policy1", sample_diode_config, sample_policy, mock_run_store)

    sink = _extract_sink(mock_load_class.return_value)
    client_instance = mock_diode_client.return_value
    client_instance.ingest.side_effect = RuntimeError("connection refused")

    entity = ingester_pb2.Entity()
    entity.device.name = "dev1"

    with patch("worker.policy.runner.apply_run_id_to_entities"):
        with pytest.raises(IngestError):
            sink.ingest([entity])

    mock_run_store.update_run.assert_called_once()
    update_kwargs = mock_run_store.update_run.call_args.kwargs
    assert update_kwargs["status"] == RunStatus.FAILED


class _FakeRpcError(grpc.RpcError):
    """Minimal grpc.RpcError test double carrying a status code."""

    def __init__(self, code: grpc.StatusCode) -> None:
        self._code = code

    def code(self) -> grpc.StatusCode:
        return self._code

    def details(self) -> str:
        return "fake rpc error"


def _raw_rpc_error(code):
    """A bare grpc.RpcError (status via code()) — defensive / non-SDK path."""
    return _FakeRpcError(code)


def _diode_client_error(code):
    """What the credentialed DiodeClient.ingest actually raises (status via .status_code)."""
    return DiodeClientError(_FakeRpcError(code))


def _otlp_client_error(code):
    """What DiodeOTLPClient.ingest actually raises (not a grpc.RpcError subclass)."""
    return OTLPClientError(_FakeRpcError(code))


@pytest.mark.parametrize(
    "make_error",
    [
        pytest.param(_raw_rpc_error, id="raw-rpc"),
        pytest.param(_diode_client_error, id="diode-client-error"),
        pytest.param(_otlp_client_error, id="otlp-client-error"),
    ],
)
@pytest.mark.parametrize(
    "code, is_transient",
    [
        pytest.param(grpc.StatusCode.UNAVAILABLE, True, id="unavailable"),
        pytest.param(grpc.StatusCode.RESOURCE_EXHAUSTED, True, id="resource-exhausted"),
        pytest.param(grpc.StatusCode.DEADLINE_EXCEEDED, True, id="deadline-exceeded"),
        pytest.param(grpc.StatusCode.INVALID_ARGUMENT, False, id="invalid-argument"),
    ],
)
def test_ingest_sink_maps_grpc_status_codes(
    make_error,
    code,
    is_transient,
    policy_runner,
    sample_policy,
    sample_diode_config,
    mock_load_class,
    mock_diode_client,
    mock_run_store,
):
    """
    Transient gRPC codes raise IngestUnavailable; others raise base IngestError.

    Covers the real SDK wrappers (DiodeClientError / OTLPClientError) the
    production clients raise — not just a bare grpc.RpcError — since the wrappers
    carry the status on .status_code rather than code().
    """
    with patch.object(policy_runner.scheduler, "start"), patch.object(
        policy_runner.scheduler, "add_job"
    ):
        policy_runner.setup("policy1", sample_diode_config, sample_policy, mock_run_store)

    sink = _extract_sink(mock_load_class.return_value)
    mock_diode_client.return_value.ingest.side_effect = make_error(code)

    entity = ingester_pb2.Entity()
    entity.device.name = "dev1"

    with patch("worker.policy.runner.apply_run_id_to_entities"):
        with pytest.raises(IngestError) as excinfo:
            sink.ingest([entity])

    assert isinstance(excinfo.value, IngestUnavailable) is is_transient
    update_kwargs = mock_run_store.update_run.call_args.kwargs
    assert update_kwargs["status"] == RunStatus.FAILED


def test_ingest_sink_translates_response_errors_to_rejected(
    policy_runner,
    sample_policy,
    sample_diode_config,
    mock_load_class,
    mock_diode_client,
    mock_run_store,
):
    """Response errors (non-empty errors list) are raised as IngestRejected."""
    with patch.object(policy_runner.scheduler, "start"), patch.object(
        policy_runner.scheduler, "add_job"
    ):
        policy_runner.setup("policy1", sample_diode_config, sample_policy, mock_run_store)

    sink = _extract_sink(mock_load_class.return_value)
    client_instance = mock_diode_client.return_value
    client_instance.ingest.return_value.errors = ["bad payload"]

    entity = ingester_pb2.Entity()
    entity.device.name = "dev1"

    with patch("worker.policy.runner.apply_run_id_to_entities"):
        with pytest.raises(IngestRejected):
            sink.ingest([entity])

    mock_run_store.update_run.assert_called_once()
    update_kwargs = mock_run_store.update_run.call_args.kwargs
    assert update_kwargs["status"] == RunStatus.FAILED


def test_ingest_sink_chunks_large_payloads(
    policy_runner,
    sample_policy,
    sample_diode_config,
    mock_load_class,
    mock_diode_client,
    mock_run_store,
):
    """sink.ingest splits large payloads into chunks and ingests each separately."""
    with patch.object(policy_runner.scheduler, "start"), patch.object(
        policy_runner.scheduler, "add_job"
    ):
        policy_runner.setup("policy1", sample_diode_config, sample_policy, mock_run_store)

    sink = _extract_sink(mock_load_class.return_value)
    client_instance = mock_diode_client.return_value
    client_instance.ingest.return_value.errors = []

    entity1 = ingester_pb2.Entity()
    entity1.device.name = "dev1"
    entity2 = ingester_pb2.Entity()
    entity2.device.name = "dev2"
    chunk_a = [entity1]
    chunk_b = [entity2]

    with patch(
        "worker.policy.runner.create_message_chunks", return_value=[chunk_a, chunk_b]
    ), patch("worker.policy.runner.apply_run_id_to_entities"):
        sink.ingest([entity1, entity2])

    assert client_instance.ingest.call_count == 2
    mock_run_store.update_run.assert_called_once()
    update_kwargs = mock_run_store.update_run.call_args.kwargs
    assert update_kwargs["status"] == RunStatus.COMPLETED


def test_run_unaffected_by_sink(
    policy_runner, sample_policy, mock_diode_client, mock_backend, mock_run_store
):
    """PolicyRunner.run() is unaffected by the ingest-sink mechanism."""
    policy_runner.name = "test_policy"
    policy_runner.run_store = mock_run_store

    entity = ingester_pb2.Entity()
    entity.device.name = "device-x"
    mock_backend.run.return_value = [entity]
    mock_diode_client.ingest.return_value.errors = []

    policy_runner.run(mock_diode_client, mock_backend, sample_policy)

    mock_backend.run.assert_called_once_with("test_policy", sample_policy)
    mock_diode_client.ingest.assert_called_once()
    mock_run_store.update_run.assert_called_once()
    update_kwargs = mock_run_store.update_run.call_args.kwargs
    assert update_kwargs["status"] == RunStatus.COMPLETED


def test_ingest_sink_records_failure_on_apply_run_id_error(
    policy_runner,
    sample_policy,
    sample_diode_config,
    mock_load_class,
    mock_diode_client,
    mock_run_store,
):
    """apply_run_id_to_entities failure inside try: records FAILED run as IngestError."""
    with patch.object(policy_runner.scheduler, "start"), patch.object(
        policy_runner.scheduler, "add_job"
    ):
        policy_runner.setup("policy1", sample_diode_config, sample_policy, mock_run_store)

    sink = _extract_sink(mock_load_class.return_value)

    entity = ingester_pb2.Entity()
    entity.device.name = "dev1"

    with patch(
        "worker.policy.runner.apply_run_id_to_entities",
        side_effect=RuntimeError("entity corrupt"),
    ):
        with pytest.raises(IngestError):
            sink.ingest([entity])

    mock_run_store.update_run.assert_called_once()
    update_kwargs = mock_run_store.update_run.call_args.kwargs
    assert update_kwargs["status"] == RunStatus.FAILED
    # The entity was materialised before apply_run_id_to_entities raised.
    assert update_kwargs["entity_count"] == 1


def test_ingest_sink_records_failure_on_iterable_error(
    policy_runner,
    sample_policy,
    sample_diode_config,
    mock_load_class,
    mock_diode_client,
    mock_run_store,
):
    """An iterable that raises on first next() records FAILED run with entity_count=0."""
    with patch.object(policy_runner.scheduler, "start"), patch.object(
        policy_runner.scheduler, "add_job"
    ):
        policy_runner.setup("policy1", sample_diode_config, sample_policy, mock_run_store)

    sink = _extract_sink(mock_load_class.return_value)

    bad_iterable = MagicMock()
    bad_iterable.__iter__ = MagicMock(side_effect=ValueError("bad"))

    with pytest.raises(IngestError):
        sink.ingest(bad_iterable)

    mock_run_store.update_run.assert_called_once()
    update_kwargs = mock_run_store.update_run.call_args.kwargs
    assert update_kwargs["status"] == RunStatus.FAILED
    # Iterable failed before any entity was materialised.
    assert update_kwargs["entity_count"] == 0
