#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""NetBox Labs - Policy Manager Unit Tests."""

from unittest.mock import MagicMock, patch

import pytest
from apscheduler.triggers.date import DateTrigger
from netboxlabs.diode.sdk.diode.v1 import ingester_pb2

from worker.backend import Backend
from worker.models import Config, DiodeConfig, Metadata, Policy, Status
from worker.policy.runner import PolicyRunner


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
    Fixture to mock the load_class function.

    Returns
    -------
        MagicMock: A mock object for the load_class function.

    """
    with patch("worker.policy.runner.load_class") as mock_load:
        mock_backend_class = MagicMock(spec=Backend)
        mock_load.return_value = mock_backend_class
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


def test_initial_status(policy_runner):
    """Test initial status of PolicyRunner."""
    assert policy_runner.status == Status.NEW


def test_setup_policy_runner_with_cron(
    policy_runner,
    sample_policy,
    sample_diode_config,
    mock_load_class,
    mock_diode_client,
):
    """Test setting up the PolicyRunner with a cron schedule."""
    with patch.object(policy_runner.scheduler, "start") as mock_start, patch.object(
        policy_runner.scheduler, "add_job"
    ) as mock_add_job:

        policy_runner.setup("policy1", sample_diode_config, sample_policy)

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
):
    """Test setting up the PolicyRunner with a one-time schedule."""
    one_time_config = Config(package="custom")
    with patch.object(policy_runner.scheduler, "start") as mock_start, patch.object(
        policy_runner.scheduler, "add_job"
    ) as mock_add_job:
        sample_policy.config = one_time_config
        policy_runner.setup("policy1", sample_diode_config, sample_policy)

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
):
    """Ensure setup falls back to DiodeOTLPClient when credentials are missing."""
    otlp_config = DiodeConfig(target="http://localhost:8080", prefix="test-prefix")
    with patch.object(policy_runner.scheduler, "start") as mock_start, patch.object(
        policy_runner.scheduler, "add_job"
    ) as mock_add_job:
        policy_runner.setup("policy1", otlp_config, sample_policy)

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
):
    """Test setting up the PolicyRunner with dry run configuration."""
    with patch.object(policy_runner.scheduler, "start") as mock_start, patch.object(
        policy_runner.scheduler, "add_job"
    ) as mock_add_job:

        policy_runner.setup("policy1", sample_diode_dry_run_config, sample_policy)

        # Ensure scheduler starts and job is added
        mock_start.assert_called_once()
        mock_add_job.assert_called_once()
        mock_load_class.assert_called_once()
        mock_diode_dry_run_client.assert_called_once()
        assert policy_runner.status == Status.RUNNING

def test_run_success(policy_runner, sample_policy, mock_diode_client, mock_backend):
    """Test the run function for a successful execution."""
    policy_runner.name = "test_policy"

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
    call_args = mock_diode_client.ingest.call_args[1]['entities']
    assert len(call_args) == 3


def test_run_passes_metadata_to_ingest(
    policy_runner, sample_policy, mock_diode_client, mock_backend
):
    """Ensure run forwards policy/backend metadata to the Diode client."""
    policy_runner.name = "policy-meta"
    policy_runner.metadata = Metadata(
        name="custom_backend", app_name="custom", app_version="0.1"
    )

    entity = ingester_pb2.Entity()
    entity.device.name = "device-1"
    mock_backend.run.return_value = [entity]
    mock_diode_client.ingest.return_value.errors = []

    policy_runner.run(mock_diode_client, mock_backend, sample_policy)

    _, kwargs = mock_diode_client.ingest.call_args
    assert kwargs["metadata"] == {
        "policy_name": "policy-meta",
        "worker_backend": "custom_backend",
    }


def test_run_ingestion_errors(
    policy_runner,
    sample_policy,
    mock_diode_client,
    mock_backend,
    caplog,
):
    """Test the run function when ingestion has errors."""
    policy_runner.name = "test_policy"

    # Create mock entities
    entities = []
    for i in range(2):
        entity = ingester_pb2.Entity()
        entity.device.name = f"test_device_{i}"
        entities.append(entity)

    mock_backend.run.return_value = entities

    # Simulate ingestion errors
    mock_diode_client.ingest.return_value.errors = ["error1", "error2"]

    # Call the run method
    with caplog.at_level("ERROR"):
        policy_runner.run(mock_diode_client, mock_backend, sample_policy)

    # Assertions
    mock_backend.run.assert_called_once_with(policy_runner.name, sample_policy)
    mock_diode_client.ingest.assert_called_once()
    assert (
        "Policy test_policy: Chunk 1 ingestion failed: ['error1', 'error2']"
        in caplog.text
    )


def test_run_backend_exception(
    policy_runner,
    sample_policy,
    mock_diode_client,
    mock_backend,
    caplog,
):
    """Test the run function when an exception is raised by the backend."""
    policy_runner.name = "test_policy"

    # Simulate backend throwing an exception
    mock_backend.run.side_effect = Exception("Backend error")

    # Call the run method
    with caplog.at_level("ERROR"):
        policy_runner.run(mock_diode_client, mock_backend, sample_policy)

    # Assertions
    mock_backend.run.assert_called_once_with(policy_runner.name, sample_policy)
    mock_diode_client.ingest.assert_not_called()  # Client ingestion should not be called
    assert "Policy test_policy: Backend error" in caplog.text


def test_stop_policy_runner(policy_runner):
    """Test stopping the PolicyRunner."""
    with patch.object(policy_runner.scheduler, "shutdown") as mock_shutdown:
        policy_runner.stop()

        # Ensure scheduler shutdown is called and status is updated
        mock_shutdown.assert_called_once()
        assert policy_runner.status == Status.FINISHED


def test_metrics_during_policy_lifecycle(
    policy_runner, sample_policy, mock_diode_client, mock_backend
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
    policy_runner, sample_policy, mock_diode_client, mock_backend
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


def test_create_message_chunks_empty_list(policy_runner):
    """Test _create_message_chunks with an empty entity list."""
    entities = []
    chunks = policy_runner._create_message_chunks(entities)

    assert len(chunks) == 1
    assert chunks[0] == []


def test_create_message_chunks_single_chunk(policy_runner):
    """Test _create_message_chunks when entities fit in a single chunk."""
    # Create small mock entities that will fit in one chunk
    entities = []
    for i in range(5):
        entity = ingester_pb2.Entity()
        entity.device.name = f"test_device_{i}"
        entities.append(entity)

    with patch.object(policy_runner, '_estimate_message_size', return_value=1024):  # Small size
        chunks = policy_runner._create_message_chunks(entities)

    assert len(chunks) == 1
    assert len(chunks[0]) == 5
    assert chunks[0] == entities


def test_create_message_chunks_multiple_chunks(policy_runner):
    """Test _create_message_chunks when entities need to be split into multiple chunks."""
    # Create entities that will exceed the target size
    entities = []
    for i in range(10):
        entity = ingester_pb2.Entity()
        entity.device.name = f"test_device_{i}"
        entities.append(entity)

    # Mock size to be larger than target (3.5MB)
    with patch.object(policy_runner, '_estimate_message_size', return_value=5 * 1024 * 1024):  # 5MB
        chunks = policy_runner._create_message_chunks(entities)

    # Should have multiple chunks
    assert len(chunks) > 1

    # All entities should be present across chunks
    total_entities = sum(len(chunk) for chunk in chunks)
    assert total_entities == 10

    # Each chunk should have at least 1 entity
    for chunk in chunks:
        assert len(chunk) >= 1


def test_create_message_chunks_edge_case_one_entity_per_chunk(policy_runner):
    """Test _create_message_chunks when each entity needs its own chunk."""
    entities = []
    for i in range(3):
        entity = ingester_pb2.Entity()
        entity.device.name = f"large_device_{i}"
        entities.append(entity)

    # Mock very large size to force one entity per chunk
    with patch.object(policy_runner, '_estimate_message_size', return_value=20 * 1024 * 1024):  # 20MB
        chunks = policy_runner._create_message_chunks(entities)

    # Should have 3 chunks with 1 entity each
    assert len(chunks) == 3
    for chunk in chunks:
        assert len(chunk) == 1


def test_estimate_message_size(policy_runner):
    """Test _estimate_message_size method."""
    # Create mock entities
    entities = []
    for i in range(3):
        entity = ingester_pb2.Entity()
        entity.device.name = f"test_device_{i}"
        entities.append(entity)

    # Call the method
    size = policy_runner._estimate_message_size(entities)

    # Should return a positive integer (actual protobuf size)
    assert isinstance(size, int)
    assert size > 0


def test_estimate_message_size_empty_list(policy_runner):
    """Test _estimate_message_size with empty entity list."""
    entities = []
    size = policy_runner._estimate_message_size(entities)

    # Even empty request should have some minimal size
    assert isinstance(size, int)
    assert size >= 0


def test_run_with_multiple_chunks(policy_runner, sample_policy, mock_diode_client, mock_backend, caplog):
    """Test the run function with entities that require multiple chunks."""
    policy_runner.name = "test_policy"

    # Create many mock entities to trigger chunking
    entities = []
    for i in range(10):
        entity = ingester_pb2.Entity()
        entity.device.name = f"test_device_{i}"
        entities.append(entity)

    mock_backend.run.return_value = entities
    mock_diode_client.ingest.return_value.errors = []

    # Mock chunking to return multiple chunks
    with patch.object(
        policy_runner,
        '_create_message_chunks',
        return_value=[entities[:5], entities[5:]]
    ) as mock_chunks, \
         patch.object(
        policy_runner,
        '_estimate_message_size',
        return_value=1024
    ):

        with caplog.at_level("DEBUG"):
            policy_runner.run(mock_diode_client, mock_backend, sample_policy)

        # Should call chunking method
        mock_chunks.assert_called_once_with(entities)

        # Should call ingest twice (once per chunk)
        assert mock_diode_client.ingest.call_count == 2

        # Verify log messages for chunking
        assert "Ingesting chunk 1 with 5 entities" in caplog.text
        assert "Ingesting chunk 2 with 5 entities" in caplog.text
        assert "Chunk 1 ingested successfully" in caplog.text
        assert "Chunk 2 ingested successfully" in caplog.text


def test_run_chunk_ingestion_error(policy_runner, sample_policy, mock_diode_client, mock_backend, caplog):
    """Test the run function when a chunk ingestion fails."""
    policy_runner.name = "test_policy"

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

    # Mock chunking to return two chunks
    with patch.object(
        policy_runner,
        '_create_message_chunks',
        return_value=[entities[:3], entities[3:]]
    ), \
         patch.object(
        policy_runner,
        '_estimate_message_size',
        return_value=1024
    ):

        with caplog.at_level("ERROR"):
            policy_runner.run(mock_diode_client, mock_backend, sample_policy)

        # Should call ingest twice but fail on second chunk
        assert mock_diode_client.ingest.call_count == 2

        # Should log the chunk error
        assert "Chunk 2 ingestion failed" in caplog.text
