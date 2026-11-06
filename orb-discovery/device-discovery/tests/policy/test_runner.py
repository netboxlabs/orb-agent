#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""NetBox Labs - Policy Manager Unit Tests."""

import logging
from datetime import datetime, timedelta
from unittest.mock import MagicMock, call, patch

import pytest
from apscheduler.triggers.base import BaseTrigger
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import ConnectionException

from device_discovery.policy.models import (
    Config,
    Defaults,
    DeviceParameters,
    InterfacePattern,
    Napalm,
    Options,
    Status,
)
from device_discovery.policy.run import RunStore
from device_discovery.policy.runner import PolicyRunner


@pytest.fixture
def policy_runner():
    """Fixture to create a PolicyRunner instance."""
    return PolicyRunner()


@pytest.fixture
def run_store():
    """Fixture to create a RunStore instance."""
    return RunStore()


@pytest.fixture
def sample_config():
    """Fixture for a sample Config object."""
    return Config(schedule="0 * * * *", defaults=Defaults(site="New York"))


@pytest.fixture
def sample_scopes():
    """Fixture for a sample list of Napalm objects."""
    return [
        Napalm(
            driver="ios",
            hostname="router1",
            username="admin",
            password="password",
            override_defaults=Defaults(role="Router", site="New York/NY"),
        ),
    ]


def test_initial_status(policy_runner):
    """Test initial status of PolicyRunner."""
    assert policy_runner.status == Status.NEW


def test_setup_policy_runner_with_cron(
    policy_runner, sample_config, sample_scopes, run_store
):
    """Test setting up the PolicyRunner with a cron schedule."""
    with (
        patch.object(policy_runner.scheduler, "start") as mock_start,
        patch.object(policy_runner.scheduler, "add_job") as mock_add_job,
    ):

        policy_runner.setup("policy1", sample_config, sample_scopes, run_store)

        # Ensure scheduler starts and job is added
        mock_start.assert_called_once()

        assert mock_add_job.call_count == 2
        call_args = mock_add_job.call_args_list[0]  # First call
        passed_config = call_args[1]["args"][2]

        assert passed_config.defaults.site == "New York/NY"
        assert passed_config.defaults.role == "Router"

        # default was not modified, only inside the scope
        assert policy_runner.status == Status.RUNNING
        assert policy_runner.config.defaults.role == "undefined"
        assert policy_runner.config.defaults.site == "New York"


def test_setup_policy_runner_with_one_time_run(policy_runner, sample_scopes, run_store):
    """Test setting up the PolicyRunner with a one-time schedule."""
    one_time_config = Config()
    with (
        patch.object(policy_runner.scheduler, "start") as mock_start,
        patch.object(policy_runner.scheduler, "add_job") as mock_add_job,
    ):

        policy_runner.setup("policy1", one_time_config, sample_scopes, run_store)

        # Verify that DateTrigger is used for one-time scheduling
        trigger = mock_add_job.call_args[1]["trigger"]
        assert isinstance(trigger, DateTrigger)
        assert mock_start.called
    assert policy_runner.status == Status.RUNNING


def test_setup_sets_misfire_grace_time_none(
    policy_runner, sample_config, sample_scopes, run_store
):
    """Ensure jobs are added with misfire_grace_time=None (run even if late)."""
    with (
        patch.object(policy_runner.scheduler, "start"),
        patch.object(policy_runner.scheduler, "add_job") as mock_add_job,
    ):
        policy_runner.setup("policy1", sample_config, sample_scopes, run_store)

        # First add_job call corresponds to the device run job
        first_call_kwargs = mock_add_job.call_args_list[0][1]
        assert "misfire_grace_time" in first_call_kwargs
        assert first_call_kwargs["misfire_grace_time"] is None


def test_setup_policy_runner_with_none_config(policy_runner, sample_scopes, run_store):
    """Ensure PolicyRunner uses default config when none is provided."""
    with (
        patch.object(policy_runner.scheduler, "start") as mock_start,
        patch.object(policy_runner.scheduler, "add_job") as mock_add_job,
    ):

        policy_runner.setup("policy1", None, sample_scopes, run_store)

        mock_start.assert_called_once()
        assert mock_add_job.call_count == 2
        assert isinstance(policy_runner.config.defaults, Defaults)
        assert isinstance(policy_runner.config.options, Options)
        assert policy_runner.status == Status.RUNNING


def test_setup_policy_runner_expands_hostname_ranges(
    policy_runner, sample_config, run_store
):
    """Ranges schedule a port scan job instead of direct discovery."""
    ranged_scope = Napalm(
        driver="ios",
        hostname="192.0.2.1-192.0.2.2",
        username="admin",
        password="password",
        override_defaults=Defaults(role="Router"),
    )

    with (
        patch.object(policy_runner.scheduler, "start"),
        patch.object(policy_runner.scheduler, "add_job") as mock_add_job,
    ):
        policy_runner.setup("policy1", sample_config, [ranged_scope], run_store)

    assert mock_add_job.call_count == 2
    first_call = mock_add_job.call_args_list[0]
    assert first_call[0][0] == policy_runner.run_scan

    hostnames, cron_trigger, passed_scope, copied_config = first_call[1]["args"]
    assert hostnames == ["192.0.2.1", "192.0.2.2"]
    assert isinstance(cron_trigger, CronTrigger)
    assert isinstance(first_call[1]["trigger"], CronTrigger)
    assert passed_scope.hostname == ranged_scope.hostname
    assert copied_config.defaults.role == "Router"


def test_setup_policy_runner_expands_hostname_ranges_one_shot(
    policy_runner, run_store
):
    """Range scan with no schedule must still use DateTrigger for run_scan."""
    ranged_scope = Napalm(
        driver="ios",
        hostname="192.0.2.1-192.0.2.2",
        username="admin",
        password="password",
    )
    one_shot_config = Config()  # no schedule

    with (
        patch.object(policy_runner.scheduler, "start"),
        patch.object(policy_runner.scheduler, "add_job") as mock_add_job,
    ):
        policy_runner.setup("policy1", one_shot_config, [ranged_scope], run_store)

    first_call = mock_add_job.call_args_list[0]
    assert first_call[0][0] == policy_runner.run_scan
    assert isinstance(first_call[1]["trigger"], DateTrigger)
    _, date_trigger_arg, _, _ = first_call[1]["args"]
    assert isinstance(date_trigger_arg, DateTrigger)


def _scheduled(policy_runner, run_store, scopes):
    """Set the policy up and return what it schedules: range hosts by range, and single targets."""
    with (
        patch.object(policy_runner.scheduler, "start"),
        patch.object(policy_runner.scheduler, "add_job") as mock_add_job,
    ):
        policy_runner.setup("policy1", Config(), scopes, run_store)
    ranges, singles = {}, []
    for scheduled in mock_add_job.call_args_list:
        if scheduled[0][0] == policy_runner.run_scan:
            hostnames, _, scope, _ = scheduled[1]["args"]
            ranges[scope.hostname] = hostnames
        elif scheduled[0][0] == policy_runner.run:
            singles.append(scheduled[1]["args"][1].hostname)
    return ranges, singles


def _entry(hostname, **kwargs):
    return Napalm(hostname=hostname, username="admin", password="invalid", **kwargs)


@pytest.mark.parametrize("own_entry", ["192.0.2.2", "192.0.2.2/32", "192.0.2.2-2"])
def test_setup_leaves_an_address_with_its_own_entry_out_of_a_range(
    policy_runner, run_store, own_entry
):
    """A device listed on its own gets one job, from its own entry, not a second from the range."""
    ranges, singles = _scheduled(
        policy_runner, run_store, [_entry("192.0.2.0/29"), _entry(own_entry, driver="ios")]
    )

    assert "192.0.2.2" not in ranges["192.0.2.0/29"]
    assert len(ranges["192.0.2.0/29"]) == 5
    assert ranges.get(own_entry) == ["192.0.2.2"] or singles == ["192.0.2.2"]


def test_setup_keeps_a_range_host_whose_own_entry_uses_another_port(policy_runner, run_store):
    """An entry on another port reaches a different service, so the range keeps the host."""
    ranges, singles = _scheduled(
        policy_runner,
        run_store,
        [_entry("192.0.2.0/29"), _entry("192.0.2.2", optional_args={"port": 2222})],
    )

    assert "192.0.2.2" in ranges["192.0.2.0/29"]
    assert singles == ["192.0.2.2"]


def test_setup_leaves_out_a_host_listed_on_the_range_port(policy_runner, run_store):
    """A range and an entry on the same port reach the same service, so the range leaves the host out."""
    port = {"optional_args": {"port": 2222}}
    ranges, _ = _scheduled(
        policy_runner, run_store, [_entry("192.0.2.0/29", **port), _entry("192.0.2.2", **port)]
    )

    assert "192.0.2.2" not in ranges["192.0.2.0/29"]


def test_setup_keeps_overlapping_ranges_independent(policy_runner, run_store):
    """Overlapping ranges are how a policy tries several accounts, so neither takes hosts from the other."""
    ranges, _ = _scheduled(
        policy_runner, run_store, [_entry("192.0.2.0/30"), _entry("192.0.2.1-192.0.2.2")]
    )

    assert ranges == {
        "192.0.2.0/30": ["192.0.2.1", "192.0.2.2"],
        "192.0.2.1-192.0.2.2": ["192.0.2.1", "192.0.2.2"],
    }


def test_setup_skips_a_range_whose_addresses_all_have_their_own_entries(policy_runner, run_store):
    """A range left with nothing to scan schedules no scan."""
    ranges, singles = _scheduled(
        policy_runner,
        run_store,
        [_entry("192.0.2.0/30"), _entry("192.0.2.1"), _entry("192.0.2.2")],
    )

    assert ranges == {}
    assert singles == ["192.0.2.1", "192.0.2.2"]


def test_setup_with_unsupported_driver_raises_error(
    policy_runner, sample_scopes, run_store
):
    """Test setup raises error if driver is unsupported."""
    sample_scopes[0].driver = "unsupported_driver"
    with (
        patch("device_discovery.policy.runner.supported_drivers", ["ios"]),
        pytest.raises(
            Exception, match="specified driver 'unsupported_driver' was not found"
        ),
    ):
        policy_runner.setup("policy1", Config(), sample_scopes, run_store)
    assert policy_runner.status == Status.NEW


def test_run_device_with_discovered_driver(
    policy_runner, sample_scopes, sample_config, run_store
):
    """Test running a device where the driver needs discovery."""
    sample_scopes[0].driver = None  # Force driver discovery
    with (
        patch(
            "device_discovery.policy.runner.discover_device_driver", return_value="ios"
        ) as mock_discover,
        patch("device_discovery.policy.runner.get_network_driver") as mock_get_driver,
        patch("device_discovery.client.Client.ingest") as mock_ingest,
    ):

        # Mock the network driver instance
        mock_driver_instance = MagicMock()
        mock_get_driver.return_value.return_value = mock_driver_instance
        mock_driver_instance.get_facts.return_value = {"hostname": "router1", "model": "SampleModel"}
        mock_driver_instance.get_interfaces.return_value = {"eth0": "up"}
        mock_driver_instance.get_interfaces_ip.return_value = {"eth0": "192.168.1.1"}

        # Set up run_store
        policy_runner.run_store = run_store
        policy_runner.name = "test_policy"

        # Run the device with the setup runner
        policy_runner.run("test_id", sample_scopes[0], sample_config)

        # Verify driver discovery and ingestion
        mock_discover.assert_called_once_with(sample_scopes[0], drivers=None, policy="test_policy")
        mock_ingest.assert_called_once()
        metadata_arg, data = mock_ingest.call_args[0]
        kwargs = mock_ingest.call_args[1]
        assert metadata_arg == {
            "policy_name": policy_runner.name,
            "policy_instance": policy_runner.instance_id,
            "hostname": sample_scopes[0].hostname,
        }
        run = run_store.get_runs_for_policy(policy_runner.name)[0]
        assert kwargs["run_id"] == run.id
        assert run.driver == "ios"
        assert data["driver"] == "ios"
        assert data["device"] == {"hostname": "router1", "model": "SampleModel"}
        assert data["interface"] == {"eth0": "up"}
        assert data["interface_ip"] == {"eth0": "192.168.1.1"}


def test_run_discovered_driver_error(
    policy_runner, sample_scopes, sample_config, run_store
):
    """Test running a device where the driver discovery fails."""
    sample_scopes[0].driver = None  # Force driver discovery
    with (
        patch(
            "device_discovery.policy.runner.discover_device_driver", return_value=None
        ) as mock_discover,
        patch("device_discovery.policy.runner.logger.warning") as mock_logger_warning,
    ):
        # Set up run_store
        policy_runner.run_store = run_store
        policy_runner.name = "test_policy"

        # Run the device with an error to check error handling
        policy_runner.run("test_id", sample_scopes[0], sample_config)

        mock_discover.assert_called_once_with(sample_scopes[0], drivers=None, policy="test_policy")
        mock_logger_warning.assert_called_once()
        assert "Not able to discover device driver" in mock_logger_warning.call_args[0][0]
        assert policy_runner.status == Status.FAILED
        failed_run = run_store.get_runs_for_policy(policy_runner.name)[0]
        assert failed_run.driver is None


def test_run_driver_failure_does_not_remove_job(policy_runner, sample_scopes, sample_config, run_store):
    """Driver discovery failure must NOT remove the job — the cron should keep firing."""
    sample_scopes[0].driver = None
    policy_runner.run_store = run_store
    policy_runner.name = "test_policy"

    with (
        patch("device_discovery.policy.runner.discover_device_driver", return_value=None),
        patch.object(policy_runner.scheduler, "remove_job") as mock_remove,
    ):
        policy_runner.run("test_id", sample_scopes[0], sample_config)

    mock_remove.assert_not_called()


def test_run_device_with_error_in_job(
    policy_runner, sample_scopes, sample_config, run_store
):
    """Test run handles an error during device interaction gracefully."""
    with (
        patch(
            "device_discovery.policy.runner.get_network_driver",
            side_effect=Exception("Connection error"),
        ),
        patch("device_discovery.policy.runner.logger.error") as mock_logger_error,
    ):
        # Set up run_store
        policy_runner.run_store = run_store
        policy_runner.name = "test_policy"

        # Run the device with an error to check error handling
        policy_runner.run("test_id", sample_scopes[0], sample_config)
        mock_logger_error.assert_called_once()


def test_run_scan_schedules_reachable_hosts(monkeypatch):
    """Reachable hosts should be scheduled for discovery with copied scope."""
    runner = PolicyRunner()
    runner.name = "policy1"
    runner.run_store = RunStore()
    runner.scheduler = MagicMock()
    scope = Napalm(
        driver="ios", hostname="seed-host", username="admin", password="password"
    )
    config = Config(options=Options(port_scan_ports=[1, 2], port_scan_timeout=0.1))
    trigger = MagicMock(spec=BaseTrigger)
    reachability = {"host-a": True, "host-b": False}

    with (
        patch(
            "device_discovery.policy.runner.find_reachable_hosts",
            return_value=reachability,
        ) as mock_reachable_hosts,
        patch(
            "uuid.uuid4", side_effect=["scan-run-id", "job-1"]
        ),  # scan run ID + job ID
    ):
        runner.run_scan(["host-a", "host-b"], trigger, scope, config)

    runner.scheduler.add_job.assert_called_once()
    scheduled_call = runner.scheduler.add_job.call_args
    assert scheduled_call[0][0] == runner.run_with_parent
    assert scheduled_call[1]["args"][0] == "job-1"
    assert scheduled_call[1]["args"][1].hostname == "host-a"
    assert scheduled_call[1]["args"][2] == config
    assert scheduled_call[1]["args"][3] == "seed-host"  # parent_target
    mock_reachable_hosts.assert_called_once_with(["host-a", "host-b"], [1, 2], 0.1)


def test_run_scan_uses_default_port_scan_options(monkeypatch):
    """Default port scan options are applied when none are provided."""
    runner = PolicyRunner()
    runner.name = "policy1"
    runner.run_store = RunStore()
    runner.scheduler = MagicMock()
    scope = Napalm(
        driver="ios", hostname="seed-host", username="admin", password="password"
    )
    trigger = MagicMock(spec=BaseTrigger)
    config = Config(options=None)

    with patch(
        "device_discovery.policy.runner.find_reachable_hosts",
        return_value={"host-a": False},
    ) as mock_reachable_hosts:
        runner.run_scan(["host-a"], trigger, scope, config)

    mock_reachable_hosts.assert_called_once()
    _, ports, timeout = mock_reachable_hosts.call_args[0]
    assert ports == [22, 23, 80, 443, 830, 57400]
    assert timeout == 0.5
    runner.scheduler.add_job.assert_not_called()


def test_stop_policy_runner(policy_runner):
    """Test stopping the PolicyRunner."""
    with patch.object(policy_runner.scheduler, "shutdown") as mock_shutdown:
        policy_runner.stop()

        # Ensure scheduler shutdown is called and status is updated
        mock_shutdown.assert_called_once()
        assert policy_runner.status == Status.FINISHED


def test_metrics_during_policy_lifecycle(
    policy_runner, sample_config, sample_scopes, run_store
):
    """Test that metrics are properly updated during the policy lifecycle."""
    # Create mock metrics
    mock_active_policies = MagicMock()
    mock_policy_executions = MagicMock()
    mock_discovery_attempts = MagicMock()
    mock_discovery_success = MagicMock()
    mock_discovery_failure = MagicMock()
    mock_device_connection_latency = MagicMock()
    mock_discovery_latency = MagicMock()

    # Map of metric names to mock objects
    mock_metrics = {
        "active_policies": mock_active_policies,
        "policy_executions": mock_policy_executions,
        "discovery_attempts": mock_discovery_attempts,
        "discovery_success": mock_discovery_success,
        "discovery_failure": mock_discovery_failure,
        "device_connection_latency": mock_device_connection_latency,
        "discovery_latency": mock_discovery_latency,
    }

    # Setup mock for get_metric function
    def mock_get_metric(name):
        return mock_metrics.get(name)

    with (
        patch("device_discovery.policy.runner.get_metric", side_effect=mock_get_metric),
        patch.object(policy_runner.scheduler, "start"),
        patch.object(policy_runner.scheduler, "add_job"),
        patch("device_discovery.policy.runner.get_network_driver"),
        patch("device_discovery.client.Client.ingest"),
    ):

        # Test setup - should increment active_policies
        policy_runner.setup("test_policy", sample_config, sample_scopes, run_store)
        mock_active_policies.add.assert_called_once_with(1, {"policy": "test_policy"})

        # Test telemetry job - should increment policy_executions
        policy_runner.telemetry()
        mock_policy_executions.add.assert_called_once_with(1, {"policy": "test_policy"})

        # Test run - should record attempts, success, and latency
        policy_runner.run("test_id", sample_scopes[0], sample_config)

        mock_discovery_attempts.add.assert_called_once_with(
            1, {"policy": "test_policy"}
        )
        mock_discovery_success.add.assert_called_once_with(1, {"policy": "test_policy"})
        mock_device_connection_latency.record.assert_called_once()
        mock_discovery_latency.record.assert_called_once()

        # Verify connection latency recorded with correct values
        latency_args = mock_device_connection_latency.record.call_args[0][0]
        latency_kwargs = mock_device_connection_latency.record.call_args[0][1]
        assert latency_args > 0.01  # 0.1 seconds in milliseconds
        assert latency_kwargs["policy"] == "test_policy"
        assert latency_kwargs["driver"] == "ios"

        # Test stop - should decrement active_policies
        with patch.object(policy_runner.scheduler, "shutdown") as mock_shutdown:
            policy_runner.stop()
            mock_shutdown.assert_called_once()
            mock_active_policies.add.assert_called_with(-1, {"policy": "test_policy"})


def test_metrics_during_failed_discovery(policy_runner, sample_config, run_store):
    """Test that metrics are properly updated when discovery fails."""
    # Create a scope with no driver to force discovery
    scope = Napalm(
        driver=None, hostname="router1", username="admin", password="password"
    )

    mock_discovery_attempts = MagicMock()
    mock_discovery_failure = MagicMock()
    mock_discovery_latency = MagicMock()

    mock_metrics = {
        "discovery_attempts": mock_discovery_attempts,
        "discovery_failure": mock_discovery_failure,
        "discovery_latency": mock_discovery_latency,
    }

    def mock_get_metric(name):
        return mock_metrics.get(name)

    with (
        patch("device_discovery.policy.runner.get_metric", side_effect=mock_get_metric),
        patch(
            "device_discovery.policy.runner.discover_device_driver", return_value="ios"
        ),
        patch(
            "device_discovery.policy.runner.get_network_driver",
            side_effect=Exception("Connection error"),
        ),
        patch.object(policy_runner.scheduler, "remove_job"),
    ):
        # Set up run_store
        policy_runner.run_store = run_store
        policy_runner.name = "test_policy"

        # Run the device with discovery that will fail
        policy_runner.run("test_id", scope, sample_config)

        # Verify failure metric was called
        mock_discovery_failure.add.assert_called_once_with(1, {"policy": "test_policy"})

        # Verify discovery latency recorded with failure status
        mock_discovery_latency.record.assert_called_once()
        latency_args = mock_discovery_latency.record.call_args[0][0]
        latency_kwargs = mock_discovery_latency.record.call_args[0][1]
        assert latency_args > 0.01
        assert latency_kwargs["status"] == "failed"


def test_run_scan_handles_port_scan_failure(policy_runner, sample_config, run_store):
    """Test that scan runs are marked as FAILED when port scanning fails."""
    scope = Napalm(
        driver=None,
        hostname="seed-host",
        username="admin",
        password="password",
    )
    trigger = MagicMock(spec=BaseTrigger)

    with (
        patch(
            "device_discovery.policy.runner.find_reachable_hosts",
            side_effect=Exception("Port scan timeout"),
        ),
        patch("uuid.uuid4", side_effect=["scan-run-id"]),
    ):
        policy_runner.run_store = run_store
        policy_runner.name = "test_policy"

        # Run scan which will fail
        policy_runner.run_scan(["10.0.0.1", "10.0.0.2"], trigger, scope, sample_config)

        # Verify scan run was created and marked as FAILED
        runs = run_store.get_runs_for_target("test_policy", "seed-host")
        assert len(runs) == 1
        assert runs[0].status.value == "failed"
        assert runs[0].entity_count == 0
        assert "Port scan timeout" in runs[0].reason


def test_run_scan_records_a_failed_run_for_an_empty_expansion(
    policy_runner, sample_config, run_store,
):
    """
    A scope that expanded to no addresses is recorded as a failed run.

    ``expand_hostnames`` returns an empty list when a target is over the
    expansion cap. Without a run record the policy reports RUNNING with no
    history for that scope, so the operator sees an unchanged status and has
    only the log to go on. A range that scans but finds nothing reachable is
    already recorded as FAILED; a range that could never be scanned at all
    must not be less visible than that.
    """
    scope = Napalm(
        driver=None,
        hostname="2001:db8::/64",
        username="admin",
        password="password",
    )
    trigger = MagicMock(spec=BaseTrigger)
    policy_runner.run_store = run_store
    policy_runner.name = "test_policy"

    policy_runner.run_scan([], trigger, scope, sample_config)

    runs = run_store.get_runs_for_target("test_policy", "2001:db8::/64")
    assert len(runs) == 1, "an over-cap scope must leave a run behind"
    assert runs[0].status.value == "failed"
    assert runs[0].entity_count == 0
    assert "no addresses" in runs[0].reason


def test_options_discovery_drivers_default_none():
    """Test that discovery_drivers defaults to None when not specified."""
    from device_discovery.policy.models import Options
    opts = Options()
    assert opts.discovery_drivers is None


def test_options_discovery_drivers_parsed():
    """Test that discovery_drivers parses a list of driver names correctly."""
    from device_discovery.policy.models import Options
    opts = Options(discovery_drivers=["ios", "panos"])
    assert opts.discovery_drivers == ["ios", "panos"]


def test_run_scan_clears_netbox_id_for_range_expanded_hosts():
    """Hosts expanded from a range/subnet must not inherit the scope's netbox_id."""
    runner = PolicyRunner()
    runner.name = "policy1"
    runner.run_store = RunStore()
    runner.scheduler = MagicMock()
    scope = Napalm(
        driver="ios",
        hostname="192.168.1.0/24",
        username="admin",
        password="password",
        netbox_id=42,
    )
    config = Config(options=Options(port_scan_ports=[22], port_scan_timeout=0.1))
    trigger = MagicMock(spec=BaseTrigger)

    with (
        patch(
            "device_discovery.policy.runner.find_reachable_hosts",
            return_value={"192.168.1.1": True},
        ),
        patch("uuid.uuid4", side_effect=["scan-run-id", "job-1"]),
    ):
        runner.run_scan(["192.168.1.1"], trigger, scope, config)

    scheduled_call = runner.scheduler.add_job.call_args
    scheduled_scope = scheduled_call[1]["args"][1]
    assert scheduled_scope.hostname == "192.168.1.1"
    assert scheduled_scope.netbox_id is None


def test_setup_raises_on_unknown_discovery_drivers():
    """setup() raises if discovery_drivers contains a driver not in supported_drivers."""
    from device_discovery.policy.models import Config, Napalm, Options
    from device_discovery.policy.run import RunStore
    from device_discovery.policy.runner import PolicyRunner

    runner = PolicyRunner()
    config = Config(options=Options(discovery_drivers=["not_a_real_driver_xyz"]))
    scope = [Napalm(hostname="192.168.1.1", username="admin", password="pass")]
    run_store = RunStore()

    with pytest.raises(Exception, match="discovery_drivers contains unknown drivers"):
        runner.setup("test-policy", config, scope, run_store)


def test_setup_raises_on_empty_discovery_drivers():
    """setup() raises if discovery_drivers is an empty list."""
    from device_discovery.policy.models import Config, Napalm, Options
    from device_discovery.policy.run import RunStore
    from device_discovery.policy.runner import PolicyRunner

    runner = PolicyRunner()
    config = Config(options=Options(discovery_drivers=[]))
    scope = [Napalm(hostname="192.168.1.1", username="admin", password="pass")]
    run_store = RunStore()

    with pytest.raises(Exception, match="discovery_drivers must not be empty"):
        runner.setup("test-policy", config, scope, run_store)


def test_setup_accepts_valid_discovery_drivers():
    """setup() does not raise when discovery_drivers contains only known drivers."""
    from device_discovery.policy.models import Config, Napalm, Options
    from device_discovery.policy.run import RunStore
    from device_discovery.policy.runner import PolicyRunner

    runner = PolicyRunner()
    config = Config(options=Options(discovery_drivers=["ios", "eos"]))
    scope = [Napalm(hostname="192.168.1.1", username="admin", password="pass")]
    run_store = RunStore()

    try:
        runner.setup("test-policy", config, scope, run_store)
    finally:
        runner.stop()


def test_collect_device_data_returns_entity_count(policy_runner):
    """_collect_device_data returns the number of ingested entities."""
    scope = Napalm(
        driver="ios",
        hostname="router1",
        username="admin",
        password="password",
    )
    config = Config(defaults=Defaults(site="NY"))

    fake_device = MagicMock()
    fake_device.get_facts.return_value = {"hostname": "router1"}
    fake_device.get_interfaces.return_value = {}
    fake_device.get_interfaces_ip.return_value = {}
    fake_device.get_vlans.return_value = {}
    fake_device.__enter__ = MagicMock(return_value=fake_device)
    fake_device.__exit__ = MagicMock(return_value=False)

    with (
        patch("device_discovery.policy.runner.get_network_driver", return_value=MagicMock(return_value=fake_device)),
        patch("device_discovery.policy.runner.Client") as mock_client_cls,
    ):
        mock_client_cls.return_value.ingest.return_value = 7

        result = policy_runner._collect_device_data(scope, "router1", config, "run-abc")

    assert result == 7


def test_run_uses_entity_count_from_collect(policy_runner, run_store):
    """run() passes the actual entity count (not 1) to update_run."""
    scope = Napalm(driver="ios", hostname="router1", username="admin", password="password")
    config = Config(defaults=Defaults(site="NY"), options=Options())
    policy_runner.run_store = run_store

    with (
        patch.object(policy_runner, "_discover_driver", return_value=True),
        patch.object(policy_runner, "_collect_device_data", return_value=5),
        patch("device_discovery.policy.runner.get_metric", return_value=None),
    ):
        policy_runner.name = "test-policy"
        run = run_store.create_run(policy_name="test-policy", target="router1")
        # Patch create_run to return our known run
        with patch.object(run_store, "create_run", return_value=run):
            with patch.object(run_store, "update_run") as mock_update:
                policy_runner.run("job-1", scope, config)

    mock_update.assert_called_once()
    call_kwargs = mock_update.call_args[1]
    assert call_kwargs["entity_count"] == 5
    assert call_kwargs["driver"] == "ios"


def test_run_with_parent_uses_entity_count_from_collect(policy_runner, run_store):
    """run_with_parent() passes the actual entity count (not 1) to update_run."""
    scope = Napalm(driver="ios", hostname="router1", username="admin", password="password")
    config = Config(defaults=Defaults(site="NY"), options=Options())
    policy_runner.run_store = run_store

    with (
        patch.object(policy_runner, "_discover_driver", return_value=True),
        patch.object(policy_runner, "_collect_device_data", return_value=12),
        patch("device_discovery.policy.runner.get_metric", return_value=None),
    ):
        policy_runner.name = "test-policy"
        run = run_store.create_run(policy_name="test-policy", target="router1")
        with patch.object(run_store, "create_run", return_value=run):
            with patch.object(run_store, "update_run") as mock_update:
                policy_runner.run_with_parent("job-1", scope, config, "192.168.1.0/24")

    mock_update.assert_called_once()
    call_kwargs = mock_update.call_args[1]
    assert call_kwargs["entity_count"] == 12
    assert call_kwargs["driver"] == "ios"


def test_run_with_parent_driver_failure_does_not_remove_job(policy_runner, run_store, sample_config):
    """Driver discovery failure in run_with_parent must NOT remove the job."""
    scope = Napalm(driver=None, hostname="192.0.2.1", username="admin", password="password")
    policy_runner.run_store = run_store
    policy_runner.name = "test_policy"

    with (
        patch("device_discovery.policy.runner.discover_device_driver", return_value=None),
        patch.object(policy_runner.scheduler, "remove_job") as mock_remove,
    ):
        policy_runner.run_with_parent("test_id", scope, sample_config, "192.0.2.0/24")

    mock_remove.assert_not_called()


def test_run_scan_skips_already_active_host(monkeypatch):
    """run_scan must not schedule a second job for a host that already has one."""
    runner = PolicyRunner()
    runner.name = "policy1"
    runner.run_store = RunStore()
    runner.scheduler = MagicMock()
    scope = Napalm(driver="ios", hostname="192.168.1.0/24", username="admin", password="password")
    config = Config(options=Options(port_scan_ports=[22], port_scan_timeout=0.1))
    trigger = MagicMock(spec=BaseTrigger)

    existing_job = MagicMock()
    runner.scheduler.get_job.return_value = existing_job

    # Pre-populate active_host_jobs as if host was already scheduled
    runner.active_host_jobs[("192.168.1.0/24", "192.168.1.1")] = "existing-job-id"

    with patch(
        "device_discovery.policy.runner.find_reachable_hosts",
        return_value={"192.168.1.1": True},
    ):
        runner.run_scan(["192.168.1.1"], trigger, scope, config)

    runner.scheduler.add_job.assert_not_called()
    runner.scheduler.get_job.assert_called_once_with("existing-job-id")


def test_run_scan_reschedules_host_when_job_no_longer_active(monkeypatch):
    """When a previous job has finished, run_scan must schedule a new one."""
    runner = PolicyRunner()
    runner.name = "policy1"
    runner.run_store = RunStore()
    runner.scheduler = MagicMock()
    runner.scheduler.get_job.return_value = None   # job is gone

    runner.active_host_jobs[("192.168.1.0/24", "192.168.1.1")] = "stale-job-id"
    scope = Napalm(driver="ios", hostname="192.168.1.0/24", username="admin", password="password")
    config = Config(options=Options(port_scan_ports=[22], port_scan_timeout=0.1))
    trigger = MagicMock(spec=BaseTrigger)

    with (
        patch(
            "device_discovery.policy.runner.find_reachable_hosts",
            return_value={"192.168.1.1": True},
        ),
        patch("uuid.uuid4", side_effect=["scan-run-id", "new-job-id"]),
    ):
        runner.run_scan(["192.168.1.1"], trigger, scope, config)

    runner.scheduler.add_job.assert_called_once()
    assert runner.active_host_jobs[("192.168.1.0/24", "192.168.1.1")] == "new-job-id"


def test_run_scan_overlapping_scopes_each_schedule_independently():
    """Two scopes whose ranges overlap must each schedule their own job for the shared host."""
    runner = PolicyRunner()
    runner.name = "policy1"
    runner.run_store = RunStore()
    runner.scheduler = MagicMock()
    runner.scheduler.get_job.return_value = None  # no prior jobs
    trigger = MagicMock(spec=BaseTrigger)
    config = Config(options=Options(port_scan_ports=[22], port_scan_timeout=0.1))

    scope_a = Napalm(driver="ios", hostname="192.168.1.0/24", username="admin", password="admin")
    scope_b = Napalm(driver="ios", hostname="192.168.1.1-192.168.1.5", username="ops", password="ops")

    with (
        patch("device_discovery.policy.runner.find_reachable_hosts", return_value={"192.168.1.1": True}),
        patch("uuid.uuid4", side_effect=["scan-a", "job-a"]),
    ):
        runner.run_scan(["192.168.1.1"], trigger, scope_a, config)

    with (
        patch("device_discovery.policy.runner.find_reachable_hosts", return_value={"192.168.1.1": True}),
        patch("uuid.uuid4", side_effect=["scan-b", "job-b"]),
    ):
        runner.run_scan(["192.168.1.1"], trigger, scope_b, config)

    assert runner.scheduler.add_job.call_count == 2
    assert runner.active_host_jobs[("192.168.1.0/24", "192.168.1.1")] == "job-a"
    assert runner.active_host_jobs[("192.168.1.1-192.168.1.5", "192.168.1.1")] == "job-b"


def test_run_scan_stores_failed_run_on_range_when_no_hosts_reachable():
    """When no host in a range is reachable, the range-level scan run must be FAILED."""
    from device_discovery.policy.run import RunStatus

    runner = PolicyRunner()
    runner.name = "policy1"
    runner.run_store = RunStore()
    runner.scheduler = MagicMock()
    scope = Napalm(driver="ios", hostname="192.168.1.0/24", username="admin", password="password")
    config = Config(options=Options(port_scan_ports=[22], port_scan_timeout=0.1))
    trigger = MagicMock(spec=BaseTrigger)

    with patch(
        "device_discovery.policy.runner.find_reachable_hosts",
        return_value={"192.168.1.1": False, "192.168.1.2": False},
    ):
        runner.run_scan(["192.168.1.1", "192.168.1.2"], trigger, scope, config)

    # Failure reported at range level, not per-host
    range_runs = runner.run_store.get_runs_for_target("policy1", "192.168.1.0/24")
    assert len(range_runs) == 1
    assert range_runs[0].status.value == "failed"
    assert "No reachable hosts found in range" in range_runs[0].reason

    # No per-host run records created for unreachable hosts
    assert runner.run_store.get_runs_for_target("policy1", "192.168.1.1") == []
    assert runner.run_store.get_runs_for_target("policy1", "192.168.1.2") == []
    runner.scheduler.add_job.assert_not_called()


def test_run_scan_stores_completed_run_when_some_hosts_reachable():
    """When at least one host is reachable, the range-level scan run is COMPLETED."""
    runner = PolicyRunner()
    runner.name = "policy1"
    runner.run_store = RunStore()
    runner.scheduler = MagicMock()
    scope = Napalm(driver="ios", hostname="192.168.1.0/24", username="admin", password="password")
    config = Config(options=Options(port_scan_ports=[22], port_scan_timeout=0.1))
    trigger = MagicMock(spec=BaseTrigger)

    with (
        patch(
            "device_discovery.policy.runner.find_reachable_hosts",
            return_value={"192.168.1.1": True, "192.168.1.2": False},
        ),
        patch("uuid.uuid4", side_effect=["scan-run-id", "job-1"]),
    ):
        runner.run_scan(["192.168.1.1", "192.168.1.2"], trigger, scope, config)

    range_runs = runner.run_store.get_runs_for_target("policy1", "192.168.1.0/24")
    assert len(range_runs) == 1
    assert range_runs[0].status.value == "completed"
    assert range_runs[0].entity_count == 1
    runner.scheduler.add_job.assert_called_once()


def test_run_scan_runs_a_found_host_now_under_a_cron_schedule():
    """A host a scheduled range finds runs right away, not at the tick after the scan."""
    runner = PolicyRunner()
    runner.name = "policy1"
    runner.run_store = RunStore()
    runner.scheduler.start(paused=True)
    scope = Napalm(driver="ios", hostname="192.0.2.0/30", username="admin", password="password")
    config = Config(options=Options(port_scan_ports=[22], port_scan_timeout=0.1))
    trigger = CronTrigger.from_crontab("0 0 1 1 *")

    try:
        with patch(
            "device_discovery.policy.runner.find_reachable_hosts",
            return_value={"192.0.2.1": True},
        ):
            runner.run_scan(["192.0.2.1"], trigger, scope, config)

        (job,) = runner.scheduler.get_jobs()
        now = datetime.now(job.next_run_time.tzinfo)
        assert abs(job.next_run_time - now) < timedelta(minutes=1)
        assert job.trigger is trigger
    finally:
        runner.scheduler.shutdown(wait=False)


def test_setup_policy_runner_override_defaults_deep_merges_nested_models(
    policy_runner, run_store
):
    """
    override_defaults on a nested sub-model must deep-merge and stay a model instance.

    Regression for AttributeError: 'dict' object has no attribute 'tags' — caused
    by model_copy(update=dict) replacing nested Pydantic sub-models with raw dicts
    and shallow-overwriting sibling fields.
    """
    base_config = Config(
        defaults=Defaults(
            site="HQ",
            tags=["switch-device-discovery", "orb-agent"],
            device=DeviceParameters(manufacturer="Cisco", model="Catalyst 2960"),
        )
    )
    override_scope = Napalm(
        driver="ios",
        hostname="192.0.2.1",
        username="admin",
        password="password",
        override_defaults=Defaults(
            device=DeviceParameters(model="Catalyst 9300"),
        ),
    )

    with (
        patch.object(policy_runner.scheduler, "start"),
        patch.object(policy_runner.scheduler, "add_job") as mock_add_job,
    ):
        policy_runner.setup("policy1", base_config, [override_scope], run_store)

    passed_config = mock_add_job.call_args_list[0][1]["args"][2]

    assert isinstance(passed_config.defaults.device, DeviceParameters)
    assert passed_config.defaults.device.model == "Catalyst 9300"
    assert passed_config.defaults.device.manufacturer == "Cisco"
    assert passed_config.defaults.tags == ["switch-device-discovery", "orb-agent"]
    assert passed_config.defaults.site == "HQ"

    assert policy_runner.config.defaults.device.model == "Catalyst 2960"


def test_setup_policy_runner_override_defaults_empty_list_preserves_parent(
    policy_runner, run_store
):
    """
    Empty list on override must not clear inherited interface_patterns.

    `Defaults.coerce_empty_list_to_none` coerces an empty list to None; combined
    with `exclude_none=True` during merge, the parent value must survive.
    """
    parent_patterns = [InterfacePattern(match=r"^Gi", type="1000base-t")]
    base_config = Config(
        defaults=Defaults(interface_patterns=parent_patterns),
    )
    override_scope = Napalm(
        driver="ios",
        hostname="192.0.2.2",
        username="admin",
        password="password",
        override_defaults=Defaults(
            interface_patterns=[],
            interface_exclude_patterns=[],
        ),
    )

    with (
        patch.object(policy_runner.scheduler, "start"),
        patch.object(policy_runner.scheduler, "add_job") as mock_add_job,
    ):
        policy_runner.setup("policy1", base_config, [override_scope], run_store)

    passed_config = mock_add_job.call_args_list[0][1]["args"][2]

    assert passed_config.defaults.interface_patterns is not None
    assert len(passed_config.defaults.interface_patterns) == 1
    assert passed_config.defaults.interface_patterns[0].match == r"^Gi"
    assert passed_config.defaults.interface_exclude_patterns is None


def test_collect_device_data_includes_interfaces_vlans(
    policy_runner, sample_scopes, sample_config, run_store
):
    """When driver exposes get_interfaces_vlans(), result lands in data['interfaces_vlans']."""
    with (
        patch("device_discovery.policy.runner.get_network_driver") as mock_get_driver,
        patch("device_discovery.client.Client.ingest") as mock_ingest,
    ):
        mock_driver_instance = MagicMock()
        mock_get_driver.return_value.return_value = mock_driver_instance
        mock_driver_instance.get_facts.return_value = {"hostname": "router1", "model": "SampleModel"}
        mock_driver_instance.get_interfaces.return_value = {}
        mock_driver_instance.get_interfaces_ip.return_value = {}
        mock_driver_instance.get_vlans.return_value = {"10": {"name": "DATA", "interfaces": []}}
        mock_driver_instance.get_interfaces_vlans.return_value = {
            "Gi1/0/1": {"mode": "access", "tagged": [], "untagged": 10},
        }

        policy_runner.run_store = run_store
        policy_runner.name = "test_policy"
        policy_runner.run("test_id", sample_scopes[0], sample_config)

        mock_ingest.assert_called_once()
        _metadata, data = mock_ingest.call_args[0]
        assert data["interfaces_vlans"] == {
            "Gi1/0/1": {"mode": "access", "tagged": [], "untagged": 10},
        }


def test_collect_device_data_handles_interfaces_vlans_failure(
    policy_runner, sample_scopes, sample_config, run_store, caplog
):
    """A failing get_interfaces_vlans() is logged and discovery continues without it."""
    import logging

    with (
        patch("device_discovery.policy.runner.get_network_driver") as mock_get_driver,
        patch("device_discovery.client.Client.ingest") as mock_ingest,
        caplog.at_level(logging.WARNING),
    ):
        mock_driver_instance = MagicMock()
        mock_get_driver.return_value.return_value = mock_driver_instance
        mock_driver_instance.get_facts.return_value = {"hostname": "router1", "model": "SampleModel"}
        mock_driver_instance.get_interfaces.return_value = {}
        mock_driver_instance.get_interfaces_ip.return_value = {}
        mock_driver_instance.get_vlans.return_value = {}
        mock_driver_instance.get_interfaces_vlans.side_effect = RuntimeError("boom")

        policy_runner.run_store = run_store
        policy_runner.name = "test_policy"
        policy_runner.run("test_id", sample_scopes[0], sample_config)

        mock_ingest.assert_called_once()
        _metadata, data = mock_ingest.call_args[0]
        assert "interfaces_vlans" not in data
        assert any(
            "Error getting interface VLANs" in r.message for r in caplog.records
        )


def test_collect_device_data_no_get_interfaces_vlans_method(
    policy_runner, sample_scopes, sample_config, run_store
):
    """Driver lacking get_interfaces_vlans is silently fine; key absent from data."""
    with (
        patch("device_discovery.policy.runner.get_network_driver") as mock_get_driver,
        patch("device_discovery.client.Client.ingest") as mock_ingest,
    ):
        # Spec only the methods the runner actually calls — no get_interfaces_vlans.
        mock_driver_instance = MagicMock(spec=[
            "open", "close", "get_facts", "get_interfaces", "get_interfaces_ip", "get_vlans",
        ])
        mock_get_driver.return_value.return_value = mock_driver_instance
        mock_driver_instance.get_facts.return_value = {"hostname": "router1", "model": "SampleModel"}
        mock_driver_instance.get_interfaces.return_value = {}
        mock_driver_instance.get_interfaces_ip.return_value = {}
        mock_driver_instance.get_vlans.return_value = {}

        policy_runner.run_store = run_store
        policy_runner.name = "test_policy"
        policy_runner.run("test_id", sample_scopes[0], sample_config)

        mock_ingest.assert_called_once()
        _metadata, data = mock_ingest.call_args[0]
        assert "interfaces_vlans" not in data


def test_collect_device_data_keeps_the_target_optional_args(policy_runner):
    """Every run must hand the driver the target's optional_args as configured."""
    original = {"port": 2222, "key_file": "/opt/orb/key", "enable_password": "invalid"}
    scope = Napalm(
        driver="eos",
        hostname="router1",
        username="admin",
        password="password",
        optional_args=dict(original),
    )
    config = Config(defaults=Defaults(site="NY"))

    fake_device = MagicMock()
    fake_device.get_facts.return_value = {"hostname": "router1"}
    fake_device.get_interfaces.return_value = {}
    fake_device.get_interfaces_ip.return_value = {}
    fake_device.get_vlans.return_value = {}
    fake_device.__enter__ = MagicMock(return_value=fake_device)
    fake_device.__exit__ = MagicMock(return_value=False)

    received = []

    def driver(hostname, username, password, timeout, optional_args):
        # Drivers such as eos and iosxr_netconf pop their own keys.
        received.append(dict(optional_args))
        optional_args.pop("enable_password", None)
        optional_args.pop("port", None)
        return fake_device

    with (
        patch("device_discovery.policy.runner.get_network_driver", return_value=driver),
        patch("device_discovery.policy.runner.Client"),
    ):
        policy_runner._collect_device_data(scope, "router1", config, "run-1")
        policy_runner._collect_device_data(scope, "router1", config, "run-2")

    assert received == [original, original]
    assert scope.optional_args == original


def test_collect_device_data_closes_the_session_before_ingest(policy_runner):
    """The device session must be closed before the ingest, which can queue behind other jobs."""
    scope = Napalm(driver="ios", hostname="router1", username="admin", password="password")
    config = Config(defaults=Defaults(site="NY"))
    events = []

    fake_device = MagicMock()
    fake_device.get_facts.return_value = {"hostname": "router1", "serial_number": "ABC123"}
    fake_device.get_interfaces.return_value = {}
    fake_device.get_interfaces_ip.return_value = {}
    fake_device.get_vlans.return_value = {}
    fake_device.open.side_effect = lambda: events.append("open")
    fake_device.close.side_effect = lambda: events.append("close")

    with (
        patch(
            "device_discovery.policy.runner.get_network_driver",
            return_value=MagicMock(return_value=fake_device),
        ),
        patch("device_discovery.policy.runner.Client") as mock_client_cls,
    ):
        mock_client_cls.return_value.ingest.side_effect = lambda *a, **k: events.append("ingest") or 3
        assert policy_runner._collect_device_data(scope, "router1", config, "run-1") == 3

    assert events == ["open", "close", "ingest"]


def _run_with_facts(policy_runner, run_store, facts):
    """Run one target with a set driver whose device reports these facts; return the run and the ingest mock."""
    scope = Napalm(driver="ios", hostname="192.0.2.10", username="admin", password="invalid")
    config = Config(defaults=Defaults(site="NY"), options=Options())
    policy_runner.name = "policy1"
    policy_runner.run_store = run_store

    fake_device = MagicMock()
    fake_device.get_facts.return_value = facts
    fake_device.get_interfaces.return_value = {}
    fake_device.get_interfaces_ip.return_value = {}
    fake_device.get_vlans.return_value = {}

    with (
        patch(
            "device_discovery.policy.runner.get_network_driver",
            return_value=MagicMock(return_value=fake_device),
        ),
        patch("device_discovery.policy.runner.Client") as mock_client_cls,
    ):
        mock_client_cls.return_value.ingest.return_value = 4
        policy_runner.run("job-1", scope, config)

    (run,) = run_store.get_runs_for_target("policy1", "192.0.2.10")
    return run, mock_client_cls.return_value.ingest


@pytest.mark.parametrize(
    "facts",
    [
        {"hostname": "Unknown", "serial_number": "Unknown", "fqdn": "Unknown"},
        {"hostname": "", "serial_number": "", "fqdn": ""},
        {"hostname": "% Invalid input detected at '^' marker.", "serial_number": "ABC123"},
        {"hostname": "None", "serial_number": "None", "fqdn": "None"},
    ],
)
def test_run_refuses_facts_that_show_the_set_driver_does_not_fit(
    policy_runner, run_store, caplog, facts
):
    """A set driver whose facts carry a CLI error, or no name and no serial, ingests nothing."""
    with caplog.at_level(logging.WARNING):
        run, ingest = _run_with_facts(policy_runner, run_store, facts)

    assert run.status.value == "failed"
    assert "'ios' driver does not fit this device" in run.reason
    ingest.assert_not_called()
    (record,) = [r for r in caplog.records if "does not fit" in r.getMessage()]
    assert record.levelno == logging.WARNING
    assert record.exc_info is None


@pytest.mark.parametrize(
    "facts",
    [
        {"hostname": "sw1", "serial_number": "Unknown", "fqdn": "sw1"},
        {"hostname": "Unknown", "serial_number": "ABC123", "fqdn": ""},
    ],
)
def test_run_ingests_a_device_with_a_name_or_a_serial(policy_runner, run_store, facts):
    """A set driver still ingests a device that reports only a name, such as a virtual one, or only a serial."""
    run, ingest = _run_with_facts(policy_runner, run_store, facts)

    assert run.status.value == "completed"
    ingest.assert_called_once()


def test_jobs_are_named_after_the_policy_and_target(policy_runner, run_store):
    """Scheduler lines name the policy and target instead of PolicyRunner.run."""
    with (
        patch.object(policy_runner.scheduler, "start"),
        patch.object(policy_runner.scheduler, "add_job") as mock_add_job,
    ):
        policy_runner.setup(
            "policy1", Config(), [_entry("192.0.2.10"), _entry("192.0.2.0/30")], run_store
        )

    names = [c[1].get("name") for c in mock_add_job.call_args_list]
    assert "Policy policy1, Hostname 192.0.2.10" in names
    assert "Policy policy1, Hostname 192.0.2.0/30" in names
    assert "Policy policy1, telemetry" in names


def test_run_scan_names_a_host_job_after_the_policy_and_host():
    """A host's job from a range names the policy and the host."""
    runner = PolicyRunner()
    runner.name = "policy1"
    runner.run_store = RunStore()
    runner.scheduler = MagicMock()
    scope = Napalm(driver="ios", hostname="192.0.2.0/30", username="admin", password="invalid")
    config = Config(options=Options(port_scan_ports=[22], port_scan_timeout=0.1))

    with patch(
        "device_discovery.policy.runner.find_reachable_hosts", return_value={"192.0.2.1": True}
    ):
        runner.run_scan(["192.0.2.1"], MagicMock(spec=BaseTrigger), scope, config)

    assert runner.scheduler.add_job.call_args[1]["name"] == "Policy policy1, Hostname 192.0.2.1"


def test_setup_matches_a_listed_device_after_removing_line_breaks(policy_runner, run_store):
    """A line break in a listed device's hostname must not let the range reach it as well."""
    ranges, _ = _scheduled(
        policy_runner, run_store, [_entry("192.0.2.0/29"), _entry("192.0.2.\r\n2/32")]
    )

    assert "192.0.2.2" not in ranges["192.0.2.0/29"]


def test_setup_names_at_most_ten_left_out_addresses(policy_runner, run_store, caplog):
    """A range that leaves out many listed devices logs a bounded line."""
    singles = [_entry(f"192.0.2.{n}") for n in range(1, 16)]

    with caplog.at_level(logging.INFO, logger="device_discovery.policy.runner"):
        _scheduled(policy_runner, run_store, [_entry("192.0.2.0/24"), *singles])

    (line,) = [r.getMessage() for r in caplog.records if "Leaving out" in r.getMessage()]
    assert "Leaving out 192.0.2.1, 192.0.2.2," in line
    assert "192.0.2.10 and 5 more," in line
    assert "192.0.2.11" not in line


class _FakeNapalmDriver(NetworkDriver):
    """A real NAPALM driver class, so its own context manager would apply if the runner used it."""

    facts = {"hostname": "sw1", "serial_number": "ABC123", "fqdn": "sw1"}
    close_error = None

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        pass

    def open(self):
        pass

    def close(self):
        if self.close_error is not None:
            raise self.close_error

    def get_facts(self):
        return self.facts

    def get_interfaces(self):
        return {}

    def get_interfaces_ip(self):
        return {}

    def get_vlans(self):
        return {}


def _run_napalm_driver(policy_runner, run_store, driver_class):
    scope = Napalm(driver="ios", hostname="192.0.2.10", username="admin", password="invalid")
    policy_runner.name = "policy1"
    policy_runner.run_store = run_store
    with (
        patch("device_discovery.policy.runner.get_network_driver", return_value=driver_class),
        patch("device_discovery.policy.runner.Client") as mock_client_cls,
    ):
        mock_client_cls.return_value.ingest.return_value = 3
        policy_runner.run("job-1", scope, Config(defaults=Defaults(site="NY"), options=Options()))
    (run,) = run_store.get_runs_for_target("policy1", "192.0.2.10")
    return run, mock_client_cls.return_value.ingest


def test_a_mismatched_set_driver_prints_nothing_to_stdout(policy_runner, run_store, capsys):
    """NAPALM's context manager prints a bug-report request for unknown exceptions; the runner must not use it."""

    class JunkFacts(_FakeNapalmDriver):
        facts = {"hostname": "Unknown", "serial_number": "Unknown", "fqdn": "Unknown"}

    run, ingest = _run_napalm_driver(policy_runner, run_store, JunkFacts)

    assert run.status.value == "failed"
    ingest.assert_not_called()
    assert capsys.readouterr().out == ""


def test_a_failing_close_keeps_what_was_read(policy_runner, run_store, caplog):
    """A session that fails to close still ingests what it read, and logs the close error on one line."""

    class CloseFails(_FakeNapalmDriver):
        close_error = RuntimeError("close-session timed out\nafter 30 seconds")

    with caplog.at_level(logging.WARNING, logger="device_discovery.policy.runner"):
        run, ingest = _run_napalm_driver(policy_runner, run_store, CloseFails)

    assert run.status.value == "completed"
    ingest.assert_called_once()
    (line,) = [r.getMessage() for r in caplog.records if "Error closing the session" in r.getMessage()]
    assert line == (
        "Policy policy1, Hostname 192.0.2.10: Error closing the session: "
        "close-session timed out after 30 seconds"
    )


def test_a_failed_open_is_closed_and_reported_as_the_open_error(policy_runner, run_store, caplog):
    """A session whose open fails is still closed, and its close error never hides the open error."""
    closed = []

    class OpenFails(_FakeNapalmDriver):
        def open(self):
            raise ConnectionException("Cannot connect to 192.0.2.10")

        def close(self):
            closed.append(True)
            raise AttributeError("'NoneType' object has no attribute 'close_session'")

    with caplog.at_level(logging.WARNING, logger="device_discovery.policy.runner"):
        run, ingest = _run_napalm_driver(policy_runner, run_store, OpenFails)

    assert closed == [True]
    assert run.status.value == "failed"
    assert "Cannot connect to 192.0.2.10" in run.reason
    ingest.assert_not_called()
    (record,) = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert record.levelno == logging.WARNING
    assert record.exc_info is None


@pytest.mark.parametrize("getter", ["get_vlans", "get_config"])
def test_a_getter_error_is_logged_on_one_line(policy_runner, run_store, caplog, getter):
    """A driver error with line breaks stays one log line: the agent splits backend output per line."""

    class GetterFails(_FakeNapalmDriver):
        pass

    def fail(self, *args, **kwargs):
        raise RuntimeError("Pattern not detected\nin output\nafter 90 seconds")

    setattr(GetterFails, getter, fail)
    policy_runner.config = None
    scope = Napalm(driver="ios", hostname="192.0.2.10", username="admin", password="invalid")
    config = Config(
        defaults=Defaults(site="NY"), options=Options(capture_running_config=True)
    )
    policy_runner.name = "policy1"
    policy_runner.run_store = run_store
    with (
        patch("device_discovery.policy.runner.get_network_driver", return_value=GetterFails),
        patch("device_discovery.policy.runner.Client"),
        caplog.at_level(logging.WARNING, logger="device_discovery.policy.runner"),
    ):
        policy_runner.run("job-1", scope, config)

    (line,) = [r.getMessage() for r in caplog.records if "Pattern not detected" in r.getMessage()]
    assert "Pattern not detected in output after 90 seconds" in line
    assert "\n" not in line


@pytest.mark.parametrize("set_in_policy", [False, True])
def test_a_discovered_driver_is_forgotten_when_collection_refuses_its_facts(
    policy_runner, run_store, set_in_policy
):
    """Facts collection refuses send a discovered driver back to discovery; a policy's driver stays."""

    class JunkFacts(_FakeNapalmDriver):
        facts = {"hostname": "", "serial_number": "", "fqdn": ""}

    scope = Napalm(
        driver="ios" if set_in_policy else None,
        hostname="192.0.2.10",
        username="admin",
        password="invalid",
    )
    policy_runner.name = "policy1"
    policy_runner.run_store = run_store
    with (
        patch("device_discovery.policy.runner.discover_device_driver", return_value="ios"),
        patch("device_discovery.policy.runner.get_network_driver", return_value=JunkFacts),
        patch("device_discovery.policy.runner.Client"),
    ):
        policy_runner.run("job-1", scope, Config(defaults=Defaults(site="NY"), options=Options()))

    assert scope.driver == ("ios" if set_in_policy else None)


def test_a_range_with_nothing_left_logs_no_schedule(policy_runner, run_store, caplog):
    """A range every address of which has its own entry says why it is skipped, not that it was scheduled."""
    with caplog.at_level(logging.INFO, logger="device_discovery.policy.runner"):
        _scheduled(policy_runner, run_store, [_entry("192.0.2.0/30"), _entry("192.0.2.1"), _entry("192.0.2.2")])

    range_lines = [r.getMessage() for r in caplog.records if "Hostname 192.0.2.0/30:" in r.getMessage()]
    assert range_lines == [
        "Policy policy1, Hostname 192.0.2.0/30: Leaving out 192.0.2.1, 192.0.2.2, "
        "discovered from their own scope entries"
    ]


def test_discovery_moves_past_a_driver_whose_facts_collection_would_refuse(policy_runner, run_store):
    """With real discovery, a driver reporting no name and no serial is passed over for the next one."""

    class EmptyFacts(_FakeNapalmDriver):
        facts = {"hostname": "", "serial_number": "", "fqdn": ""}

    drivers = {"first": EmptyFacts, "good": _FakeNapalmDriver}
    scope = Napalm(hostname="192.0.2.10", username="admin", password="invalid")
    config = Config(defaults=Defaults(site="NY"), options=Options(discovery_drivers=["first", "good"]))
    policy_runner.name = "policy1"
    policy_runner.run_store = run_store
    with (
        patch("device_discovery.discovery.get_network_driver", side_effect=drivers.__getitem__),
        patch("device_discovery.policy.runner.get_network_driver", side_effect=drivers.__getitem__),
        patch("device_discovery.policy.runner.Client") as mock_client_cls,
    ):
        mock_client_cls.return_value.ingest.return_value = 2
        policy_runner.run("job-1", scope, config)

    (run,) = run_store.get_runs_for_target("policy1", "192.0.2.10")
    assert run.status.value == "completed"
    assert scope.driver == "good"


@pytest.mark.parametrize("entry_point", ["run", "run_with_parent"])
def test_a_forgotten_discovered_driver_still_labels_the_failure_metric(policy_runner, run_store, entry_point):
    """The failure metric names the driver that was refused, not the None left after forgetting it."""

    class JunkFacts(_FakeNapalmDriver):
        facts = {"hostname": "", "serial_number": "", "fqdn": ""}

    metric = MagicMock()
    scope = Napalm(hostname="192.0.2.10", username="admin", password="invalid")
    policy_runner.name = "policy1"
    policy_runner.run_store = run_store
    with (
        patch("device_discovery.policy.runner.discover_device_driver", return_value="ios"),
        patch("device_discovery.policy.runner.get_network_driver", return_value=JunkFacts),
        patch("device_discovery.policy.runner.Client"),
        patch("device_discovery.policy.runner.get_metric", return_value=metric),
    ):
        config = Config(defaults=Defaults(site="NY"), options=Options())
        if entry_point == "run":
            policy_runner.run("job-1", scope, config)
        else:
            policy_runner.run_with_parent("job-1", scope, config, "192.0.2.0/24")

    failed = [c.args[1] for c in metric.record.call_args_list if c.args[1].get("status") == "failed"]
    assert [labels["driver"] for labels in failed] == ["ios"]


def test_a_port_scan_failure_is_logged_on_one_line(caplog):
    """A scan error with line breaks stays one log line, with the same text as the run reason."""
    runner = PolicyRunner()
    runner.name = "policy1"
    runner.run_store = RunStore()
    runner.scheduler = MagicMock()
    scope = Napalm(hostname="192.0.2.0/30", username="admin", password="invalid")
    config = Config(options=Options(port_scan_ports=[22], port_scan_timeout=0.1))

    with (
        patch(
            "device_discovery.policy.runner.find_reachable_hosts",
            side_effect=OSError("Too many open files\nwhile probing"),
        ),
        caplog.at_level(logging.ERROR, logger="device_discovery.policy.runner"),
    ):
        runner.run_scan(["192.0.2.1"], MagicMock(spec=BaseTrigger), scope, config)

    (line,) = [r.getMessage() for r in caplog.records]
    (run,) = runner.run_store.get_runs_for_target("policy1", "192.0.2.0/30")
    assert line.endswith(": Too many open files while probing")
    assert run.reason == "Too many open files while probing"


def _run_set_driver(policy_runner, run_store, facts, *, netbox_id=None, asset_tag=None, emit_device_name=True):
    """Run one target whose driver is set in the policy and whose device reports these facts."""

    class Facts(_FakeNapalmDriver):
        pass

    Facts.facts = facts
    scope = Napalm(
        driver="ios", hostname="192.0.2.10", username="admin", password="invalid", netbox_id=netbox_id
    )
    defaults = Defaults(site="NY", device=DeviceParameters(asset_tag=asset_tag) if asset_tag else None)
    config = Config(defaults=defaults, options=Options(emit_device_name=emit_device_name))
    policy_runner.name = "policy1"
    policy_runner.run_store = run_store
    with (
        patch("device_discovery.policy.runner.get_network_driver", return_value=Facts),
        patch("device_discovery.policy.runner.Client") as mock_client_cls,
    ):
        mock_client_cls.return_value.ingest.return_value = 2
        policy_runner.run("job-1", scope, config)
    (run,) = run_store.get_runs_for_target("policy1", "192.0.2.10")
    return run, mock_client_cls.return_value.ingest


_NO_NAME_NO_SERIAL = {"hostname": "Unknown", "serial_number": "Unknown", "fqdn": "Unknown"}


@pytest.mark.parametrize("matcher", [{"netbox_id": 1003}, {"asset_tag": "AT-0003"}])
def test_facts_without_a_name_still_update_a_device_matched_without_one(policy_runner, run_store, matcher):
    """With emit_device_name off and a netbox_id or asset tag, no name is sent, so the facts are not junk."""
    run, ingest = _run_set_driver(
        policy_runner, run_store, _NO_NAME_NO_SERIAL, emit_device_name=False, **matcher
    )

    assert run.status.value == "completed"
    ingest.assert_called_once()


def test_facts_without_a_name_are_refused_when_the_name_would_be_sent(policy_runner, run_store):
    """A netbox_id alone does not help: the device would be renamed "Unknown"."""
    run, ingest = _run_set_driver(policy_runner, run_store, _NO_NAME_NO_SERIAL, netbox_id=1003)

    assert run.status.value == "failed"
    ingest.assert_not_called()


def test_cli_error_text_in_the_fqdn_alone_does_not_refuse_a_set_driver(policy_runner, run_store):
    """The FQDN is never sent as the name when it holds error text, so it does not decide the fit."""
    run, ingest = _run_set_driver(
        policy_runner,
        run_store,
        {"hostname": "asa5", "serial_number": "ABC123", "fqdn": "ERROR: % Invalid input detected at '^' marker."},
    )

    assert run.status.value == "completed"
    ingest.assert_called_once()
