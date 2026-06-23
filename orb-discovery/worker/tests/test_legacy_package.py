#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
End-to-end check that a real legacy (setup-only) package still works.

Unlike test_runner.py — which patches load_class with an in-test class — this
loads the nbl-custom-legacy sample package through the genuine
``worker.backend.load_class`` import machinery and drives it through
``PolicyRunner.setup()``, exercising the deprecated fallback path the way a real
legacy integration would hit it.
"""

import pathlib
import sys
from unittest.mock import MagicMock, patch

import pytest

from worker.backend import _implements_describe, load_class
from worker.models import Config, DiodeConfig, Policy
from worker.policy.run import RunStore
from worker.policy.runner import PolicyRunner

_LEGACY_PKG_DIR = pathlib.Path(__file__).resolve().parent / "nbl-custom-legacy"


@pytest.fixture
def legacy_package_on_path():
    """Make the nbl_custom_legacy sample package importable, then clean up."""
    sys.path.insert(0, str(_LEGACY_PKG_DIR))
    try:
        yield
    finally:
        if str(_LEGACY_PKG_DIR) in sys.path:
            sys.path.remove(str(_LEGACY_PKG_DIR))
        sys.modules.pop("nbl_custom_legacy", None)
        sys.modules.pop("nbl_custom_legacy.impl", None)


def test_legacy_package_loads_via_real_load_class(legacy_package_on_path):
    """load_class resolves the legacy backend, and it is detected as not implementing describe()."""
    with pytest.warns(DeprecationWarning, match="deprecated"):
        backend_class = load_class("nbl_custom_legacy")

    assert backend_class.__name__ == "LegacyMockBackend"
    assert _implements_describe(backend_class) is False


def test_policy_runner_sets_up_and_schedules_real_legacy_backend(
    legacy_package_on_path, caplog
):
    """
    PolicyRunner.setup() drives the legacy package through the fallback path.

    The instance whose setup() ran is the one scheduled (state is live), it was
    constructed bare despite its custom no-kwargs __init__, and the ingest sink
    is attached afterwards.
    """
    runner = PolicyRunner()
    dry_run_config = DiodeConfig(
        target="",
        prefix="test",
        dry_run=True,
        dry_run_output_dir="/tmp/dry_run_legacy",
    )
    policy = Policy(config=Config(package="nbl_custom_legacy"), scope={})
    run_store = MagicMock(spec=RunStore)

    with patch.object(runner.scheduler, "start"), patch.object(
        runner.scheduler, "add_job"
    ) as mock_add_job, caplog.at_level("WARNING"):
        runner.setup("legacy-policy", dry_run_config, policy, run_store)

    assert "deprecated setup() fallback" in caplog.text
    assert runner.metadata.name == "legacy_mock"

    scheduled_backend = mock_add_job.call_args.kwargs["args"][1]
    assert scheduled_backend.__class__.__name__ == "LegacyMockBackend"
    # setup() ran on the scheduled instance (its state is live).
    assert scheduled_backend.app_started is True
    # No sink: API-triggered sync requires the modern describe() contract, so a
    # legacy backend gets scheduled runs only.
    assert getattr(scheduled_backend, "ingest_sink", None) is None
