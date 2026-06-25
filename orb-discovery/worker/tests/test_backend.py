#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""NetBox Labs - Backend Unit Tests."""

import warnings
from unittest.mock import MagicMock, patch

import pytest

from worker.backend import Backend, load_class
from worker.models import Metadata, Policy


@pytest.fixture
def mock_import_module():
    """Fixture to mock importlib.import_module."""
    with patch("worker.backend.importlib.import_module") as mock_import:
        yield mock_import


def test_backend_describe_not_implemented():
    """Test that Backend.describe raises NotImplementedError."""
    with pytest.raises(
        NotImplementedError, match="The 'describe' classmethod must be implemented."
    ):
        Backend.describe()


def test_backend_setup_not_implemented():
    """Test that Backend.setup raises NotImplementedError."""
    backend = Backend()
    with pytest.raises(
        NotImplementedError, match="The 'setup' method must be implemented."
    ):
        backend.setup()


def test_backend_run_not_implemented():
    """Test that Backend.run raises NotImplementedError."""
    backend = Backend()
    mock_policy = MagicMock(spec=Policy)
    with pytest.raises(
        NotImplementedError, match="The 'run' method must be implemented."
    ):
        list(backend.run("mock", mock_policy))


def test_load_class_valid_backend_class(mock_import_module):
    """Test that load_class successfully loads a valid Backend class."""
    mock_module_name = "worker.test_module"

    class MockBackend(Backend):
        pass

    mock_module = MagicMock()
    setattr(mock_module, "MockBackend", MockBackend)
    mock_import_module.return_value = mock_module

    result = load_class(mock_module_name)
    assert result == MockBackend
    mock_import_module.assert_called_once_with(mock_module_name)


def test_load_class_no_backend_class(mock_import_module):
    """Test that load_class raises RuntimeError if no Backend class is found."""
    mock_module_name = "worker.test_module"
    mock_import_module.return_value = MagicMock()

    with patch("worker.backend.inspect.getmembers", return_value=[]):
        with pytest.raises(
            RuntimeError,
            match=f"Failed to load a class inheriting from 'Backend' in module "
            f"'{mock_module_name}': No class inheriting 'Backend'",
        ):
            load_class(mock_module_name)


def test_load_class_import_error(mock_import_module):
    """Test that load_class raises RuntimeError for import errors."""
    mock_module_name = "worker.invalid_module"

    mock_import_module.side_effect = ImportError("Module not found")
    with pytest.raises(
        RuntimeError,
        match=f"Failed to load a class inheriting from 'Backend' in module '{mock_module_name}': Module not found",
    ):
        load_class(mock_module_name)


def test_load_class_attribute_error(mock_import_module):
    """Test that load_class raises RuntimeError for attribute errors."""
    mock_module_name = "worker.invalid_module"

    mock_import_module.side_effect = AttributeError("Attribute error")
    with pytest.raises(
        RuntimeError,
        match=f"Failed to load a class inheriting from 'Backend' in module '{mock_module_name}': Attribute error",
    ):
        load_class(mock_module_name)


def test_backend_init_default_no_args():
    """Zero-arg construction still works (back-compat with older worker)."""
    b = Backend()
    assert b.ingest_sink is None


def test_backend_init_stores_ingest_sink():
    """ingest_sink is stored on the instance."""

    class _Sink:
        def ingest(self, entities, **kwargs):
            return None

        def record_failure(self, error, **kwargs):
            return None

    sink = _Sink()
    b = Backend(ingest_sink=sink)
    assert b.ingest_sink is sink


def test_backend_init_absorbs_unknown_kwargs():
    """Forward-compat: unknown kwargs don't raise."""
    Backend(unknown_future_resource="x", another_one=42)  # must not raise


def test_backend_run_accepts_kwargs():
    """run() signature absorbs **kwargs (passive forward-compat door)."""
    b = Backend()
    # The base implementation raises NotImplementedError; the point is
    # that calling with kwargs reaches the body without a TypeError.
    try:
        b.run("policy", MagicMock(spec=Policy), future_kwarg="x")
    except NotImplementedError:
        pass


def test_subclass_overriding_setup_without_describe_warns_deprecated():
    """Defining a setup()-only subclass emits a DeprecationWarning at class creation."""
    with pytest.warns(DeprecationWarning, match="implement the describe"):

        class LegacySetupBackend(Backend):
            def setup(self) -> Metadata:
                return Metadata(name="legacy", app_name="legacy", app_version="0.0.0")


def test_subclass_with_describe_defines_without_warning():
    """A describe()-implementing subclass is clean, even if it also keeps setup()."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)

        class ModernBackend(Backend):
            @classmethod
            def describe(cls) -> Metadata:
                return Metadata(name="modern", app_name="modern", app_version="0.0.0")

            def setup(self) -> Metadata:
                return self.describe()


def test_base_setup_call_emits_runtime_deprecation():
    """Calling the base setup() directly warns (PEP 702 runtime) and still raises."""
    with pytest.warns(DeprecationWarning), pytest.raises(NotImplementedError):
        Backend().setup()


def test_subclass_with_describe_missing_classmethod_warns():
    """A describe() defined without @classmethod is flagged at class creation (does not crash)."""
    with pytest.warns(RuntimeWarning, match="not as a @classmethod"):

        class BadDescribeBackend(Backend):
            def describe(self) -> Metadata:  # forgot @classmethod
                return Metadata(name="bad", app_name="bad", app_version="0.0.0")
