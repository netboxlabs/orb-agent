#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""NetBox Labs - Backend Unit Tests."""

from unittest.mock import MagicMock, patch

import pytest

from worker.backend import Backend, load_class
from worker.models import Policy


@pytest.fixture
def mock_import_module():
    """Fixture to mock importlib.import_module."""
    with patch("worker.backend.importlib.import_module") as mock_import:
        yield mock_import


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
