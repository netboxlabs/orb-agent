"""Pytest config for ProCurve driver tests."""

from pathlib import Path

from tests.custom_drivers.base_test import parametrize_scenarios

MOCK_DATA_ROOT = Path(__file__).parent / "mock_data"


def pytest_generate_tests(metafunc):
    """Parametrize the ``scenario`` fixture from mock_data sub-folders."""
    parametrize_scenarios(metafunc, MOCK_DATA_ROOT)
