"""pytest conftest for the iosxr driver tests; auto-discovers mock-data scenarios."""

from pathlib import Path

from tests.custom_drivers.base_test import parametrize_scenarios

MOCK_DATA_ROOT = Path(__file__).parent / "mock_data"


def pytest_generate_tests(metafunc):
    """Parametrize test_<method> with every scenario directory under mock_data/<method>/."""
    parametrize_scenarios(metafunc, MOCK_DATA_ROOT)
