"""Unit tests for custom_napalm.exos.ExosDriver."""

from pathlib import Path

from custom_napalm.exos import ExosDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestExosDriver(BaseDriverTest):
    """Unit tests for ExosDriver using file-based CLI mocks."""

    driver_cls = ExosDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
