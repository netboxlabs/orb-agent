"""Unit tests for custom_napalm.extreme_slx.SLXOSDriver."""

from pathlib import Path

from custom_napalm.extreme_slx import SLXOSDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestSLXOSDriver(BaseDriverTest):
    """Unit tests for SLXOSDriver using file-based CLI mocks."""

    driver_cls = SLXOSDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
