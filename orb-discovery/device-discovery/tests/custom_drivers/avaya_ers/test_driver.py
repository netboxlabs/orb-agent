"""Unit tests for custom_napalm.avaya_ers.AvayaERSDriver."""

from pathlib import Path

from custom_napalm.avaya_ers import AvayaERSDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestAvayaERSDriver(BaseDriverTest):
    """Unit tests for AvayaERSDriver using file-based CLI mocks."""

    driver_cls = AvayaERSDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
