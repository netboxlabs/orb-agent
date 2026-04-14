"""Unit tests for custom_napalm.ers.ERSDriver."""

from pathlib import Path

from custom_napalm.ers import ERSDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestERSDriver(BaseDriverTest):
    """Unit tests for ERSDriver using file-based CLI mocks."""

    driver_cls = ERSDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
