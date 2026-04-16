"""Unit tests for custom_napalm.smart.SmartDriver."""

from pathlib import Path

from custom_napalm.smart import SmartDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestSmartDriver(BaseDriverTest):
    """Unit tests for SmartDriver using file-based CLI mocks."""

    driver_cls = SmartDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
