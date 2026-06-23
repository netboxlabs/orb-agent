"""Unit tests for custom_napalm.dell_ftos.FTOSDriver."""

from pathlib import Path

from custom_napalm.dell_ftos import FTOSDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestFTOSDriver(BaseDriverTest):
    """Unit tests for FTOSDriver using file-based CLI mocks."""

    driver_cls = FTOSDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
