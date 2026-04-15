"""Unit tests for custom_napalm.arubaos.ArubaOSDriver."""

from pathlib import Path

from custom_napalm.arubaos import ArubaOSDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestArubaOSDriver(BaseDriverTest):
    """Unit tests for ArubaOSDriver using file-based CLI mocks."""

    driver_cls = ArubaOSDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
