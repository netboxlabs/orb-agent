"""Unit tests for custom_napalm.dell_powerconnect.PowerConnectDriver."""

from pathlib import Path

from custom_napalm.dell_powerconnect import PowerConnectDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestPowerConnectDriver(BaseDriverTest):
    """Unit tests for PowerConnectDriver using file-based CLI mocks."""

    driver_cls = PowerConnectDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
