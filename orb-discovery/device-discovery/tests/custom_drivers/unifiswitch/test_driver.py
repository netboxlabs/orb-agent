"""Unit tests for custom_napalm.unifiswitch.UniFiSwitchDriver."""

from pathlib import Path

from custom_napalm.unifiswitch import UniFiSwitchDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestUniFiSwitchDriver(BaseDriverTest):
    """Unit tests for UniFiSwitchDriver using file-based CLI mocks."""

    driver_cls = UniFiSwitchDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
