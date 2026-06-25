"""Unit tests for custom_napalm.cisco_wlc.WLCDriver."""

from pathlib import Path

from custom_napalm.cisco_wlc import WLCDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestWLCDriver(BaseDriverTest):
    """Unit tests for WLCDriver using file-based CLI mocks."""

    driver_cls = WLCDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
