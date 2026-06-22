"""Unit tests for custom_napalm.ericsson_ipos.IPOSDriver."""

from pathlib import Path

from custom_napalm.ericsson_ipos import IPOSDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestIPOSDriver(BaseDriverTest):
    """Unit tests for IPOSDriver using file-based CLI mocks."""

    driver_cls = IPOSDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
