"""Unit tests for custom_napalm.extreme_vsp.VSPDriver."""

from pathlib import Path

from custom_napalm.extreme_vsp import VSPDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestVSPDriver(BaseDriverTest):
    """Unit tests for VSPDriver using file-based CLI mocks."""

    driver_cls = VSPDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
