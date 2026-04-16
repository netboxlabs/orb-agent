"""Unit tests for custom_napalm.vrp.VRPDriver."""

from pathlib import Path

from custom_napalm.vrp import VRPDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestVRPDriver(BaseDriverTest):
    """Unit tests for VRPDriver using file-based CLI mocks."""

    driver_cls = VRPDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
