"""Unit tests for custom_napalm.netiron.NetIronDriver."""

from pathlib import Path

from custom_napalm.netiron import NetIronDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestNetIronDriver(BaseDriverTest):
    """Unit tests for NetIronDriver using file-based CLI mocks."""

    driver_cls = NetIronDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
