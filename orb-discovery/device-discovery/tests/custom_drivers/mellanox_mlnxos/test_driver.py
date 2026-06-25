"""Unit tests for custom_napalm.mellanox_mlnxos.MLNXOSDriver."""

from pathlib import Path

from custom_napalm.mellanox_mlnxos import MLNXOSDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestMLNXOSDriver(BaseDriverTest):
    """Unit tests for MLNXOSDriver using file-based CLI mocks."""

    driver_cls = MLNXOSDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
