"""Unit tests for custom_napalm.fxos.FXOSDriver."""

from pathlib import Path

from custom_napalm.fxos import FXOSDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestFXOSDriver(BaseDriverTest):
    """Unit tests for FXOSDriver using file-based CLI mocks."""

    driver_cls = FXOSDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
