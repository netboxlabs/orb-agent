"""Unit tests for custom_napalm.hp_comware.ComwareDriver."""

from pathlib import Path

from custom_napalm.hp_comware import ComwareDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestComwareDriver(BaseDriverTest):
    """Unit tests for ComwareDriver using file-based CLI mocks."""

    driver_cls = ComwareDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
