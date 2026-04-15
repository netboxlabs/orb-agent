"""Unit tests for custom_napalm.aos.AOSDriver."""

from pathlib import Path

from custom_napalm.aos import AOSDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestAOSDriver(BaseDriverTest):
    """Unit tests for AOSDriver using file-based CLI mocks."""

    driver_cls = AOSDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
