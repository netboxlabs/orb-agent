"""Unit tests for custom_napalm.alcatel_aos.AlcatelAOSDriver."""

from pathlib import Path

from custom_napalm.alcatel_aos import AlcatelAOSDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestAlcatelAOSDriver(BaseDriverTest):
    """Unit tests for AlcatelAOSDriver using file-based CLI mocks."""

    driver_cls = AlcatelAOSDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
