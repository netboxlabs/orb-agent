"""Unit tests for custom_napalm.checkpoint_gaia.GaiaDriver."""

from pathlib import Path

from custom_napalm.checkpoint_gaia import GaiaDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestGaiaDriver(BaseDriverTest):
    """Unit tests for GaiaDriver using file-based CLI mocks."""

    driver_cls = GaiaDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
