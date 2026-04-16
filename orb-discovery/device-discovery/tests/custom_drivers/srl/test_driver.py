"""Unit tests for custom_napalm.srl.SRLDriver."""

from pathlib import Path

from custom_napalm.srl import SRLDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestSRLDriver(BaseDriverTest):
    """Unit tests for SRLDriver using file-based CLI mocks."""

    driver_cls = SRLDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
