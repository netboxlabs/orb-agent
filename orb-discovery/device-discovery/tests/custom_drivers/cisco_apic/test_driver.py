"""Unit tests for custom_napalm.cisco_apic.APICDriver."""

from pathlib import Path

from custom_napalm.cisco_apic import APICDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestAPICDriver(BaseDriverTest):
    """Unit tests for APICDriver using file-based CLI mock."""

    driver_cls = APICDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
