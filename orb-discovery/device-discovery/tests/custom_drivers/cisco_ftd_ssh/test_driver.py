"""Unit tests for custom_napalm.cisco_ftd_ssh.FTDSSHDriver."""

from pathlib import Path

from custom_napalm.cisco_ftd_ssh import FTDSSHDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestFTDSSHDriver(BaseDriverTest):
    """Unit tests for FTDSSHDriver using file-based CLI mocks."""

    driver_cls = FTDSSHDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
