"""Unit tests for custom_napalm.fortios_ssh.FortiOSSSHDriver."""

from pathlib import Path

from custom_napalm.fortios_ssh import FortiOSSSHDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestFortiOSSSHDriver(BaseDriverTest):
    """Unit tests for FortiOSSSHDriver using file-based CLI mocks."""

    driver_cls = FortiOSSSHDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
