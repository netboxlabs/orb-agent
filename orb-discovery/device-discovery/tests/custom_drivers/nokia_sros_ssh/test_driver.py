"""Unit tests for custom_napalm.nokia_sros_ssh.SROSSSHDriver."""

from pathlib import Path

from custom_napalm.nokia_sros_ssh import SROSSSHDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestSROSSSHDriver(BaseDriverTest):
    """Unit tests for SROSSSHDriver using file-based CLI mocks."""

    driver_cls = SROSSSHDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
