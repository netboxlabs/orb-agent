"""Unit tests for custom_napalm.aoscx_ssh.AOSCXSSHDriver."""

from pathlib import Path

from custom_napalm.aoscx_ssh import AOSCXSSHDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestAOSCXSSHDriver(BaseDriverTest):
    """Unit tests for AOSCXSSHDriver using file-based CLI mock."""

    driver_cls = AOSCXSSHDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
