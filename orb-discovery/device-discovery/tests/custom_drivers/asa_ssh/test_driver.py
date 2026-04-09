"""Unit tests for custom_napalm.asa_ssh.ASASSHDriver."""

from pathlib import Path

from custom_napalm.asa_ssh import ASASSHDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestASASSHDriver(BaseDriverTest):
    """Unit tests for ASASSHDriver using file-based CLI mocks."""

    driver_cls = ASASSHDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
