"""Unit tests for custom_napalm.viptela_ssh.ViptelaSSHDriver."""

from pathlib import Path

from custom_napalm.viptela_ssh import ViptelaSSHDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestViptelaSSHDriver(BaseDriverTest):
    """Unit tests for ViptelaSSHDriver using file-based CLI mocks."""

    driver_cls = ViptelaSSHDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
