"""Unit tests for custom_napalm.aruba_aoscx_ssh.AOSCXSSHDriver."""

from pathlib import Path

from custom_napalm.aruba_aoscx_ssh import AOSCXSSHDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestAOSCXSSHDriver(BaseDriverTest):
    """Unit tests for AOSCXSSHDriver using file-based CLI mock."""

    driver_cls = AOSCXSSHDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"

    def test_aruba_ssh_driver_exposes_get_modules(self):
        """AOSCXSSHDriver must expose a callable get_modules (fails hard, no skip)."""
        assert hasattr(self.driver_cls, "get_modules")
        assert callable(self.driver_cls.get_modules)
