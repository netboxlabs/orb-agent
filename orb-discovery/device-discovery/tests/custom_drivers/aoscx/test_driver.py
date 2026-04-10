"""Unit tests for custom_napalm.aoscx.AOSCXDriver."""

from pathlib import Path

from custom_napalm.aoscx import AOSCXDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakePyaoscxSession


class TestAOSCXDriver(BaseDriverTest):
    """Unit tests for AOSCXDriver using file-based REST mock."""

    driver_cls = AOSCXDriver
    fake_device_cls = FakePyaoscxSession
    mock_data_root = Path(__file__).parent / "mock_data"

    def _build_driver(self, mock_dir: Path):
        """Instantiate AOSCXDriver with a fake pyaoscx session instead of a real one."""
        driver = object.__new__(AOSCXDriver)
        driver.hostname = "test-host"
        driver.username = "test-user"
        driver.password = "test-pass"
        driver.timeout = 60
        driver._verify_ssl = False
        driver.session = FakePyaoscxSession(mock_dir)
        return driver
