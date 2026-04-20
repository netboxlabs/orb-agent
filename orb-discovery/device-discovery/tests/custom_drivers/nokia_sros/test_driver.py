"""Unit tests for custom_napalm.nokia_sros.SROSDriver."""

from pathlib import Path

from custom_napalm.nokia_sros import SROSDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeNetconfConn


class TestSROSDriver(BaseDriverTest):
    """Unit tests for SROSDriver using file-based NETCONF XML mocks."""

    driver_cls = SROSDriver
    fake_device_cls = FakeNetconfConn
    mock_data_root = Path(__file__).parent / "mock_data"

    def _build_driver(self, mock_dir: Path) -> SROSDriver:
        """Instantiate SROSDriver with a fake NETCONF connection (no real device needed)."""
        driver = object.__new__(SROSDriver)
        driver.hostname = "test-host"
        driver.username = "test-user"
        driver.password = "test-pass"
        driver.timeout = 60
        driver.R19 = False
        driver.conn = FakeNetconfConn(mock_dir)
        return driver
