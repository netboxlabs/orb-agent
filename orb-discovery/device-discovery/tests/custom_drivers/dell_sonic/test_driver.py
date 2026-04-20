"""Unit tests for custom_napalm.dell_sonic.SONiCDriver."""

from pathlib import Path

from custom_napalm.dell_sonic import SONiCDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestSONiCDriver(BaseDriverTest):
    """Test suite for the Dell SONiC NAPALM driver."""

    driver_cls = SONiCDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
