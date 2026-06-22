"""Unit tests for custom_napalm.cisco_asa.ASADriver."""

from pathlib import Path

from custom_napalm.cisco_asa import ASADriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeRestDevice


class TestASADriver(BaseDriverTest):
    """Unit tests for ASADriver using file-based REST mock."""

    driver_cls = ASADriver
    fake_device_cls = FakeRestDevice
    mock_data_root = Path(__file__).parent / "mock_data"
