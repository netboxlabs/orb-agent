"""Unit tests for custom_napalm.fastiron.FastIronDriver."""

from pathlib import Path

from custom_napalm.fastiron import FastIronDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestFastIronDriver(BaseDriverTest):
    """Unit tests for FastIronDriver using file-based CLI mocks."""

    driver_cls = FastIronDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
