"""Unit tests for custom_napalm.edgerouter.EdgeRouterDriver."""

from pathlib import Path

from custom_napalm.edgerouter import EdgeRouterDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestEdgeRouterDriver(BaseDriverTest):
    """Unit tests for EdgeRouterDriver using file-based CLI mocks."""

    driver_cls = EdgeRouterDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
