"""Unit tests for custom_napalm.procurve.ProcurveDriver."""

from pathlib import Path

from custom_napalm.procurve import ProcurveDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestProcurveDriver(BaseDriverTest):
    """Unit tests for ProcurveDriver using file-based CLI mocks."""

    driver_cls = ProcurveDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
