"""Unit tests for custom_napalm.paloalto_panos.PANOSDriver."""

from pathlib import Path

from custom_napalm.paloalto_panos import PANOSDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeXmlDevice


class TestPANOSDriver(BaseDriverTest):
    """Unit tests for PANOSDriver using file-based XML mocks."""

    driver_cls = PANOSDriver
    fake_device_cls = FakeXmlDevice
    mock_data_root = Path(__file__).parent / "mock_data"
