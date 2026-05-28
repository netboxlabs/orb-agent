"""Tests for the custom IOS-XR NETCONF driver shim."""

from pathlib import Path

import pytest

from custom_napalm.iosxr_netconf import IOSXRNETCONFDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeNetconfConn


class TestIOSXRNetconfDriver(BaseDriverTest):
    """Tests for the custom IOS-XR NETCONF driver shim."""

    driver_cls = IOSXRNETCONFDriver
    fake_device_cls = FakeNetconfConn
    mock_data_root = Path(__file__).parent / "mock_data"

    # All non-modules getters are inherited from the upstream class unchanged.
    def test_get_facts(self, scenario):
        """Skip inherited facts test — driver inherits unchanged from upstream."""
        pytest.skip("inherited from napalm.iosxr_netconf.iosxr_netconf.IOSXRNETCONFDriver")

    def test_get_interfaces(self, scenario):
        """Skip inherited interfaces test — inherited unchanged."""
        pytest.skip("inherited from napalm.iosxr_netconf.iosxr_netconf.IOSXRNETCONFDriver")

    def test_get_interfaces_ip(self, scenario):
        """Skip inherited IP test — inherited unchanged."""
        pytest.skip("inherited from napalm.iosxr_netconf.iosxr_netconf.IOSXRNETCONFDriver")

    def test_get_config(self, scenario):
        """Skip inherited config test — inherited unchanged."""
        pytest.skip("inherited from napalm.iosxr_netconf.iosxr_netconf.IOSXRNETCONFDriver")

    def test_get_config_sanitized(self, scenario):
        """Skip inherited sanitized-config test — inherited unchanged."""
        pytest.skip("inherited from napalm.iosxr_netconf.iosxr_netconf.IOSXRNETCONFDriver")

    def test_get_vlans(self, scenario):
        """Skip inherited VLANs test — inherited unchanged."""
        pytest.skip("inherited from napalm.iosxr_netconf.iosxr_netconf.IOSXRNETCONFDriver")

    def test_iosxr_netconf_driver_exposes_get_modules(self) -> None:
        """Fail-hard guard: the driver must expose a callable get_modules."""
        assert hasattr(self.driver_cls, "get_modules"), (
            f"{self.driver_cls.__name__} is missing get_modules"
        )
        assert callable(getattr(self.driver_cls, "get_modules"))
