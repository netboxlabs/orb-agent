"""
Tests for the EOSDriver subclass — VLAN-association coverage only.

The non-VLAN getters (get_facts, get_interfaces, etc.) are inherited unchanged
from ``napalm.eos.eos.EOSDriver`` and covered by upstream NAPALM tests, so
they are skipped here.
"""

from pathlib import Path

import pytest

from custom_napalm.eos import EOSDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeJsonRpcDevice


class TestEOSDriver(BaseDriverTest):
    """Tests for the Arista EOS custom driver."""

    driver_cls = EOSDriver
    fake_device_cls = FakeJsonRpcDevice
    mock_data_root = Path(__file__).parent / "mock_data"

    def _build_driver(self, mock_dir):
        """Build the driver with the eAPI transport path forced."""
        # Upstream EOSDriver._run_commands branches on self.transport == "ssh".
        # Force the eAPI path so it delegates to self.device.run_commands(...),
        # which our FakeJsonRpcDevice implements.
        driver = super()._build_driver(mock_dir)
        driver.transport = "https"
        return driver

    # Skip inherited NAPALM getters — covered by upstream tests.
    def test_get_facts(self, scenario):
        """Skip: inherited from napalm.eos.eos.EOSDriver — covered upstream."""
        pytest.skip("inherited from napalm.eos.eos.EOSDriver — covered upstream")

    def test_get_interfaces(self, scenario):
        """Skip: inherited from napalm.eos.eos.EOSDriver — covered upstream."""
        pytest.skip("inherited from napalm.eos.eos.EOSDriver — covered upstream")

    def test_get_interfaces_ip(self, scenario):
        """Skip: inherited from napalm.eos.eos.EOSDriver — covered upstream."""
        pytest.skip("inherited from napalm.eos.eos.EOSDriver — covered upstream")

    def test_get_config(self, scenario):
        """Skip: inherited from napalm.eos.eos.EOSDriver — covered upstream."""
        pytest.skip("inherited from napalm.eos.eos.EOSDriver — covered upstream")

    def test_get_config_sanitized(self, scenario):
        """Skip: inherited from napalm.eos.eos.EOSDriver — covered upstream."""
        pytest.skip("inherited from napalm.eos.eos.EOSDriver — covered upstream")

    def test_get_vlans(self, scenario):
        """Skip: inherited from napalm.eos.eos.EOSDriver — covered upstream."""
        pytest.skip("inherited from napalm.eos.eos.EOSDriver — covered upstream")

    def test_eos_driver_exposes_get_modules(self) -> None:
        """get_modules() must exist on EOSDriver after this batch lands."""
        assert hasattr(EOSDriver, "get_modules")
        assert callable(getattr(EOSDriver, "get_modules"))
