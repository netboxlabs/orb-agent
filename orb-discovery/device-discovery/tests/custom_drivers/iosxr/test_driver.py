"""Tests for the custom IOS-XR (pyIOSXR / XML-Agent) driver shim."""

from pathlib import Path

import pytest

from custom_napalm.iosxr import IOSXRDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeIOSXRDevice


class TestIOSXRDriver(BaseDriverTest):
    """Tests for the custom IOS-XR driver shim (pyIOSXR / XML-Agent over SSH)."""

    driver_cls = IOSXRDriver
    fake_device_cls = FakeIOSXRDevice
    mock_data_root = Path(__file__).parent / "mock_data"

    # All non-modules getters are inherited from the upstream class unchanged
    # (see cisco_nxos/test_driver.py for the established skip-pattern). The
    # custom shim only adds get_modules, so the other test methods skip.
    def test_get_facts(self, scenario):
        """Skip inherited facts test — driver inherits unchanged from upstream."""
        pytest.skip("inherited from napalm.iosxr.iosxr.IOSXRDriver")

    def test_get_interfaces(self, scenario):
        """Skip inherited interfaces test — inherited unchanged."""
        pytest.skip("inherited from napalm.iosxr.iosxr.IOSXRDriver")

    def test_get_interfaces_ip(self, scenario):
        """Skip inherited IP test — inherited unchanged."""
        pytest.skip("inherited from napalm.iosxr.iosxr.IOSXRDriver")

    def test_get_config(self, scenario):
        """Skip inherited config test — inherited unchanged."""
        pytest.skip("inherited from napalm.iosxr.iosxr.IOSXRDriver")

    def test_get_config_sanitized(self, scenario):
        """Skip inherited sanitized-config test — inherited unchanged."""
        pytest.skip("inherited from napalm.iosxr.iosxr.IOSXRDriver")

    def test_get_vlans(self, scenario):
        """Skip inherited VLANs test — inherited unchanged."""
        pytest.skip("inherited from napalm.iosxr.iosxr.IOSXRDriver")

    def test_iosxr_driver_exposes_get_modules(self) -> None:
        """Fail-hard guard: the driver must expose a callable get_modules."""
        assert hasattr(self.driver_cls, "get_modules"), (
            f"{self.driver_cls.__name__} is missing get_modules"
        )
        assert callable(getattr(self.driver_cls, "get_modules"))


def test_orphan_optic_on_unknown_rack_dropped_with_warning(caplog):
    """
    An orphan optic naming a rack no chassis reported must be dropped, with a warning.

    Minting a rack from an optic name is correct only when inventory listed
    no slot bays at all (the fixed-port case). Once a rack roster exists, a
    foreign rack would be lost anyway — silently by the standalone tail,
    which emits one rack, or two layers away by translate's generic
    orphan_member drop — so the promotion pass refuses it by name instead.
    """
    import logging
    from unittest.mock import MagicMock

    from custom_napalm.iosxr import _iosxr_get_modules_impl

    inventory = """NAME: "0/0/CPU0", DESCR: "24-Port 10GE Line Card"
PID: A9K-24X10GE-SE, VID: V01, SN: FOXROSTERLC

NAME: "0/0/0", DESCR: "Cisco SFP+ 10G LR Optics"
PID: SFP-10G-LR, VID: V01, SN: OPTICINROSTER

NAME: "7/0/0", DESCR: "Cisco SFP+ 10G LR Optics"
PID: SFP-10G-LR, VID: V01, SN: OPTICOFFROSTER
"""

    driver = MagicMock()
    driver.device._execute_show.return_value = inventory

    with caplog.at_level(logging.DEBUG, logger="custom_napalm.iosxr"):
        result = _iosxr_get_modules_impl(driver)

    assert result is not None
    members = result["members"]
    assert set(members.keys()) == {None}, "rack 7 must not become its own member bucket"

    def _serials(bays):
        for bay in bays:
            module = bay["module"]
            yield module["serial"]
            yield from _serials(module.get("sub_bays") or [])

    all_serials = {
        serial for member in members.values() for serial in _serials(member["bays"])
    }
    assert "OPTICINROSTER" in all_serials, "the in-roster optic must still be attached"
    assert "OPTICOFFROSTER" not in all_serials, (
        "an optic on a rack no chassis reported must not be promoted anywhere"
    )
    assert "7/0/0" not in members[None]["interfaces_by_bay"], (
        "a refused optic must not leave an interface route to a bay that is not emitted"
    )

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any(
        "7/0/0" in r.getMessage() and "not in chassis set" in r.getMessage()
        for r in warnings
    ), "expected a warning naming the dropped orphan optic and its unknown rack"
