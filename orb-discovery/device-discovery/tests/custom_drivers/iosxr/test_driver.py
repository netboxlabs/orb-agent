"""Tests for the custom IOS-XR (pyIOSXR / XML-Agent) driver shim."""

import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from custom_napalm.iosxr import IOSXRDriver, _iosxr_get_modules_impl
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


def _all_serials(bays) -> set[str]:
    """Collect every module serial in a bay list, descending into sub_bays."""
    found: set[str] = set()
    for bay in bays:
        module = bay["module"]
        found.add(module["serial"])
        found |= _all_serials(module.get("sub_bays") or [])
    return found


def _modules_from_inventory(inventory: str, caplog):
    """Run get_modules against a literal show-inventory text, capturing driver logs."""
    driver = MagicMock()
    driver.device._execute_show.return_value = inventory
    with caplog.at_level(logging.DEBUG, logger="custom_napalm.iosxr"):
        return _iosxr_get_modules_impl(driver)


def test_orphan_optic_on_unknown_rack_dropped_with_warning(caplog):
    """
    An orphan optic naming a rack no chassis reported must be dropped, with a warning.

    Minting a rack from an optic name is correct only for the first orphan on
    a device that reported no slot bays at all (the fixed-port case). Once a
    rack roster exists, a foreign rack is unemittable either way — the
    standalone tail emits one rack, and translate warn-drops an unknown vsf
    member — so the promotion pass refuses it by name rather than letting the
    drop happen wordlessly further downstream.
    """
    inventory = """NAME: "0/0/CPU0", DESCR: "24-Port 10GE Line Card"
PID: A9K-24X10GE-SE, VID: V01, SN: FOXROSTERLC

NAME: "0/0/0", DESCR: "Cisco SFP+ 10G LR Optics"
PID: SFP-10G-LR, VID: V01, SN: OPTICINROSTER

NAME: "7/0/0", DESCR: "Cisco SFP+ 10G LR Optics"
PID: SFP-10G-LR, VID: V01, SN: OPTICOFFROSTER
"""

    result = _modules_from_inventory(inventory, caplog)

    assert result is not None
    members = result["members"]
    assert set(members.keys()) == {None}, "rack 7 must not become its own member bucket"

    all_serials = {
        serial for member in members.values() for serial in _all_serials(member["bays"])
    }
    assert "OPTICINROSTER" in all_serials, "the in-roster optic must still be attached"
    assert "OPTICOFFROSTER" not in all_serials, (
        "an optic on a rack no chassis reported must not be promoted anywhere"
    )
    assert "7/0/0" not in members[None]["interfaces_by_bay"], (
        "a refused optic must not leave a route keyed on a bay that is never emitted"
    )

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any(
        "7/0/0" in r.getMessage() and "not in chassis set" in r.getMessage()
        for r in warnings
    ), "expected a warning naming the dropped orphan optic and its unknown rack"


def test_second_rack_from_optic_only_inventory_refused_with_warning(caplog):
    """
    With no slot bays at all, the FIRST orphan mints its rack and a differing second is refused.

    Regression pin for the roster test reading ``bays_by_rack`` live rather
    than a snapshot taken before the promotion loop. Snapshotted, an empty
    roster made the guard inert for every orphan: rack 7 was minted too, the
    standalone tail then emitted rack 0 only, and the rack-7 bay vanished
    with no warning at all — the exact silent drop the guard exists to name.
    """
    inventory = """NAME: "Rack 0", DESCR: "Fixed-Port Router Chassis"
PID: NCS-55A1-24H, VID: V01, SN: FOXMINTCHAS

NAME: "0/0/0/1", DESCR: "Cisco SFP+ 10G LR Optics"
PID: SFP-10G-LR, VID: V01, SN: OPTICMINTRK0

NAME: "7/0/0/1", DESCR: "Cisco SFP+ 10G LR Optics"
PID: SFP-10G-LR, VID: V01, SN: OPTICRACK7
"""

    result = _modules_from_inventory(inventory, caplog)

    assert result is not None
    members = result["members"]
    assert set(members.keys()) == {None}, (
        "an optic-only inventory stays standalone — no rack may become a member bucket"
    )

    all_serials = {
        serial for member in members.values() for serial in _all_serials(member["bays"])
    }
    assert "OPTICMINTRK0" in all_serials, (
        "the first orphan must mint its rack and be promoted — the fixed-port case"
    )
    assert "OPTICRACK7" not in all_serials, (
        "an orphan on a second, differing rack must not be promoted"
    )
    assert "7/0/0/1" not in members[None]["interfaces_by_bay"], (
        "the refused optic must not leave a route keyed on a bay that is never emitted"
    )

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any(
        "7/0/0/1" in r.getMessage() and "not in chassis set" in r.getMessage()
        for r in warnings
    ), (
        "the refusal must be named: a snapshotted roster drops rack 7 silently, "
        "so asserting only its absence would not catch the regression"
    )
