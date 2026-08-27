#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
Unit tests for module discovery explaining itself when it emits nothing.

Every path here already behaved correctly in the sense that it declined to
invent data. What it did not do was say so. The reported symptom was always
"no modules, no errors, identical entity count", because the whole decision
path logged at DEBUG or not at all. These tests pin the messages an operator
needs at the default log level, and just as importantly pin that a device with
genuinely nothing to report stays quiet.
"""

import logging
from pathlib import Path

from custom_napalm.ios import IOSDriver, _parse_inventory_rows
from tests.custom_drivers.mock_device import FakeCLIDevice

_LOGGER = "custom_napalm.ios"
_MOCK_ROOT = Path(__file__).parent / "mock_data" / "test_get_modules"


def _driver(scenario: str) -> IOSDriver:
    """Build an IOSDriver over a mock_data scenario, bypassing open()."""
    driver = object.__new__(IOSDriver)
    driver.hostname = "test-host"
    driver.username = "test-user"
    driver.password = "test-pass"
    driver.timeout = 60
    driver.device = FakeCLIDevice(_MOCK_ROOT / scenario)
    return driver


class TestModuleDiscoveryDiagnostics:
    """Warnings emitted when get_modules declines to emit anything."""

    def test_placeholder_pid_on_optic_row_is_announced(self, caplog) -> None:
        """
        An ifname row whose PID is a placeholder warns instead of vanishing.

        ``Unspecified`` is what a WS-C2960S reports for an SFP it cannot
        identify. It is truthy, so it passes the ``pid and sn`` filter and
        never reaches the blank-PID warning, then gets rejected by the
        transceiver type gate with a bare ``continue``. The rejection is
        correct (there is no model to emit) but it must be visible.
        """
        rows = [
            {
                "name": "1", "descr": "WS-C2960S-24PD-L",
                "pid": "WS-C2960S-24PD-L", "vid": "V03", "sn": "SN0081001",
            },
            {
                "name": "GigabitEthernet1/0/25", "descr": "1000BaseSX SFP",
                "pid": "Unspecified", "vid": "", "sn": "OPT0081025",
            },
        ]

        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            _, transceivers, _ = _parse_inventory_rows(rows, False)

        assert transceivers == {}, "a placeholder PID must not become a module"
        messages = [r.getMessage() for r in caplog.records]
        assert any(
            "GigabitEthernet1/0/25" in m and "Unspecified" in m for m in messages
        ), f"the skipped port and its PID must both be named, got {messages}"

    def test_placeholder_pid_reason_reaches_the_operator(self, caplog) -> None:
        """
        The rejected row's reason survives all the way out of get_modules.

        One placeholder-PID optic, nothing else, so the payload is None. The
        requirement is not an extra summary line at the end -- it is that the
        operator can see WHICH port was dropped and WHY without having to turn
        on debug logging.
        """
        driver = _driver("unidentified_optic_pid")

        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            result = driver.get_modules()

        assert result is None
        messages = [r.getMessage() for r in caplog.records]
        assert any(
            "GigabitEthernet1/0/25" in m and "Unspecified" in m for m in messages
        ), f"the operator must see the port and the placeholder PID, got {messages}"

    def test_every_optic_declined_is_announced(self, caplog) -> None:
        """
        Optics found but all declined promotion warns, and says how many.

        The transceiver rows parse fine, every one is declined for want of a
        modeled parent, and the payload collapses to None. The per-port reason
        stays at DEBUG, but the fact that it happened at all has to surface,
        and the count is what tells the operator this is not an empty device.
        """
        driver = _driver("all_optics_declined")

        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            result = driver.get_modules()

        assert result is None
        messages = [r.getMessage() for r in caplog.records]
        assert any("1" in m and "declined" in m for m in messages), (
            f"expected a declined-optics warning naming the count, got {messages}"
        )
        assert any("debug" in m.lower() for m in messages), (
            "the warning must point at debug logging for the per-port reason"
        )

    def test_unparseable_inventory_is_announced(self, caplog) -> None:
        """
        Inventory that yields zero rows warns rather than returning a quiet None.

        ``show inventory`` came back with nothing usable. Every Cisco chassis
        reports at least its own row, so zero parsed rows means the command was
        rejected or the output did not parse, not that the device is empty.
        That is a different problem from "no modules found" and the operator
        needs to be able to tell them apart.
        """
        driver = _driver("empty_inventory")

        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            result = driver.get_modules()

        assert result is None
        assert any(
            "no parseable" in r.getMessage() for r in caplog.records
        ), f"expected an unparseable-inventory warning, got {[r.getMessage() for r in caplog.records]}"

    def test_device_with_genuinely_no_modules_stays_quiet(self, caplog) -> None:
        """
        A switch with nothing to report must not warn about it.

        A fixed 3850 with no optics installed has a chassis row and a PSU row
        and that is all. Returning no modules is the correct and expected
        outcome, not a diagnostic event. An operator running this against a
        fleet of access switches would otherwise get one warning per switch per
        cycle for entirely normal behavior, which is how a useful warning stops
        being read.
        """
        driver = _driver("standalone_3850_no_modules")

        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            result = driver.get_modules()

        assert result is None
        assert not caplog.records, (
            f"a module-free device must stay quiet, got {[r.getMessage() for r in caplog.records]}"
        )
