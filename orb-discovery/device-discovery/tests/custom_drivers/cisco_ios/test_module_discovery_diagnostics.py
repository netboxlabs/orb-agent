#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
Unit tests for module discovery explaining itself, and for what it now emits.

Some paths here decline to invent data and warn instead of vanishing quietly:
the reported symptom was always "no modules, no errors, identical entity
count", because the whole decision path logged at DEBUG or not at all. Those
tests pin the messages an operator needs at the default log level, and just as
importantly pin that a device with genuinely nothing to report stays quiet.

Other tests here cover the opposite case: a row the device serialised but did
not name -- a blank PID, or the literal placeholder "Unspecified" -- used to
be dropped for want of a model. It is now emitted as an unidentified module,
using its description as the model, so an operator gets a complete inventory
instead of a silently incomplete one.
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

    def test_placeholder_pid_is_emitted_as_an_unidentified_transceiver(self) -> None:
        """
        A 2960S reports "Unspecified" for an SFP it cannot identify.

        The row has a serial and a usable description, so the part is real
        and present and must be recorded.

        The type assertion is the load-bearing one:
        classify_module_type_cisco_ios returns "linecard" for both "" and
        "Unspecified", so deriving the type from the PID would file an optic as
        a linecard AND let it survive linecards mode, where a transceiver is
        correctly dropped. The row's NAME being an interface is the signal.
        """
        rows = [
            {"name": "1", "descr": "WS-C2960S-24PD-L",
             "pid": "WS-C2960S-24PD-L", "vid": "V03", "sn": "SN0081001"},
            {"name": "GigabitEthernet1/0/25", "descr": "1000BaseSX SFP",
             "pid": "Unspecified", "vid": "", "sn": "OPT0081025"},
        ]

        _, transceivers, _ = _parse_inventory_rows(rows, False)

        optic = transceivers[None]["GigabitEthernet1/0/25"]
        assert optic.identified is False
        assert optic.model == "1000BaseSX SFP"
        assert optic.serial == "OPT0081025"
        assert optic.type == "transceiver"

    def test_blank_pid_optic_is_emitted_as_an_unidentified_transceiver(self) -> None:
        """The DAC case from the C9200L: a serial, a description, no PID."""
        rows = [
            {"name": "Switch 1", "descr": "C9200L-24PXG-4X",
             "pid": "C9200L-24PXG-4X", "vid": "V01", "sn": "FCW0000001"},
            {"name": "Te1/1/3", "descr": "SFP-10GBase-CX1",
             "pid": "", "vid": "", "sn": "OPT0001113"},
        ]

        _, transceivers, _ = _parse_inventory_rows(rows, False)

        optic = transceivers[None]["Te1/1/3"]
        assert optic.identified is False
        assert optic.model == "SFP-10GBase-CX1"
        assert optic.type == "transceiver"

    def test_identified_optic_is_unchanged(self) -> None:
        """A real PID must still produce an identified transceiver."""
        rows = [
            {"name": "Switch 1", "descr": "C9200L-24PXG-4X",
             "pid": "C9200L-24PXG-4X", "vid": "V01", "sn": "FCW0000001"},
            {"name": "Te1/1/1", "descr": "SFP-10GBase-SR",
             "pid": "SFP-10G-SR", "vid": "V03", "sn": "OPT0001111"},
        ]

        _, transceivers, _ = _parse_inventory_rows(rows, False)

        optic = transceivers[None]["Te1/1/1"]
        assert optic.identified is True
        assert optic.model == "SFP-10G-SR"

    def test_a_slot_row_without_a_pid_is_also_emitted(self) -> None:
        """
        The relaxed filter is not optic-specific.

        It sits above the slot and FRU branches, so a linecard the device
        serialised but did not name is recorded too, typed from its row shape
        rather than its absent PID.
        """
        rows = [
            {"name": "Slot 2 Linecard", "descr": "48-port GE line card",
             "pid": "", "vid": "", "sn": "LC0000002"},
        ]

        bays, _, _ = _parse_inventory_rows(rows, False)

        card = bays[None]["2"].module
        assert card.identified is False
        assert card.model == "48-port GE line card"
        assert card.type == "linecard"

    def test_a_serial_bearing_fru_row_without_a_pid_now_builds_a_bay(self) -> None:
        """
        The relaxed filter sits BELOW _ios_claim_slot but ABOVE the slot and FRU branches.

        So a FRU row the device serialised but did not name changes from
        claim-only to claim-and-build.

        That matters for promotion: an optic whose slot is claimed by a row that
        built no bay is declined, whereas one whose slot has a real bay nests
        under it. This row now builds a bay, so Te1/1/1 must nest rather than be
        declined. The existing fru_row_unusable_not_promoted fixture is
        unaffected because its FRU row has a BLANK SERIAL, which `if not sn`
        still drops.
        """
        rows = [
            {"name": "Switch 1", "descr": "C9300-48T",
             "pid": "C9300-48T", "vid": "V01", "sn": "FCW1"},
            {"name": "Switch 1 FRU Uplink Module 1", "descr": "8x10GE Network Module",
             "pid": "", "vid": "", "sn": "FRU1"},
            {"name": "Te1/1/1", "descr": "SFP-10GBase-LR",
             "pid": "SFP-10G-LR", "vid": "V02", "sn": "OPT1"},
        ]

        bays, transceivers, claimed = _parse_inventory_rows(rows, False)

        uplink = bays[None]["1"].module
        assert uplink.identified is False
        assert uplink.model == "8x10GE Network Module"
        assert uplink.type == "linecard"
        assert (None, "1") in claimed, "the slot claim must survive the relaxation"
        assert "Te1/1/1" in transceivers[None]

    def test_row_with_no_pid_and_no_description_is_skipped(self) -> None:
        """Nothing to name the part, so there is nothing to emit."""
        rows = [
            {"name": "Te1/1/4", "descr": "", "pid": "", "vid": "", "sn": "OPT0001114"},
        ]

        _, transceivers, _ = _parse_inventory_rows(rows, False)

        assert transceivers == {}

    def test_unidentified_optics_reach_netbox_entities(self) -> None:
        """
        Through the real translate path, not a hand-built payload.

        On PR #570 every probe test mocked the client factory, none reached
        the real constructor, and a configuration the real code rejected
        outright shipped. The same failure mode is available here.
        """
        from netboxlabs.diode.sdk.ingester import Device as PBDevice
        from netboxlabs.diode.sdk.ingester import DeviceType, Manufacturer

        from device_discovery.policy.models import Options
        from device_discovery.translate_modules import emit_modules_if_requested

        driver = _driver("unidentified_optics_emitted")
        payload = driver.get_modules()
        # The manufacturer must be set explicitly. Passing device_type as a bare
        # string builds a DeviceType with no manufacturer, and
        # _manufacturer_from_device then returns "Unknown" for EVERY module --
        # which would make the assertions below pass whether or not this
        # feature works.
        device = PBDevice(
            name="sw1",
            device_type=DeviceType(model="C9200L-24PXG-4X",
                                   manufacturer=Manufacturer(name="Cisco")),
            site="s",
        )
        entities: list = []

        emit_modules_if_requested({"modules": payload},
                                  Options(discover_modules="full"),
                                  {None: device}, entities)

        modules = [e.module for e in entities if e.WhichOneof("entity") == "module"]
        assert len(modules) == 4, "all four installed optics must reach NetBox"
        by_serial = {m.serial: m for m in modules}
        # The discriminating pair: same device, same run, different manufacturer.
        assert by_serial["OPT0001113"].module_type.manufacturer.name == "Unknown"
        assert by_serial["OPT0001111"].module_type.manufacturer.name == "Cisco"
        assert by_serial["OPT0001113"].module_type.model == "SFP-10GBase-CX1"
