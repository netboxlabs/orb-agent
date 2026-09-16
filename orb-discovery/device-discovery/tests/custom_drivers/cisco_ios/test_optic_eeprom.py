#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
Unit tests for reading an optic's EEPROM when the inventory cannot name it.

``show inventory`` has no manufacturer field and reports no PID for a part
Cisco does not recognise, which is why such rows were previously emitted under
a generic manufacturer with their description standing in for the model. The
optic's own EEPROM names both, so where it answers we record the real part.
"""

import logging

from custom_napalm._modules import ModuleEntry
from custom_napalm.ios import _ios_read_optic_eeprom, _parse_idprom

_LOGGER = "custom_napalm.ios"

# The shape a Catalyst returns. Only two of these lines are read; the rest are
# byte dumps, and are present here so the parser is exercised against the
# noise it actually sees.
_IDPROM = """General SFP Information
-----------------------------------------------
Identifier            :   0x03
Connector             :   0x07
Transceiver           :   0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x00
Encoding              :   0x01
BR_Nominal            :   0x0D
Vendor Name           :   CISCO-FINISAR
Vendor Part Number    :   FTRJ8519P1BNL-C3
Vendor Revision       :   0x31 0x30 0x2E 0x30
Vendor Serial Number  :   SN00000001
-----------------------------------------------
"""


class _FakeDevice:
    """Records the commands issued and answers from a fixed map."""

    def __init__(self, responses: dict[str, str | Exception]) -> None:
        self.responses = responses
        self.commands: list[str] = []

    def send_command(self, command: str) -> str:
        self.commands.append(command)
        answer = self.responses.get(command, "")
        if isinstance(answer, Exception):
            raise answer
        return answer


class _FakeDriver:
    def __init__(self, responses: dict[str, str | Exception]) -> None:
        self.device = _FakeDevice(responses)


def _unidentified(model: str = "1000BaseSX SFP") -> ModuleEntry:
    return ModuleEntry(
        model=model, serial="OPT0000001", type="transceiver",
        description=model, identified=False,
    )


class TestParseIdprom:
    """Parsing `show idprom interface` output."""

    def test_reads_vendor_and_part(self) -> None:
        """The two fields we read come back from a real-shaped answer."""
        assert _parse_idprom(_IDPROM) == ("CISCO-FINISAR", "FTRJ8519P1BNL-C3")

    def test_missing_fields_are_empty_not_guessed(self) -> None:
        """A field that is not there is reported absent, never inferred."""
        assert _parse_idprom("Vendor Name : ACME\n") == ("ACME", "")
        assert _parse_idprom("Vendor Part Number : XYZ-1\n") == ("", "XYZ-1")
        assert _parse_idprom("") == ("", "")
        assert _parse_idprom("% Invalid input detected at '^' marker.") == ("", "")

    def test_blank_values_do_not_count(self) -> None:
        """A label with nothing after it names nothing."""
        assert _parse_idprom("Vendor Name           :   \nVendor Part Number : \n") == ("", "")


class TestReadOpticEEPROM:
    """Probing the optics the inventory could not name."""

    def test_upgrades_an_optic_the_inventory_could_not_name(self) -> None:
        """A vendor and part number from the EEPROM replace the description."""
        entry = _unidentified()
        driver = _FakeDriver({"show idprom interface Gi1/0/25": _IDPROM})

        _ios_read_optic_eeprom(driver, {None: {"Gi1/0/25": entry}})

        assert entry.identified is True
        assert entry.model == "FTRJ8519P1BNL-C3"
        assert entry.manufacturer == "CISCO-FINISAR"
        # The description is left alone: it is still what the switch said.
        assert entry.description == "1000BaseSX SFP"

    def test_an_identified_optic_is_never_probed(self) -> None:
        """
        Cost one command per unnamed optic, not per port.

        A switch whose optics are all recognised must issue none.
        """
        entry = ModuleEntry(
            model="GLC-SX-MMD", serial="OPT0000002", type="transceiver",
            description="1000BaseSX SFP",
        )
        driver = _FakeDriver({})

        _ios_read_optic_eeprom(driver, {None: {"Gi1/0/26": entry}})

        assert driver.device.commands == []
        assert entry.model == "GLC-SX-MMD"
        assert entry.manufacturer == ""

    def test_command_failure_keeps_the_description(self, caplog) -> None:
        """Not every platform or image has the command; that is not fatal."""
        entry = _unidentified()
        driver = _FakeDriver({
            "show idprom interface Gi1/0/25": OSError("Invalid input detected"),
        })

        with caplog.at_level(logging.DEBUG, logger=_LOGGER):
            _ios_read_optic_eeprom(driver, {None: {"Gi1/0/25": entry}})

        assert entry.identified is False
        assert entry.model == "1000BaseSX SFP"
        assert entry.manufacturer == ""

    def test_half_an_answer_is_not_used(self) -> None:
        """
        Half an answer is not used.

        A part number needs a manufacturer to key a NetBox ModuleType, and a
        manufacturer alone names nothing. Either on its own leaves the row as
        it was rather than producing a half-identified part.
        """
        entry = _unidentified()
        driver = _FakeDriver({
            "show idprom interface Gi1/0/25": "Vendor Name : CISCO-FINISAR\n",
        })

        _ios_read_optic_eeprom(driver, {None: {"Gi1/0/25": entry}})

        assert entry.identified is False
        assert entry.model == "1000BaseSX SFP"
        assert entry.manufacturer == ""

    def test_probes_every_member_of_a_stack(self) -> None:
        """Transceivers are bucketed per member; all buckets are covered."""
        one, two = _unidentified(), _unidentified()
        driver = _FakeDriver({
            "show idprom interface Te1/1/3": _IDPROM,
            "show idprom interface Te2/1/3": _IDPROM,
        })

        _ios_read_optic_eeprom(driver, {1: {"Te1/1/3": one}, 2: {"Te2/1/3": two}})

        assert sorted(driver.device.commands) == [
            "show idprom interface Te1/1/3",
            "show idprom interface Te2/1/3",
        ]
        assert one.identified is True
        assert two.identified is True

    def test_no_unidentified_optics_issues_no_commands(self) -> None:
        """An empty bucket map is a no-op, not an error."""
        driver = _FakeDriver({})
        _ios_read_optic_eeprom(driver, {})
        assert driver.device.commands == []
