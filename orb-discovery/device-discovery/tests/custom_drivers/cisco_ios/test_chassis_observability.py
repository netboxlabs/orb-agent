#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""The reason no VirtualChassis was emitted must be diagnosable from the log."""

import logging

from custom_napalm.ios import _ios_get_chassis_members_impl


class _FakeDevice:
    """Returns canned output per command, and "" for anything unasked-for."""

    def __init__(self, responses):
        self._responses = responses
        self.commands: list[str] = []

    def send_command(self, command):
        """Record the command and return its canned response."""
        self.commands.append(command)
        return self._responses.get(command, "")


class _FakeDriver:
    """Minimal stand-in for IOSDriver: a device plus the hostname used in logs."""

    def __init__(self, responses, hostname="device-01"):
        self.device = _FakeDevice(responses)
        self.hostname = hostname


CLI_ERROR = "                  ^\n% Invalid input detected at '^' marker.\n"

SWITCH_TABLE_HEADER = (
    "Switch/Stack Mac Address : 0026.5a4b.c000 - Local Mac Address\n"
    "                                             H/W   Current\n"
    "Switch#   Role    Mac Address     Priority Version  State\n"
    "-------------------------------------------------------------\n"
)


def _warnings(caplog):
    return [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_unsupported_platform_is_quiet(caplog):
    """A router with no stack concept must not warn on every discovery cycle."""
    driver = _FakeDriver({"show switch detail": CLI_ERROR, "show switch": CLI_ERROR})
    with caplog.at_level(logging.DEBUG, logger="custom_napalm.ios"):
        assert _ios_get_chassis_members_impl(driver) is None
    assert _warnings(caplog) == []
    assert any("device-01" in r.getMessage() for r in caplog.records)


def test_standalone_is_quiet(caplog):
    """An explicit standalone answer is expected, not a problem worth warning."""
    driver = _FakeDriver({"show switch detail": "Switch is not on any stack.\n"})
    with caplog.at_level(logging.DEBUG, logger="custom_napalm.ios"):
        assert _ios_get_chassis_members_impl(driver) is None
    assert _warnings(caplog) == []


def test_unparseable_switch_table_warns_with_hostname_and_command(caplog):
    """Output that LOOKS like a member table but yields nothing is the loud case."""
    unparseable = SWITCH_TABLE_HEADER + " 1  Active  <unexpected>\n"
    driver = _FakeDriver(
        {"show switch detail": unparseable, "show switch": unparseable}
    )
    with caplog.at_level(logging.DEBUG, logger="custom_napalm.ios"):
        assert _ios_get_chassis_members_impl(driver) is None
    warnings = _warnings(caplog)
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert "device-01" in message
    assert "show switch" in message


def test_single_member_warns_with_the_count(caplog):
    """One member cannot form a VirtualChassis; say so rather than going quiet."""
    driver = _FakeDriver(
        {
            "show switch detail": (
                SWITCH_TABLE_HEADER
                + "*1       Active   0026.5a4b.c000     15     V02     Ready\n"
            ),
            "show inventory": (
                'NAME: "Switch 1", DESCR: "Cisco Catalyst 9300 Switch"\n'
                "PID: C9300-24T          , VID: V02 , SN: FOC1111111\n"
            ),
        }
    )
    with caplog.at_level(logging.DEBUG, logger="custom_napalm.ios"):
        _ios_get_chassis_members_impl(driver)
    warnings = _warnings(caplog)
    assert len(warnings) == 1
    assert "1" in warnings[0].getMessage()
    assert "device-01" in warnings[0].getMessage()


def test_falls_back_to_show_switch_and_sends_both_commands():
    """SVL rejects the detail form, so both commands must be tried in order."""
    driver = _FakeDriver(
        {
            "show switch detail": CLI_ERROR,
            "show switch": (
                SWITCH_TABLE_HEADER
                + "*1       Active   e41f.0000.0001     15     V02     Ready\n"
                + " 2       Standby  e41f.0000.0002     14     V02     Ready\n"
            ),
            "show inventory": (
                'NAME: "Switch 1 Chassis", DESCR: "Cisco Catalyst 9500 Series Chassis"\n'
                "PID: C9500-48Y4C       , VID: V02  , SN: CAT11111111\n"
                "\n"
                'NAME: "Switch 2 Chassis", DESCR: "Cisco Catalyst 9500 Series Chassis"\n'
                "PID: C9500-48Y4C       , VID: V02  , SN: CAT22222222\n"
            ),
        }
    )
    result = _ios_get_chassis_members_impl(driver)
    assert result is not None
    assert [m["id"] for m in result["members"]] == [1, 2]
    sent = driver.device.commands
    assert sent[0] == "show switch detail"
    assert "show switch" in sent[1:]


def test_domain_is_not_requested_on_a_single_member():
    """The SVL domain command is only worth sending once a stack is confirmed."""
    driver = _FakeDriver(
        {
            "show switch detail": (
                SWITCH_TABLE_HEADER
                + "*1       Active   0026.5a4b.c000     15     V02     Ready\n"
            ),
            "show inventory": (
                'NAME: "Switch 1", DESCR: "Cisco Catalyst 9300 Switch"\n'
                "PID: C9300-24T          , VID: V02 , SN: FOC1111111\n"
            ),
        }
    )
    _ios_get_chassis_members_impl(driver)
    assert "show stackwise-virtual" not in driver.device.commands
