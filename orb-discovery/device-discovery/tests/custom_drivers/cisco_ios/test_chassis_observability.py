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


def _warnings(caplog, logger="custom_napalm.ios"):
    """
    Return WARNING+ records from one logger.

    Scoped by logger because _chassis.to_payload legitimately warns about each
    serial-less member it drops; that is complementary detail, not a duplicate of
    the driver's summary, and it is not what these tests are pinning.
    """
    return [
        r for r in caplog.records
        if r.levelno >= logging.WARNING and r.name == logger
    ]


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


def test_honest_single_unit_does_not_warn(caplog):
    """
    A standalone stack-capable Catalyst reports one row and must stay quiet.

    2960S/2960X/3850/9200/9300 answer "show switch detail" with a one-row member
    table when they are not stacked. That is the most common deployment in a
    fleet, so warning would fire on every device on every discovery cycle. Only
    a stack we could not REPRESENT is worth a warning (see the test below).
    """
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
    assert _warnings(caplog) == []
    assert any("single unit" in r.getMessage() for r in caplog.records)


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


def test_unresolvable_serial_on_a_real_stack_warns(caplog):
    """
    A reported stack we cannot represent IS worth a warning.

    Two member rows but only one resolvable serial means to_payload drops a
    member, so the pair silently degrades to a single Device. That is the case
    an operator needs to see, as distinct from an honest single unit.
    """
    driver = _FakeDriver(
        {
            "show switch detail": (
                SWITCH_TABLE_HEADER
                + "*1       Active   0026.5a4b.c000     15     V02     Ready\n"
                + " 2       Standby  0026.5a4b.d000     14     V02     Ready\n"
            ),
            # Only member 1 has an inventory chassis row.
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
    message = warnings[0].getMessage()
    assert "device-01" in message
    assert "resolvable serial" in message


def test_send_command_failure_still_tries_the_next_command():
    """
    A raising command must not abort the fallback.

    If the first command raises (transport hiccup, unexpected prompt) the loop
    must continue to "show switch"; returning early instead would make SVL
    discovery depend on a command that platform does not implement.
    """
    calls: list[str] = []

    class _RaisingDevice:
        def send_command(self, command):
            calls.append(command)
            if command == "show switch detail":
                raise RuntimeError("transport hiccup")
            if command == "show switch":
                return (
                    SWITCH_TABLE_HEADER
                    + "*1       Active   e41f.0000.0001     15     V02     Ready\n"
                    + " 2       Standby  e41f.0000.0002     14     V02     Ready\n"
                )
            if command == "show inventory":
                return (
                    'NAME: "Switch 1 Chassis", DESCR: "C9500"\n'
                    "PID: C9500-48Y4C , VID: V02 , SN: CAT11111111\n"
                    "\n"
                    'NAME: "Switch 2 Chassis", DESCR: "C9500"\n'
                    "PID: C9500-48Y4C , VID: V02 , SN: CAT22222222\n"
                )
            return ""

    driver = _FakeDriver({})
    driver.device = _RaisingDevice()
    result = _ios_get_chassis_members_impl(driver)
    assert result is not None
    assert [m["id"] for m in result["members"]] == [1, 2]
    assert "show switch" in calls
