#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Unit tests for the driver-local stack-member table parser."""

import pathlib

import pytest
from ntc_templates.parse import parse_output

from custom_napalm.ios import _parse_switch_table

FIXTURES = (
    pathlib.Path(__file__).parent / "mock_data" / "test_get_chassis_members"
)


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (
            "*1       Active   e41f.0000.0001     15     V02     Ready",
            {"switch": "1", "role": "Active", "mac_address": "e41f.0000.0001",
             "priority": "15", "version": "V02", "state": "Ready"},
        ),
        (
            " 2       Standby  e41f.0000.0002     14     V02     Ready",
            {"switch": "2", "role": "Standby", "mac_address": "e41f.0000.0002",
             "priority": "14", "version": "V02", "state": "Ready"},
        ),
        (
            " 2       Standby  0026.5a4b.d000     14             Ready",
            {"switch": "2", "role": "Standby", "mac_address": "0026.5a4b.d000",
             "priority": "14", "version": "", "state": "Ready"},
        ),
        # The ntc template raises TextFSMError on these two, discarding EVERY
        # row, because its STATE value is (\w+). That is the bug this parser
        # exists to fix; do not "simplify" these cases away.
        (
            " 2       Standby  0026.5a4b.d000     14     V02     Version Mismatch",
            {"switch": "2", "role": "Standby", "mac_address": "0026.5a4b.d000",
             "priority": "14", "version": "V02", "state": "Version Mismatch"},
        ),
        (
            " 2       Standby  0026.5a4b.d000     14     V02     Sync not started",
            {"switch": "2", "role": "Standby", "mac_address": "0026.5a4b.d000",
             "priority": "14", "version": "V02", "state": "Sync not started"},
        ),
        (
            " 2       Member   0000.0000.0000     0              Provisioned",
            {"switch": "2", "role": "Member", "mac_address": "0000.0000.0000",
             "priority": "0", "version": "", "state": "Provisioned"},
        ),
        (
            " 3       Member   e4:1f:00:00:00:03  5      V02     Ready",
            {"switch": "3", "role": "Member", "mac_address": "e4:1f:00:00:00:03",
             "priority": "5", "version": "V02", "state": "Ready"},
        ),
    ],
)
def test_parses_member_rows(line, expected):
    """Every real member-row shape is recovered, including multi-word states."""
    assert _parse_switch_table(line) == [expected]


@pytest.mark.parametrize(
    "line",
    [
        "Switch#   Role    Mac Address     Priority Version  State",
        "-------------------------------------------------------------",
        "Switch/Stack Mac Address : e41f.0000.0001 - Local Mac Address",
        "Mac persistency wait time: Indefinite",
        "% Invalid input detected at '^' marker.",
        "Switch is not on any stack.",
        "Switch#  Port 1     Port 2",
        "  1       Ok         Ok",
    ],
)
def test_rejects_non_member_lines(line):
    """
    Headers, separators, banners and stack-port rows are never members.

    The stack-port data row "1  Ok  Ok" is the highest-risk false positive; it
    is rejected because it carries no MAC column.
    """
    assert _parse_switch_table(line) == []


def test_stops_at_stack_port_section():
    """Rows after the Stack Port header are not scanned."""
    text = (
        "Switch#   Role    Mac Address     Priority Version  State\n"
        "-------------------------------------------------------------\n"
        "*1       Active   e41f.0000.0001     15     V02     Ready\n"
        "\n"
        "Stack Port Status\n"
        " 9       Member   0026.5a4b.9999     9      V02     Ready\n"
    )
    assert [r["switch"] for r in _parse_switch_table(text)] == ["1"]


def _fixture_dirs():
    return sorted(d for d in FIXTURES.iterdir() if (d / "show_switch_detail.txt").exists())


@pytest.mark.parametrize("fixture", _fixture_dirs(), ids=lambda d: d.name)
def test_parity_with_ntc_template(fixture):
    """
    The local parser is a strict superset of the template on every fixture.

    Where the template succeeds it must agree exactly. Where the template
    raises (it is all-or-nothing) the local parser must still return a list,
    never raise.
    """
    text = (fixture / "show_switch_detail.txt").read_text()
    local_ids = [r["switch"] for r in _parse_switch_table(text)]
    try:
        template_rows = parse_output(
            platform="cisco_ios", command="show switch detail", data=text
        )
    except Exception:
        assert isinstance(local_ids, list)
        return
    assert local_ids == [r["switch"] for r in template_rows]
