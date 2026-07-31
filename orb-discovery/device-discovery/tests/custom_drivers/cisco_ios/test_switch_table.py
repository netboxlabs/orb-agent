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
        # Regression: a digit-anchored version pattern put "P2B" into state
        # (a real 2960X H/W version, letter-leading), producing
        # state="P2B     Ready" instead of version="P2B" state="Ready".
        (
            "*1       Active   0011.2233.4455     15     P2B     Ready",
            {"switch": "1", "role": "Active", "mac_address": "0011.2233.4455",
             "priority": "15", "version": "P2B", "state": "Ready"},
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


# The shared field set both parsers populate. Comparing only "switch" would
# let a field-level regression (e.g. version data bleeding into state) pass
# unnoticed, which is exactly what happened before the version group was
# widened from a digit-leading pattern to \S+.
_COMPARISON_FIELDS = ("switch", "role", "mac_address", "priority", "version", "state")


def _comparable(row: dict) -> tuple:
    """
    Extract the six shared fields from a row dict as a tuple, in fixed order.

    A missing key or an explicit ``None`` both normalise to ``""`` so a
    template row that omits an unset field compares equal to the local
    parser's row, which always sets it to ``""``.
    """
    return tuple((row.get(field) or "") for field in _COMPARISON_FIELDS)


@pytest.mark.parametrize("fixture", _fixture_dirs(), ids=lambda d: d.name)
def test_parity_with_ntc_template(fixture):
    """
    The local parser agrees with the template field-for-field, and is a strict superset.

    Where the template succeeds, every row must match on all six shared
    fields (switch, role, mac_address, priority, version, state) — not just
    the switch id, which would miss a field-level regression such as version
    data bleeding into state. Where the template raises (it is
    all-or-nothing) the local parser must still return a list, never raise;
    for the one fixture that triggers this today ("Switch is not on any
    stack.", which carries no member row at all) that list is empty, and the
    test asserts that exact count rather than merely the type.
    """
    text = (fixture / "show_switch_detail.txt").read_text()
    local_rows = _parse_switch_table(text)
    try:
        template_rows = parse_output(
            platform="cisco_ios", command="show switch detail", data=text
        )
    except Exception:
        # local_rows was already produced above, unguarded, so simply
        # reaching this branch already proves the local parser did not
        # raise where the template did. The substantive check is that its
        # row count is the one actually correct for this input: this
        # fixture's raw text is only the "not on any stack" banner, with no
        # member row for either parser to find.
        assert local_rows == []
        return
    assert [_comparable(r) for r in local_rows] == [_comparable(r) for r in template_rows]
