#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Unit tests for chassis-row matching in show inventory."""

from custom_napalm.ios import _index_inventory_by_switch


def _rows(*triples):
    """Build show-inventory row dicts from (name, pid, sn) triples."""
    return [{"name": n, "pid": p, "sn": s} for n, p, s in triples]


def test_accepts_switch_n_chassis_from_real_svl_inventory():
    """The C9500 SVL chassis rows resolve to per-member serial and model."""
    rows = _rows(
        ("Switch 1 Chassis", "C9500-48Y4C", "CAT11111111"),
        ("Switch 1 Power Supply Module 0", "C9K-PWR-650WAC-R", "XXXXXXXXXXX"),
        ("Switch 1 Fan Tray 0", "C9K-T1-FANTRAY", ""),
        ("Switch 1 Slot 1 Supervisor", "C9500-48Y4C", "CAT11111111"),
        ("TwentyFiveGigE1/0/43", "SFP-10/25G-CSR-S", "XXXXXXXXXXX"),
        ("Switch 2 Chassis", "C9500-48Y4C", "CAT22222222"),
        ("Switch 2 Slot 1 Supervisor", "C9500-48Y4C", "CAT22222222"),
    )
    serial, model = _index_inventory_by_switch(rows)
    assert serial == {1: "CAT11111111", 2: "CAT22222222"}
    assert model == {1: "C9500-48Y4C", 2: "C9500-48Y4C"}


def test_modular_chassis_does_not_take_component_identity():
    r"""
    On a modular 9400 the member must take the CHASSIS pid and serial.

    A matcher loosened to r"^Switch\s+(\d+)\b" also matches the supervisor and
    power supply rows and, being last-write-wins, yields
    model="C9400-PWR-3200AC" and the power supply's serial. Serial is NetBox's
    device matcher, so that attaches discovery to the wrong record. This test
    fails against that loosened regex.
    """
    rows = _rows(
        ("Switch 1 Chassis", "C9407R", "FOX1111111"),
        ("Switch 1 Slot 3 Supervisor", "C9400-SUP-1XL", "JAE2222222"),
        ("Switch 1 Power Supply Module 0", "C9400-PWR-3200AC", "ART3333333"),
    )
    serial, model = _index_inventory_by_switch(rows)
    assert serial == {1: "FOX1111111"}
    assert model == {1: "C9407R"}


def test_still_accepts_legacy_physical_stack_names():
    """Bare "Switch N" and bare "N" keep working for physical stacks."""
    serial, model = _index_inventory_by_switch(
        _rows(
            ("Switch 1", "WS-C3850-12XS", "FOC1111111"),
            ("2", "WS-C3850-12XS", "FOC2222222"),
        )
    )
    assert serial == {1: "FOC1111111", 2: "FOC2222222"}
    assert model == {1: "WS-C3850-12XS", 2: "WS-C3850-12XS"}


def test_standalone_chassis_row_without_a_number_is_ignored():
    """A bare "Chassis" NAME carries no member id, so it yields nothing."""
    assert _index_inventory_by_switch(
        _rows(("Chassis", "WS-C3850-12XS", "FOC2401L0AB"))
    ) == ({}, {})


def test_component_rows_alone_yield_nothing():
    """Component rows must never supply a member identity on their own."""
    assert _index_inventory_by_switch(
        _rows(
            ("Switch 1 Power Supply Module 0", "C9K-PWR-650WAC-R", "XXXXXXXXXXX"),
            ("Switch 1 Slot 1 Supervisor", "C9500-48Y4C", "CAT11111111"),
            ("Switch 1 Fan Tray 0", "C9K-T1-FANTRAY", ""),
        )
    ) == ({}, {})


def test_serial_and_model_come_from_the_same_row():
    """
    Fields must be committed atomically, never mixed across rows.

    The pre-fix code wrote serial and model through two independent
    conditionals, so a bare row and a Chassis row could each supply one field.
    """
    rows = _rows(
        ("Switch 1", "WRONG-PID", "WRONG-SN"),
        ("Switch 1 Chassis", "C9500-48Y4C", "CAT11111111"),
    )
    serial, model = _index_inventory_by_switch(rows)
    assert serial == {1: "CAT11111111"}
    assert model == {1: "C9500-48Y4C"}


def test_a_chassis_row_with_no_serial_loses_to_a_row_that_has_one():
    """Preferring a serial-bearing row keeps both fields from that one row."""
    rows = _rows(
        ("Switch 1 Chassis", "C9500-48Y4C", ""),
        ("Switch 1", "C9500-48Y4C", "CAT11111111"),
    )
    serial, model = _index_inventory_by_switch(rows)
    assert serial == {1: "CAT11111111"}
    assert model == {1: "C9500-48Y4C"}


def test_whitespace_and_casing_tolerated():
    """Real captures pad the NAME column; casing varies between releases."""
    serial, model = _index_inventory_by_switch(
        _rows(("  switch 1 chassis  ", "C9500-48Y4C", "CAT11111111"))
    )
    assert serial == {1: "CAT11111111"}
    assert model == {1: "C9500-48Y4C"}
