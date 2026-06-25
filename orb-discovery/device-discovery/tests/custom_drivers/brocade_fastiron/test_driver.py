"""Unit tests for custom_napalm.brocade_fastiron.FastIronDriver."""

import logging
from pathlib import Path
from unittest.mock import MagicMock

from custom_napalm.brocade_fastiron import (
    FastIronDriver,
    _fastiron_get_chassis_members_impl,
    _parse_fastiron_stack,
    _parse_fastiron_version_units,
)
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestFastIronDriver(BaseDriverTest):
    """Unit tests for FastIronDriver using file-based CLI mocks."""

    driver_cls = FastIronDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"


# --- FastIron stack helper unit tests ----------------------------------------


def test_parse_fastiron_stack_basic_row():
    """A canonical `show stack` row parses into id/role/priority/mac/state/model."""
    text = (
        "T=11:54:25 GMT-04:00, eta 22h 5m remaining\n"
        "alone: standalone, D: dynamic config, S: static config, "
        "A: active, B: backup, M: member, X: not joined\n"
        "ID    Type            Role     Mac Address     Pri State   Comment\n"
        "1   S ICX7250-24P     active   cc4e.246b.b800 128  local   Ready\n"
        "2   S ICX7250-24P     standby  cc4e.246b.c700 128  remote  Ready\n"
    )
    rows = _parse_fastiron_stack(text)
    assert [(r["id"], r["role"], r["priority"], r["state"]) for r in rows] == [
        (1, "active", 128, "local"),
        (2, "standby", 128, "remote"),
    ]
    assert rows[0]["mac"] == "cc4e.246b.b800"
    assert rows[0]["model"] == "ICX7250-24P"


def test_parse_fastiron_stack_empty_output():
    """`No stack` / empty output returns no rows — caller logs DEBUG and returns None."""
    assert _parse_fastiron_stack("") == []
    assert _parse_fastiron_stack("T=08:00:00 GMT+00:00\nNo stack\n") == []


def test_parse_fastiron_stack_skips_topology_art():
    """ASCII topology art under the table must not produce phantom rows."""
    text = (
        "ID    Type            Role     Mac Address     Pri State   Comment\n"
        "1   S ICX7150-48     active   609c.9f00.0001 128  local   Ready\n"
        "\n"
        "     active\n"
        "     +---+\n"
        "-2/1 | 1 |2/2-\n"
        "     +---+\n"
    )
    rows = _parse_fastiron_stack(text)
    assert [r["id"] for r in rows] == [1]


def test_parse_fastiron_version_units_handles_poe_models():
    """ICX7250 PoE units (which break the ntc-template) must yield serial+model."""
    text = (
        "  UNIT 1\n"
        "    SW: Version 08.0.92T213\n"
        "  UNIT 2\n"
        "    SW: Version 08.0.92T213\n"
        "\n"
        "===============================================================\n"
        "UNIT 1: SL 1: ICX7250-24P PoE 24-port 100M/1GbE Module\n"
        "  Serial  #: ABC2456N1001\n"
        "  License: ICX7250_L3_SOFT_PACKAGE\n"
        "\n"
        "UNIT 2: SL 1: ICX7250-24P PoE 24-port 100M/1GbE Module\n"
        "  Serial  #: ABC2456N1002\n"
    )
    serial_by_id, model_by_id = _parse_fastiron_version_units(text)
    assert serial_by_id == {1: "ABC2456N1001", 2: "ABC2456N1002"}
    assert model_by_id == {1: "ICX7250-24P", 2: "ICX7250-24P"}


def test_parse_fastiron_version_units_empty_returns_empty_maps():
    """Empty / non-Hardware-section input yields empty maps; impl drops members on join."""
    assert _parse_fastiron_version_units("") == ({}, {})
    assert _parse_fastiron_version_units("  UNIT 1\n    SW: Version 08.0\n") == ({}, {})


def test_parse_fastiron_version_units_accepts_bare_serial_colon():
    """Some FastIron releases drop the ``#`` and print just ``Serial:`` — must still parse."""
    text = (
        "UNIT 1: SL 1: ICX7450-48 48-port 100M/1GbE Module\n"
        "  Serial: ICX7450X0001\n"
    )
    serial_by_id, _ = _parse_fastiron_version_units(text)
    assert serial_by_id == {1: "ICX7450X0001"}


def test_parse_fastiron_stack_accepts_alt_cfg_marker():
    """Legend lists `M` (master) / `R` (reserve) markers; widen cfg to any letter so those rows parse."""
    text = (
        "ID    Type            Role     Mac Address     Pri State   Comment\n"
        "1   M ICX7250-24P     active   cc4e.246b.b800 128  local   Ready\n"
    )
    rows = _parse_fastiron_stack(text)
    assert [(r["id"], r["role"]) for r in rows] == [(1, "active")]


def test_parse_fastiron_version_units_first_serial_wins_per_unit():
    """Multiple module entries under a unit only take the first Serial #: token."""
    text = (
        "UNIT 1: SL 1: ICX7450-48 48-port 100M/1GbE Module\n"
        "  Serial  #: PRIMARY_SN\n"
        "  License: ICX7450_L3_SOFT_PACKAGE\n"
        "UNIT 1: SL 2: ICX7400-1X10GR 1-port 10GbE Module\n"
        "  Serial  #: MODULE_SN\n"
    )
    serial_by_id, _ = _parse_fastiron_version_units(text)
    assert serial_by_id == {1: "PRIMARY_SN"}


def test_chassis_members_show_stack_exception_logs_warning_with_traceback(caplog):
    """A surprise exception from `show stack` must surface at WARNING with exc_info."""
    driver = MagicMock()
    driver.device.send_command.side_effect = RuntimeError("boom")
    with caplog.at_level(logging.DEBUG, logger="custom_napalm.brocade_fastiron"):
        result = _fastiron_get_chassis_members_impl(driver)
    assert result is None
    warning_records = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("show stack failed" in r.message for r in warning_records)
    assert any(r.exc_info is not None and r.exc_info[0] is RuntimeError for r in warning_records)


def test_chassis_members_empty_stack_output_logs_debug(caplog):
    """`No stack` banner → DEBUG, not WARNING; result is None."""
    driver = MagicMock()
    driver.device.send_command.return_value = "T=08:00:00 GMT+00:00\nNo stack\n"
    with caplog.at_level(logging.DEBUG, logger="custom_napalm.brocade_fastiron"):
        result = _fastiron_get_chassis_members_impl(driver)
    assert result is None
    assert not any(r.levelno >= logging.WARNING for r in caplog.records)
    assert any(
        r.levelno == logging.DEBUG and "no stack rows" in r.message for r in caplog.records
    )


def test_chassis_members_version_failure_drops_members_logs_warning(caplog):
    """`show version` error: WARNING+exc_info, members drop on empty serial, result is None."""
    driver = MagicMock()

    def _send(cmd):
        if cmd == "show stack":
            return (
                "ID    Type            Role     Mac Address     Pri State   Comment\n"
                "1   S ICX7250-24P     active   cc4e.246b.b800 128  local   Ready\n"
                "2   S ICX7250-24P     standby  cc4e.246b.c700 128  remote  Ready\n"
            )
        raise RuntimeError("version went sideways")

    driver.device.send_command.side_effect = _send
    with caplog.at_level(logging.DEBUG, logger="custom_napalm.brocade_fastiron"):
        result = _fastiron_get_chassis_members_impl(driver)
    assert result is None
    warning_records = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("show version failed" in r.message for r in warning_records)
    assert any(r.exc_info is not None and r.exc_info[0] is RuntimeError for r in warning_records)
