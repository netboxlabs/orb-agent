"""Unit tests for custom_napalm.huawei_vrp.VRPDriver."""

import logging
from pathlib import Path
from unittest.mock import MagicMock

from custom_napalm.huawei_vrp import (
    VRPDriver,
    _huawei_vrp_get_chassis_members_impl,
    _normalize_vrp_istack_role,
    _parse_huawei_stack,
    _parse_vrp_esn_by_slot,
)
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestVRPDriver(BaseDriverTest):
    """Unit tests for VRPDriver using file-based CLI mocks."""

    driver_cls = VRPDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"


# --- VRP iStack helper unit tests --------------------------------------------


def test_normalize_vrp_istack_role_huawei_specific_slave_maps_to_member():
    """Huawei iStack `Slave` is the 3rd+ unit (member), NOT the secondary master (standby)."""
    assert _normalize_vrp_istack_role("Slave") == "member"
    assert _normalize_vrp_istack_role("slave") == "member"


def test_normalize_vrp_istack_role_master_and_standby():
    """Master / Standby map to active / standby as expected."""
    assert _normalize_vrp_istack_role("Master") == "active"
    assert _normalize_vrp_istack_role("Standby") == "standby"


def test_normalize_vrp_istack_role_empty_or_unknown_defaults_to_member():
    """Unknown / empty role tokens fall through to normalize_role → member."""
    assert _normalize_vrp_istack_role("") == "member"
    assert _normalize_vrp_istack_role(None) == "member"
    assert _normalize_vrp_istack_role("Pending") == "member"


def test_parse_huawei_stack_basic_rows():
    """A canonical `display stack` row table parses into per-member dicts."""
    text = (
        "Stack mode: Yes\n"
        "Stack topology type: Ring\n"
        "Stack system MAC: 00e0-fc12-3456\n"
        "\n"
        "Slot   Role        Mac Address        Priority   Device Type\n"
        "-----------------------------------------------------------------\n"
        " 1     Master      00e0-fc12-3456     200        S5720-32X-EI-AC\n"
        " 2     Standby     00e0-fc12-7890     100        S5720-32X-EI-AC\n"
    )
    rows = _parse_huawei_stack(text)
    assert [(r["id"], r["role"], r["priority"]) for r in rows] == [
        (1, "Master", 200),
        (2, "Standby", 100),
    ]
    assert rows[0]["mac"] == "00e0-fc12-3456"
    assert rows[0]["model"] == "S5720-32X-EI-AC"


def test_parse_huawei_stack_skips_settings_block_and_separators():
    """Settings-block lines (`Stack mode: Yes`, etc.) and separators must not match the row regex."""
    text = (
        "Stack mode: Yes\n"
        "Slot of the active management port: 0\n"
        "-----------------------------------------------------------------\n"
        "Slot   Role        Mac Address        Priority   Device Type\n"
        "-----------------------------------------------------------------\n"
        " 1     Master      00e0-fc12-3456     200        S5720-32X-EI-AC\n"
    )
    rows = _parse_huawei_stack(text)
    assert [r["id"] for r in rows] == [1]


def test_parse_huawei_stack_strips_trailing_slot_chassis_column():
    """VRP CX-line variants append a Slot/Chassis column (`... CX310 1/120`); strip it from model."""
    text = (
        "Slot   Role        Mac Address        Priority   Device Type    Slot/Chassis\n"
        " 1     Master      00e0-fc12-3456     200        CX310          1/120\n"
        " 2     Slave       00e0-fc12-7890     100        CX310          1/121\n"
    )
    rows = _parse_huawei_stack(text)
    assert [(r["id"], r["model"]) for r in rows] == [(1, "CX310"), (2, "CX310")]


def test_parse_huawei_stack_accepts_three_token_device_type():
    """Some VRP releases append power/hardware variant tokens after the model name."""
    text = (
        "Slot   Role        Mac Address        Priority   Device Type\n"
        " 1     Master      00e0-fc12-3456     200        S5720-32X-EI-AC PWR-AC HW\n"
    )
    rows = _parse_huawei_stack(text)
    assert [r["id"] for r in rows] == [1]
    assert rows[0]["model"] == "S5720-32X-EI-AC PWR-AC HW"


def test_parse_huawei_stack_empty_output():
    """`Error: ...` standalone banner and empty input return no rows."""
    assert _parse_huawei_stack("") == []
    assert (
        _parse_huawei_stack(
            "Error: This command is supported only when the device works in stack mode.\n"
        )
        == []
    )


def test_parse_vrp_esn_by_slot_multi_line():
    """`display esn` on stacked VRP repeats one line per slot."""
    text = (
        "ESN of slot 1: 210235AAAA0000000001\n"
        "ESN of slot 2: 210235AAAA0000000002\n"
        "ESN of slot 3: 210235AAAA0000000003\n"
    )
    assert _parse_vrp_esn_by_slot(text) == {
        1: "210235AAAA0000000001",
        2: "210235AAAA0000000002",
        3: "210235AAAA0000000003",
    }


def test_parse_vrp_esn_by_slot_ignores_standalone_form():
    """`ESN of device:` (standalone form) is intentionally not consumed by the slot parser."""
    text = "ESN of device: 210235FFFFFF99999999\n"
    assert _parse_vrp_esn_by_slot(text) == {}


def test_parse_vrp_esn_by_slot_accepts_is_separator_variant():
    """Some VRP releases print `ESN of slot N is: SN` — the separator must not be captured as the serial."""
    text = "ESN of slot 1 is: 210235ISVARIANT00001\n"
    assert _parse_vrp_esn_by_slot(text) == {1: "210235ISVARIANT00001"}


def test_parse_vrp_esn_by_slot_requires_explicit_colon():
    """A line missing both `:` and `is:` separators must NOT match (no phantom serial like `is:`)."""
    text = "ESN of slot 1 ABC123\n"
    assert _parse_vrp_esn_by_slot(text) == {}


def test_chassis_members_display_stack_exception_logs_warning_with_traceback(caplog):
    """A surprise exception from `display stack` must surface at WARNING with exc_info."""
    driver = MagicMock()
    driver.device.send_command.side_effect = RuntimeError("boom")
    with caplog.at_level(logging.DEBUG, logger="custom_napalm.huawei_vrp"):
        result = _huawei_vrp_get_chassis_members_impl(driver)
    assert result is None
    warning_records = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("display stack failed" in r.message for r in warning_records)
    assert any(r.exc_info is not None and r.exc_info[0] is RuntimeError for r in warning_records)


def test_chassis_members_empty_stack_output_logs_debug(caplog):
    """Standalone VRP / CSS device → empty `display stack` → DEBUG, not WARNING."""
    driver = MagicMock()
    driver.device.send_command.return_value = (
        "Error: This command is supported only when the device works in stack mode.\n"
    )
    with caplog.at_level(logging.DEBUG, logger="custom_napalm.huawei_vrp"):
        result = _huawei_vrp_get_chassis_members_impl(driver)
    assert result is None
    assert not any(r.levelno >= logging.WARNING for r in caplog.records)
    assert any(
        r.levelno == logging.DEBUG and "no stack rows" in r.message for r in caplog.records
    )


def test_chassis_members_esn_failure_drops_members_logs_warning(caplog):
    """`display esn` error: WARNING+exc_info; members drop on empty serial; result is None."""
    driver = MagicMock()

    def _send(cmd):
        if cmd == "display stack":
            return (
                "Slot   Role        Mac Address        Priority   Device Type\n"
                "-----------------------------------------------------------------\n"
                " 1     Master      00e0-fc12-3456     200        S5720-32X-EI-AC\n"
                " 2     Standby     00e0-fc12-7890     100        S5720-32X-EI-AC\n"
            )
        raise RuntimeError("esn went sideways")

    driver.device.send_command.side_effect = _send
    with caplog.at_level(logging.DEBUG, logger="custom_napalm.huawei_vrp"):
        result = _huawei_vrp_get_chassis_members_impl(driver)
    assert result is None
    warning_records = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("display esn failed" in r.message for r in warning_records)
    assert any(r.exc_info is not None and r.exc_info[0] is RuntimeError for r in warning_records)
