"""Unit tests for custom_napalm.huawei_vrp.VRPDriver."""

import logging
from pathlib import Path
from unittest.mock import MagicMock

from custom_napalm import huawei_vrp
from custom_napalm.huawei_vrp import (
    VRPDriver,
    _huawei_vrp_get_chassis_members_impl,
    _normalize_vrp_istack_role,
    _parse_huawei_stack,
    _parse_vrp_esn_by_slot,
    _yunshan_version_facts,
)
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestVRPDriver(BaseDriverTest):
    """Unit tests for VRPDriver using file-based CLI mocks."""

    driver_cls = VRPDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"

    def test_vrp_driver_exposes_get_modules(self):
        """VRPDriver must expose a callable get_modules (fails hard, no skip)."""
        assert hasattr(self.driver_cls, "get_modules")
        assert callable(self.driver_cls.get_modules)


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


# --- YunShan OS display version ----------------------------------------------

_YUNSHAN_HEADER = (
    "Huawei YunShan OS\n"
    "Version 1.23.1.1 (S5700 V600R023C10SPC500)\n"
    "Copyright (C) 2021-2024 Huawei Technologies Co., Ltd.\n"
    "HUAWEI CloudEngine S5735-L-V2 uptime is 120 days, 3 hours, 15 minutes\n"
)


def test_yunshan_version_facts_reads_version_and_master_board():
    """YunShan's `Version` line gives os_version; the Master board line, not another member's, gives the model."""
    text = (
        _YUNSHAN_HEADER
        + "\nS5735-L24T4XE-A-V2(Standby) 2 : uptime is  120 days, 3 hours, 13 minutes\n"
        + "\nS5735-L48T4XE-A-V2(Master) 1 : uptime is  120 days, 3 hours, 14 minutes\n"
    )
    assert _yunshan_version_facts(text) == {"os_version": "1.23.1.1", "model": "S5735-L48T4XE-A-V2"}


def test_yunshan_version_facts_without_master_board_leaves_model_alone():
    """No Master board line: only os_version is returned, so the template's headline model stays."""
    assert _yunshan_version_facts(_YUNSHAN_HEADER) == {"os_version": "1.23.1.1"}


def test_yunshan_version_facts_ignores_a_control_board_named_master():
    """On a modular chassis the Master line names the control board (`MPU`), not a model of the headline series."""
    text = (
        "Huawei YunShan OS\n"
        "Version 1.22.0.1 (S12700E V600R022C10SPC100)\n"
        "HUAWEI S12700E-8 uptime is 30 days, 1 hour, 5 minutes\n"
        "\nMPU(Master) 9 : uptime is 30 days, 1 hour, 4 minutes\n"
    )
    assert _yunshan_version_facts(text) == {"os_version": "1.22.0.1"}


def test_yunshan_version_facts_reads_the_series_after_the_vendor_name():
    """The series is the product word after `HUAWEI`, so a trailing `Routing Switch` does not hide it."""
    text = (
        "Huawei YunShan OS\n"
        "Version 1.23.1.1 (S5700 V600R023C10SPC500)\n"
        "HUAWEI S5735-L48T4X-A1 Routing Switch uptime is 2 days, 1 hour, 5 minutes\n"
        "\nS5735-L48T4X-A1(Master) 1 : uptime is 2 days, 1 hour, 4 minutes\n"
    )
    assert _yunshan_version_facts(text) == {"os_version": "1.23.1.1", "model": "S5735-L48T4X-A1"}


def test_yunshan_version_facts_without_headline_leaves_model_alone():
    """Without the uptime headline there is no series to check the board against, so no model is taken."""
    text = "Huawei YunShan OS\nVersion 1.23.1.1 (S5700 V600R023C10SPC500)\n\nS5735-L48T4XE-A-V2(Master) 1 : uptime is 1 day\n"
    assert _yunshan_version_facts(text) == {"os_version": "1.23.1.1"}


def _yunshan_driver(getter_dir: str) -> VRPDriver:
    driver = object.__new__(VRPDriver)
    driver.hostname = "192.0.2.20"
    driver.device = FakeCLIDevice(Path(__file__).parent / "mock_data" / getter_dir / "yunshan")
    return driver


def test_get_facts_warning_names_the_device(monkeypatch, caplog):
    """Skipped YunShan lines are logged against the device's host, so a policy with many targets stays traceable."""
    monkeypatch.setattr(huawei_vrp, "_skip_warned", set())

    with caplog.at_level(logging.WARNING, logger="custom_napalm.huawei_vrp"):
        _yunshan_driver("test_get_facts").get_facts()

    messages = [r.getMessage() for r in caplog.records]
    assert len(messages) == 2
    assert all("192.0.2.20" in m for m in messages)


def test_get_interfaces_warning_names_the_device(monkeypatch, caplog):
    """`display interface` skips are logged against the device's host too."""
    monkeypatch.setattr(huawei_vrp, "_skip_warned", set())

    with caplog.at_level(logging.WARNING, logger="custom_napalm.huawei_vrp"):
        _yunshan_driver("test_get_interfaces").get_interfaces()

    messages = [r.getMessage() for r in caplog.records]
    assert len(messages) == 1
    assert "192.0.2.20" in messages[0]
    assert "skipped 2 lines" in messages[0]


def test_yunshan_version_facts_ignores_vrp_output():
    """VRP output without the YunShan banner is left to the template, even with lookalike lines."""
    text = (
        "Huawei Versatile Routing Platform Software\n"
        "VRP (R) software, Version 5.170 (S5735 V200R022C00SPC500)\n"
        "HUAWEI S5735-L48T4X-A1 Routing Switch uptime is 10 weeks, 1 day, 2 hours, 3 minutes\n"
        "\n"
        "Version 9.9.9 (lookalike)\n"
        "S5735-L48T4X-A1(Master) 0 : uptime is 10 weeks\n"
    )
    assert _yunshan_version_facts(text) == {}
