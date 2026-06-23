"""
Tests for the JunOSDriver subclass.

Covers two extension surfaces beyond the inherited NAPALM behaviour:

- ``get_interfaces_vlans``: VLAN-interface associations parsed from the
  ELS / non-ELS ``<get-ethernet-switching-interface-information>`` reply.
  Driven by file-based scenario fixtures via ``BaseDriverTest``.
- ``get_chassis_members``: Junos Virtual Chassis discovery via
  ``<get-virtual-chassis-information>``. Scenario fixtures cover the
  parsing paths; the unit-level tests below pin the log-level discipline
  (``RpcError`` → DEBUG; other exceptions → WARNING) so standalone
  EX/QFX devices do not produce per-cycle warning noise.
"""

import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from jnpr.junos.exception import RpcError

from custom_napalm.junos import (
    JunOSDriver,
    _junos_get_chassis_members_impl,
    classify_module_type_junos,
)
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakePyEZDevice


@pytest.mark.parametrize("part_number,description,name,expected", [
    # Junos reports transceivers as "Xcvr N" leaf elements — the element NAME
    # is the optic signal, NOT the description (which can advertise port caps).
    ("740-021308", "SFP+-10G-SR", "Xcvr 0", "transceiver"),
    ("740-061405", "SFP28-25G-SR", "Xcvr 0", "transceiver"),
    ("740-058734", "QSFP28-100G-LR4", "Xcvr 1", "transceiver"),
    # MSA-prefixed part still wins via is_optic_pid regardless of name.
    ("QSFP-100G-LR4", "", "Xcvr 0", "transceiver"),
    # codex-3 regression (the bug): FPC/PIC descriptions advertise PORT
    # CAPABILITIES ("48x SFP/SFP+ ports", "4x 40GE QSFP+") that the old
    # description regex false-matched as transceiver, dropping the linecard
    # bay + its interfaces in linecards mode. Name-gating keeps them linecard.
    ("750-054576", "48x SFP/SFP+ ports", "PIC 0", "linecard"),
    ("750-054576", "4x 40GE QSFP+", "PIC 1", "linecard"),
    ("750-068369", "MPC7E 3D MRATE-12xQSFPP-XGE-XLGE-CGE", "FPC 0", "linecard"),
    # Routing Engine maps to supervisor (Junos uses RE terminology).
    ("740-031116", "RE-S-1800x4 Routing Engine", "Routing Engine 0", "supervisor"),
    # RE classification is name-based for robustness: even an empty/terse
    # description maps to supervisor when the element is named "Routing Engine N".
    ("740-x", "RE-S-2X00x6", "Routing Engine 0", "supervisor"),
    # A non-MSA element NOT named Xcvr falls through to linecard (name-gating).
    ("750-xxxx", "some linecard", "FPC 2", "linecard"),
    # A Midplane-like FRU classifies as linecard (the default) — but the parse
    # gate skips it at the top level, so this never reaches Diode emission.
    # The gate is the real protection; the classifier is secondary.
    ("711-x", "Midplane", "Midplane", "linecard"),
])
def test_classify_module_type_junos(part_number, description, name, expected):
    """Optics classify by the Xcvr element name (or MSA part); descriptions never gate."""
    assert classify_module_type_junos(part_number, description, name) == expected


class TestJunOSDriver(BaseDriverTest):
    """Tests for the Juniper Junos custom NAPALM driver."""

    driver_cls = JunOSDriver
    fake_device_cls = FakePyEZDevice
    mock_data_root = Path(__file__).parent / "mock_data"

    def test_get_facts(self, scenario):
        """Skip: inherited from napalm.junos.junos.JunOSDriver."""
        pytest.skip("inherited from napalm.junos.junos.JunOSDriver")

    def test_get_interfaces(self, scenario):
        """Skip: inherited from napalm.junos.junos.JunOSDriver."""
        pytest.skip("inherited from napalm.junos.junos.JunOSDriver")

    def test_get_interfaces_ip(self, scenario):
        """Skip: inherited from napalm.junos.junos.JunOSDriver."""
        pytest.skip("inherited from napalm.junos.junos.JunOSDriver")

    def test_get_config(self, scenario):
        """Skip: inherited from napalm.junos.junos.JunOSDriver."""
        pytest.skip("inherited from napalm.junos.junos.JunOSDriver")

    def test_get_config_sanitized(self, scenario):
        """Skip: inherited from napalm.junos.junos.JunOSDriver."""
        pytest.skip("inherited from napalm.junos.junos.JunOSDriver")

    def test_get_vlans(self, scenario):
        """Skip: inherited from napalm.junos.junos.JunOSDriver."""
        pytest.skip("inherited from napalm.junos.junos.JunOSDriver")

    def test_junos_driver_exposes_get_modules(self) -> None:
        """get_modules() must exist on JunOSDriver after this batch lands."""
        assert hasattr(JunOSDriver, "get_modules")
        assert callable(getattr(JunOSDriver, "get_modules"))


def test_chassis_members_rpc_error_logs_debug_not_warning(caplog):
    """
    Standalone EX/QFX (no VC) raises RpcError — must log at DEBUG, not WARNING.

    Without this discipline every non-VC Junos device would emit a per-cycle
    WARNING during discovery, drowning out signals operators actually care about.
    """
    driver = MagicMock()
    driver.device.rpc.get_virtual_chassis_information.side_effect = RpcError(
        rsp="virtual-chassis information not available"
    )

    with caplog.at_level(logging.DEBUG, logger="custom_napalm.junos"):
        result = _junos_get_chassis_members_impl(driver)

    assert result is None
    assert not any(
        r.levelno >= logging.WARNING for r in caplog.records
    ), "RpcError on standalone Junos must NOT log at WARNING level"
    assert any(
        r.levelno == logging.DEBUG and "RPC not supported" in r.message
        for r in caplog.records
    ), "expected DEBUG log explaining the standalone-Junos fallback"


def test_chassis_members_unexpected_exception_logs_warning(caplog):
    """
    Any non-RpcError exception (transport / driver bug) must still surface as WARNING.

    The WARNING must include exception info (traceback) — without it, operators
    only see the exception string, which is rarely enough to root-cause transport
    or PyEZ failures.
    """
    driver = MagicMock()
    driver.device.rpc.get_virtual_chassis_information.side_effect = RuntimeError("boom")

    with caplog.at_level(logging.DEBUG, logger="custom_napalm.junos"):
        result = _junos_get_chassis_members_impl(driver)

    assert result is None
    warning_records = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "unexpected RPC failure" in r.message
    ]
    assert warning_records, "non-RpcError exceptions must log at WARNING so operators see real problems"
    # Traceback must be attached. Python sets r.exc_info to a 3-tuple when
    # exc_info=True is passed (or via logger.exception); falsy otherwise.
    assert warning_records[0].exc_info is not None and warning_records[0].exc_info[0] is RuntimeError, (
        "WARNING record must carry the traceback (exc_info) so operators can diagnose"
    )
