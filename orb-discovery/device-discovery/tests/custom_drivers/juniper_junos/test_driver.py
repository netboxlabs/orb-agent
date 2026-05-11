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

from custom_napalm.junos import JunOSDriver, _junos_get_chassis_members_impl
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakePyEZDevice


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
