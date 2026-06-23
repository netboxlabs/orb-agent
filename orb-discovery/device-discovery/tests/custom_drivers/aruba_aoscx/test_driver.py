"""Unit tests for custom_napalm.aruba_aoscx.AOSCXDriver."""

from pathlib import Path

from custom_napalm.aruba_aoscx import AOSCXDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakePyaoscxSession


class TestAOSCXDriver(BaseDriverTest):
    """Unit tests for AOSCXDriver using file-based REST mock."""

    driver_cls = AOSCXDriver
    fake_device_cls = FakePyaoscxSession
    mock_data_root = Path(__file__).parent / "mock_data"

    def _build_driver(self, mock_dir: Path):
        """Instantiate AOSCXDriver with a fake pyaoscx session instead of a real one."""
        driver = object.__new__(AOSCXDriver)
        driver.hostname = "test-host"
        driver.username = "test-user"
        driver.password = "test-pass"
        driver.timeout = 60
        driver._verify_ssl = False
        driver.session = FakePyaoscxSession(mock_dir)
        return driver

    def test_aruba_rest_driver_exposes_get_modules(self):
        """AOSCXDriver must expose a callable get_modules (fails hard, no skip)."""
        assert hasattr(self.driver_cls, "get_modules")
        assert callable(self.driver_cls.get_modules)


def test_chassis_members_404_logs_debug_not_warning(caplog):
    """
    A 404 from pyaoscx (expected on non-VSF firmware) must log at DEBUG, not WARNING.

    Mirrors the Junos batch-2 RpcError → DEBUG discipline. Without this, every
    standalone AOS-CX device would emit a per-cycle WARNING during discovery
    because the VSF endpoint simply isn't there.
    """
    import logging
    from unittest.mock import MagicMock

    from napalm.base.exceptions import CommandErrorException

    from custom_napalm.aruba_aoscx import _aoscx_get_chassis_members_impl

    driver = MagicMock()
    driver._get.side_effect = CommandErrorException(
        "REST GET 'system/vsf_members?depth=2' returned HTTP 404: Not Found"
    )

    with caplog.at_level(logging.DEBUG, logger="custom_napalm.aruba_aoscx"):
        result = _aoscx_get_chassis_members_impl(driver)

    assert result is None
    assert not any(
        r.levelno >= logging.WARNING for r in caplog.records
    ), "404 (expected on non-VSF firmware) must NOT log at WARNING level"
    assert any(
        r.levelno == logging.DEBUG and "VSF endpoint not present" in r.message
        for r in caplog.records
    ), "expected DEBUG log explaining the standalone-AOS-CX fallback"


def test_chassis_members_unexpected_exception_logs_warning_with_traceback(caplog):
    """Any non-404 exception (transport / pyaoscx bug) must surface as WARNING with exc_info."""
    import logging
    from unittest.mock import MagicMock

    from custom_napalm.aruba_aoscx import _aoscx_get_chassis_members_impl

    driver = MagicMock()
    driver._get.side_effect = RuntimeError("boom")

    with caplog.at_level(logging.DEBUG, logger="custom_napalm.aruba_aoscx"):
        result = _aoscx_get_chassis_members_impl(driver)

    assert result is None
    warning_records = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "unexpected fetch failure" in r.message
    ]
    assert warning_records, "non-404 exceptions must log at WARNING so operators see real problems"
    # Traceback must be attached (exc_info=True). Same regression guard as the Junos batch-2 test.
    assert warning_records[0].exc_info is not None and warning_records[0].exc_info[0] is RuntimeError, (
        "WARNING record must carry the traceback (exc_info) so operators can diagnose"
    )
