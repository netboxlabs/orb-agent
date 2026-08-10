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


def test_orphan_optic_out_of_roster_member_dropped_with_warning(caplog):
    """
    An orphan optic naming an out-of-roster VSF member must be dropped, with a warning.

    Mirrors the subsystem loop's own out-of-roster guard ("subsystem member
    %s not in VSF set") so the promotion path reads the same way instead of
    staying silent and deferring to translate's generic orphan_member
    warning two layers away.
    """
    import logging
    from unittest.mock import MagicMock

    from napalm.base.exceptions import CommandErrorException

    from custom_napalm.aruba_aoscx import _aruba_get_modules_impl

    subsystems = {
        "chassis,1": {
            "product_info": {"part_number": "JL375A", "serial_number": "SGROSTCHA1", "product_name": "8400 Chassis"},
        },
        "line_card,1/3": {
            "product_info": {"part_number": "JL363A", "serial_number": "SGROSTLC1", "product_name": "8400X 32p"},
        },
        "chassis,2": {
            "product_info": {"part_number": "JL375A", "serial_number": "SGROSTCHA2", "product_name": "8400 Chassis"},
        },
        "line_card,2/3": {
            "product_info": {"part_number": "JL363A", "serial_number": "SGROSTLC2", "product_name": "8400X 32p"},
        },
    }
    # Optic on member 3 — no line_card,3/x subsystem exists, so it's an
    # orphan; member 3 is also absent from the roster (only 1 and 2 own
    # subsystem slots), so the promotion guard must refuse it.
    interfaces = {
        "3/1/1": {
            "name": "3/1/1",
            "hw_intf_info": {"product_number": "SFP-10G-LR", "serial_number": "OPTIC-OUT-OF-ROSTER"},
        },
    }

    def fake_get(path: str):
        if path.startswith("system/subsystems"):
            return subsystems
        if path.startswith("system/interfaces"):
            return interfaces
        raise CommandErrorException(f"REST GET {path!r} returned HTTP 404: Not Found")

    driver = MagicMock()
    driver._get.side_effect = fake_get

    with caplog.at_level(logging.DEBUG, logger="custom_napalm.aruba_aoscx"):
        result = _aruba_get_modules_impl(driver)

    assert result is not None
    members = result["members"]
    assert set(members.keys()) == {1, 2}, "out-of-roster member 3 must not appear as a bucket"
    all_serials = {
        bay["module"]["serial"] for member in members.values() for bay in member["bays"]
    }
    assert "OPTIC-OUT-OF-ROSTER" not in all_serials, (
        "orphan optic on an out-of-roster member must not be promoted anywhere"
    )

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any(
        "3/1/1" in r.message and "not in VSF set" in r.message for r in warnings
    ), "expected a warning naming the dropped orphan optic and its out-of-roster member"
