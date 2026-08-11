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

    def test_get_modules_declines_promotion_onto_unusable_line_card_slot(self, caplog) -> None:
        """
        A claimed-but-unusable ``line_card`` slot is not promoted.

        ``line_card,1/3`` is present (so slot ``1/3`` is claimed by the RAW
        subsystem inventory) but its own row has a blank serial, so no bay
        was built for it. The optic at ``1/3/1`` must NOT be promoted to a
        device-rooted bay — that would invent a chassis-level parent for a
        line card that genuinely exists in hardware. ``line_card,1/4`` (a
        usable claim, in the same fixture) still promotes its own optic
        normally, proving the guard doesn't overreach.
        """
        import logging

        mock_dir = self.mock_data_root / "test_get_modules" / "line_card_row_unusable_not_promoted"
        driver = self._build_driver(mock_dir)

        with caplog.at_level(logging.DEBUG, logger="custom_napalm.aruba_aoscx"):
            result = driver.get_modules()

        assert result is not None
        member = result["members"][None]
        bay_names = {bay["name"] for bay in member["bays"]}
        assert "1/3" not in bay_names
        assert "1/3/1" not in bay_names
        all_serials = {bay["module"]["serial"] for bay in member["bays"]} | {
            sub["module"]["serial"]
            for bay in member["bays"]
            for sub in bay["module"]["sub_bays"]
        }
        assert "OPTICCASEB01" not in all_serials, (
            "the optic on the claimed-but-unusable line_card,1/3 slot must not be promoted"
        )
        # line_card,1/4's own optic (a normal, usable claim) still promotes.
        assert "OPTICCASEB02" in all_serials

        assert any(
            "1/3" in r.getMessage() and "unusable" in r.getMessage()
            for r in caplog.records
        ), "declining promotion must name the claimed slot at debug"

    def test_get_modules_unknown_chassis_family_declines_with_warning_naming_part_number(
        self, caplog,
    ) -> None:
        """
        An unknown chassis family must decline promotion and warn, naming the part number.

        ``system/subsystems`` reports only a chassis row whose family (a
        fictitious "9300") is not on the fixed-port allowlist, with no
        line_card subsystem at all — the same shape a genuinely new Aruba
        fixed-port family would report before its family is added to the
        allowlist. The optic at ``1/1/1`` must be declined, and the WARNING
        must name the chassis part number so a new family surfaces in logs
        rather than silently disabling discovery for it.
        """
        import logging

        mock_dir = self.mock_data_root / "test_get_modules" / "unknown_chassis_family_declined"
        driver = self._build_driver(mock_dir)

        with caplog.at_level(logging.DEBUG, logger="custom_napalm.aruba_aoscx"):
            result = driver.get_modules()

        assert result is None

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert any(
            "JL999Z" in r.getMessage() and "not a known fixed-port family" in r.getMessage()
            for r in warnings
        ), "declining promotion for an unknown chassis family must name its part number"

    def test_get_modules_psu_fan_slot_collision_still_promotes_optic(self) -> None:
        """
        A PSU/fan sharing an optic slot's address does not suppress that optic.

        ``power_supply,1/1`` and ``fan,1/1`` collide in address with a fixed
        6300M's optic slot ``1/1``. Both are subsystem types positively
        known to never be a bay, so neither claims the slot — the optic at
        ``1/1/1`` is still promoted. A shape-only claim (not type-aware)
        would have suppressed it.
        """
        mock_dir = self.mock_data_root / "test_get_modules" / "psu_fan_collision_still_promoted"
        driver = self._build_driver(mock_dir)
        result = driver.get_modules()
        assert result is not None
        member = result["members"][None]
        assert len(member["bays"]) == 1
        assert member["bays"][0]["name"] == "1/1/1"
        assert member["bays"][0]["module"]["serial"] == "OPTICCOLL001"


def test_unrecognised_subsystem_type_claims_slot_and_warns(caplog) -> None:
    """
    An unrecognised subsystem type at a two-segment addr claims the slot AND warns.

    A brand-new subsystem kind this driver has never classified must fail
    safe: claim the slot (so an optic there is declined rather than
    promoted to a device-rooted bay) and say so at WARNING, naming the
    type string, rather than silently behaving like a known non-bay type.
    """
    import logging
    from unittest.mock import MagicMock

    from napalm.base.exceptions import CommandErrorException

    from custom_napalm.aruba_aoscx import _aruba_get_modules_impl

    subsystems = {
        "chassis,1": {
            "product_info": {"part_number": "JL658A", "serial_number": "SGUNREC0001", "product_name": "6300M 48p"},
        },
        "environmental_module,1/2": {
            "product_info": {"part_number": "", "serial_number": "", "product_name": ""},
        },
    }
    interfaces = {
        "1/2/1": {
            "name": "1/2/1",
            "hw_intf_info": {"product_number": "SFP-10G-LR", "serial_number": "OPTICUNREC01"},
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

    # The declined optic leaves nothing else to promote — get_modules
    # returns None (the chassis row itself never becomes a bay either).
    assert result is None

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any(
        "environmental_module" in r.message and "1/2" in r.message for r in warnings
    ), "expected a warning naming the unrecognised subsystem type and its addr"


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
