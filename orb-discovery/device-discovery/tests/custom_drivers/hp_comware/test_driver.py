"""Unit tests for custom_napalm.hp_comware.ComwareDriver."""

import logging
from pathlib import Path
from unittest.mock import MagicMock

from custom_napalm.hp_comware import (
    _COMWARE_FAMILY_PREFIXES,
    _COMWARE_SUPERVISOR_TOKENS,
    ComwareDriver,
    _comware_classify_module,
    _comware_get_chassis_members_impl,
    _comware_is_modular,
    _normalize_irf_mac,
    _parse_comware_irf,
)
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestComwareDriver(BaseDriverTest):
    """Unit tests for ComwareDriver using file-based CLI mocks."""

    driver_cls = ComwareDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"


# --- IRF helper unit tests ---------------------------------------------------


def test_normalize_irf_mac_handles_dashed_form():
    """Comware's 4-hex-group dashed MAC reduces to lowercase no-separator form."""
    assert _normalize_irf_mac("0023-AABB-CCDD") == "0023aabbccdd"
    assert _normalize_irf_mac("0023-aabb-ccdd") == "0023aabbccdd"


def test_normalize_irf_mac_rejects_zero_sentinel():
    """The 0000-0000-0000 placeholder Comware uses for Down members must return None."""
    assert _normalize_irf_mac("0000-0000-0000") is None


def test_normalize_irf_mac_rejects_garbage():
    """Empty, None, and unparseable strings all return None (no exceptions)."""
    assert _normalize_irf_mac(None) is None
    assert _normalize_irf_mac("") is None
    assert _normalize_irf_mac("not-a-mac") is None
    assert _normalize_irf_mac("0023-aabb") is None  # too short


def test_parse_comware_irf_stops_at_legend():
    """Row parsing must stop at the `* indicates ...` legend so settings-block tokens don't leak in."""
    text = (
        "MemberID    Role        Priority  CPU-Mac           Description\n"
        "*+1         Master      32        0023-aabb-ccdd    ---\n"
        "  2         Standby     32        0023-aabb-ccef    ---\n"
        "\n"
        "* indicates the device is the master.\n"
        "+ indicates the device through which the user logs in.\n"
        "\n"
        # These post-legend lines deliberately look member-row-ish to ensure the
        # legend break is the gate, not the regex shape.
        "The Bridge MAC of the IRF is: 0023-aabb-ccff\n"
        "Domain ID                   : 30\n"
    )
    rows, domain = _parse_comware_irf(text)
    assert [r["id"] for r in rows] == [1, 2]
    assert domain == "30"


def test_parse_comware_irf_empty_input():
    """Empty input returns empty rows and None domain — caller logs DEBUG and returns None."""
    rows, domain = _parse_comware_irf("")
    assert rows == []
    assert domain is None


def test_parse_comware_irf_tolerates_slot_column():
    """Modular H3C/HPE platforms print `MemberID Slot Role ...` — must still parse."""
    text = (
        "MemberID    Slot    Role        Priority  CPU-Mac           Description\n"
        "*+1         0       Master      32        0023-3333-aaaa    chassis-A\n"
        "  2         0       Slave       16        0023-4444-bbbb    chassis-B\n"
        "\n"
        "* indicates the device is the master.\n"
        "Domain ID                   : 7\n"
    )
    rows, domain = _parse_comware_irf(text)
    assert [(r["id"], r["role"], r["priority"]) for r in rows] == [
        (1, "Master", 32),
        (2, "Slave", 16),
    ]
    assert domain == "7"


def test_parse_comware_irf_no_domain_block():
    """Older Comware releases omit the Domain ID line — payload domain stays None."""
    text = (
        "MemberID    Role        Priority  CPU-Mac           Description\n"
        "*+1         Master      32        0023-aabb-ccdd    ---\n"
    )
    _, domain = _parse_comware_irf(text)
    assert domain is None


def test_parse_comware_irf_accepts_disabled_stack_marker():
    """A `>` prefix marks a member with stack capability disabled — must still parse."""
    text = (
        "MemberID    Role        Priority  CPU-Mac           Description\n"
        "*+1         Master      32        0023-aabb-ccdd    ---\n"
        ">  2        Standby     16        0023-aabb-ccef    disabled\n"
        "\n"
        "* indicates the device is the master.\n"
        "Domain ID                   : 12\n"
    )
    rows, domain = _parse_comware_irf(text)
    assert [(r["id"], r["role"], r["priority"]) for r in rows] == [
        (1, "Master", 32),
        (2, "Standby", 16),
    ]
    assert domain == "12"


def test_parse_comware_irf_accepts_topo_domain_label():
    """Legacy Comware 5 outputs print ``Topo-domain ID`` instead of ``Domain ID``."""
    text = (
        "MemberID    Role        Priority  CPU-Mac           Description\n"
        "*+1         Master      32        0023-aabb-ccdd    ---\n"
        "  2         Standby     16        0023-aabb-ccef    ---\n"
        "\n"
        "* indicates the device is the master.\n"
        "Topo-domain ID              : 55\n"
    )
    _, domain = _parse_comware_irf(text)
    assert domain == "55"


def test_chassis_members_irf_exception_logs_warning_with_traceback(caplog):
    """A surprise exception from `display irf` must surface at WARNING with exc_info."""
    driver = MagicMock()
    driver.device.send_command.side_effect = RuntimeError("boom")
    with caplog.at_level(logging.DEBUG, logger="custom_napalm.hp_comware"):
        result = _comware_get_chassis_members_impl(driver)
    assert result is None
    warning_records = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warning_records, "expected a WARNING record"
    assert any("display irf failed" in r.message for r in warning_records)
    # The traceback must be attached — confirms exc_info=True was passed.
    assert any(r.exc_info is not None and r.exc_info[0] is RuntimeError for r in warning_records)


def test_chassis_members_empty_irf_output_logs_debug(caplog):
    """No IRF rows in `display irf` is the standalone case — DEBUG, not WARNING."""
    driver = MagicMock()
    # display irf returns an empty / unrecognized banner; display device manuinfo
    # never gets called because we return early.
    driver.device.send_command.return_value = ""
    with caplog.at_level(logging.DEBUG, logger="custom_napalm.hp_comware"):
        result = _comware_get_chassis_members_impl(driver)
    assert result is None
    assert not any(r.levelno >= logging.WARNING for r in caplog.records)
    assert any(
        r.levelno == logging.DEBUG and "no IRF rows" in r.message for r in caplog.records
    )


def test_chassis_members_manuinfo_failure_drops_members_logs_warning(caplog):
    """`display device manuinfo` error: WARNING+exc_info, members drop on empty serial, result is None."""
    driver = MagicMock()

    def _send(cmd):
        if cmd == "display irf":
            return (
                "MemberID    Role        Priority  CPU-Mac           Description\n"
                "*+1         Master      32        0023-aabb-ccdd    ---\n"
                "  2         Standby     32        0023-aabb-ccef    ---\n"
                "\n"
                "* indicates the device is the master.\n"
                "Domain ID                   : 30\n"
            )
        raise RuntimeError("manuinfo went sideways")

    driver.device.send_command.side_effect = _send
    with caplog.at_level(logging.DEBUG, logger="custom_napalm.hp_comware"):
        result = _comware_get_chassis_members_impl(driver)
    # No serial join data → every member drops via to_payload → result is None.
    assert result is None
    warning_records = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("display device manuinfo failed" in r.message for r in warning_records)
    assert any(r.exc_info is not None and r.exc_info[0] is RuntimeError for r in warning_records)


# --- get_modules attribute test ---------------------------------------------


def test_driver_exposes_get_modules():
    """ComwareDriver MUST expose a callable get_modules method."""
    assert hasattr(ComwareDriver, "get_modules")
    assert callable(ComwareDriver.get_modules)


# --- classifier unit tests ---------------------------------------------------


def test_classifier_supervisor_by_mpu_token():
    """SKUs containing ``MPU`` classify as supervisor across every family."""
    assert _comware_classify_module("LSQM1MPUC0") == "supervisor"   # S7500E
    assert _comware_classify_module("LSUM1MPUH1") == "supervisor"   # S10500
    assert _comware_classify_module("LSXM1MPUD0") == "supervisor"   # S10500
    assert _comware_classify_module("LSXM2MPUD0") == "supervisor"   # S12500X-AF
    assert _comware_classify_module("LSXM2MPUA1") == "supervisor"   # S12900


def test_classifier_supervisor_by_sup_token():
    """The rarer ``SUP``-token variants (e.g. ``LSUM1SUPXD0``) also classify as supervisor."""
    assert _comware_classify_module("LSUM1SUPXD0") == "supervisor"


def test_classifier_interface_cards_with_supervisor_prefix_are_linecards():
    """
    LSQM / LSUM / LSXM interface cards (NOT containing MPU/SUP) classify as linecard.

    This is the regression that the family-prefix-only classifier failed: H3C
    reuses the same family prefix for MPU and interface cards, so prefix
    matching alone would mis-emit every interface card as a supervisor.
    """
    assert _comware_classify_module("LSQM1FH48EA") == "linecard"   # S7500E interface
    assert _comware_classify_module("LSQM1FV48EA") == "linecard"
    assert _comware_classify_module("LSXM2SF40C") == "linecard"    # S12500X-AF fabric
    assert _comware_classify_module("LSXM2QGS56QHB1") == "linecard"  # interface card
    assert _comware_classify_module("LSXM2FX48LEB1") == "linecard"
    assert _comware_classify_module("LSUM1QGS24XEC0") == "linecard"  # S10500 interface


def test_classifier_other_family_prefixes_are_linecards():
    """LSQS / LSXS / LSQ1 / LSQ2 / LSQK / LSX1 / LSX2 / LSR / LSU classify as linecard."""
    for prefix in ("LSQS", "LSXS", "LSQ1", "LSQ2", "LSQK", "LSX1", "LSX2", "LSR", "LSU"):
        assert _comware_classify_module(f"{prefix}1FX48LEB1") == "linecard", prefix


def test_classifier_case_insensitive():
    """Classifier is case-insensitive (real output is uppercase; defensive)."""
    assert _comware_classify_module("lsxm2mpud0") == "supervisor"
    assert _comware_classify_module("lsxs1fab320a") == "linecard"


def test_classifier_unknown_returns_other():
    """SKUs that match no family prefix classify as 'other' (dropped by impl)."""
    assert _comware_classify_module("XYZ-UNKNOWN") == "other"
    assert _comware_classify_module("") == "other"
    assert _comware_classify_module("   ") == "other"


def test_classifier_supervisor_token_wins_over_family_prefix():
    """
    Supervisor-token check runs BEFORE family-prefix fallback.

    Without this ordering, an MPU SKU on an LSQM/LSUM/LSXM-family chassis
    would classify as linecard via the family-prefix branch.
    """
    sku = "LSXM2MPUD0"
    assert sku.startswith(_COMWARE_FAMILY_PREFIXES)
    assert any(token in sku for token in _COMWARE_SUPERVISOR_TOKENS)
    assert _comware_classify_module(sku) == "supervisor"


# --- family detection unit tests --------------------------------------------


def test_is_modular_accepts_documented_families():
    """All four modular families resolve to True."""
    assert _comware_is_modular("S7503E")
    assert _comware_is_modular("S10508")
    assert _comware_is_modular("S12508X-AF")
    assert _comware_is_modular("S12916-AF")


def test_is_modular_handles_vendor_prefixed_models():
    """Vendor-prefixed and HPE-rebranded model strings still resolve correctly."""
    assert _comware_is_modular("H3C S12508X-AF")
    assert _comware_is_modular("HPE FlexFabric S12500")
    assert _comware_is_modular("HP S10508")
    # HPE rebrand strips the ``S`` prefix on the family name.
    assert _comware_is_modular("HPE FlexFabric 12500 Switch")
    # Comware-5 HP-branded ``A`` prefix on the family name.
    assert _comware_is_modular("HP A10500")


def test_is_modular_rejects_fixed_families():
    """Fixed pizza-box families return False."""
    assert not _comware_is_modular("S5500-28C-EI")
    assert not _comware_is_modular("S5800-32F")
    assert not _comware_is_modular("S6800-54QF")
    assert not _comware_is_modular("")
    assert not _comware_is_modular("Unknown")
