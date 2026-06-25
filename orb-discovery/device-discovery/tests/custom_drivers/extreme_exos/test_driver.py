"""Unit tests for custom_napalm.extreme_exos.ExosDriver."""

from pathlib import Path

from custom_napalm.extreme_exos import (
    _EXOS_MODULE_CLASSIFIER,
    ExosDriver,
    _exos_classify_module,
    _exos_is_modular,
    _parse_show_slot_detail,
)
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestExosDriver(BaseDriverTest):
    """Unit tests for ExosDriver using file-based CLI mocks."""

    driver_cls = ExosDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"


def test_get_facts_captures_multi_token_model(tmp_path: Path) -> None:
    """get_facts() must capture multi-token System Type values like 'BlackDiamond X8'."""
    mock_dir = tmp_path / "test_get_facts" / "bdx8"
    mock_dir.mkdir(parents=True)
    (mock_dir / "show_version.txt").write_text(
        "Switch      : BD-X8 (800533-00-01) Rev 1.0 Boot PROM Version v1.0.0.1\n"
        "System MAC  : 00:04:96:01:02:03\n"
        "System Type : BlackDiamond X8\n"
        "SysName     : bdx8-lab\n"
        "SysSerial   : 1234N-12345\n"
        "Recovery Mode: None\n"
        "MSM/MM      : MSM-A (Master) - Up 1 day\n"
        "PowerSupply : Internal-PS\n"
        "\nImage   : Version 30.7.1.4 build by release-manager\n"
    )
    drv = object.__new__(ExosDriver)
    drv.hostname = drv.username = drv.password = "test"
    drv.timeout = 60
    drv.device = FakeCLIDevice(mock_dir)
    facts = drv.get_facts()
    assert facts["model"] == "BlackDiamond X8"


# --- get_modules attribute test ----------------------------------------------


def test_driver_exposes_get_modules() -> None:
    """ExosDriver MUST expose a callable get_modules method."""
    assert hasattr(ExosDriver, "get_modules")
    assert callable(ExosDriver.get_modules)


# --- classifier unit tests ---------------------------------------------------


def test_classifier_supervisor_beats_linecard_prefix() -> None:
    """BDX-MM (supervisor) MUST be checked before BDXA-/BDXB- linecard prefixes."""
    assert _exos_classify_module("BDX-MM1") == "supervisor"


def test_classifier_fabric_modules_are_linecards() -> None:
    """Extreme BD-X8 Fabric Modules classify as linecards (no NetBox fabric type)."""
    assert _exos_classify_module("BDXA-FM-160T") == "linecard"
    # Hypothetical future BDXB-FM-* still resolves via the BDXB- fallback.
    assert _exos_classify_module("BDXB-FM-320T") == "linecard"


def test_classifier_io_modules_are_linecards() -> None:
    """BDXA-/BDXB- I/O modules classify as linecards."""
    assert _exos_classify_module("BDXA-10G48X") == "linecard"
    assert _exos_classify_module("BDXA-40G24X") == "linecard"
    assert _exos_classify_module("BDXB-100G12X") == "linecard"


def test_classifier_unknown_returns_other() -> None:
    """SKUs that match no prefix classify as 'other'."""
    assert _exos_classify_module("XYZ-UNKNOWN") == "other"
    assert _exos_classify_module("") == "other"
    assert _exos_classify_module("   ") == "other"


def test_classifier_ordering_invariant() -> None:
    """Longer prefixes that contain shorter prefixes as substrings MUST appear first."""
    prefixes = [p for p, _ in _EXOS_MODULE_CLASSIFIER]
    for i, short in enumerate(prefixes):
        for j, longer in enumerate(prefixes):
            if i == j or len(longer) <= len(short):
                continue
            if longer.startswith(short):
                assert j < i, (
                    f"ordering bug: longer prefix {longer!r} must appear "
                    f"before shorter prefix {short!r}"
                )


# --- family detection unit tests --------------------------------------------


def test_is_modular_accepts_bdx8_variants() -> None:
    """Both ``BD-X8`` and ``BlackDiamond X8`` model strings resolve to True."""
    assert _exos_is_modular("BD-X8")
    assert _exos_is_modular("BlackDiamond X8")
    assert _exos_is_modular("bd-x8")
    assert _exos_is_modular("blackdiamond x8")


def test_is_modular_matches_switch_line_without_system_type() -> None:
    """
    BD-X8 ``show version`` may omit ``System Type:`` but still print ``Switch : BD-X8``.

    Extreme's command-reference example for BD-X8 lists ``Chassis`` / ``Slot-*`` /
    ``FM-*`` entries without an explicit ``System Type`` line. Scanning the full
    ``show version`` output for the BD-X8 signature still triggers modular
    detection in that shape.
    """
    ver_output = (
        "Switch      : 800533-00-01 Rev 1.0 BootROM: 1.0.5.7   IMG: 30.7.1.4\n"
        "Chassis     : BD-X8\n"
        "Slot-1      : BDXA-10G48X\n"
        "FM-1        : BDXA-FM-160T\n"
    )
    assert _exos_is_modular(ver_output)


def test_is_modular_rejects_fixed_x8_variants() -> None:
    """BD-X8-X32 / BD-X8-32 (stackable) and X670 / X870 (pizza-box) reject."""
    assert not _exos_is_modular("BD-X8-32")
    assert not _exos_is_modular("BD-X8-X32")
    assert not _exos_is_modular("BlackDiamond X8-32")
    assert not _exos_is_modular("X670-48x-FB")
    assert not _exos_is_modular("X870-32c")
    assert not _exos_is_modular("X480-48t")
    assert not _exos_is_modular("")


# --- slot-detail parser unit tests ------------------------------------------


def test_parse_show_slot_detail_extracts_blocks() -> None:
    """Block-per-slot output yields one row per slot with hw type + serial."""
    text = (
        "MSM-A information:\n"
        "                State:                 Operational\n"
        "                Hw Module Type:        BDX-MM1\n"
        "                Serial number:         12345N-A001\n"
        "\n"
        "Slot-1 information:\n"
        "                State:                 Operational\n"
        "                Hw Module Type:        BDXA-10G48X\n"
        "                Serial number:         12345N-S101\n"
    )
    rows = _parse_show_slot_detail(text)
    assert rows == [
        {"slot": "MSM-A", "hw_module_type": "BDX-MM1", "serial": "12345N-A001"},
        {"slot": "Slot-1", "hw_module_type": "BDXA-10G48X", "serial": "12345N-S101"},
    ]


def test_parse_show_slot_detail_normalises_space_separator() -> None:
    """``Slot 1`` header (space separator) normalises to ``Slot-1``."""
    text = (
        "Slot 1 information:\n"
        "                Hw Module Type:        BDXA-10G48X\n"
        "                Serial number:         12345N-S001\n"
    )
    rows = _parse_show_slot_detail(text)
    assert rows == [
        {"slot": "Slot-1", "hw_module_type": "BDXA-10G48X", "serial": "12345N-S001"},
    ]


def test_parse_show_slot_detail_drops_empty_slot() -> None:
    """Blocks missing Hw Module Type or Serial are dropped silently."""
    text = (
        "Slot-7 information:\n"
        "                State:                 Empty\n"
        "\n"
        "Slot-8 information:\n"
        "                Hw Module Type:        BDXA-10G48X\n"
        "                Serial number:         12345N-S801\n"
    )
    rows = _parse_show_slot_detail(text)
    assert rows == [
        {"slot": "Slot-8", "hw_module_type": "BDXA-10G48X", "serial": "12345N-S801"},
    ]


def test_parse_show_slot_detail_empty_input_returns_empty() -> None:
    """Empty / unparseable input returns an empty list."""
    assert _parse_show_slot_detail("") == []
    assert _parse_show_slot_detail("no slot headers here") == []


def test_parse_show_slot_detail_captures_multi_token_serial() -> None:
    """
    Real BD-X8 ``Serial number:`` lines have two whitespace-separated tokens.

    Extreme's BD-X8 support output prints ``Serial number: 800432-00-09 1534G-01368``
    (part-number plus the unique serial). The captured value must include both
    tokens — capturing only the first leads to non-unique NetBox module serials.
    """
    text = (
        "Slot-1 information:\n"
        "                Hw Module Type:        BDXA-10G48X\n"
        "                Serial number:         800432-00-09 1534G-01368\n"
    )
    rows = _parse_show_slot_detail(text)
    assert rows == [
        {
            "slot": "Slot-1",
            "hw_module_type": "BDXA-10G48X",
            "serial": "800432-00-09 1534G-01368",
        },
    ]


def test_parse_show_slot_detail_case_insensitive_header() -> None:
    """Lowercase / mixed-case slot headers parse just like TitleCase."""
    text = (
        "slot-1 information:\n"
        "                Hw Module Type:        BDXA-10G48X\n"
        "                Serial number:         12345N-S001\n"
        "\n"
        "msm-a information:\n"
        "                Hw Module Type:        BDX-MM1\n"
        "                Serial number:         12345N-A001\n"
    )
    rows = _parse_show_slot_detail(text)
    assert [r["slot"] for r in rows] == ["slot-1", "msm-a"]
