"""Unit tests for custom_napalm.paloalto_panos.PANOSDriver."""

from pathlib import Path

from custom_napalm.paloalto_panos import PANOSDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeXmlDevice


class TestPANOSDriver(BaseDriverTest):
    """Unit tests for PANOSDriver using file-based XML mocks."""

    driver_cls = PANOSDriver
    fake_device_cls = FakeXmlDevice
    mock_data_root = Path(__file__).parent / "mock_data"


def test_driver_exposes_get_modules():
    """PANOSDriver MUST expose a callable get_modules method."""
    assert hasattr(PANOSDriver, "get_modules")
    assert callable(PANOSDriver.get_modules)


def test_classify_module_type_panos_sku_substrings():
    """SKU substring classifier covers PA-7000 / PA-7500 / PA-5400 card types."""
    from custom_napalm.paloalto_panos import classify_module_type_panos
    assert classify_module_type_panos("PA-7000-100G-NPC-A") == "linecard"
    assert classify_module_type_panos("PA-7050-SMC") == "supervisor"
    assert classify_module_type_panos("PA-7080-SMC") == "supervisor"
    assert classify_module_type_panos("PA-7000-LFC-A") == "linecard"
    assert classify_module_type_panos("PA-7000-DPC-A") == "linecard"
    assert classify_module_type_panos("PA-7500-SFC-A") == "linecard"
    assert classify_module_type_panos("PA-7500-MPC-A") == "supervisor"
    assert classify_module_type_panos("PA-5400-NC-A") == "linecard"
    assert classify_module_type_panos("PA-5400-MPC-A") == "supervisor"
    assert classify_module_type_panos("PA-5400-DPC-A") == "linecard"
    # PA-5450 Base Card — first-class system card, classified as linecard
    assert classify_module_type_panos("PA-5400-BC-A") == "linecard"
    # PA-7000 first-generation Log Processing Card — `LPC` SKU
    assert classify_module_type_panos("PAN-PA-7000-LPC") == "linecard"
    assert classify_module_type_panos("PA-7000-LPC-A") == "linecard"
    # PaloAlto compatibility docs sometimes list SKUs with a `PAN-` prefix
    # — classifier still hits the substring tokens regardless of prefix
    assert classify_module_type_panos("PAN-PA-7000-100G-NPC-A") == "linecard"
    assert classify_module_type_panos("PAN-PA-5400-BC-A") == "linecard"
    assert classify_module_type_panos("PAN-PA-7080-SMC") == "supervisor"
    # Unrelated / fan / psu SKUs classify as other
    assert classify_module_type_panos("PA-5440-PSU") == "other"
    assert classify_module_type_panos("PA-XXX-FAN") == "other"
    assert classify_module_type_panos("") == "other"


def test_is_modular_panos_prefixes_and_suffixed_variants():
    """Bare-prefix and suffixed model strings classify as modular."""
    from custom_napalm.paloalto_panos import _is_modular_panos
    assert _is_modular_panos("PA-7050") is True
    assert _is_modular_panos("PA-7080") is True
    assert _is_modular_panos("PA-7500") is True
    assert _is_modular_panos("PA-5450") is True
    # Suffixed variants — PAN-OS sometimes returns trailing power-supply or
    # variant suffixes in `get_facts().model`.
    assert _is_modular_panos("PA-7050B") is True
    assert _is_modular_panos("PA-5450-AC") is True
    assert _is_modular_panos("PA-7080-PWR-AC-A") is True
    # Case-insensitive
    assert _is_modular_panos("pa-7080") is True


def test_is_modular_panos_fixed_models():
    """Fixed-config / VM / Panorama models classify as non-modular."""
    from custom_napalm.paloalto_panos import _is_modular_panos
    assert _is_modular_panos("PA-3220") is False
    assert _is_modular_panos("PA-440") is False
    assert _is_modular_panos("PA-VM") is False
    assert _is_modular_panos("M-700") is False
    assert _is_modular_panos("PA-5440") is False
    assert _is_modular_panos("") is False
    assert _is_modular_panos(None) is False
