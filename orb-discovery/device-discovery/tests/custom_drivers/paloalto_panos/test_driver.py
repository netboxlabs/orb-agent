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


def test_mgmt_ip_from_system_info_ipv4_and_ipv6():
    """Mgmt IPv4 + prefixed IPv6 are emitted under the 'management' key."""
    from custom_napalm.paloalto_panos import _mgmt_ip_from_system_info
    info = {
        "ip-address": "10.0.0.5",
        "netmask": "255.255.255.0",
        "ipv6-address": "2001:db8:abcd::5/64",
        "mac-address": "00:50:56:aa:bb:cc",
    }
    assert _mgmt_ip_from_system_info(info) == {
        "management": {
            "ipv4": {"10.0.0.5": {"prefix_length": 24}},
            "ipv6": {"2001:db8:abcd::5": {"prefix_length": 64}},
        }
    }


def test_mgmt_ip_from_system_info_skips_ipv6_without_prefix():
    """Mgmt IPv6 lacking an explicit prefix is dropped; IPv4 still emitted."""
    from custom_napalm.paloalto_panos import _mgmt_ip_from_system_info
    info = {"ip-address": "10.0.0.5", "netmask": "255.255.255.0", "ipv6-address": "2001:db8::99"}
    assert _mgmt_ip_from_system_info(info) == {
        "management": {"ipv4": {"10.0.0.5": {"prefix_length": 24}}}
    }


def test_mgmt_ip_from_system_info_skips_link_local_and_unknown():
    """Link-local / unknown / empty system info yield no spurious mgmt IPs."""
    from custom_napalm.paloalto_panos import _mgmt_ip_from_system_info
    info = {"ip-address": "10.0.0.5", "netmask": "255.255.255.0", "ipv6-address": "fe80::1/64"}
    assert _mgmt_ip_from_system_info(info) == {
        "management": {"ipv4": {"10.0.0.5": {"prefix_length": 24}}}
    }
    assert _mgmt_ip_from_system_info({"ip-address": "unknown", "netmask": "unknown"}) == {}
    assert _mgmt_ip_from_system_info({}) == {}


def test_mgmt_ip_from_system_info_skips_dhcp_unconfigured_and_mac_only():
    """DHCP-unconfigured 0.0.0.0 and MAC-only system info emit nothing."""
    from custom_napalm.paloalto_panos import _mgmt_ip_from_system_info
    # DHCP-unconfigured mgmt plane reports 0.0.0.0 — must be skipped.
    assert _mgmt_ip_from_system_info(
        {"ip-address": "0.0.0.0", "netmask": "0.0.0.0", "mac-address": "00:50:56:aa:bb:cc"}
    ) == {}
    # MAC present but no usable IP at all -> nothing emitted.
    assert _mgmt_ip_from_system_info({"mac-address": "00:50:56:aa:bb:cc"}) == {}


def test_mgmt_ip_from_system_info_skips_out_of_range_prefixes():
    """Out-of-range IPv6 prefix and malformed netmask are skipped, not emitted."""
    from custom_napalm.paloalto_panos import _mgmt_ip_from_system_info
    assert _mgmt_ip_from_system_info(
        {"ip-address": "10.0.0.5", "netmask": "255.255.255.0", "ipv6-address": "2001:db8::1/999"}
    ) == {"management": {"ipv4": {"10.0.0.5": {"prefix_length": 24}}}}
    # Malformed (5-octet) netmask -> no ipv4 emitted.
    assert _mgmt_ip_from_system_info(
        {"ip-address": "10.0.0.5", "netmask": "255.255.255.255.255"}
    ) == {}


def test_system_info_dict_returns_empty_on_panxapi_error():
    """A failed `show system info` RPC degrades to {} rather than propagating."""
    import pan.xapi

    from custom_napalm.paloalto_panos import PANOSDriver

    class _BoomDevice:
        def op(self, cmd=""):
            raise pan.xapi.PanXapiError("boom")

        def xml_root(self):
            return ""

    drv = object.__new__(PANOSDriver)
    drv.device = _BoomDevice()
    assert drv._system_info_dict() == {}


def test_netmask_to_prefix_rejects_non_contiguous_and_malformed():
    """Non-contiguous / wrong-length / out-of-range netmasks return None."""
    from custom_napalm.paloalto_panos import _netmask_to_prefix
    assert _netmask_to_prefix("255.255.255.0") == 24
    assert _netmask_to_prefix("255.0.255.0") is None       # non-contiguous
    assert _netmask_to_prefix("255.255.255.255.255") is None  # 5 octets
    assert _netmask_to_prefix("255.255.300.0") is None     # out of range


def test_mgmt_ip_from_system_info_skips_non_fe80_link_local():
    """Link-local beyond fe80 (fe80::/10 -> fe9x/feax/febx) is skipped."""
    from custom_napalm.paloalto_panos import _mgmt_ip_from_system_info
    assert _mgmt_ip_from_system_info(
        {"ip-address": "10.0.0.5", "netmask": "255.255.255.0", "ipv6-address": "fe9c::1/64"}
    ) == {"management": {"ipv4": {"10.0.0.5": {"prefix_length": 24}}}}
    # Non-contiguous mgmt netmask -> no IPv4 emitted.
    assert _mgmt_ip_from_system_info(
        {"ip-address": "10.0.0.5", "netmask": "255.0.255.0"}
    ) == {}


def test_system_info_dict_returns_empty_on_malformed_xml():
    """A malformed `show system info` XML body degrades to {} (ExpatError)."""
    from custom_napalm.paloalto_panos import PANOSDriver

    class _BadXmlDevice:
        def op(self, cmd=""):
            return None

        def xml_root(self):
            return "<response><result><system>"  # truncated / unparseable

    drv = object.__new__(PANOSDriver)
    drv.device = _BadXmlDevice()
    assert drv._system_info_dict() == {}


def test_mgmt_ip_from_system_info_skips_malformed_and_scoped_ipv6():
    """A malformed / non-v6 / zone-index mgmt IPv6 is rejected, not emitted."""
    from custom_napalm.paloalto_panos import _mgmt_ip_from_system_info
    assert _mgmt_ip_from_system_info({"ipv6-address": "not-an-addr/64"}) == {}
    assert _mgmt_ip_from_system_info({"ipv6-address": "2001:db8::1%mgmt/64"}) == {}
    # IPv4 in the v6 field is rejected on the v6 path.
    assert _mgmt_ip_from_system_info({"ipv6-address": "10.0.0.5/24"}) == {}


def test_mgmt_ip_from_system_info_skips_invalid_ipv4():
    """A malformed / non-IPv4 ip-address is rejected, not emitted."""
    from custom_napalm.paloalto_panos import _mgmt_ip_from_system_info
    assert _mgmt_ip_from_system_info({"ip-address": "not-an-ip", "netmask": "255.255.255.0"}) == {}
    # An IPv6 literal in the ip-address field is not a valid IPv4.
    assert _mgmt_ip_from_system_info({"ip-address": "2001:db8::5", "netmask": "255.255.255.0"}) == {}
