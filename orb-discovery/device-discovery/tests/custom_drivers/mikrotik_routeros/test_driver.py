"""Unit tests for custom_napalm.mikrotik_routeros.ROSDriver."""

from pathlib import Path

from custom_napalm.mikrotik_routeros import ROSDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestROSDriver(BaseDriverTest):
    """Unit tests for ROSDriver using file-based CLI mocks."""

    driver_cls = ROSDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"


def test_ros_type_to_netbox_mapping():
    """RouterOS interface types map to NetBox types; physical/unknown stay unset."""
    from custom_napalm.mikrotik_routeros import _ros_type_to_netbox

    assert _ros_type_to_netbox("bond") == "lag"
    assert _ros_type_to_netbox("vlan") == "virtual"
    assert _ros_type_to_netbox("bridge") == "bridge"
    assert _ros_type_to_netbox("gre-tunnel") == "virtual"
    assert _ros_type_to_netbox("VLAN") == "virtual"  # case-insensitive
    # physical / wireless / unknown -> unset (fall through to existing logic)
    assert _ros_type_to_netbox("ether") is None
    assert _ros_type_to_netbox("wlan") is None
    assert _ros_type_to_netbox("") is None


def test_get_interfaces_ip_never_raises(caplog):
    """
    A parse failure costs the addresses, not the device.

    The runner calls get_interfaces_ip outside any handler of its own, so an
    exception escaping it fails the whole run for that device and loses its
    interfaces, VLANs and config as well. It must return empty instead, and
    say so at warning level: silence is what made the RouterOS 7 column change
    present as a successful run with no addresses.
    """
    import logging

    from custom_napalm.mikrotik_routeros import ROSDriver

    class _ExplodingDevice:
        @staticmethod
        def send_command(_cmd):
            return object()  # not str: blows up in the parser

    driver = object.__new__(ROSDriver)
    driver.device = _ExplodingDevice()

    with caplog.at_level(logging.WARNING):
        assert driver.get_interfaces_ip() == {}
    assert any(
        "ip address print" in r.message and r.levelno >= logging.WARNING
        for r in caplog.records
    )


def test_get_interfaces_ip_warns_when_the_device_returns_nothing(caplog):
    """An empty response is a reportable condition, not an empty device."""
    import logging

    from custom_napalm.mikrotik_routeros import ROSDriver

    class _SilentDevice:
        @staticmethod
        def send_command(_cmd):
            return ""

    driver = object.__new__(ROSDriver)
    driver.device = _SilentDevice()

    with caplog.at_level(logging.WARNING):
        assert driver.get_interfaces_ip() == {}
    assert any("returned no output" in r.message for r in caplog.records)
