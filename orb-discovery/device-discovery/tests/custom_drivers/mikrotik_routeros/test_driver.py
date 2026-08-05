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
