"""
Tests for prefix VLANs resolved from device-reported VLAN IDs.

Covers the runner's ``_collect_interfaces_vlan_id`` gate and the seam between
the drivers' ``get_interfaces_vlan_id()`` and the translator: interfaces whose
names carry no usable VLAN ID (``sfpplus1.156``, ``ve400``, ``vlan.20``,
``irb.166``) still link their prefix to the VLAN the device binds them to.
"""

import logging
from pathlib import Path
from unittest.mock import MagicMock

from custom_napalm.brocade_fastiron import FastIronDriver
from custom_napalm.junos import JunOSDriver
from custom_napalm.mikrotik_routeros import ROSDriver
from device_discovery.policy.models import Config, Defaults, Options
from device_discovery.policy.runner import PolicyRunner
from device_discovery.translate import translate_data
from tests.custom_drivers.mock_device import FakeCLIDevice, FakePyEZDevice

_DRIVERS = Path(__file__).parent / "custom_drivers"


def _device_info(vendor: str, model: str) -> dict:
    return {
        "hostname": "r1",
        "model": model,
        "vendor": vendor,
        "serial_number": "TEST0001",
        "os_version": "test",
        "interface_list": [],
    }


def _runner(emit_prefix_vlan: str = "svi-name", **options) -> PolicyRunner:
    runner = PolicyRunner()
    runner.name = "test-policy"
    runner.config = Config(
        defaults=Defaults(), options=Options(emit_prefix_vlan=emit_prefix_vlan, **options)
    )
    return runner


# ---------------------------------------------------------------------------
# runner gate
# ---------------------------------------------------------------------------


def test_collect_interfaces_vlan_id_stores_the_driver_result():
    """The driver's map lands on data['interfaces_vlan_id']."""
    runner = _runner()
    dev = MagicMock(spec=["get_interfaces_vlan_id"])
    dev.get_interfaces_vlan_id = MagicMock(return_value={"sfpplus1.156": 156})
    data: dict = {}
    runner._collect_interfaces_vlan_id(runner.config, dev, data, "r1")
    assert data["interfaces_vlan_id"] == {"sfpplus1.156": 156}


def test_collect_interfaces_vlan_id_skips_the_driver_when_prefix_vlans_are_off():
    """With emit_prefix_vlan off nothing consumes the map, so no device call is made."""
    runner = _runner(emit_prefix_vlan="off")
    dev = MagicMock(spec=["get_interfaces_vlan_id"])
    dev.get_interfaces_vlan_id = MagicMock(return_value={"sfpplus1.156": 156})
    data: dict = {}
    runner._collect_interfaces_vlan_id(runner.config, dev, data, "r1")
    dev.get_interfaces_vlan_id.assert_not_called()
    assert "interfaces_vlan_id" not in data


def test_collect_interfaces_vlan_id_skips_the_driver_when_prefixes_are_off():
    """With emit_prefixes off no prefix carries a VLAN, so no device call is made."""
    runner = _runner(emit_prefixes=False)
    dev = MagicMock(spec=["get_interfaces_vlan_id"])
    dev.get_interfaces_vlan_id = MagicMock(return_value={"sfpplus1.156": 156})
    data: dict = {}
    runner._collect_interfaces_vlan_id(runner.config, dev, data, "r1")
    dev.get_interfaces_vlan_id.assert_not_called()
    assert "interfaces_vlan_id" not in data


def test_collect_interfaces_vlan_id_tolerates_drivers_without_it():
    """A driver with no get_interfaces_vlan_id is skipped silently."""
    runner = _runner()
    dev = MagicMock(spec=["get_facts"])
    data: dict = {}
    runner._collect_interfaces_vlan_id(runner.config, dev, data, "r1")
    assert "interfaces_vlan_id" not in data


def test_collect_interfaces_vlan_id_failure_is_a_warning_not_a_lost_device(caplog):
    """A raising driver costs only the device-reported VLAN IDs."""
    runner = _runner()
    dev = MagicMock(spec=["get_interfaces_vlan_id"])
    dev.get_interfaces_vlan_id = MagicMock(side_effect=RuntimeError("boom"))
    data: dict = {}
    with caplog.at_level(logging.WARNING):
        runner._collect_interfaces_vlan_id(runner.config, dev, data, "r1")
    assert "interfaces_vlan_id" not in data
    assert "Error getting interface VLAN IDs: boom" in caplog.text


# ---------------------------------------------------------------------------
# drivers, end to end
# ---------------------------------------------------------------------------


def _driver(cls, mock_dir: Path):
    driver = object.__new__(cls)
    driver.hostname = driver.username = driver.password = "test"
    driver.timeout = 60
    driver.device = FakeCLIDevice(mock_dir)
    return driver


def _prefix_vlans(data: dict) -> dict[str, int | None]:
    return {
        e.prefix.prefix: (e.prefix.vlan.vid if e.prefix.HasField("vlan") else None)
        for e in translate_data(data)
        if e.WhichOneof("entity") == "prefix"
    }


def test_mikrotik_routed_vlan_subinterfaces_link_their_prefixes():
    """RouterOS VLAN interfaces named after their parent reach their VLAN."""
    mock = _DRIVERS / "mikrotik_routeros" / "mock_data"
    vlans = _driver(ROSDriver, mock / "test_get_vlans" / "v6_with_comments").get_vlans()
    vlan_ids = _driver(
        ROSDriver, mock / "test_get_interfaces_vlan_id" / "v6_routed_subinterfaces"
    ).get_interfaces_vlan_id()

    data = {
        "device": _device_info("MikroTik", "CCR1016-12S-1S+"),
        "interface": {name: {"is_up": True, "is_enabled": True, "type": "virtual"} for name in vlan_ids},
        "interface_ip": {
            "sfpplus1.156": {"ipv4": {"192.0.2.1": {"prefix_length": 30}}},
            "sfpplus1.810": {"ipv4": {"198.51.100.1": {"prefix_length": 29}}},
        },
        "vlan": vlans,
        "interfaces_vlan_id": vlan_ids,
        "driver": "mikrotik_routeros",
        "defaults": Defaults(site="dc1"),
        "options": Options(emit_prefix_vlan="svi-name"),
    }

    got = _prefix_vlans(data)
    assert got["192.0.2.0/30"] == 156
    assert got["198.51.100.0/29"] == 810

    # Without the driver map the dotted names resolve to nothing, as before.
    data.pop("interfaces_vlan_id")
    got = _prefix_vlans(data)
    assert got["192.0.2.0/30"] is None
    assert got["198.51.100.0/29"] is None


def test_fastiron_ve_links_to_the_vlan_that_binds_it():
    """A VE reaches the VLAN of its router-interface line, not the VLAN its number names."""
    mock = _DRIVERS / "brocade_fastiron" / "mock_data" / "test_get_interfaces_vlan_id" / "ve_number_differs_from_vid"
    driver = _driver(FastIronDriver, mock)

    data = {
        "device": _device_info("Brocade", "ICX7250-24P"),
        "interface": {"ve400": {"is_up": True, "is_enabled": True}, "ve20": {"is_up": True, "is_enabled": True}},
        "interface_ip": {
            "ve400": {"ipv4": {"10.40.0.1": {"prefix_length": 24}}},
            "ve20": {"ipv4": {"10.20.0.1": {"prefix_length": 24}}},
        },
        "vlan": driver.get_vlans(),
        "interfaces_vlan_id": driver.get_interfaces_vlan_id(),
        "driver": "brocade_fastiron",
        "defaults": Defaults(site="dc1"),
        "options": Options(emit_prefix_vlan="svi-name"),
    }

    got = _prefix_vlans(data)
    assert got["10.40.0.0/24"] == 40
    assert got["10.20.0.0/24"] is None, "a VE bound by two VLANs must not be linked"


def test_junos_l3_vlan_interfaces_link_and_routed_units_stay_unlinked():
    """
    ``vlan.N`` links through the VLAN table; a routed unit outside it does not.

    The VLAN IDs come from the EX4550's own extensive VLAN reply. The VLAN table
    handed to the translator mirrors what upstream ``get_vlans`` builds from the
    same device (tag -> name). ``ae120.1876`` carries a tag the switch has no
    VLAN for, so its prefix is left without one by design.
    """
    mock = _DRIVERS / "juniper_junos" / "mock_data" / "test_get_interfaces_vlan_id" / "ex4550_non_els"
    driver = object.__new__(JunOSDriver)
    driver.device = FakePyEZDevice(mock)
    vlan_ids = driver.get_interfaces_vlan_id()

    data = {
        "device": _device_info("Juniper", "EX4550-32F"),
        "interface": {},
        "interface_ip": {
            "vlan.20": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}},
            "vlan.156": {"ipv4": {"198.51.100.1": {"prefix_length": 24}}},
            "ae120.1876": {"ipv4": {"203.0.113.1": {"prefix_length": 30}}},
        },
        "vlan": {
            "20": {"name": "MGMT", "interfaces": []},
            "50": {"name": "Internet", "interfaces": []},
            "156": {"name": "VL156", "interfaces": []},
            "100": {"name": "VL100", "interfaces": []},
        },
        "interfaces_vlan_id": vlan_ids,
        "driver": "junos",
        "defaults": Defaults(site="dc1"),
        "options": Options(emit_prefix_vlan="svi-name"),
    }

    got = _prefix_vlans(data)
    assert got["192.0.2.0/24"] == 20
    assert got["198.51.100.0/24"] == 156
    assert got["203.0.113.0/30"] is None, "a routed unit with no VLAN in the table must stay unlinked"
