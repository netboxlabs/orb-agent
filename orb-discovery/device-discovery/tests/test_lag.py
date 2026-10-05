"""
Tests for link-aggregation membership (``Interface.lag``).

Covers the translator post-pass (``device_discovery.lag``), its wiring into
``translate_data`` on both the single-device and the stack path, the
``prune_nested_refs`` handling of a lag that lives on another stack member,
the runner's ``_collect_lag_membership`` gate, and the Junos driver feeding
the translator end to end from a captured terse reply.
"""

import logging
from pathlib import Path
from unittest.mock import MagicMock

from jnpr.junos.exception import RpcError
from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb
from netboxlabs.diode.sdk.ingester import Device, Entity, Interface

from custom_napalm.junos import JunOSDriver
from device_discovery.lag import apply_interface_lags
from device_discovery.policy.models import Config, Defaults, Options
from device_discovery.policy.runner import PolicyRunner
from device_discovery.stubs import prune_nested_refs
from device_discovery.translate import translate_data
from tests.custom_drivers.mock_device import FakePyEZDevice

_LAG_MOCK_DATA = Path(__file__).parent / "custom_drivers" / "juniper_junos" / "mock_data" / "test_get_interfaces_lag"


def _iface(name: str, if_type: str, device: str = "sw1") -> Entity:
    return Entity(interface=Interface(device=Device(name=device), name=name, type=if_type))


def _by_name(entities) -> dict[str, pb.Interface]:
    return {e.interface.name: e.interface for e in entities if e.HasField("interface")}


def _napalm_iface(speed: int = 10000) -> dict:
    return {
        "is_enabled": True,
        "is_up": True,
        "speed": speed,
        "mtu": 1514,
        "mac_address": "",
        "description": "",
        "last_flapped": -1.0,
    }


def _junos_data(interfaces_lag, options: Options | None = None) -> dict:
    """Single-device payload shaped like the measured EX4550."""
    return {
        "driver": "junos",
        "device": {
            "hostname": "ex4550",
            "vendor": "Juniper",
            "model": "EX4550-32F",
            "os_version": "15.1R7-S13",
            "serial_number": "GG0000000001",
            "uptime": 1.0,
            "fqdn": "ex4550",
            "interface_list": [],
        },
        "interface": {
            "xe-0/0/24": _napalm_iface(),
            "xe-0/0/24.0": _napalm_iface(),
            "xe-0/0/24.1876": _napalm_iface(),
            "xe-0/0/28": _napalm_iface(),
            "xe-0/0/28.0": _napalm_iface(),
            "ae0": _napalm_iface(),
            "ae0.0": _napalm_iface(),
            "ae120": _napalm_iface(),
            "ae120.1876": _napalm_iface(),
        },
        "interface_ip": {},
        "interfaces_lag": interfaces_lag,
        "options": options or Options(),
        "target_hostname": "ex4550",
    }


# ---------------------------------------------------------------------------
# apply_interface_lags
# ---------------------------------------------------------------------------


def test_member_points_at_its_aggregate():
    """A physical member gets a lag reference naming the aggregate and its type."""
    entities = [_iface("xe-0/0/24", "10gbase-x-sfpp"), _iface("ae120", "lag")]
    assert apply_interface_lags(entities, {"xe-0/0/24": "ae120"}) == 1
    member = _by_name(entities)["xe-0/0/24"]
    assert member.lag.name == "ae120"
    assert member.lag.type == "lag"
    assert member.lag.device.name == "sw1"
    assert not _by_name(entities)["ae120"].HasField("lag")


def test_lag_reference_carries_the_aggregates_own_device():
    """On a stack, the reference names the member that owns the aggregate, not the member port's."""
    entities = [_iface("xe-1/0/0", "10gbase-x-sfpp", device="vc-2"), _iface("ae0", "lag", device="vc-1")]
    apply_interface_lags(entities, {"xe-1/0/0": "ae0"})
    member = _by_name(entities)["xe-1/0/0"]
    assert member.device.name == "vc-2"
    assert member.lag.device.name == "vc-1"


def test_aggregate_not_typed_lag_is_refused(caplog):
    """An aggregate the translator did not type lag is not referenced; NetBox would refuse it."""
    entities = [_iface("xe-0/0/1", "10gbase-x-sfpp"), _iface("ae1", "other")]
    with caplog.at_level(logging.WARNING, logger="device_discovery.lag"):
        assert apply_interface_lags(entities, {"xe-0/0/1": "ae1"}) == 0
    assert not _by_name(entities)["xe-0/0/1"].HasField("lag")
    assert "not lag" in caplog.text


def test_member_of_a_type_netbox_refuses_a_lag_on_is_skipped(caplog):
    """A virtual, bridge or lag member would fail the interface outright, so it is skipped."""
    for member_type in ("virtual", "bridge", "lag"):
        entities = [_iface("m1", member_type), _iface("ae1", "lag")]
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="device_discovery.lag"):
            assert apply_interface_lags(entities, {"m1": "ae1"}) == 0
        assert not _by_name(entities)["m1"].HasField("lag")
        assert "cannot carry a lag" in caplog.text


def test_missing_aggregate_warns_and_missing_member_is_quiet(caplog):
    """An excluded member is routine; a member whose aggregate was not emitted is worth a warning."""
    entities = [_iface("xe-0/0/1", "10gbase-x-sfpp")]
    with caplog.at_level(logging.WARNING, logger="device_discovery.lag"):
        assert apply_interface_lags(entities, {"xe-0/0/1": "ae9", "xe-0/0/2": "ae9"}) == 0
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1
    assert "'ae9'" in warnings[0].getMessage() and "'xe-0/0/1'" in warnings[0].getMessage()


def test_ambiguous_names_are_refused(caplog):
    """A name more than one emitted interface carries cannot be attributed, so nothing is set."""
    entities = [
        _iface("xe-0/0/1", "10gbase-x-sfpp"),
        _iface("ae1", "lag", device="vc-1"),
        _iface("ae1", "lag", device="vc-2"),
    ]
    with caplog.at_level(logging.WARNING, logger="device_discovery.lag"):
        assert apply_interface_lags(entities, {"xe-0/0/1": "ae1"}) == 0
    assert "matches 2 emitted interfaces" in caplog.text


def test_self_membership_and_malformed_entries_are_skipped():
    """A member that is its own aggregate, and non-string or empty names, set nothing."""
    entities = [_iface("ae1", "lag"), _iface("xe-0/0/1", "10gbase-x-sfpp")]
    payload = {"ae1": "ae1", "xe-0/0/1": "", "": "ae1", 5: "ae1"}
    assert apply_interface_lags(entities, payload) == 0
    assert not any(i.HasField("lag") for i in _by_name(entities).values())


def test_non_dict_payload_is_ignored(caplog):
    """A driver returning the wrong shape costs the lag references, not the device."""
    entities = [_iface("xe-0/0/1", "10gbase-x-sfpp"), _iface("ae1", "lag")]
    with caplog.at_level(logging.WARNING, logger="device_discovery.lag"):
        assert apply_interface_lags(entities, [("xe-0/0/1", "ae1")]) == 0
    assert "not a dict" in caplog.text
    assert apply_interface_lags(entities, None) == 0
    assert apply_interface_lags(entities, {}) == 0


# ---------------------------------------------------------------------------
# translate_data
# ---------------------------------------------------------------------------


def test_translate_sets_lag_on_physical_members_only():
    """The measured EX4550 relationships land on the physical ports, never on the units."""
    entities = list(translate_data(_junos_data({"xe-0/0/24": "ae120", "xe-0/0/28": "ae0"})))
    by_name = _by_name(entities)
    assert by_name["xe-0/0/24"].lag.name == "ae120"
    assert by_name["xe-0/0/28"].lag.name == "ae0"
    for unit in ("xe-0/0/24.0", "xe-0/0/24.1876", "xe-0/0/28.0", "ae0", "ae120", "ae120.1876"):
        assert not by_name[unit].HasField("lag"), unit
    # The units keep their parent; lag membership does not disturb it.
    assert by_name["xe-0/0/24.1876"].parent.name == "xe-0/0/24"


def test_translate_honours_emit_lag_membership_false():
    """With the option off, a pre-populated payload still produces no lag references."""
    data = _junos_data({"xe-0/0/24": "ae120"}, options=Options(emit_lag_membership=False))
    entities = list(translate_data(data))
    assert not any(i.HasField("lag") for i in _by_name(entities).values())


def test_translate_without_payload_is_unchanged():
    """Drivers that never report membership see no difference."""
    data = _junos_data(None)
    del data["interfaces_lag"]
    entities = list(translate_data(data))
    assert not any(i.HasField("lag") for i in _by_name(entities).values())


def test_emit_lag_membership_defaults_to_true():
    """On by default, matching snmp-discovery."""
    assert Options().emit_lag_membership is True


def _stack_data(interfaces_lag) -> dict:
    """Two-member stack whose port-channel is routed to the master and one member port to member 2."""
    return {
        "driver": "ios",
        "device": {
            "hostname": "core-sw",
            "vendor": "Cisco",
            "model": "WS-C3850-12XS",
            "os_version": "17.6.4",
            "serial_number": "FOC2401L0AB",
            "uptime": 1.0,
            "fqdn": "core-sw.lab",
            "interface_list": [],
        },
        "interface": {
            "GigabitEthernet1/0/1": _napalm_iface(1000),
            "GigabitEthernet2/0/1": _napalm_iface(1000),
            "Port-channel1": _napalm_iface(2000),
        },
        "interface_ip": {},
        "interfaces_lag": interfaces_lag,
        "chassis_members": {
            "members": [
                {
                    "id": 1,
                    "serial": "FOC2401L0AB",
                    "model": "WS-C3850-12XS",
                    "role": "active",
                    "priority": 15,
                    "mac": "aabb.cc00.0001",
                    "state": "ready",
                },
                {
                    "id": 2,
                    "serial": "FOC2401L0CD",
                    "model": "WS-C3850-12XS",
                    "role": "standby",
                    "priority": 14,
                    "mac": "aabb.cc00.0002",
                    "state": "ready",
                },
            ],
            "domain": None,
        },
        "target_hostname": "core-sw",
    }


def test_stack_member_port_references_the_aggregate_on_the_master():
    """A cross-member LAG keeps each side on its own stack member, through stub pruning too."""
    entities = list(
        translate_data(
            _stack_data(
                {
                    "GigabitEthernet1/0/1": "Port-channel1",
                    "GigabitEthernet2/0/1": "Port-channel1",
                }
            )
        )
    )
    prune_nested_refs(entities)
    by_name = _by_name(entities)
    remote = by_name["GigabitEthernet2/0/1"]
    assert remote.device.name == "core-sw-2"
    assert remote.lag.name == "Port-channel1"
    assert remote.lag.device.name == "core-sw-1", "the lag must name the member that owns the aggregate"
    local = by_name["GigabitEthernet1/0/1"]
    assert local.lag.device.name == "core-sw-1"
    # Both references are the same master matcher stub, distinct from member 2's.
    assert remote.lag.device == local.lag.device
    assert remote.lag.device != remote.device


# ---------------------------------------------------------------------------
# runner gate
# ---------------------------------------------------------------------------


def _runner(emit_lag_membership: bool = True) -> PolicyRunner:
    runner = PolicyRunner()
    runner.name = "test-policy"
    runner.config = Config(defaults=Defaults(), options=Options(emit_lag_membership=emit_lag_membership))
    return runner


def test_collect_lag_membership_stores_the_driver_result():
    """The driver's map lands on data['interfaces_lag']."""
    runner = _runner()
    dev = MagicMock(spec=["get_interfaces_lag"])
    dev.get_interfaces_lag = MagicMock(return_value={"xe-0/0/24": "ae120"})
    data: dict = {}
    runner._collect_lag_membership(runner.config, dev, data, "ex4550")
    assert data["interfaces_lag"] == {"xe-0/0/24": "ae120"}


def test_collect_lag_membership_skips_the_driver_when_off():
    """emit_lag_membership: false makes no device call at all."""
    runner = _runner(emit_lag_membership=False)
    dev = MagicMock(spec=["get_interfaces_lag"])
    dev.get_interfaces_lag = MagicMock(return_value={"xe-0/0/24": "ae120"})
    data: dict = {}
    runner._collect_lag_membership(runner.config, dev, data, "ex4550")
    dev.get_interfaces_lag.assert_not_called()
    assert "interfaces_lag" not in data


def test_collect_lag_membership_tolerates_drivers_without_it():
    """A driver with no get_interfaces_lag is skipped silently."""
    runner = _runner()
    dev = MagicMock(spec=["get_facts"])
    data: dict = {}
    runner._collect_lag_membership(runner.config, dev, data, "sw1")
    assert "interfaces_lag" not in data


def test_collect_lag_membership_failure_is_a_warning_not_a_lost_device(caplog):
    """A raising driver costs only the lag references."""
    runner = _runner()
    dev = MagicMock(spec=["get_interfaces_lag"])
    dev.get_interfaces_lag = MagicMock(side_effect=RuntimeError("boom"))
    data: dict = {}
    with caplog.at_level(logging.WARNING):
        runner._collect_lag_membership(runner.config, dev, data, "sw1")
    assert "interfaces_lag" not in data
    assert "Error getting LAG membership: boom" in caplog.text


# ---------------------------------------------------------------------------
# Junos driver, end to end
# ---------------------------------------------------------------------------


def _junos_driver(mock_dir: Path | None = None) -> JunOSDriver:
    driver = JunOSDriver.__new__(JunOSDriver)
    driver.device = FakePyEZDevice(mock_dir) if mock_dir else MagicMock()
    return driver


def test_junos_asks_for_the_terse_form():
    """Only the terse operational RPC is used: no configuration read, no LACP RPC."""
    driver = _junos_driver()
    driver.device.rpc.get_interface_information.return_value = None
    driver.get_interfaces_lag()
    driver.device.rpc.get_interface_information.assert_called_once_with(terse=True)
    driver.device.rpc.get_config.assert_not_called()
    driver.device.rpc.get_lacp_interface_information.assert_not_called()


def test_junos_rpc_failure_returns_empty_with_a_warning(caplog):
    """A refused RPC (most often a permission problem) is visible, and costs only the lag references."""
    driver = _junos_driver()
    driver.device.rpc.get_interface_information.side_effect = RpcError(rsp="permission denied")
    with caplog.at_level(logging.WARNING, logger="custom_napalm.junos"):
        assert driver.get_interfaces_lag() == {}
    assert "no LAG membership this cycle" in caplog.text


def test_junos_contradictory_port_is_logged(caplog):
    """A port whose units name two aggregates is named in a warning, and left out."""
    driver = _junos_driver(_LAG_MOCK_DATA / "units_name_two_aggregates")
    with caplog.at_level(logging.WARNING, logger="custom_napalm.junos"):
        assert driver.get_interfaces_lag() == {"xe-0/0/6": "ae1"}
    assert "xe-0/0/5" in caplog.text and "ae1, ae2" in caplog.text


def test_junos_reply_survives_an_xml_comment():
    """A comment node in the reply is skipped rather than costing the whole map."""
    from lxml import etree

    from custom_napalm.junos import _lag_members_from_terse

    text = (_LAG_MOCK_DATA / "ex4550_lacp" / "get-interface-information-terse.xml").read_text(encoding="utf-8")
    text = text.replace("<name>xe-0/0/28</name>", "<!-- left by the switch --><name>xe-0/0/28</name>", 1)
    assert "<!--" in text
    result = _lag_members_from_terse(etree.fromstring(text.encode("utf-8")))
    assert result == {"xe-0/0/24": "ae120", "xe-0/0/28": "ae0"}


def test_junos_capture_end_to_end():
    """The captured EX4550 terse reply, through the driver and translator, yields the expected references."""
    lag_map = _junos_driver(_LAG_MOCK_DATA / "ex4550_lacp").get_interfaces_lag()
    entities = list(translate_data(_junos_data(lag_map)))
    prune_nested_refs(entities)
    by_name = _by_name(entities)
    assert {n: i.lag.name for n, i in by_name.items() if i.HasField("lag")} == {
        "xe-0/0/24": "ae120",
        "xe-0/0/28": "ae0",
    }
    assert by_name["xe-0/0/24"].lag.type == "lag"
    assert by_name["xe-0/0/24"].lag.device.name == "ex4550"


def test_unresolvable_lag_device_drops_the_lag_rather_than_misattributing_it(caplog):
    """A lag whose device is not a top-level Device is dropped, never re-pointed at the member's own device."""
    member = Interface(device=Device(name="vc-2"), name="xe-1/0/0", type="10gbase-x-sfpp")
    member.lag.CopyFrom(Interface(device=Device(name="not-emitted"), name="ae0", type="lag"))
    entities = [Entity(device=Device(name="vc-2")), Entity(interface=member)]
    with caplog.at_level(logging.WARNING, logger="device_discovery.stubs"):
        prune_nested_refs(entities)
    pruned = _by_name(entities)["xe-1/0/0"]
    assert not pruned.HasField("lag")
    assert pruned.device.name == "vc-2"
    assert "dropping the lag" in caplog.text


def test_junos_srx_reth_and_fab_children_are_not_lag_memberships(caplog):
    """SRX cluster reth / fab child links also use the aenet family, but are not LAGs."""
    from lxml import etree

    from custom_napalm.junos import _lag_members_from_terse

    def unit(port, bundle):
        return (
            f"<physical-interface><name>{port}</name><logical-interface><name>{port}.0</name>"
            f"<address-family><address-family-name>aenet</address-family-name>"
            f"<ae-bundle-name>{bundle}</ae-bundle-name></address-family></logical-interface></physical-interface>"
        )

    xml = (
        "<interface-information>"
        + unit("ge-0/0/4", "reth0.0")
        + unit("ge-0/0/2", "fab0.0")
        + unit("ge-0/0/6", "ae3.0")
        + "</interface-information>"
    )
    with caplog.at_level(logging.WARNING, logger="custom_napalm.junos"):
        assert _lag_members_from_terse(etree.fromstring(xml)) == {"ge-0/0/6": "ae3"}
    assert not caplog.records


def test_junos_member_name_falls_back_to_the_logical_unit():
    """A physical-interface without its own name element still yields the port, from the unit's name."""
    from lxml import etree

    from custom_napalm.junos import _lag_members_from_terse

    xml = (
        "<interface-information><physical-interface><logical-interface><name>xe-0/0/9.0</name>"
        "<address-family><address-family-name>aenet</address-family-name><ae-bundle-name>ae4.0</ae-bundle-name>"
        "</address-family></logical-interface></physical-interface></interface-information>"
    )
    assert _lag_members_from_terse(etree.fromstring(xml)) == {"xe-0/0/9": "ae4"}


def test_junos_virtual_chassis_member_port_points_at_the_master_aggregate():
    """On a Junos VC, a port on member 1 references the ae interface attributed to the master."""
    data = _junos_data({"xe-0/0/24": "ae120", "xe-1/0/0": "ae120"})
    data["interface"]["xe-1/0/0"] = _napalm_iface()
    data["chassis_members"] = {
        "members": [
            {"id": 0, "serial": "GG0000000001", "model": "EX4550-32F", "role": "master", "priority": 255, "mac": "", "state": "ready"},
            {"id": 1, "serial": "GG0000000002", "model": "EX4550-32F", "role": "backup", "priority": 254, "mac": "", "state": "ready"},
        ],
        "domain": None,
    }
    entities = list(translate_data(data))
    prune_nested_refs(entities)
    by_name = _by_name(entities)
    master = by_name["ae120"].device.name
    assert by_name["xe-1/0/0"].device.name != master
    assert by_name["xe-1/0/0"].lag.name == "ae120"
    assert by_name["xe-1/0/0"].lag.device.name == master
    assert by_name["xe-0/0/24"].lag.device.name == master
