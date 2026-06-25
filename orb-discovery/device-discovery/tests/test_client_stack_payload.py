"""
End-to-end pruning test for stack graphs.

The most likely production failure path: translate emits master + VC + N
member Devices + per-member interfaces, then Client.ingest's pipeline runs
apply_run_id_to_entities + prune_nested_refs + estimate_message_size. With
the multi-Device aware pruner from sub-PR 1.a, member interfaces must
keep their own device-refs through the entire pipeline.
"""

from unittest.mock import patch

import pytest

from device_discovery.client import Client


def _stack_data(netbox_id: int | None = None):
    return {
        "driver": "ios",
        "device": {
            "hostname": "core-sw",
            "vendor": "Cisco",
            "model": "WS-C3850-12XS",
            "os_version": "17.6.4",
            "serial_number": "FOC2401L0AB",
            "uptime": 12345.0,
            "fqdn": "core-sw.lab",
            "interface_list": [],
        },
        "interface": {
            "GigabitEthernet1/0/1": {
                "is_enabled": True, "is_up": True, "speed": 1000, "mtu": 1500,
                "mac_address": "", "description": "", "last_flapped": -1.0,
            },
            "GigabitEthernet2/0/1": {
                "is_enabled": True, "is_up": True, "speed": 1000, "mtu": 1500,
                "mac_address": "", "description": "", "last_flapped": -1.0,
            },
            "Vlan10": {
                "is_enabled": True, "is_up": True, "speed": 0, "mtu": 1500,
                "mac_address": "", "description": "", "last_flapped": -1.0,
            },
        },
        "interface_ip": {},
        "chassis_members": {
            "members": [
                {"id": 1, "serial": "FOC2401L0AB", "model": "WS-C3850-12XS",
                 "role": "active", "priority": 15, "mac": "aabb.cc00.0001", "state": "ready"},
                {"id": 2, "serial": "FOC2401L0CD", "model": "WS-C3850-12XS",
                 "role": "standby", "priority": 14, "mac": "aabb.cc00.0002", "state": "ready"},
            ],
            "domain": None,
        },
        "target_hostname": "core-sw",
        "netbox_id": netbox_id,
    }


@pytest.fixture
def mock_diode_client_class():
    """Mock the DiodeClient class — same fixture pattern as test_client.py."""
    with patch("device_discovery.client.DiodeClient") as mock:
        yield mock


def _captured_entities_after_ingest(client_instance, data, mock_diode_instance):
    """Run Client.ingest and return the entities passed to diode_client.ingest()."""
    mock_diode_instance.ingest.return_value.errors = []
    client_instance.ingest({"policy_name": "test", "hostname": "core-sw"}, data, run_id="r1")
    args, kwargs = mock_diode_instance.ingest.call_args
    return list(kwargs.get("entities") or args[0])


def test_stack_payload_after_run_id_and_prune_preserves_member_attribution(
    mock_diode_client_class,
):
    """After the full Client.ingest pipeline, member interfaces must NOT collapse to master."""
    client = Client()
    client.init_client(prefix="", target="t", client_id="x", client_secret="y")
    mock_diode = mock_diode_client_class.return_value

    entities = _captured_entities_after_ingest(client, _stack_data(), mock_diode)

    iface_entities = [e for e in entities if e.HasField("interface")]
    by_name = {e.interface.name: e.interface for e in iface_entities}

    # Member 2's interface keeps its own device-ref (the multi-device pruner from
    # sub-PR 1.a is what makes this work end-to-end).
    assert by_name["GigabitEthernet1/0/1"].device.name == "core-sw-1"
    assert by_name["GigabitEthernet2/0/1"].device.name == "core-sw-2"
    # Vlan10 routes to master.
    assert by_name["Vlan10"].device.name == "core-sw-1"


def test_stack_payload_emission_order_preserved_through_pipeline(mock_diode_client_class):
    """Through the full ingest pipeline, master Device → VC → member Device order is preserved."""
    client = Client()
    client.init_client(prefix="", target="t", client_id="x", client_secret="y")
    mock_diode = mock_diode_client_class.return_value

    entities = _captured_entities_after_ingest(client, _stack_data(), mock_diode)

    device_indices = [i for i, e in enumerate(entities) if e.HasField("device")]
    vc_indices = [i for i, e in enumerate(entities) if e.HasField("virtual_chassis")]

    assert device_indices, "expected at least one Device entity"
    assert vc_indices, "expected exactly one VirtualChassis entity"
    # Master Device → VC → member Devices.
    assert device_indices[0] < vc_indices[0] < device_indices[1]


def test_source_match_absent_on_member_interface_stubs(mock_diode_client_class):
    """source_match on the master must not propagate to member interface stubs."""
    client = Client()
    client.init_client(prefix="", target="t", client_id="x", client_secret="y")
    mock_diode = mock_diode_client_class.return_value

    entities = _captured_entities_after_ingest(client, _stack_data(netbox_id=42), mock_diode)
    iface_entities = [e for e in entities if e.HasField("interface")]

    member2_iface = next(
        e.interface for e in iface_entities
        if e.interface.name == "GigabitEthernet2/0/1"
    )
    # The pruned device-stub on member 2's interface must NOT carry source_match.
    assert "source_match" not in member2_iface.device.metadata

    # The master's interface stub should carry the master's source_match.
    master_iface = next(
        e.interface for e in iface_entities
        if e.interface.name == "GigabitEthernet1/0/1"
    )
    assert "source_match" in master_iface.device.metadata, (
        "expected master interface stub to carry source_match"
    )
