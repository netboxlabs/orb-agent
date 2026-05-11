#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""NetBox Labs - Stubs Unit Tests."""

from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb
from netboxlabs.diode.sdk.ingester import Entity

from device_discovery.stubs import (
    _device_match_stub,
    _index_top_level_devices,
    _interface_match_stub,
    _ip_match_stub,
    prune_nested_refs,
)


def test_ip_match_stub_keeps_address_and_vrf_drops_assigned_object():
    """Stub keeps address+vrf, drops assigned_object_interface and other rich fields."""
    rich = pb.IPAddress(address="192.0.2.1/24")
    rich.vrf.CopyFrom(pb.VRF(name="mgmt"))
    rich.assigned_object_interface.CopyFrom(pb.Interface(name="eth0"))
    rich.description = "uplink"
    rich.status = "active"

    stub = _ip_match_stub(rich)

    assert stub.address == "192.0.2.1/24"
    assert stub.HasField("vrf")
    assert stub.vrf.name == "mgmt"
    assert not stub.HasField("assigned_object_interface")
    assert stub.description == ""
    assert stub.status == ""


def test_ip_match_stub_no_vrf():
    """Stub has no vrf when the rich IPAddress has none."""
    rich = pb.IPAddress(address="10.0.0.1/24")
    stub = _ip_match_stub(rich)
    assert stub.address == "10.0.0.1/24"
    assert not stub.HasField("vrf")


def test_index_top_level_devices_finds_device():
    """Returns a name→Device map of every top-level Device in the entity list."""
    device_entity = Entity(device=pb.Device(name="sw1"))
    iface_entity = Entity(interface=pb.Interface(name="eth0"))
    result = _index_top_level_devices([iface_entity, device_entity])
    assert "sw1" in result
    assert result["sw1"].name == "sw1"


def test_index_top_level_devices_no_device_returns_empty():
    """Returns an empty dict when no Device entity is present."""
    iface_entity = Entity(interface=pb.Interface(name="eth0"))
    assert _index_top_level_devices([iface_entity]) == {}


def test_index_top_level_devices_empty_returns_empty():
    """Returns an empty dict for an empty entity list."""
    assert _index_top_level_devices([]) == {}


def test_index_top_level_devices_indexes_multiple():
    """Multi-Device translate paths (switch stacks) emit several top-level Devices."""
    a = Entity(device=pb.Device(name="sw1"))
    b = Entity(device=pb.Device(name="sw2"))
    result = _index_top_level_devices([a, b])
    assert set(result) == {"sw1", "sw2"}


def test_device_match_stub_keeps_required_fields_drops_rest():
    """Stub keeps matcher and validation-required fields; drops rich-only fields and breaks IP cycles."""
    rich = pb.Device(
        name="sw1",
        serial="FCW1234X5YZ",
        status="active",
        description="ignore me",
        comments="and me",
    )
    rich.site.CopyFrom(pb.Site(name="dc1"))
    rich.tenant.CopyFrom(pb.Tenant(name="acme"))
    rich.role.CopyFrom(pb.DeviceRole(name="access-switch"))
    rich.device_type.CopyFrom(pb.DeviceType(model="Catalyst 9300"))
    rich.platform.CopyFrom(pb.Platform(name="ios-xe"))
    rich.primary_ip4.CopyFrom(pb.IPAddress(address="192.0.2.10/24"))
    rich.primary_ip4.assigned_object_interface.CopyFrom(pb.Interface(name="eth0"))
    rich.primary_ip6.CopyFrom(pb.IPAddress(address="2001:db8::1/64"))
    rich.asset_tag = "ASSET-001"

    stub = _device_match_stub(rich)

    # Matcher / required fields kept.
    assert stub.name == "sw1"
    assert stub.HasField("site") and stub.site.name == "dc1"
    assert stub.HasField("tenant") and stub.tenant.name == "acme"
    assert stub.HasField("role") and stub.role.name == "access-switch"
    assert stub.HasField("device_type") and stub.device_type.model == "Catalyst 9300"
    assert stub.asset_tag == "ASSET-001"

    # PrimaryIp4/6 stubbed (no assigned_object_interface) — cycle break.
    assert stub.HasField("primary_ip4")
    assert stub.primary_ip4.address == "192.0.2.10/24"
    assert not stub.primary_ip4.HasField("assigned_object_interface")
    assert stub.HasField("primary_ip6")
    assert stub.primary_ip6.address == "2001:db8::1/64"

    # Non-matcher / non-required fields cleared.
    assert not stub.HasField("platform")
    assert stub.serial == ""
    assert stub.status == ""
    assert stub.description == ""
    assert stub.comments == ""


def test_device_match_stub_minimal_rich():
    """Stub from a minimal rich Device only carries the populated matcher fields."""
    rich = pb.Device(name="sw1")
    rich.site.CopyFrom(pb.Site(name="dc1"))
    stub = _device_match_stub(rich)
    assert stub.name == "sw1"
    assert stub.HasField("site")
    assert not stub.HasField("primary_ip4")
    assert not stub.HasField("primary_ip6")
    assert stub.asset_tag == ""


def test_device_match_stub_no_asset_tag():
    """Stub has empty asset_tag when the rich Device has none."""
    rich = pb.Device(name="sw1")
    stub = _device_match_stub(rich)
    assert stub.asset_tag == ""


def test_interface_match_stub_keeps_required_fields_drops_rest():
    """Stub keeps name+type+device(stub)+primary_mac (mac only); drops parent/bridge/lag/mtu/description."""
    dev_stub = pb.Device(name="sw1")
    rich = pb.Interface(
        name="Gi1/0/1",
        type="1000base-t",
        mtu=1500,
        description="uplink",
        enabled=True,
    )
    rich.device.CopyFrom(pb.Device(name="sw1", serial="FCW123"))
    rich.primary_mac_address.CopyFrom(
        pb.MACAddress(mac_address="aa:bb:cc:dd:ee:ff", description="primary")
    )
    rich.parent.CopyFrom(pb.Interface(name="Po1"))
    rich.bridge.CopyFrom(pb.Interface(name="br0"))
    rich.lag.CopyFrom(pb.Interface(name="Po1"))

    stub = _interface_match_stub(rich, dev_stub)

    # Matcher / required fields kept.
    assert stub.name == "Gi1/0/1"
    assert stub.type == "1000base-t"
    assert stub.HasField("device")
    assert stub.device.name == "sw1"
    assert stub.device.serial == ""  # confirms dev_stub was used, not rich.device

    # primary_mac_address stubbed to mac-only (no description).
    assert stub.HasField("primary_mac_address")
    assert stub.primary_mac_address.mac_address == "aa:bb:cc:dd:ee:ff"
    assert stub.primary_mac_address.description == ""

    # Other fields cleared.
    assert stub.mtu == 0
    assert stub.description == ""
    assert not stub.HasField("parent")
    assert not stub.HasField("bridge")
    assert not stub.HasField("lag")


def test_interface_match_stub_no_mac():
    """Stub has no primary_mac_address when the rich Interface has none."""
    dev_stub = pb.Device(name="sw1")
    rich = pb.Interface(name="eth0", type="virtual")
    stub = _interface_match_stub(rich, dev_stub)
    assert stub.name == "eth0"
    assert stub.type == "virtual"
    assert not stub.HasField("primary_mac_address")


def _build_rich_entities():
    """Construct a rich entity list approximating translate_data output."""
    rich_dev = pb.Device(name="sw1", serial="FCW123", status="active")
    rich_dev.site.CopyFrom(pb.Site(name="lab"))
    rich_dev.role.CopyFrom(pb.DeviceRole(name="access-switch"))
    rich_dev.device_type.CopyFrom(pb.DeviceType(model="ISR4451"))

    parent_iface = pb.Interface(name="Po1", type="lag")
    parent_iface.device.CopyFrom(rich_dev)

    rich_iface = pb.Interface(name="Gi1/0/1", type="1000base-t", mtu=1500)
    rich_iface.device.CopyFrom(rich_dev)
    rich_iface.parent.CopyFrom(parent_iface)
    rich_iface.primary_mac_address.CopyFrom(pb.MACAddress(mac_address="aa:bb:cc:dd:ee:01"))

    nested_iface_for_ip = pb.Interface(name="Gi1/0/2", type="1000base-t")
    nested_iface_for_ip.device.CopyFrom(rich_dev)

    rich_ip = pb.IPAddress(address="10.0.0.1/24")
    rich_ip.assigned_object_interface.CopyFrom(nested_iface_for_ip)

    return [
        Entity(device=rich_dev),
        Entity(interface=rich_iface),
        Entity(ip_address=rich_ip),
    ]


def test_prune_nested_refs_rewrites_nested_device_and_interface_refs():
    """Sweep replaces nested Device refs and Interface refs (parent, IP.assigned_object_interface) with stubs."""
    entities = _build_rich_entities()

    prune_nested_refs(entities)

    # Top-level Device unchanged — still rich.
    top_device = entities[0].device
    assert top_device.serial == "FCW123"
    assert top_device.status == "active"

    # Interface entity: device replaced with stub (no rich fields).
    iface = entities[1].interface
    assert iface.name == "Gi1/0/1"
    assert iface.type == "1000base-t"
    assert iface.mtu == 1500  # rich Interface fields unchanged
    assert iface.device.name == "sw1"
    assert iface.device.serial == ""  # stub Device has no rich fields
    assert iface.device.HasField("device_type")
    assert iface.device.HasField("role")

    # Parent on interface is also stubbed.
    assert iface.HasField("parent")
    assert iface.parent.name == "Po1"
    assert iface.parent.type == "lag"
    assert iface.parent.device.name == "sw1"
    assert iface.parent.device.serial == ""

    # IPAddress.assigned_object_interface replaced with a stub.
    ip = entities[2].ip_address
    assert ip.HasField("assigned_object_interface")
    assigned = ip.assigned_object_interface
    assert assigned.name == "Gi1/0/2"
    assert assigned.type == "1000base-t"
    assert assigned.device.name == "sw1"
    assert assigned.device.serial == ""


def test_prune_nested_refs_empty_is_noop():
    """Sweep is a no-op on an empty entity list."""
    entities: list[Entity] = []
    prune_nested_refs(entities)
    assert entities == []


def test_prune_nested_refs_no_top_device_is_noop():
    """Sweep is a no-op when no top-level Device is present (nothing to derive a stub from)."""
    iface = pb.Interface(name="eth0", type="virtual")
    iface.device.CopyFrom(pb.Device(name="orphan", serial="XYZ"))
    entities = [Entity(interface=iface)]
    prune_nested_refs(entities)
    # No rich Device → no-op; rich nested device preserved.
    assert entities[0].interface.device.serial == "XYZ"
