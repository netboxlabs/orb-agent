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

    # primary_ip4/6 are STRIPPED by default — only the cycle-closer IP entity
    # (the top-level ipam.ipaddress for the primary IP) may set device.primary_ip4
    # in a single change set. Every other nested device stub resolves via
    # name+site+tenant / asset_tag, so carrying primary_ip4 here would make the
    # plugin try (and fail) to SET it on first ingest.
    assert not stub.HasField("primary_ip4")
    assert not stub.HasField("primary_ip6")

    # Non-matcher / non-required fields cleared.
    assert not stub.HasField("platform")
    assert stub.serial == ""
    assert stub.status == ""
    assert stub.description == ""
    assert stub.comments == ""


def test_device_match_stub_keep_primary_ip4_keeps_address_only_stub():
    """With keep_primary_ip4=True the stub carries primary_ip4 as an address-only stub."""
    rich = pb.Device(name="sw1")
    rich.site.CopyFrom(pb.Site(name="dc1"))
    rich.primary_ip4.CopyFrom(pb.IPAddress(address="192.0.2.10/24"))
    rich.primary_ip4.assigned_object_interface.CopyFrom(pb.Interface(name="eth0"))
    rich.primary_ip6.CopyFrom(pb.IPAddress(address="2001:db8::1/64"))

    stub = _device_match_stub(rich, keep_primary_ip4=True)

    # primary_ip4 kept, address-only (no back-pointer interface — cycle break).
    assert stub.HasField("primary_ip4")
    assert stub.primary_ip4.address == "192.0.2.10/24"
    assert not stub.primary_ip4.HasField("assigned_object_interface")
    # primary_ip6 still stripped (keep flag defaults False).
    assert not stub.HasField("primary_ip6")


def test_device_match_stub_keep_primary_ip6_keeps_address_only_stub():
    """With keep_primary_ip6=True the stub carries primary_ip6 as an address-only stub."""
    rich = pb.Device(name="sw1")
    rich.site.CopyFrom(pb.Site(name="dc1"))
    rich.primary_ip4.CopyFrom(pb.IPAddress(address="192.0.2.10/24"))
    rich.primary_ip6.CopyFrom(pb.IPAddress(address="2001:db8::1/64"))
    rich.primary_ip6.assigned_object_interface.CopyFrom(pb.Interface(name="eth0"))

    stub = _device_match_stub(rich, keep_primary_ip6=True)

    assert stub.HasField("primary_ip6")
    assert stub.primary_ip6.address == "2001:db8::1/64"
    assert not stub.primary_ip6.HasField("assigned_object_interface")
    # primary_ip4 still stripped (keep flag defaults False).
    assert not stub.HasField("primary_ip4")


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


def test_prune_nested_refs_strips_rich_device_from_module_and_module_bay():
    """
    Module + ModuleBay entities get their nested Device replaced with a stub.

    Without this pass, a chassis with N transceivers would carry the
    full Device proto (often with running-config text) on every Module
    and every ModuleBay — for a 100-port linecard that's a 100×+ wire
    bloat. The matcher-only stub keeps just the name/type/role fields
    Diode needs to resolve the chassis.
    """
    # Top-level rich device — what nested refs should resolve to.
    rich_dev = pb.Device(name="sw1", serial="FCW123", status="active")
    rich_dev.device_type.CopyFrom(
        pb.DeviceType(model="C9404R", manufacturer=pb.Manufacturer(name="Cisco")),
    )

    # ModuleBay entity (top-level slot) with a rich Device on it.
    bay = pb.ModuleBay(name="1", position="1")
    bay.device.CopyFrom(rich_dev)

    # Module entity that's installed in the same chassis; module_bay sub-message
    # also carries a rich Device copy (this is the bloat path).
    module = pb.Module(serial="JAE2401LC02")
    module.device.CopyFrom(rich_dev)
    module.module_bay.CopyFrom(bay)
    module.module_type.CopyFrom(
        pb.ModuleType(model="C9400-LC-48U", manufacturer=pb.Manufacturer(name="Cisco")),
    )

    entities = [Entity(device=rich_dev), Entity(module_bay=bay), Entity(module=module)]
    prune_nested_refs(entities)

    # ModuleBay.device replaced with stub.
    pruned_bay = entities[1].module_bay
    assert pruned_bay.name == "1"
    assert pruned_bay.device.name == "sw1"
    assert pruned_bay.device.serial == ""  # rich field stripped
    assert pruned_bay.device.status == ""  # rich field stripped
    assert pruned_bay.device.HasField("device_type")  # matcher kept

    # Module.device replaced with stub.
    pruned_mod = entities[2].module
    assert pruned_mod.serial == "JAE2401LC02"
    assert pruned_mod.device.name == "sw1"
    assert pruned_mod.device.serial == ""
    assert pruned_mod.device.status == ""

    # Module.module_bay.device is the recursive bloat path — must be stubbed too.
    assert pruned_mod.HasField("module_bay")
    assert pruned_mod.module_bay.device.name == "sw1"
    assert pruned_mod.module_bay.device.serial == ""


def test_prune_nested_refs_strips_nested_parent_module_device():
    """
    A sub-bay's nested ``module`` ref, if present, gets its device stubbed too.

    ``translate_modules`` currently emits sub-bays device-rooted (no
    ``module=parent_linecard`` link — see the docstring on
    ``_emit_bay_recursive`` for why). This test still exercises the pruner's
    contract on the shape: if any caller does attach a parent Module ref
    to a ModuleBay, the prune sweep must reduce both the bay's own
    ``device`` AND the nested ``module.device`` to matcher-only stubs so
    per-transceiver wire size stays bounded.
    """
    rich_dev = pb.Device(name="sw1", serial="FCW123", status="active")
    rich_dev.device_type.CopyFrom(
        pb.DeviceType(model="C9404R", manufacturer=pb.Manufacturer(name="Cisco")),
    )
    parent_module = pb.Module(serial="JAE2401LC02")
    parent_module.device.CopyFrom(rich_dev)
    parent_module.module_type.CopyFrom(
        pb.ModuleType(model="C9400-LC-48U", manufacturer=pb.Manufacturer(name="Cisco")),
    )

    sub_bay = pb.ModuleBay(name="Te2/0/1", position="Te2/0/1")
    sub_bay.device.CopyFrom(rich_dev)
    sub_bay.module.CopyFrom(parent_module)

    entities = [Entity(device=rich_dev), Entity(module_bay=sub_bay)]
    prune_nested_refs(entities)

    pruned = entities[1].module_bay
    # Own device stubbed.
    assert pruned.device.serial == ""
    # Parent module ref kept, its device stubbed too — no recursive bloat.
    assert pruned.HasField("module")
    assert pruned.module.serial == "JAE2401LC02"
    assert pruned.module.device.name == "sw1"
    assert pruned.module.device.serial == ""


def test_prune_nested_refs_stubs_interface_module_reference():
    """
    Interface.module is replaced with a matcher-only Module proto.

    The translator attaches the full rich Module (carrying device,
    module_bay, module_type, description, etc.) to every Interface in
    the slot. Without stubbing, a 48-port linecard duplicates that rich
    subtree 48 times in the ingest payload. The stub keeps only the
    fields Diode needs to resolve the module — device, serial, and a
    positional module_bay shell — plus module_type, which NetBox requires
    if the reference has to be created rather than matched — so
    per-interface wire cost is bounded.
    """
    rich_dev = pb.Device(name="sw1", serial="FCW123", status="active")
    rich_dev.device_type.CopyFrom(
        pb.DeviceType(model="C9404R", manufacturer=pb.Manufacturer(name="Cisco")),
    )

    bay = pb.ModuleBay(name="2", position="2")
    bay.device.CopyFrom(rich_dev)

    rich_module = pb.Module(serial="JAE2401LC02", description="48-port UPOE+")
    rich_module.device.CopyFrom(rich_dev)
    rich_module.module_bay.CopyFrom(bay)
    rich_module.module_type.CopyFrom(
        pb.ModuleType(
            model="C9400-LC-48U",
            manufacturer=pb.Manufacturer(name="Cisco", slug="cisco", description="vendor"),
            part_number="C9400-LC-48U-A",
            description="48 port UPOE+ line card",
            comments="rich field a driver may start populating",
        ),
    )

    iface = pb.Interface(name="GigabitEthernet2/0/1", type="1000base-t")
    iface.device.CopyFrom(rich_dev)
    iface.module.CopyFrom(rich_module)

    entities = [Entity(device=rich_dev), Entity(interface=iface)]
    prune_nested_refs(entities)

    pruned_iface = entities[1].interface
    # iface.module kept (matcher present), but rich fields stripped.
    assert pruned_iface.HasField("module")
    assert pruned_iface.module.serial == "JAE2401LC02"
    assert pruned_iface.module.description == ""
    # module_type is retained: a nested ref that fails to match is created
    # instead, and NetBox rejects a Module without one.
    assert pruned_iface.module.module_type.model == "C9400-LC-48U"
    assert pruned_iface.module.module_type.manufacturer.name == "Cisco"
    # ...but only the (manufacturer, model) matcher pair, so the reference cannot
    # grow as drivers start populating the richer ModuleType fields.
    assert pruned_iface.module.module_type.part_number == ""
    assert pruned_iface.module.module_type.description == ""
    assert pruned_iface.module.module_type.comments == ""
    assert pruned_iface.module.module_type.manufacturer.slug == ""
    assert pruned_iface.module.module_type.manufacturer.description == ""
    # Nested device on the module ref is also a stub.
    assert pruned_iface.module.device.name == "sw1"
    assert pruned_iface.module.device.serial == ""
    # Module bay positional ref preserved as a stub.
    assert pruned_iface.module.HasField("module_bay")
    assert pruned_iface.module.module_bay.name == "2"
    assert pruned_iface.module.module_bay.device.name == "sw1"
    assert pruned_iface.module.module_bay.device.serial == ""


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


def test_prune_nested_refs_keeps_primary_ip_only_on_cycle_closer():
    """
    Only the primary IP's own ipam.ipaddress entity keeps primary_ip4 on its nested device stub.

    The cycle-closer (the top-level ipam.ipaddress for the primary IP, whose
    assigned_object_interface points back at the device) is the one entity that
    can validly SET device.primary_ip4 in a single change set: it does the
    IP→interface assignment AND closes the cycle via its nested device stub's
    primary_ip4. Every OTHER nested device stub (non-primary IP entity, plain
    interface entity) must strip primary_ip4 so the plugin doesn't try to SET it
    and fail on first ingest.
    """
    rich_dev = pb.Device(name="sw1", serial="FCW123", status="active")
    rich_dev.site.CopyFrom(pb.Site(name="lab"))
    rich_dev.device_type.CopyFrom(pb.DeviceType(model="ISR4451"))
    rich_dev.primary_ip4.CopyFrom(pb.IPAddress(address="10.0.0.1/24"))
    back_iface = pb.Interface(name="Gi1/0/1", type="1000base-t")
    back_iface.device.CopyFrom(rich_dev)
    rich_dev.primary_ip4.assigned_object_interface.CopyFrom(back_iface)

    # Cycle-closer: the top-level IP entity for the primary IP.
    closer_iface = pb.Interface(name="Gi1/0/1", type="1000base-t")
    closer_iface.device.CopyFrom(rich_dev)
    closer_ip = pb.IPAddress(address="10.0.0.1/24")
    closer_ip.assigned_object_interface.CopyFrom(closer_iface)

    # A non-primary IP entity on the same device.
    other_iface = pb.Interface(name="Gi1/0/2", type="1000base-t")
    other_iface.device.CopyFrom(rich_dev)
    other_ip = pb.IPAddress(address="10.0.0.99/24")
    other_ip.assigned_object_interface.CopyFrom(other_iface)

    # A plain interface entity on the same device.
    plain_iface = pb.Interface(name="Gi1/0/3", type="1000base-t")
    plain_iface.device.CopyFrom(rich_dev)

    entities = [
        Entity(device=rich_dev),
        Entity(ip_address=closer_ip),
        Entity(ip_address=other_ip),
        Entity(interface=plain_iface),
    ]
    prune_nested_refs(entities)

    # Cycle-closer IP keeps primary_ip4 (address-only) on its nested device stub.
    closer_dev = entities[1].ip_address.assigned_object_interface.device
    assert closer_dev.HasField("primary_ip4")
    assert closer_dev.primary_ip4.address == "10.0.0.1/24"
    assert not closer_dev.primary_ip4.HasField("assigned_object_interface")

    # Non-primary IP's nested device stub strips primary_ip4.
    other_dev = entities[2].ip_address.assigned_object_interface.device
    assert not other_dev.HasField("primary_ip4")

    # Plain interface's nested device stub strips primary_ip4.
    plain_dev = entities[3].interface.device
    assert not plain_dev.HasField("primary_ip4")


def test_prune_nested_refs_cycle_closer_matches_full_identity_not_host():
    """
    A same-host IP with a different prefix is NOT treated as the cycle-closer.

    Two IP entities can share a host address yet be different IP objects (e.g. a
    /32 loopback and a /24 SVI). Only the IP object the device's primary actually
    references may keep primary_ip4; matching on the host alone would let the other
    object's change set try to set device.primary_ip4 and re-open the cycle.
    """
    rich_dev = pb.Device(name="sw1", serial="FCW123")
    rich_dev.site.CopyFrom(pb.Site(name="lab"))
    rich_dev.primary_ip4.CopyFrom(pb.IPAddress(address="10.0.0.1/24"))
    back_iface = pb.Interface(name="Gi1/0/1", type="1000base-t")
    back_iface.device.CopyFrom(rich_dev)
    rich_dev.primary_ip4.assigned_object_interface.CopyFrom(back_iface)

    # Cycle-closer: exact same address + prefix as the device's primary.
    closer_iface = pb.Interface(name="Gi1/0/1", type="1000base-t")
    closer_iface.device.CopyFrom(rich_dev)
    closer_ip = pb.IPAddress(address="10.0.0.1/24")
    closer_ip.assigned_object_interface.CopyFrom(closer_iface)

    # Same host, DIFFERENT prefix — a different IP object, must NOT keep primary_ip4.
    diff_prefix_iface = pb.Interface(name="Lo0", type="virtual")
    diff_prefix_iface.device.CopyFrom(rich_dev)
    diff_prefix_ip = pb.IPAddress(address="10.0.0.1/32")
    diff_prefix_ip.assigned_object_interface.CopyFrom(diff_prefix_iface)

    entities = [
        Entity(device=rich_dev),
        Entity(ip_address=closer_ip),
        Entity(ip_address=diff_prefix_ip),
    ]
    prune_nested_refs(entities)

    assert entities[1].ip_address.assigned_object_interface.device.HasField("primary_ip4")
    assert not entities[2].ip_address.assigned_object_interface.device.HasField("primary_ip4")


def test_prune_nested_refs_cycle_closer_disambiguates_by_vrf():
    """Same address in two VRFs: only the IP in the device's primary VRF keeps primary_ip4."""
    rich_dev = pb.Device(name="sw1", serial="FCW123")
    rich_dev.site.CopyFrom(pb.Site(name="lab"))
    prim = pb.IPAddress(address="10.0.0.1/24")
    prim.vrf.CopyFrom(pb.VRF(name="mgmt"))
    rich_dev.primary_ip4.CopyFrom(prim)
    back_iface = pb.Interface(name="Gi1/0/1", type="1000base-t")
    back_iface.device.CopyFrom(rich_dev)
    rich_dev.primary_ip4.assigned_object_interface.CopyFrom(back_iface)

    # Cycle-closer: same address AND same VRF.
    closer_iface = pb.Interface(name="Gi1/0/1", type="1000base-t")
    closer_iface.device.CopyFrom(rich_dev)
    closer_ip = pb.IPAddress(address="10.0.0.1/24")
    closer_ip.vrf.CopyFrom(pb.VRF(name="mgmt"))
    closer_ip.assigned_object_interface.CopyFrom(closer_iface)

    # Same address, DIFFERENT VRF — a different IP object, must NOT keep primary_ip4.
    other_vrf_iface = pb.Interface(name="Gi1/0/2", type="1000base-t")
    other_vrf_iface.device.CopyFrom(rich_dev)
    other_vrf_ip = pb.IPAddress(address="10.0.0.1/24")
    other_vrf_ip.vrf.CopyFrom(pb.VRF(name="customer-a"))
    other_vrf_ip.assigned_object_interface.CopyFrom(other_vrf_iface)

    entities = [
        Entity(device=rich_dev),
        Entity(ip_address=closer_ip),
        Entity(ip_address=other_vrf_ip),
    ]
    prune_nested_refs(entities)

    assert entities[1].ip_address.assigned_object_interface.device.HasField("primary_ip4")
    assert not entities[2].ip_address.assigned_object_interface.device.HasField("primary_ip4")


def test_prune_nested_refs_cycle_closer_disambiguates_by_interface():
    """
    Same CIDR + VRF on two interfaces: only the device's chosen primary interface keeps it.

    assign_primary_ip deterministically selects one interface when a device reports
    the same address on several. Identity must include the assigned interface so the
    duplicate IP entity (a different object on another interface) does not also keep
    primary_ip4 and set the device primary to the wrong/last-processed interface.
    """
    rich_dev = pb.Device(name="sw1", serial="FCW123")
    rich_dev.site.CopyFrom(pb.Site(name="lab"))
    rich_dev.primary_ip4.CopyFrom(pb.IPAddress(address="10.0.0.1/24"))
    back_iface = pb.Interface(name="Gi1/0/1", type="1000base-t")
    back_iface.device.CopyFrom(rich_dev)
    rich_dev.primary_ip4.assigned_object_interface.CopyFrom(back_iface)

    # Cycle-closer: same address + the chosen interface.
    closer_iface = pb.Interface(name="Gi1/0/1", type="1000base-t")
    closer_iface.device.CopyFrom(rich_dev)
    closer_ip = pb.IPAddress(address="10.0.0.1/24")
    closer_ip.assigned_object_interface.CopyFrom(closer_iface)

    # Same address + VRF but a DIFFERENT interface — must NOT keep primary_ip4.
    dup_iface = pb.Interface(name="Gi1/0/2", type="1000base-t")
    dup_iface.device.CopyFrom(rich_dev)
    dup_ip = pb.IPAddress(address="10.0.0.1/24")
    dup_ip.assigned_object_interface.CopyFrom(dup_iface)

    entities = [
        Entity(device=rich_dev),
        Entity(ip_address=closer_ip),
        Entity(ip_address=dup_ip),
    ]
    prune_nested_refs(entities)

    assert entities[1].ip_address.assigned_object_interface.device.HasField("primary_ip4")
    assert not entities[2].ip_address.assigned_object_interface.device.HasField("primary_ip4")


def test_prune_nested_refs_cycle_closer_disambiguates_by_vrf_rd():
    """Same address and VRF name but a different rd is a different VRF — not the cycle-closer."""
    rich_dev = pb.Device(name="sw1", serial="FCW123")
    rich_dev.site.CopyFrom(pb.Site(name="lab"))
    prim = pb.IPAddress(address="10.0.0.1/24")
    prim.vrf.CopyFrom(pb.VRF(name="shared", rd="65000:1"))
    rich_dev.primary_ip4.CopyFrom(prim)
    back_iface = pb.Interface(name="Gi1/0/1", type="1000base-t")
    back_iface.device.CopyFrom(rich_dev)
    rich_dev.primary_ip4.assigned_object_interface.CopyFrom(back_iface)

    # Cycle-closer: same address, same VRF name AND rd.
    closer_iface = pb.Interface(name="Gi1/0/1", type="1000base-t")
    closer_iface.device.CopyFrom(rich_dev)
    closer_ip = pb.IPAddress(address="10.0.0.1/24")
    closer_ip.vrf.CopyFrom(pb.VRF(name="shared", rd="65000:1"))
    closer_ip.assigned_object_interface.CopyFrom(closer_iface)

    # Same address, same VRF name, DIFFERENT rd — a different VRF, must NOT keep primary_ip4.
    other_rd_iface = pb.Interface(name="Gi1/0/2", type="1000base-t")
    other_rd_iface.device.CopyFrom(rich_dev)
    other_rd_ip = pb.IPAddress(address="10.0.0.1/24")
    other_rd_ip.vrf.CopyFrom(pb.VRF(name="shared", rd="65000:2"))
    other_rd_ip.assigned_object_interface.CopyFrom(other_rd_iface)

    entities = [
        Entity(device=rich_dev),
        Entity(ip_address=closer_ip),
        Entity(ip_address=other_rd_ip),
    ]
    prune_nested_refs(entities)

    assert entities[1].ip_address.assigned_object_interface.device.HasField("primary_ip4")
    assert not entities[2].ip_address.assigned_object_interface.device.HasField("primary_ip4")


def test_prune_nested_refs_cycle_closer_stub_is_distinct_from_cached_stripped_stub():
    """
    The cycle-closer's nested device is a DISTINCT instance from the cached stripped stub.

    The keep-primary stub must never be written into the shared stub_cache, so the
    device's cached stripped stub (used by every other nested ref) still lacks
    primary_ip4 even after the keep stub is built.
    """
    rich_dev = pb.Device(name="sw1", serial="FCW123")
    rich_dev.site.CopyFrom(pb.Site(name="lab"))
    rich_dev.device_type.CopyFrom(pb.DeviceType(model="ISR4451"))
    rich_dev.primary_ip4.CopyFrom(pb.IPAddress(address="10.0.0.1/24"))
    rich_dev.primary_ip4.assigned_object_interface.CopyFrom(pb.Interface(name="Gi1/0/1", type="1000base-t"))

    closer_iface = pb.Interface(name="Gi1/0/1", type="1000base-t")
    closer_iface.device.CopyFrom(rich_dev)
    closer_ip = pb.IPAddress(address="10.0.0.1/24")
    closer_ip.assigned_object_interface.CopyFrom(closer_iface)

    plain_iface = pb.Interface(name="Gi1/0/3", type="1000base-t")
    plain_iface.device.CopyFrom(rich_dev)

    entities = [
        Entity(device=rich_dev),
        Entity(ip_address=closer_ip),
        Entity(interface=plain_iface),
    ]
    prune_nested_refs(entities)

    closer_dev = entities[1].ip_address.assigned_object_interface.device
    plain_dev = entities[2].interface.device
    # Distinct instances — the keep stub bypasses the cache.
    assert closer_dev is not plain_dev
    # Cached stripped stub still lacks primary_ip4.
    assert not plain_dev.HasField("primary_ip4")


def test_prune_nested_refs_vc_member_modules_each_get_own_device_stub():
    """
    In a VC payload, member 1's Module gets member 1's Device stub, not master's.

    Pins multi-device-aware stubbing for VC-of-modular: a Module
    entity attached to member-2 must resolve against the member-2
    top-level Device in the index — not the master Device — so its
    stubbed device-ref carries the right member name. Without
    per-member resolution, Diode would reconcile every module under
    the master chassis instead of the right member.
    """
    master = pb.Device(name="stack-sw", serial="FCW0001", status="active")
    master.device_type.CopyFrom(
        pb.DeviceType(model="C9300L-48T-4X", manufacturer=pb.Manufacturer(name="Cisco")),
    )
    member2 = pb.Device(name="stack-sw-2", serial="FCW0002", status="active")
    member2.device_type.CopyFrom(
        pb.DeviceType(model="C9300L-48T-4X", manufacturer=pb.Manufacturer(name="Cisco")),
    )

    bay1 = pb.ModuleBay(name="1", position="1")
    bay1.device.CopyFrom(master)
    mod1 = pb.Module(serial="NM1")
    mod1.device.CopyFrom(master)
    mod1.module_type.CopyFrom(
        pb.ModuleType(model="C9300-NM-8X", manufacturer=pb.Manufacturer(name="Cisco")),
    )

    bay2 = pb.ModuleBay(name="1", position="1")
    bay2.device.CopyFrom(member2)
    mod2 = pb.Module(serial="NM2")
    mod2.device.CopyFrom(member2)
    mod2.module_type.CopyFrom(
        pb.ModuleType(model="C9300-NM-8X", manufacturer=pb.Manufacturer(name="Cisco")),
    )

    entities = [
        Entity(device=master),
        Entity(device=member2),
        Entity(module_bay=bay1),
        Entity(module=mod1),
        Entity(module_bay=bay2),
        Entity(module=mod2),
    ]
    prune_nested_refs(entities)

    pruned_mod1 = entities[3].module
    pruned_mod2 = entities[5].module
    # Each Module's stubbed Device carries that MEMBER's name, not master's.
    assert pruned_mod1.device.name == "stack-sw"
    assert pruned_mod1.device.serial == ""  # stubbed
    assert pruned_mod2.device.name == "stack-sw-2"
    assert pruned_mod2.device.serial == ""
    # Per-member ModuleBay also resolves to its own device.
    pruned_bay1 = entities[2].module_bay
    pruned_bay2 = entities[4].module_bay
    assert pruned_bay1.device.name == "stack-sw"
    assert pruned_bay2.device.name == "stack-sw-2"

