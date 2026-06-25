"""
Regression tests for prune_nested_refs() with more than one top-level Device.

Background: prune_nested_refs() previously assumed a single top-level Device
and rewrote every nested Interface/IPAddress device-ref to that device's
matcher stub. With future multi-Device translator paths (switch stacks /
Virtual Chassis), each nested ref must be rewritten to ITS OWN device's
stub, not "the first device in the list".
"""

from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb
from netboxlabs.diode.sdk.ingester import Entity

from device_discovery.stubs import prune_nested_refs


def _make_device(name: str, serial: str, source_match: str | None = None) -> pb.Device:
    d = pb.Device(name=name, serial=serial)
    d.site.CopyFrom(pb.Site(name="lab"))
    d.role.CopyFrom(pb.DeviceRole(name="switch"))
    d.device_type.CopyFrom(
        pb.DeviceType(model="WS-C3850-12XS", manufacturer=pb.Manufacturer(name="cisco"))
    )
    if source_match:
        d.metadata["source_match"] = source_match
    return d


def _make_interface(name: str, dev_name: str, dev_serial: str) -> pb.Interface:
    iface = pb.Interface(name=name, type="1000base-t")
    iface.device.CopyFrom(_make_device(dev_name, dev_serial))
    return iface


def test_two_top_level_devices_each_keep_own_interfaces():
    """Each member's interface stub references its OWN device, not the first one in the list."""
    dev_a = _make_device("core-sw-1", "FOC1")
    dev_b = _make_device("core-sw-2", "FOC2")
    iface_a = _make_interface("GigabitEthernet1/0/1", "core-sw-1", "FOC1")
    iface_b = _make_interface("GigabitEthernet2/0/1", "core-sw-2", "FOC2")

    entities = [
        Entity(device=dev_a),
        Entity(device=dev_b),
        Entity(interface=iface_a),
        Entity(interface=iface_b),
    ]

    prune_nested_refs(entities)

    pruned_a = entities[2].interface
    pruned_b = entities[3].interface
    assert pruned_a.device.name == "core-sw-1"
    assert pruned_b.device.name == "core-sw-2"


def test_ip_address_resolves_to_correct_member_via_assigned_interface():
    """IPAddress.assigned_object_interface device-ref resolves to the owning member, not device #0."""
    dev_a = _make_device("core-sw-1", "FOC1")
    dev_b = _make_device("core-sw-2", "FOC2")
    ip = pb.IPAddress(address="10.0.0.2/24")
    ip.assigned_object_interface.CopyFrom(_make_interface("GigabitEthernet2/0/1", "core-sw-2", "FOC2"))

    entities = [Entity(device=dev_a), Entity(device=dev_b), Entity(ip_address=ip)]

    prune_nested_refs(entities)

    pruned_iface = entities[2].ip_address.assigned_object_interface
    assert pruned_iface.device.name == "core-sw-2"


def test_unresolvable_device_ref_passes_through_with_warning(caplog):
    """Nested device-refs that don't match any top-level Device are logged and left untouched."""
    dev_a = _make_device("core-sw-1", "FOC1")
    iface = _make_interface("GigabitEthernet9/0/1", "core-sw-9", "FOC9")  # not a top-level Device

    entities = [Entity(device=dev_a), Entity(interface=iface)]

    with caplog.at_level("WARNING", logger="device_discovery.stubs"):
        prune_nested_refs(entities)

    assert any("could not resolve nested device" in rec.message.lower() for rec in caplog.records)
    # Entity is preserved; we don't crash and we don't silently rewrite to dev_a.
    assert entities[1].interface.device.name == "core-sw-9"


def test_unresolvable_ip_address_device_ref_passes_through_with_warning(caplog):
    """IPAddress nested device-refs that don't match any top-level Device are logged and left untouched."""
    dev_a = _make_device("core-sw-1", "FOC1")
    ip = pb.IPAddress(address="10.0.0.99/32")
    ip.assigned_object_interface.CopyFrom(
        _make_interface("GigabitEthernet9/0/1", "core-sw-9", "FOC9")
    )

    entities = [Entity(device=dev_a), Entity(ip_address=ip)]

    with caplog.at_level("WARNING", logger="device_discovery.stubs"):
        prune_nested_refs(entities)

    assert any("could not resolve nested device" in rec.message.lower() for rec in caplog.records)
    # Entity is preserved; nested device-ref is left untouched, not silently rewritten to dev_a.
    assert entities[1].ip_address.assigned_object_interface.device.name == "core-sw-9"


def test_resolve_falls_back_to_serial_when_name_does_not_match():
    """Resolve via serial fallback when nested ref's name doesn't match any top-level Device."""
    dev_a = _make_device("core-sw-1", "FOC1")
    dev_b = _make_device("core-sw-2", "FOC2")

    iface = pb.Interface(name="GigabitEthernet2/0/1", type="1000base-t")
    # Nested device-ref has an unmatched name but the right serial.
    iface.device.name = "stale-or-wrong-name"
    iface.device.serial = "FOC2"

    entities = [Entity(device=dev_a), Entity(device=dev_b), Entity(interface=iface)]
    prune_nested_refs(entities)

    # Resolved via serial fallback to dev_b — and rewritten to dev_b's stub.
    assert entities[2].interface.device.name == "core-sw-2"


def test_source_match_only_on_master_does_not_leak_to_member_stubs():
    """Master device's source_match metadata never leaks onto a member device's stub."""
    master = _make_device("core-sw-1", "FOC1", source_match="netbox_id:42")
    member = _make_device("core-sw-2", "FOC2")  # no source_match
    iface_master = _make_interface("GigabitEthernet1/0/1", "core-sw-1", "FOC1")
    iface_member = _make_interface("GigabitEthernet2/0/1", "core-sw-2", "FOC2")

    entities = [
        Entity(device=master),
        Entity(device=member),
        Entity(interface=iface_master),
        Entity(interface=iface_member),
    ]

    prune_nested_refs(entities)

    # Master interface stub keeps source_match.
    assert entities[2].interface.device.metadata["source_match"] == "netbox_id:42"
    # Member interface stub does NOT pick up the master's source_match.
    assert "source_match" not in entities[3].interface.device.metadata


def test_single_device_path_unchanged():
    """Existing single-Device behavior must be preserved (regression gate)."""
    dev = _make_device("core-sw", "FOC1", source_match="netbox_id:7")
    dev.asset_tag = "ASSET-001"
    # Set a primary-IP back-pointer on the rich device.
    dev.primary_ip4.address = "10.0.0.1/32"
    dev.primary_ip4.assigned_object_interface.CopyFrom(_make_interface("Loopback0", "core-sw", "FOC1"))

    iface = _make_interface("GigabitEthernet0/1", "core-sw", "FOC1")

    entities = [Entity(device=dev), Entity(interface=iface)]

    prune_nested_refs(entities)

    pruned_iface = entities[1].interface
    assert pruned_iface.device.name == "core-sw"
    # serial is intentionally not part of the matcher stub — confirms stub used, not rich device.
    assert pruned_iface.device.serial == ""
    assert pruned_iface.device.metadata["source_match"] == "netbox_id:7"
    assert pruned_iface.device.asset_tag == "ASSET-001"

    # Primary-IP back-pointer was rewritten to a matcher-only stub of the same device.
    pruned_back_iface = entities[0].device.primary_ip4.assigned_object_interface
    assert pruned_back_iface.device.name == "core-sw"
    assert pruned_back_iface.device.serial == ""


def test_parent_bridge_lag_refs_use_owning_device_stub():
    """Nested parent/bridge/lag Interface refs rewrite to the owning member's stub."""
    dev_a = _make_device("core-sw-1", "FOC1")
    dev_b = _make_device("core-sw-2", "FOC2")

    # Build a member-2 interface that references parent/bridge/lag interfaces also on member 2.
    iface_b_main = _make_interface("GigabitEthernet2/0/1", "core-sw-2", "FOC2")
    iface_b_main.parent.CopyFrom(_make_interface("Port-channel1", "core-sw-2", "FOC2"))
    iface_b_main.bridge.CopyFrom(_make_interface("Vlan10", "core-sw-2", "FOC2"))
    iface_b_main.lag.CopyFrom(_make_interface("Port-channel99", "core-sw-2", "FOC2"))

    entities = [Entity(device=dev_a), Entity(device=dev_b), Entity(interface=iface_b_main)]
    prune_nested_refs(entities)

    pruned = entities[2].interface
    assert pruned.device.name == "core-sw-2"
    assert pruned.parent.device.name == "core-sw-2"
    assert pruned.bridge.device.name == "core-sw-2"
    assert pruned.lag.device.name == "core-sw-2"


def test_primary_ip4_back_pointer_pruned_per_device():
    """Each top-level Device's primary_ip4 back-pointer is pruned against its own stub."""
    dev_a = _make_device("core-sw-1", "FOC1")
    dev_a.primary_ip4.address = "10.0.0.1/32"
    dev_a.primary_ip4.assigned_object_interface.CopyFrom(_make_interface("Vlan100", "core-sw-1", "FOC1"))

    dev_b = _make_device("core-sw-2", "FOC2")
    dev_b.primary_ip4.address = "10.0.0.2/32"
    dev_b.primary_ip4.assigned_object_interface.CopyFrom(_make_interface("Vlan200", "core-sw-2", "FOC2"))

    entities = [Entity(device=dev_a), Entity(device=dev_b)]
    prune_nested_refs(entities)

    a_back = entities[0].device.primary_ip4.assigned_object_interface
    b_back = entities[1].device.primary_ip4.assigned_object_interface
    # Each member's back-pointer Interface must reference its OWN device by name —
    # the stub-cache key is the device name. Serial is not on the matcher stub.
    assert a_back.device.name == "core-sw-1"
    assert b_back.device.name == "core-sw-2"
    # Sanity: the two stubs are not the same instance (per-device cache, not a single shared stub).
    assert a_back.device is not b_back.device


def test_stack_keeps_primary_ip_only_on_master_cycle_closer():
    """
    In a stack only the master has primary_ip4; only the master's cycle-closer IP keeps it.

    Members have no primary IP, so their IP entities have nothing to keep. The
    master's primary IP entity is the only cycle-closer that may SET
    device.primary_ip4 — and it keeps it address-only on its nested device stub.
    """
    master = _make_device("core-sw-1", "FOC1")
    master.primary_ip4.address = "10.0.0.1/32"
    master.primary_ip4.assigned_object_interface.CopyFrom(
        _make_interface("Loopback0", "core-sw-1", "FOC1")
    )
    member = _make_device("core-sw-2", "FOC2")

    # Master's cycle-closer IP entity.
    master_ip = pb.IPAddress(address="10.0.0.1/32")
    master_ip.assigned_object_interface.CopyFrom(
        _make_interface("Loopback0", "core-sw-1", "FOC1")
    )
    # A member IP entity (member has no primary).
    member_ip = pb.IPAddress(address="10.0.0.50/24")
    member_ip.assigned_object_interface.CopyFrom(
        _make_interface("GigabitEthernet2/0/1", "core-sw-2", "FOC2")
    )

    entities = [
        Entity(device=master),
        Entity(device=member),
        Entity(ip_address=master_ip),
        Entity(ip_address=member_ip),
    ]
    prune_nested_refs(entities)

    master_ip_dev = entities[2].ip_address.assigned_object_interface.device
    member_ip_dev = entities[3].ip_address.assigned_object_interface.device
    # Only the master's cycle-closer keeps primary_ip4.
    assert master_ip_dev.HasField("primary_ip4")
    assert master_ip_dev.primary_ip4.address == "10.0.0.1/32"
    assert not master_ip_dev.primary_ip4.HasField("assigned_object_interface")
    # Member IP strips.
    assert not member_ip_dev.HasField("primary_ip4")


def test_repeated_address_across_devices_keeps_only_the_primary_owner():
    """
    Same address on interfaces of DIFFERENT devices: only the entity whose owning device's primary matches keeps it.

    dev_a has 10.0.0.1/24 as its primary; dev_b merely has an interface with the
    same address (not its primary). Only the IP entity resolving to dev_a's
    interface keeps primary_ip4; the one resolving to dev_b strips.
    """
    dev_a = _make_device("core-sw-1", "FOC1")
    dev_a.primary_ip4.address = "10.0.0.1/24"
    dev_a.primary_ip4.assigned_object_interface.CopyFrom(
        _make_interface("Vlan10", "core-sw-1", "FOC1")
    )
    dev_b = _make_device("core-sw-2", "FOC2")  # no primary_ip4

    ip_on_a = pb.IPAddress(address="10.0.0.1/24")
    ip_on_a.assigned_object_interface.CopyFrom(
        _make_interface("Vlan10", "core-sw-1", "FOC1")
    )
    ip_on_b = pb.IPAddress(address="10.0.0.1/24")
    ip_on_b.assigned_object_interface.CopyFrom(
        _make_interface("Vlan10", "core-sw-2", "FOC2")
    )

    entities = [
        Entity(device=dev_a),
        Entity(device=dev_b),
        Entity(ip_address=ip_on_a),
        Entity(ip_address=ip_on_b),
    ]
    prune_nested_refs(entities)

    dev_for_a = entities[2].ip_address.assigned_object_interface.device
    dev_for_b = entities[3].ip_address.assigned_object_interface.device
    # The same address resolves to different owning devices; only dev_a's keeps it.
    assert dev_for_a.name == "core-sw-1"
    assert dev_for_a.HasField("primary_ip4")
    assert dev_for_b.name == "core-sw-2"
    assert not dev_for_b.HasField("primary_ip4")


def test_member_device_stub_drops_virtual_chassis_and_vc_position():
    """
    Member Device stubs intentionally drop virtual_chassis + vc_position.

    The Diode plugin's dcim.device matcher cascade resolves at one of: asset_tag,
    primary_ip4/6, oob_ip, name+site+tenant, name+site, rack+position+face — and only
    falls through to virtual_chassis+vc_position as the last resort. In practice the
    stub always resolves at name+site+tenant or higher, so virtual_chassis +
    vc_position are unreachable and copying them would just bloat the wire payload
    (the rich virtual_chassis subtree carries a nested master Device ref).
    """
    master = _make_device("core-sw-1", "FOC1")
    member = _make_device("core-sw-2", "FOC2")
    member.vc_position = 2
    member.virtual_chassis.CopyFrom(
        pb.VirtualChassis(
            name="core-sw",
            master=pb.Device(name="core-sw-1", serial="FOC1"),
        )
    )
    iface = _make_interface("GigabitEthernet2/0/1", "core-sw-2", "FOC2")
    entities = [Entity(device=master), Entity(device=member), Entity(interface=iface)]

    prune_nested_refs(entities)

    pruned_dev_ref = entities[2].interface.device
    # Stub resolves at higher-precedence matchers (name+site+tenant), so VC fields are dropped.
    assert pruned_dev_ref.name == "core-sw-2"
    assert pruned_dev_ref.vc_position == 0, (
        "member Device stub unexpectedly carries vc_position — wire payload bloat"
    )
    assert not pruned_dev_ref.HasField("virtual_chassis"), (
        "member Device stub unexpectedly carries virtual_chassis subtree — wire payload bloat"
    )
