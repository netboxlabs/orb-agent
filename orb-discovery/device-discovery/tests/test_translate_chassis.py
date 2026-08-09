"""
Tests for the VC emission branch in translate.translate_data.

The branch fires when data['chassis_members'] has 2+ valid members. It must
produce, in order:
  1. master Device (PLAIN — no vc_position, no virtual_chassis)
  2. top-level VirtualChassis with inline master that does NOT recurse into
     another virtual_chassis
  3. non-master member Devices, each with vc_position and an inline
     virtual_chassis reference whose master is the same matcher block (and
     also does not recurse)
  4. interface entities, each routed to the correct member by parse_member_id
"""

from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb
from netboxlabs.diode.sdk.ingester import VLAN

from device_discovery.policy.models import (
    Defaults,
    DeviceParameters,
    Options,
    TenantParameters,
)
from device_discovery.translate import translate_data
from device_discovery.translate_chassis import _build_per_member_interfaces


def _base_data(chassis_members):
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
            "Port-channel1": {
                "is_enabled": True, "is_up": True, "speed": 2000, "mtu": 1500,
                "mac_address": "", "description": "", "last_flapped": -1.0,
            },
        },
        "interface_ip": {},
        "chassis_members": chassis_members,
        "target_hostname": "core-sw",
    }


def _two_member_payload(active_role_on_id=1):
    return {
        "members": [
            {"id": 1, "serial": "FOC2401L0AB", "model": "WS-C3850-12XS",
             "role": "active" if active_role_on_id == 1 else "standby",
             "priority": 15, "mac": "aabb.cc00.0001", "state": "ready"},
            {"id": 2, "serial": "FOC2401L0CD", "model": "WS-C3850-12XS",
             "role": "active" if active_role_on_id == 2 else "standby",
             "priority": 14, "mac": "aabb.cc00.0002", "state": "ready"},
        ],
        "domain": None,
    }


def test_single_member_no_vc_emitted():
    """A single-member payload behaves identically to today's single-Device path."""
    data = _base_data({"members": [
        {"id": 1, "serial": "FOC2401L0AB", "model": "WS-C3850-12XS",
         "role": "active", "priority": 15, "mac": "aabb.cc00.0001", "state": "ready"},
    ], "domain": None})
    entities = list(translate_data(data))
    vcs = [e for e in entities if e.HasField("virtual_chassis")]
    devs = [e for e in entities if e.HasField("device")]
    assert len(vcs) == 0
    assert len(devs) == 1


def test_two_members_emits_master_plain_then_vc_then_member():
    """A 2-member payload emits master Device, then VC, then non-master member with vc ref."""
    data = _base_data(_two_member_payload())
    entities = list(translate_data(data))

    devs = [e for e in entities if e.HasField("device")]
    vcs = [e for e in entities if e.HasField("virtual_chassis")]
    assert len(devs) == 2
    assert len(vcs) == 1

    # Order: master device first, then VC, then non-master member.
    device_indices = [i for i, e in enumerate(entities) if e.HasField("device")]
    vc_indices = [i for i, e in enumerate(entities) if e.HasField("virtual_chassis")]
    assert device_indices[0] < vc_indices[0] < device_indices[1]

    master = entities[device_indices[0]].device
    member = entities[device_indices[1]].device
    vc = entities[vc_indices[0]].virtual_chassis

    # Master device is PLAIN.
    assert master.name == "core-sw-1"
    assert master.serial == "FOC2401L0AB"
    assert master.vc_position == 0  # protobuf default for unset int
    assert not master.HasField("virtual_chassis")

    # Top-level VC carries inline master that does NOT recurse.
    assert vc.name == "core-sw"
    assert vc.HasField("master")
    assert vc.master.name == "core-sw-1"
    assert vc.master.serial == "FOC2401L0AB"
    assert not vc.master.HasField("virtual_chassis")

    # Non-master member Device carries vc_position + virtual_chassis ref
    # whose master also does not recurse.
    assert member.name == "core-sw-2"
    assert member.serial == "FOC2401L0CD"
    assert member.vc_position == 2
    assert member.HasField("virtual_chassis")
    assert member.virtual_chassis.name == "core-sw"
    assert member.virtual_chassis.HasField("master")
    assert not member.virtual_chassis.master.HasField("virtual_chassis")


def test_custom_stack_member_name_template_applies_to_master_and_members():
    """A custom template renames master, member, and the VC master ref."""
    data = _base_data(_two_member_payload())
    data["defaults"] = Defaults(stack_member_name_template="{name}-css{id}")
    entities = list(translate_data(data))

    device_indices = [i for i, e in enumerate(entities) if e.HasField("device")]
    vc = next(e.virtual_chassis for e in entities if e.HasField("virtual_chassis"))
    master = entities[device_indices[0]].device
    member = entities[device_indices[1]].device

    assert master.name == "core-sw-css1"
    assert member.name == "core-sw-css2"
    assert vc.name == "core-sw"  # VC name itself is not templated
    assert vc.master.name == "core-sw-css1"
    assert member.virtual_chassis.master.name == "core-sw-css1"


def test_custom_stack_member_name_template_routes_interfaces():
    """Interfaces route to the templated member names."""
    data = _base_data(_two_member_payload())
    data["defaults"] = Defaults(stack_member_name_template="{name}-css{id}")
    entities = list(translate_data(data))
    by_name = {e.interface.name: e.interface for e in entities if e.HasField("interface")}
    assert by_name["GigabitEthernet1/0/1"].device.name == "core-sw-css1"
    assert by_name["GigabitEthernet2/0/1"].device.name == "core-sw-css2"


def test_bad_stack_member_name_template_falls_back_to_default():
    """An unusable template is normalized to the default → legacy names, no crash."""
    data = _base_data(_two_member_payload())
    data["defaults"] = Defaults(stack_member_name_template="{name}-{id:09d}")
    entities = list(translate_data(data))
    names = {e.device.name for e in entities if e.HasField("device")}
    assert names == {"core-sw-1", "core-sw-2"}


def test_interface_routed_to_correct_member():
    """An interface name with a parseable member id routes to that member's Device."""
    data = _base_data(_two_member_payload())
    entities = list(translate_data(data))
    by_name = {e.interface.name: e.interface for e in entities if e.HasField("interface")}
    assert by_name["GigabitEthernet1/0/1"].device.name == "core-sw-1"
    assert by_name["GigabitEthernet2/0/1"].device.name == "core-sw-2"


def test_uplink_interface_routed_to_master():
    """Vlan/Loopback/Port-channel have no parseable member id → routed to master."""
    data = _base_data(_two_member_payload())
    entities = list(translate_data(data))
    by_name = {e.interface.name: e.interface for e in entities if e.HasField("interface")}
    assert by_name["Vlan10"].device.name == "core-sw-1"
    assert by_name["Port-channel1"].device.name == "core-sw-1"


def test_master_failover_doesnt_change_vc_identity():
    """Logical master is pinned to lowest id present, regardless of role."""
    entities_run1 = list(translate_data(_base_data(_two_member_payload(active_role_on_id=1))))
    entities_run2 = list(translate_data(_base_data(_two_member_payload(active_role_on_id=2))))

    vc1 = next(e.virtual_chassis for e in entities_run1 if e.HasField("virtual_chassis"))
    vc2 = next(e.virtual_chassis for e in entities_run2 if e.HasField("virtual_chassis"))
    assert vc1.name == vc2.name == "core-sw"
    assert vc1.master.serial == vc2.master.serial == "FOC2401L0AB"


def test_member_with_missing_serial_dropped_in_validation():
    """A serialless member is dropped at validation time; <2 valid members falls through to single-Device."""
    data = _base_data({"members": [
        {"id": 1, "serial": "FOC2401L0AB", "model": "X", "role": "active",
         "priority": 15, "mac": None, "state": "ready"},
        {"id": 2, "serial": "", "model": "X", "role": "standby",
         "priority": 14, "mac": None, "state": "ready"},
    ], "domain": None})
    entities = list(translate_data(data))
    # Only 1 valid member → single-Device path (no VC emitted).
    assert not any(e.HasField("virtual_chassis") for e in entities)


def test_malformed_chassis_payload_falls_through():
    """Non-dict, missing 'members' key, or wrong-typed members → single-Device path."""
    for payload in [None, {}, {"members": None}, {"members": "not-a-list"}, "not-a-dict"]:
        if payload is None:
            data = _base_data({})
            del data["chassis_members"]
        else:
            data = _base_data(payload)
        entities = list(translate_data(data))
        assert not any(e.HasField("virtual_chassis") for e in entities), (
            f"unexpected VC emission for payload={payload!r}"
        )


def test_subinterface_lands_on_same_member_as_parent():
    """Subinterface (Gi2/0/1.100) attributes to member 2, like its parent Gi2/0/1."""
    data = _base_data(_two_member_payload())
    data["interface"]["GigabitEthernet2/0/1.100"] = {
        "is_enabled": True, "is_up": True, "speed": 1000, "mtu": 1500,
        "mac_address": "", "description": "", "last_flapped": -1.0,
    }
    entities = list(translate_data(data))
    by_name = {e.interface.name: e.interface for e in entities if e.HasField("interface")}
    assert by_name["GigabitEthernet2/0/1.100"].device.name == "core-sw-2"
    assert by_name["GigabitEthernet2/0/1"].device.name == "core-sw-2"


def test_member_devices_have_no_asset_tag():
    """Non-master members must NOT inherit defaults.device.asset_tag (high-precedence matcher collision)."""
    data = _base_data(_two_member_payload())
    data["defaults"] = Defaults(device=DeviceParameters(asset_tag="TENANT-A-DEFAULT"))

    entities = list(translate_data(data))
    member_devices = [
        e.device for e in entities
        if e.HasField("device") and e.device.HasField("virtual_chassis")
    ]
    assert member_devices, "expected at least one member Device"
    for md in member_devices:
        assert md.asset_tag == "", (
            f"member Device {md.name} unexpectedly carried asset_tag {md.asset_tag!r}"
        )


def test_vc_master_ref_carries_master_asset_tag_and_source_match():
    """VC master inline ref must repeat the emitted master's matcher fields (asset_tag + source_match)."""
    data = _base_data(_two_member_payload())
    data["defaults"] = Defaults(device=DeviceParameters(asset_tag="TENANT-A-DEFAULT"))
    data["netbox_id"] = 42

    entities = list(translate_data(data))
    master = next(e.device for e in entities
                  if e.HasField("device") and not e.device.HasField("virtual_chassis"))
    vc = next(e.virtual_chassis for e in entities if e.HasField("virtual_chassis"))
    member = next(e.device for e in entities
                  if e.HasField("device") and e.device.HasField("virtual_chassis"))

    # The emitted master carries both. The VC inline ref MUST carry both as well —
    # otherwise unique_master matcher resolves to a different record on re-runs.
    assert master.asset_tag == "TENANT-A-DEFAULT"
    assert "source_match" in master.metadata

    assert vc.master.asset_tag == "TENANT-A-DEFAULT"
    assert "source_match" in vc.master.metadata

    # Same invariant on the member's nested virtual_chassis.master.
    assert member.virtual_chassis.master.asset_tag == "TENANT-A-DEFAULT"
    assert "source_match" in member.virtual_chassis.master.metadata


def test_vc_master_ref_carries_master_tenant():
    """defaults.tenant must propagate to master AND to the inline VC master ref."""
    data = _base_data(_two_member_payload())
    data["defaults"] = Defaults(tenant=TenantParameters(name="Tenant A", group="Group A"))

    entities = list(translate_data(data))
    master = next(e.device for e in entities
                  if e.HasField("device") and not e.device.HasField("virtual_chassis"))
    vc = next(e.virtual_chassis for e in entities if e.HasField("virtual_chassis"))
    member = next(e.device for e in entities
                  if e.HasField("device") and e.device.HasField("virtual_chassis"))

    assert master.HasField("tenant")
    assert master.tenant.name == "Tenant A"
    assert master.tenant.group.name == "Group A"

    # VC inline master MUST carry the same tenant or the unique_master matcher
    # will resolve to a different record on re-runs in tenant-scoped policies.
    assert vc.master.HasField("tenant"), (
        "VC master inline ref is missing tenant — matcher divergence vs. emitted master"
    )
    assert vc.master.tenant.name == "Tenant A"
    assert vc.master.tenant.group.name == "Group A"

    # Member's nested virtual_chassis.master must carry tenant too.
    nested = member.virtual_chassis.master
    assert nested.HasField("tenant")
    assert nested.tenant.name == "Tenant A"


def test_vc_master_ref_picks_up_defaults_device_model_override():
    """defaults.device.model override must be reflected on master AND inline VC master ref."""
    data = _base_data(_two_member_payload())
    data["defaults"] = Defaults(device=DeviceParameters(model="OVERRIDE-MODEL"))

    entities = list(translate_data(data))
    master = next(e.device for e in entities
                  if e.HasField("device") and not e.device.HasField("virtual_chassis"))
    vc = next(e.virtual_chassis for e in entities if e.HasField("virtual_chassis"))

    assert master.device_type.model == "OVERRIDE-MODEL"
    assert vc.master.device_type.model == "OVERRIDE-MODEL"


def test_ip_only_interface_routed_to_correct_member():
    """Interfaces present only in interface_ip (e.g. loopbacks) must NOT be silently dropped."""
    data = _base_data(_two_member_payload())
    # interface_ip carries an entry whose key isn't in interfaces[].
    data["interface_ip"]["Loopback0"] = {
        "ipv4": {"10.0.0.1": {"prefix_length": 32}},
    }
    # And one with a parseable member id.
    data["interface_ip"]["GigabitEthernet2/0/9"] = {
        "ipv4": {"10.0.2.9": {"prefix_length": 24}},
    }

    entities = list(translate_data(data))
    by_name = {e.interface.name: e.interface for e in entities if e.HasField("interface")}
    # IP-only interfaces become Interface entities.
    assert "Loopback0" in by_name, "expected Loopback0 stub interface from interface_ip"
    assert "GigabitEthernet2/0/9" in by_name
    # Loopback0 routes to master (no parseable member id).
    assert by_name["Loopback0"].device.name == "core-sw-1"
    # Gi2/0/9 routes to member 2.
    assert by_name["GigabitEthernet2/0/9"].device.name == "core-sw-2"


def test_unknown_member_id_is_skipped_with_warning(caplog):
    """
    An interface whose parsed member id was dropped from chassis_members is SKIPPED, not routed to master.

    Routing orphaned member interfaces to master would silently misattribute them to
    the wrong device — e.g. Gi9/0/1 (a member-9 port) showing up on member 2 just
    because member 9 lost its serial during validation. Skipping with a warning is
    safer: NetBox is missing the orphaned ports (operator-visible via the warning),
    not corrupted with port→device assignments that don't match physical reality.
    """
    import logging

    data = _base_data(_two_member_payload())
    data["interface"]["GigabitEthernet9/0/1"] = {
        "is_enabled": True, "is_up": True, "speed": 1000, "mtu": 1500,
        "mac_address": "", "description": "", "last_flapped": -1.0,
    }
    # IP-only entry on the same orphaned member must also be skipped.
    data["interface_ip"]["GigabitEthernet9/0/1"] = {
        "ipv4": {"10.9.9.1": {"prefix_length": 24}},
    }

    with caplog.at_level(logging.WARNING, logger="device_discovery.translate_chassis"):
        entities = list(translate_data(data))

    by_name = {e.interface.name: e.interface for e in entities if e.HasField("interface")}
    assert "GigabitEthernet9/0/1" not in by_name, (
        "orphaned member interface must NOT be emitted (routing to master would misattribute)"
    )
    # No IP entity for the orphaned address either.
    ips = [e.ip_address.address for e in entities if e.HasField("ip_address")]
    assert "10.9.9.1/24" not in ips, "orphaned member IP must NOT be emitted"
    assert any(
        "unknown member id 9" in r.message and "skipping" in r.message
        for r in caplog.records
    ), "expected a WARNING explicitly stating the interface was skipped"


def test_validation_drops_duplicate_ids_and_serials(caplog):
    """Duplicate ids/serials are dropped at validation time with a warning."""
    import logging

    data = _base_data({
        "members": [
            {"id": 1, "serial": "FOC-A", "model": "X", "role": "active",
             "priority": 15, "mac": None, "state": "ready"},
            {"id": 1, "serial": "FOC-DUP-ID", "model": "X", "role": "standby",
             "priority": 10, "mac": None, "state": "ready"},
            {"id": 2, "serial": "FOC-A", "model": "X", "role": "standby",
             "priority": 14, "mac": None, "state": "ready"},
            {"id": 3, "serial": "FOC-C", "model": "X", "role": "member",
             "priority": 1, "mac": None, "state": "ready"},
        ],
        "domain": None,
    })

    # Warnings come from validate_chassis_payload, which lives in
    # device_discovery.translate_chassis (not device_discovery.translate).
    with caplog.at_level(logging.WARNING, logger="device_discovery.translate_chassis"):
        entities = list(translate_data(data))

    devices = [e.device for e in entities if e.HasField("device")]
    serials = sorted(d.serial for d in devices)
    assert serials == ["FOC-A", "FOC-C"], (
        "expected only the first occurrence of each id/serial to survive"
    )
    msgs = " ".join(r.message for r in caplog.records)
    assert "duplicate member id" in msgs
    assert "duplicate serial" in msgs


def test_vc_master_ref_strips_primary_ip_but_top_level_master_keeps_it():
    """
    The VC master inline ref STRIPS primary_ip4 — only the top-level master keeps it.

    The VC-master ref is NOT a cycle-closer: it resolves via
    name+serial+site+tenant+role+device_type, never via primary_ip4. Carrying
    primary_ip4 on it would make the plugin try (and fail) to SET device.primary_ip4
    in a change set that does not also do the IP→interface assignment. Only the
    top-level master Device entity (set by assign_primary_ip) keeps its rich
    primary_ip4; the single cycle-closer that validly sets it is the master's own
    ipam.ipaddress entity.

    Also a regression guard against the ordering bug — assign_primary_ip must run
    BEFORE the master Entity is built, so the top-level master retains primary_ip4.
    """
    data = _base_data(_two_member_payload())
    data["interface_ip"]["GigabitEthernet1/0/1"] = {
        "ipv4": {"10.0.0.1": {"prefix_length": 24}},
    }
    data["target_hostname"] = "10.0.0.1"

    entities = list(translate_data(data))
    master = next(e.device for e in entities
                  if e.HasField("device") and not e.device.HasField("virtual_chassis"))
    vc = next(e.virtual_chassis for e in entities if e.HasField("virtual_chassis"))
    member = next(e.device for e in entities
                  if e.HasField("device") and e.device.HasField("virtual_chassis"))

    # Rich top-level master keeps the full primary_ip4 (including back-pointer interface).
    assert master.HasField("primary_ip4")
    assert master.primary_ip4.address == "10.0.0.1/24"

    # VC master inline ref STRIPS primary_ip4 — it is not a cycle-closer.
    assert not vc.master.HasField("primary_ip4"), "VC master ref must not carry primary_ip4 — it is not a cycle-closer"

    # Same on each member's nested virtual_chassis.master.
    assert not member.virtual_chassis.master.HasField("primary_ip4")


def test_master_primary_ip_propagates_to_emitted_entity():
    """assign_primary_ip must mutate master_dev BEFORE it is wrapped into Entity (proto copy)."""
    data = _base_data(_two_member_payload())
    # Give the master interface an IP that resolves to the target_hostname so
    # assign_primary_ip picks it.
    data["interface_ip"]["GigabitEthernet1/0/1"] = {
        "ipv4": {"10.0.0.1": {"prefix_length": 24}},
    }
    data["target_hostname"] = "10.0.0.1"

    entities = list(translate_data(data))
    master = next(
        e.device for e in entities
        if e.HasField("device") and not e.device.HasField("virtual_chassis")
    )
    assert master.HasField("primary_ip4"), (
        "master Entity is missing primary_ip4 — assign_primary_ip ran AFTER Entity copy"
    )
    assert master.primary_ip4.address == "10.0.0.1/24"


def test_validation_rejects_non_string_optional_field():
    """A member whose optional field has the wrong type is dropped, not allowed to crash translate."""
    data = _base_data({
        "members": [
            {"id": 1, "serial": "FOC-A", "model": 123, "role": "active",  # bad model type
             "priority": 15, "mac": None, "state": "ready"},
            {"id": 2, "serial": "FOC-B", "model": "X", "role": "standby",
             "priority": 14, "mac": None, "state": "ready"},
            {"id": 3, "serial": "FOC-C", "model": "X", "role": "member",
             "priority": 1, "mac": None, "state": "ready"},
        ],
        "domain": None,
    })
    entities = list(translate_data(data))
    member_serials = sorted(e.device.serial for e in entities if e.HasField("device"))
    # Member 1 dropped (bad model type) → only 2 valid → translate emits VC for 2 + 3.
    assert member_serials == ["FOC-B", "FOC-C"]


# ---- VC with module discovery ------------------------------------------


def test_vc_with_modules_emits_per_member_module_entities():
    """
    A VC + per-member modules payload emits per-member Module entities.

    Module / ModuleBay entities attach to the right member Device, and
    each member's Interface entities carry module= refs to their own
    member's modules. Pins the end-to-end VC-of-modular dispatch from
    translate_as_stack through emit_modules_if_requested into
    per-member build_interface_entities.
    """
    from device_discovery.policy.models import Options

    data = _base_data(_two_member_payload())
    data["options"] = Options(discover_modules="linecards")
    data["modules"] = {
        "members": {
            1: {
                "bays": [{
                    "name": "1", "position": "1",
                    "module": {
                        "model": "C9300-NM-8X", "serial": "NM1",
                        "description": "", "type": "linecard",
                        "sub_bays": [],
                    },
                }],
                "interfaces_by_bay": {"1": ["GigabitEthernet1/0/1"]},
            },
            2: {
                "bays": [{
                    "name": "1", "position": "1",
                    "module": {
                        "model": "C9300-NM-8X", "serial": "NM2",
                        "description": "", "type": "linecard",
                        "sub_bays": [],
                    },
                }],
                "interfaces_by_bay": {"1": ["GigabitEthernet2/0/1"]},
            },
        },
    }
    entities = list(translate_data(data))

    devices = [e.device for e in entities if e.HasField("device")]
    assert len(devices) == 2  # master + 1 non-master = VC of 2.

    modules = [e.module for e in entities if e.HasField("module")]
    assert {m.serial for m in modules} == {"NM1", "NM2"}
    # Modules attach to DIFFERENT member Devices (not both to master).
    nm1 = next(m for m in modules if m.serial == "NM1")
    nm2 = next(m for m in modules if m.serial == "NM2")
    assert nm1.device.name != nm2.device.name

    # Each member's Interface entity carries module= to its OWN member's module.
    interfaces = [e.interface for e in entities if e.HasField("interface")]
    iface_m1 = next(i for i in interfaces if i.name == "GigabitEthernet1/0/1")
    iface_m2 = next(i for i in interfaces if i.name == "GigabitEthernet2/0/1")
    assert iface_m1.HasField("module")
    assert iface_m1.module.serial == "NM1"
    assert iface_m2.HasField("module")
    assert iface_m2.module.serial == "NM2"



def test_vc_cascade_propagates_options_through_per_member_builder():
    """
    VC path regression: options.propagate_defaults_to_prefix_scope must reach the per-member interface builder.

    Without the fix at translate_chassis.py:282, build_interface_entities
    runs without options on the VC path → emitted Prefix has no scope
    even when defaults.site + propagate_* are set. This test asserts
    the cascade works end-to-end through translate_data → translate_as_stack
    → _build_per_member_interfaces → build_interface_entities.
    """
    from device_discovery.policy.models import Options

    data = _base_data(_two_member_payload())
    data["defaults"] = Defaults(site="DC-East")
    data["options"] = Options(propagate_defaults_to_prefix_scope=True)
    data["interface_ip"]["GigabitEthernet2/0/9"] = {
        "ipv4": {"10.0.2.9": {"prefix_length": 24}},
    }

    entities = list(translate_data(data))
    prefixes = [e.prefix for e in entities if e.HasField("prefix")]
    assert prefixes, "expected at least one Prefix from interface_ip on the VC path"
    # Cascade from defaults.site → Prefix.scope_site (NetBox 4.2+ scope oneof).
    assert prefixes[0].scope_site.name == "DC-East"


def test_single_member_payload_does_not_warn(caplog):
    """
    A one-member payload is a standalone device, not a partial parse.

    validate_chassis_payload is driver-agnostic and several drivers emit a
    single-member payload as documented-normal behaviour, so warning here would
    fire for every standalone device in a fleet on every discovery cycle.
    """
    import logging

    from device_discovery.translate_chassis import validate_chassis_payload

    payload = {
        "members": [
            {"id": 1, "serial": "FOC1111111", "model": "C9300-24T", "role": "active"}
        ],
        "domain": None,
    }
    with caplog.at_level(logging.DEBUG, logger="device_discovery.translate_chassis"):
        assert validate_chassis_payload(payload) is None
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


def test_dropped_members_do_warn(caplog):
    """
    Validation dropping members IS worth a warning.

    Two members in, fewer than two out means a driver handed us a stack we could
    not represent. The silent version of this was invisible until a user noticed
    missing NetBox data.
    """
    import logging

    from device_discovery.translate_chassis import validate_chassis_payload

    payload = {
        "members": [
            {"id": 1, "serial": "FOC1111111", "model": "C9300-24T", "role": "active"},
            # Same serial: dropped as a duplicate, leaving one valid member.
            {"id": 2, "serial": "FOC1111111", "model": "C9300-24T", "role": "standby"},
        ],
        "domain": None,
    }
    with caplog.at_level(logging.DEBUG, logger="device_discovery.translate_chassis"):
        assert validate_chassis_payload(payload) is None
    warnings = [
        r for r in caplog.records
        if r.levelno >= logging.WARNING
        and "survived validation" in r.getMessage()
    ]
    assert len(warnings) == 1
    assert "1 of 2" in warnings[0].getMessage()


# Prefix VLAN unanimity must span the whole stack, not one member at a time.


def _stack_vlan_inputs():
    """Two members sharing one network: an SVI on member 1, a routed port on member 2."""
    return {
        "member_ids": [1, 2],
        "member_devices": {1: pb.Device(name="sw-1"), 2: pb.Device(name="sw-2")},
        "grouped_interfaces": {
            1: {"Vlan10": {"is_up": True, "is_enabled": True, "mtu": 1500, "speed": 1000}},
            2: {"Ethernet2/0/1": {"is_up": True, "is_enabled": True, "mtu": 1500, "speed": 1000}},
        },
        "grouped_ips": {
            1: {"Vlan10": {"ipv4": {"10.0.0.1": {"prefix_length": 24}}}},
            2: {"Ethernet2/0/1": {"ipv4": {"10.0.0.2": {"prefix_length": 24}}}},
        },
        "defaults": Defaults(site="dc1"),
        "options": Options(emit_prefix_vlan="corroborated"),
        "vlan_cache": {10: VLAN(vid=10, name="office")},
    }


def _prefixes_named(per_member, network):
    out = []
    for entities in per_member.values():
        out.extend(e.prefix for e in entities if e.HasField("prefix") and e.prefix.prefix == network)
    return out


def test_prefix_vlan_unanimity_spans_every_stack_member():
    """
    A routed port on another member abstains, so the whole group withholds.

    Reconciling one member at a time lets member 1's SVI win alone, emitting
    one Prefix with a vlan and another without for the same network — the
    disagreement that makes the reconciler reject the entire changeset.
    """
    per_member = _build_per_member_interfaces(**_stack_vlan_inputs())

    got = _prefixes_named(per_member, "10.0.0.0/24")
    assert len(got) == 2, "both members contribute an address to this network"
    assert not any(p.HasField("vlan") for p in got), (
        "one contributor could not resolve a VLAN, so no member's prefix may carry one"
    )


def test_prefix_vlan_still_attaches_when_every_member_agrees():
    """The cross-member tally must not withhold when nothing actually disagrees."""
    inputs = _stack_vlan_inputs()
    # Member 2 reaches the same network through the same VLAN, so the group is unanimous.
    inputs["grouped_interfaces"][2] = {
        "Vlan10": {"is_up": True, "is_enabled": True, "mtu": 1500, "speed": 1000}
    }
    inputs["grouped_ips"][2] = {"Vlan10": {"ipv4": {"10.0.0.2": {"prefix_length": 24}}}}

    per_member = _build_per_member_interfaces(**inputs)

    got = _prefixes_named(per_member, "10.0.0.0/24")
    assert len(got) == 2
    assert all(p.vlan.vid == 10 for p in got), "an unanimous stack keeps its VLAN"


def test_prefix_vlan_option_off_is_inert_on_a_stack():
    """With the option off no prefix carries a VLAN, whatever the members disagree about."""
    inputs = _stack_vlan_inputs()
    inputs["options"] = Options()

    per_member = _build_per_member_interfaces(**inputs)

    got = _prefixes_named(per_member, "10.0.0.0/24")
    assert len(got) == 2
    assert not any(p.HasField("vlan") for p in got)
