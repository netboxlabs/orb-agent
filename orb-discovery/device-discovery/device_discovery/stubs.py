#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
Matcher-only stubs of diode entities used to shrink nested references in the wire payload.

These helpers run at the client boundary, after run_id annotation and before message-size
estimation, so the rich entity graph is preserved through translation/annotation and only
the wire payload is trimmed.
"""

import logging

from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb
from netboxlabs.diode.sdk.ingester import Entity

from custom_napalm._modules import MAX_BAY_DEPTH
from device_discovery.proto_presence import copy_scalar_if_set

logger = logging.getLogger(__name__)


def _vrf_match_stub(vrf: pb.VRF) -> pb.VRF:
    """
    Return a VRF carrying only matcher identifiers (name, rd).

    The ipam.vrf matchers key on `name` and (when set) `rd`; tags/comments/description on
    the rich VRF would just bloat the wire and could leak into create-time attributes if
    the plugin's match-then-create fallback fires.
    """
    stub = pb.VRF(name=vrf.name)
    if vrf.rd:
        stub.rd = vrf.rd
    return stub


def _same_primary_ip(primary: pb.IPAddress, ip: pb.IPAddress) -> bool:
    """
    Return True when ``ip`` is the exact IP object the device's primary references.

    Match on full identity — address WITH prefix, VRF (name + rd, matching how
    _vrf_match_stub keys VRF identity), and the assigned interface — not just the
    host portion. Two IP entities can share a host address yet be different objects:
    a differing prefix length (a /32 loopback vs a /24 SVI), a differing VRF (the
    same address in two routing tables, or the same VRF name under a different rd),
    or the same CIDR reported on more than one interface (where assign_primary_ip
    deterministically selects one). Only the IP the device's primary actually points
    at may keep primary_ip4/primary_ip6 on its nested device stub (the cycle-closer);
    a looser match would let a different IP object's change set set device.primary_ip4
    and re-open the circular reference this pruning avoids.
    """
    if primary.address != ip.address:
        return False
    primary_vrf = (primary.vrf.name, primary.vrf.rd) if primary.HasField("vrf") else None
    ip_vrf = (ip.vrf.name, ip.vrf.rd) if ip.HasField("vrf") else None
    if primary_vrf != ip_vrf:
        return False
    primary_iface = primary.assigned_object_interface.name if primary.HasField("assigned_object_interface") else ""
    ip_iface = ip.assigned_object_interface.name if ip.HasField("assigned_object_interface") else ""
    return primary_iface == ip_iface


def _ip_match_stub(ip: pb.IPAddress) -> pb.IPAddress:
    """
    Return an IPAddress carrying only matcher fields.

    `assigned_object_interface` is intentionally unset — that breaks the IP→Interface→Device
    cycle when this stub is embedded in a Device stub's primary_ip4/primary_ip6 fields.
    """
    stub = pb.IPAddress(address=ip.address)
    if ip.HasField("vrf"):
        stub.vrf.CopyFrom(_vrf_match_stub(ip.vrf))
    return stub


def _index_top_level_devices(entities: list[Entity]) -> dict[str, pb.Device]:
    """
    Return a name→Device map of every top-level Device proto.

    Used by prune_nested_refs to derive each nested Interface/IPAddress's stub
    from its OWN device, not from a single 'first device' assumption. With
    switch-stack emission, the same translate call produces N top-level
    Devices (master + members); each member's interfaces must keep their
    own device-ref through pruning.

    Empty dict when entities has no top-level Device — pruning becomes a no-op.
    """
    index: dict[str, pb.Device] = {}
    for e in entities:
        if e.HasField("device"):
            if e.device.name in index:
                logger.warning(
                    "prune_nested_refs: duplicate top-level Device name %r — "
                    "second occurrence overwrites first; "
                    "this indicates an upstream translator bug",
                    e.device.name,
                )
            index[e.device.name] = e.device
    return index


def _resolve_device(
    nested: pb.Device, index: dict[str, pb.Device]
) -> pb.Device | None:
    """Look up the rich top-level Device for a nested reference. Name first, serial fallback."""
    if nested.name and nested.name in index:
        return index[nested.name]
    if nested.serial:
        matches = [d for d in index.values() if d.serial == nested.serial]
        if matches:
            if len(matches) > 1:
                logger.warning(
                    "prune_nested_refs: duplicate serial %r across %d top-level Devices — picking %r; resolution is non-deterministic",
                    nested.serial,
                    len(matches),
                    matches[0].name,
                )
            return matches[0]
    return None


def _copy_device_relations(
    stub: pb.Device,
    d: pb.Device,
    *,
    keep_primary_ip4: bool = False,
    keep_primary_ip6: bool = False,
) -> None:
    """
    Copy site/tenant/device_type/role onto ``stub``; primary IPs only when explicitly kept.

    Site/tenant/device_type/role are copied unconditionally. primary_ip4 / primary_ip6
    are copied only when the matching keep flag is set — by default every nested stub
    strips them so the plugin never tries to SET device.primary_ip4 from a change set
    that cannot resolve the circular reference.
    """
    if d.HasField("site"):
        stub.site.CopyFrom(pb.Site(name=d.site.name))
    if d.HasField("tenant"):
        stub.tenant.CopyFrom(_tenant_match_stub(d.tenant))
    if d.HasField("device_type"):
        stub.device_type.CopyFrom(_device_type_match_stub(d.device_type))
    if d.HasField("role"):
        stub.role.CopyFrom(pb.DeviceRole(name=d.role.name))
    if keep_primary_ip4 and d.HasField("primary_ip4"):
        stub.primary_ip4.CopyFrom(_ip_match_stub(d.primary_ip4))
    if keep_primary_ip6 and d.HasField("primary_ip6"):
        stub.primary_ip6.CopyFrom(_ip_match_stub(d.primary_ip6))


def _device_match_stub(
    d: pb.Device,
    *,
    keep_primary_ip4: bool = False,
    keep_primary_ip6: bool = False,
) -> pb.Device:
    """
    Return a Device carrying matcher-only fields plus NetBox-required-for-create fields.

    INVARIANT: this set must be a superset of every dcim.device matcher field the Diode
    plugin would actually consult to resolve this stub. In practice resolution succeeds
    at name+site+tenant (or asset_tag, when defaults.device.asset_tag is set) for every
    device, so those fields are always carried.

    primary_ip4 is the plugin's matcher #2, but device.primary_ip4 is a circular
    reference the plugin can only resolve inside a single change set — and each emitted
    entity is its own change set. The only entity that can validly set device.primary_ip4
    is the top-level ipam.ipaddress for the primary IP: it performs the IP→interface
    assignment AND, through its nested device stub, sets primary_ip4 in the same change
    set (the "cycle-closer"). So primary_ip4 / primary_ip6 are kept on a stub ONLY when
    that stub is the cycle-closer (``keep_primary_ip4`` / ``keep_primary_ip6`` set by the
    caller); every other nested stub strips them and resolves via name+site+tenant /
    asset_tag.

    virtual_chassis + vc_position are intentionally NOT copied here: they would only be
    consulted by a lower-precedence matcher that is never reached, and including them
    would copy a rich virtual_chassis subtree (with a nested master Device ref) into every
    member interface's nested device-stub, bloating the wire payload.

    `asset_tag` is the highest-precedence matcher and is populated when the policy sets
    defaults.device.asset_tag — kept on the stub so the rich entity and stub never resolve
    via different matchers.
    """
    # copy_scalar_if_set, not pb.Device(name=d.name): Device.name declares proto
    # presence, so reading an unset name as "" and passing it to the constructor
    # would mark the field PRESENT and send an explicit empty name.
    stub = pb.Device()
    copy_scalar_if_set(stub, d, "name")
    _copy_device_relations(
        stub, d, keep_primary_ip4=keep_primary_ip4, keep_primary_ip6=keep_primary_ip6
    )
    if d.asset_tag:
        stub.asset_tag = d.asset_tag
    # Carry source_match (e.g., netbox_id) — that is the plugin's PK-based
    # match path and must not diverge between rich and stub. Annotation
    # metadata such as run_id is intentionally not copied.
    if "source_match" in d.metadata:
        stub.metadata["source_match"] = d.metadata["source_match"]
    return stub


def _tenant_match_stub(tenant: pb.Tenant) -> pb.Tenant:
    """Return a Tenant carrying only name (and group name, if set)."""
    stub = pb.Tenant(name=tenant.name)
    if tenant.HasField("group"):
        stub.group.CopyFrom(pb.TenantGroup(name=tenant.group.name))
    return stub


def _device_type_match_stub(dt: pb.DeviceType) -> pb.DeviceType:
    """Return a DeviceType carrying only model (and manufacturer name, if set)."""
    stub = pb.DeviceType(model=dt.model)
    if dt.HasField("manufacturer"):
        stub.manufacturer.CopyFrom(pb.Manufacturer(name=dt.manufacturer.name))
    return stub


def _interface_match_stub(iface: pb.Interface, dev_stub: pb.Device) -> pb.Interface:
    """
    Return an Interface carrying matcher fields plus the validation-required `type` field.

    Used wherever an Interface appears as a nested reference: parent, bridge, lag,
    IPAddress.assigned_object_interface.

    Why type: interfaces referenced as IPAddress.assigned_object_interface are filtered from
    top-level emission in some translator paths, so the nested stub can be the only wire
    payload representing them. NetBox rejects dcim.interface creation when type is empty.

    primary_mac_address is preserved (stubbed to mac-only) so the stub keeps the
    unique_primary_mac_address matcher precedence and resolves to the same interface as the
    rich top-level entity.
    """
    stub = pb.Interface(name=iface.name, type=iface.type)
    stub.device.CopyFrom(dev_stub)
    if iface.HasField("primary_mac_address"):
        stub.primary_mac_address.CopyFrom(
            pb.MACAddress(mac_address=iface.primary_mac_address.mac_address)
        )
    return stub


def _replace_iface_field(parent: pb.Interface, field: str, dev_stub: pb.Device) -> None:
    """Replace a nested Interface field on ``parent`` with a matcher-only stub, if set."""
    if not parent.HasField(field):
        return
    nested = getattr(parent, field)
    nested.CopyFrom(_interface_match_stub(nested, dev_stub))


def _module_match_stub(rich: pb.Module, dev_stub: pb.Device) -> pb.Module:
    """
    Build a matcher-only Module for use as a nested reference.

    Keeps just the fields Diode needs to resolve a Module — the chassis
    device (matcher-stubbed) and the serial — plus a positional
    module_bay reference (device-stubbed) when the rich Module carries
    one. Drops module_type, description, asset_tag, status, and any
    rich device fields, so that copying this stub into hundreds of
    Interface entities does not duplicate the running-config-bearing
    Device proto per port.
    """
    stub = pb.Module()
    copy_scalar_if_set(stub, rich, "serial")
    stub.device.CopyFrom(dev_stub)
    if rich.HasField("module_bay"):
        bay_stub = pb.ModuleBay(name=rich.module_bay.name)
        copy_scalar_if_set(bay_stub, rich.module_bay, "position")
        bay_stub.device.CopyFrom(dev_stub)
        stub.module_bay.CopyFrom(bay_stub)
    return stub


def _prune_interface_entity(iface: pb.Interface, dev_stub: pb.Device) -> None:
    """Replace ``iface.device`` + any nested parent/bridge/lag/module with stubs in place."""
    iface.device.CopyFrom(dev_stub)
    _replace_iface_field(iface, "parent", dev_stub)
    _replace_iface_field(iface, "bridge", dev_stub)
    _replace_iface_field(iface, "lag", dev_stub)
    if iface.HasField("module"):
        iface.module.CopyFrom(_module_match_stub(iface.module, dev_stub))


def _stub_primary_ip_iface(ip: pb.IPAddress, dev_stub: pb.Device) -> None:
    """Replace the back-pointer Interface on a top-level Device's primary_ip with a stub."""
    if not ip.HasField("assigned_object_interface"):
        return
    ip.assigned_object_interface.CopyFrom(
        _interface_match_stub(ip.assigned_object_interface, dev_stub)
    )


def _prune_interface_against_index(
    iface: pb.Interface,
    index: dict[str, pb.Device],
    stub_for,
) -> None:
    """Resolve iface.device against the top-level index, then stub iface in place."""
    rich = _resolve_device(iface.device, index)
    if rich is None:
        logger.warning(
            "prune_nested_refs: could not resolve nested device %r for interface %r — leaving untouched",
            iface.device.name,
            iface.name,
        )
        return
    _prune_interface_entity(iface, stub_for(rich))


def _prune_ip_address_against_index(
    ip: pb.IPAddress,
    index: dict[str, pb.Device],
    stub_for,
    keep_primary_stub_for,
) -> None:
    """Resolve ip.assigned_object_interface.device, then replace the back-pointer with a stub."""
    if not ip.HasField("assigned_object_interface"):
        return
    nested_iface = ip.assigned_object_interface
    rich = _resolve_device(nested_iface.device, index)
    if rich is None:
        logger.warning(
            "prune_nested_refs: could not resolve nested device %r for IP %r — leaving untouched",
            nested_iface.device.name,
            ip.address,
        )
        return
    # This IP entity is the "cycle-closer" only when it is the resolved device's
    # OWN primary IP: it does the IP→interface assignment AND, via its nested
    # device stub's primary_ip4/6, validly sets device.primary_ip4/6 in one change
    # set. Only then does the nested device stub keep primary_ip4/6; otherwise it
    # uses the cached stripped stub (which never carries primary IPs).
    keep4 = rich.HasField("primary_ip4") and _same_primary_ip(rich.primary_ip4, ip)
    keep6 = rich.HasField("primary_ip6") and _same_primary_ip(rich.primary_ip6, ip)
    chosen_stub = keep_primary_stub_for(rich, keep4=keep4, keep6=keep6) if (keep4 or keep6) else stub_for(rich)
    ip.assigned_object_interface.CopyFrom(_interface_match_stub(nested_iface, chosen_stub))


# Hard cap on nested device-stub recursion through Module / ModuleBay protos.
# Cisco modular chassis are depth 2 (chassis → linecard → transceiver), Junos
# is depth 3 (chassis → FPC → PIC → transceiver).
#
# Each bay-tier in the emitted entity tree adds TWO recursion steps,
# not one: from a Module we descend into its ``module_bay`` (depth +1),
# then from that ModuleBay into its ``module`` parent ref (depth +1).
# So a depth-N hierarchy needs the recursion to reach depth 2*N to
# flush the topmost ancestor's device proto. With ``MAX_BAY_DEPTH=3``
# (Junos PIC) the leaf transceiver's ancestor chain has rich device
# fields at depths 0..5; setting the cap to ``2 * MAX_BAY_DEPTH``
# ensures every one of them gets stubbed before the recursion stops.
# An earlier cap of ``MAX_BAY_DEPTH + 1`` was too low and left the
# FPC-grandparent device unstubbed on Junos-shape payloads,
# reintroducing wire-size bloat for the deepest leaves.
_MAX_DEVICE_STUB_DEPTH = 2 * MAX_BAY_DEPTH


def _stub_device_recursive(msg, dev_stub: pb.Device, depth: int = 0) -> None:
    """
    Walk a Module / ModuleBay sub-tree and replace every nested ``device`` with a stub.

    The emitter sets ``device`` on every Module and ModuleBay (the chassis
    is the matching scope for both), and the nested ``module`` /
    ``module_bay`` / ``installed_module`` sub-messages each carry their
    own rich Device copy from protobuf CopyFrom semantics. Without this
    pass, a chassis with N transceivers duplicates the full Device proto
    (often with running-config text) N+1 times on the wire.
    """
    if depth >= _MAX_DEVICE_STUB_DEPTH:
        return
    if msg.HasField("device"):
        msg.device.CopyFrom(dev_stub)
    for field in ("module", "module_bay", "installed_module"):
        # HasField only works on message fields; ModuleBay has module +
        # installed_module, Module has module_bay. Wrap so we don't raise
        # when the field doesn't exist on this message type.
        try:
            present = msg.HasField(field)
        except ValueError:
            continue
        if present:
            _stub_device_recursive(getattr(msg, field), dev_stub, depth + 1)


def _prune_module_against_index(
    module: pb.Module,
    index: dict[str, pb.Device],
    stub_for,
) -> None:
    """Resolve module.device against the top-level index, then stub the whole sub-tree."""
    rich = _resolve_device(module.device, index)
    if rich is None:
        logger.warning(
            "prune_nested_refs: could not resolve nested device %r for module %r — leaving untouched",
            module.device.name,
            module.serial,
        )
        return
    _stub_device_recursive(module, stub_for(rich))


def _prune_module_bay_against_index(
    bay: pb.ModuleBay,
    index: dict[str, pb.Device],
    stub_for,
) -> None:
    """Resolve bay.device against the top-level index, then stub the whole sub-tree."""
    rich = _resolve_device(bay.device, index)
    if rich is None:
        logger.warning(
            "prune_nested_refs: could not resolve nested device %r for module_bay %r — leaving untouched",
            bay.device.name,
            bay.name,
        )
        return
    _stub_device_recursive(bay, stub_for(rich))


def prune_nested_refs(entities: list[Entity]) -> None:
    """
    Walk entities once and replace nested Device and Interface references with stubs.

    Call from Client.ingest AFTER apply_run_id_to_entities and BEFORE estimate_message_size
    / diode_client.ingest.

    Multi-Device aware: each Interface/IPAddress/Module/ModuleBay nested
    device-ref is resolved against the top-level Device index by name
    (serial as fallback). Stack-emitting translate paths produce N
    top-level Devices; member interfaces must keep their own attribution.

    Module / ModuleBay entities additionally have nested ``module`` /
    ``module_bay`` / ``installed_module`` sub-messages that each carry
    their own rich Device proto copy — without recursive stubbing, a
    chassis with N transceivers duplicates the full Device (often with
    running-config text) N+1 times on the wire.

    No-op if entities is empty or no top-level Device is present.
    Unresolved nested device-refs are logged at WARNING and left untouched.
    """
    if not entities:
        return
    index = _index_top_level_devices(entities)
    if not index:
        return

    # Cache stubs per top-level device — _device_match_stub builds matcher copies,
    # and re-running it for every interface would multiply work for large stacks.
    stub_cache: dict[str, pb.Device] = {}

    def _stub_for(rich: pb.Device) -> pb.Device:
        if rich.name not in stub_cache:
            stub_cache[rich.name] = _device_match_stub(rich)
        return stub_cache[rich.name]

    def _keep_primary_stub_for(rich: pb.Device, *, keep4: bool, keep6: bool) -> pb.Device:
        # Non-caching: the cycle-closer stub carries primary_ip4/6 and must NEVER
        # be written into (or read from) stub_cache — that cache holds the stripped
        # stub shared by every other nested ref. Build a fresh keep stub each call.
        return _device_match_stub(rich, keep_primary_ip4=keep4, keep_primary_ip6=keep6)

    for e in entities:
        _prune_entity(e, index, _stub_for, _keep_primary_stub_for)


def _prune_entity(e: Entity, index: dict[str, pb.Device], stub_for, keep_primary_stub_for) -> None:
    """Dispatch one entity to the right per-type pruner (or fix up its own back-refs)."""
    if e.HasField("device"):
        # Per-Device: the stub used here MUST be derived from THIS device, not
        # from a single shared "rich device" — otherwise a multi-Device entity
        # list (switch stacks) would point member primary-IP back-pointers at
        # the master's stub.
        own_stub = stub_for(e.device)
        _stub_primary_ip_iface(e.device.primary_ip4, own_stub)
        _stub_primary_ip_iface(e.device.primary_ip6, own_stub)
    elif e.HasField("interface"):
        _prune_interface_against_index(e.interface, index, stub_for)
    elif e.HasField("ip_address"):
        _prune_ip_address_against_index(e.ip_address, index, stub_for, keep_primary_stub_for)
    elif e.HasField("module"):
        _prune_module_against_index(e.module, index, stub_for)
    elif e.HasField("module_bay"):
        _prune_module_bay_against_index(e.module_bay, index, stub_for)
