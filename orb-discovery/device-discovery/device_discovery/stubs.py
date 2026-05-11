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


def _copy_device_relations(stub: pb.Device, d: pb.Device) -> None:
    """Copy site/tenant/device_type/role/primary_ip4/primary_ip6 onto ``stub``."""
    if d.HasField("site"):
        stub.site.CopyFrom(pb.Site(name=d.site.name))
    if d.HasField("tenant"):
        stub.tenant.CopyFrom(_tenant_match_stub(d.tenant))
    if d.HasField("device_type"):
        stub.device_type.CopyFrom(_device_type_match_stub(d.device_type))
    if d.HasField("role"):
        stub.role.CopyFrom(pb.DeviceRole(name=d.role.name))
    if d.HasField("primary_ip4"):
        stub.primary_ip4.CopyFrom(_ip_match_stub(d.primary_ip4))
    if d.HasField("primary_ip6"):
        stub.primary_ip6.CopyFrom(_ip_match_stub(d.primary_ip6))


def _device_match_stub(d: pb.Device) -> pb.Device:
    """
    Return a Device carrying matcher-only fields plus NetBox-required-for-create fields.

    INVARIANT: this set must be a superset of every dcim.device matcher field that the
    Diode plugin would actually use to resolve this stub. The plugin's matcher precedence
    (highest first) is: asset_tag → primary_ip4 → primary_ip6 → oob_ip → name+site+tenant
    → name+site → rack+position+face → virtual_chassis+vc_position. Resolution stops at
    the first matcher that produces a hit; in practice device-discovery populates
    asset_tag (when defaults.device.asset_tag is set), primary_ip4 (master only), and
    name+site+tenant for every device — so resolution always succeeds at one of those
    higher-precedence matchers. virtual_chassis + vc_position are intentionally NOT
    copied here: they would only be consulted by matcher #8, which is never reached, and
    including them would copy a rich virtual_chassis subtree (with a nested master Device
    ref) into every member interface's nested device-stub, bloating the wire payload.

    `asset_tag` is the highest-precedence matcher and is populated when the policy sets
    defaults.device.asset_tag — kept on the stub so the rich entity and stub never resolve
    via different matchers.
    """
    stub = pb.Device(name=d.name)
    _copy_device_relations(stub, d)
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


def _prune_interface_entity(iface: pb.Interface, dev_stub: pb.Device) -> None:
    """Replace ``iface.device`` and any nested parent/bridge/lag with stubs in place."""
    iface.device.CopyFrom(dev_stub)
    _replace_iface_field(iface, "parent", dev_stub)
    _replace_iface_field(iface, "bridge", dev_stub)
    _replace_iface_field(iface, "lag", dev_stub)


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
    ip.assigned_object_interface.CopyFrom(
        _interface_match_stub(nested_iface, stub_for(rich))
    )


def prune_nested_refs(entities: list[Entity]) -> None:
    """
    Walk entities once and replace nested Device and Interface references with stubs.

    Call from Client.ingest AFTER apply_run_id_to_entities and BEFORE estimate_message_size
    / diode_client.ingest.

    Multi-Device aware: each Interface/IPAddress nested device-ref is resolved against
    the top-level Device index by name (serial as fallback). Stack-emitting translate
    paths produce N top-level Devices; member interfaces must keep their own attribution.

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

    for e in entities:
        if e.HasField("device"):
            # Per-Device: the stub used here MUST be derived from THIS device, not
            # from a single shared "rich device" — otherwise a multi-Device entity
            # list (switch stacks) would point member primary-IP back-pointers at
            # the master's stub.
            own_stub = _stub_for(e.device)
            _stub_primary_ip_iface(e.device.primary_ip4, own_stub)
            _stub_primary_ip_iface(e.device.primary_ip6, own_stub)
        elif e.HasField("interface"):
            _prune_interface_against_index(e.interface, index, _stub_for)
        elif e.HasField("ip_address"):
            _prune_ip_address_against_index(e.ip_address, index, _stub_for)
