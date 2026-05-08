#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
Matcher-only stubs of diode entities used to shrink nested references in the wire payload.

These helpers run at the client boundary, after run_id annotation and before message-size
estimation, so the rich entity graph is preserved through translation/annotation and only
the wire payload is trimmed.
"""

from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb
from netboxlabs.diode.sdk.ingester import Entity


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


def _current_device_from(entities: list[Entity]) -> pb.Device | None:
    """
    Return the rich top-level Device proto, or None.

    device-discovery emits exactly one top-level Device per call to translate_data. This O(N)
    lookup avoids threading the device pointer through to the client separately.
    """
    for e in entities:
        if e.HasField("device"):
            return e.device
    return None


def _device_match_stub(d: pb.Device) -> pb.Device:
    """
    Return a Device carrying matcher-only fields plus NetBox-required-for-create fields.

    INVARIANT: this set must be a superset of (a) every dcim.device matcher field
    device-discovery currently populates, and (b) every field NetBox treats as required for
    create. As of the spec date, device-discovery does NOT populate oob_ip, position, face,
    virtual_chassis, or vc_position. If a new translator path starts setting any of those,
    this stub must grow to include them — otherwise the rich entity and the stub will
    resolve via different matcher precedence paths or fail validation on the first cycle.

    `asset_tag` is the highest-precedence matcher and is populated when the policy sets
    defaults.device.asset_tag — kept on the stub so the rich entity and stub never resolve
    via different matchers.
    """
    stub = pb.Device(name=d.name)
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


def prune_nested_refs(entities: list[Entity]) -> None:
    """
    Walk entities once and replace nested Device and Interface references with stubs.

    Call from Client.ingest AFTER apply_run_id_to_entities and BEFORE estimate_message_size
    / diode_client.ingest. Running before annotation would either skip the rich Device or
    bloat every stub with run_id metadata. Running before estimate_message_size means
    chunking sees the trimmed payload size.

    No-op if entities is empty or no top-level Device is present.
    """
    if not entities:
        return
    rich_device = _current_device_from(entities)
    if rich_device is None:
        return
    dev_stub = _device_match_stub(rich_device)

    for e in entities:
        if e.HasField("device"):
            # Rich Device kept as-is, but trim the back-pointer Interface that
            # assign_primary_ip nested under primary_ip4/6.assigned_object_interface
            # — that nested Interface is only used to resolve the primary-IP's
            # interface row, so a matcher-only stub is sufficient and avoids
            # carrying the rich device.config (and other non-matcher fields)
            # along the back-pointer.
            _stub_primary_ip_iface(e.device.primary_ip4, dev_stub)
            _stub_primary_ip_iface(e.device.primary_ip6, dev_stub)
            continue
        if e.HasField("interface"):
            _prune_interface_entity(e.interface, dev_stub)
        elif e.HasField("ip_address"):
            ip = e.ip_address
            if ip.HasField("assigned_object_interface"):
                ip.assigned_object_interface.CopyFrom(
                    _interface_match_stub(ip.assigned_object_interface, dev_stub)
                )
