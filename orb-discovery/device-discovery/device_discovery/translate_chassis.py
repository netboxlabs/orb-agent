#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
Translate switch-stack / NetBox VirtualChassis payloads.

Consumed by ``device_discovery.translate.translate_data`` when a NAPALM driver
returns a ``chassis_members`` payload via the optional ``get_chassis_members()``
method (see ``custom_napalm/_chassis.py``).

Emission shape, in order:

  1. Master ``Device`` (PLAIN — no ``vc_position``, no ``virtual_chassis`` ref)
  2. Top-level ``VirtualChassis`` with an inline non-recursive master ref
  3. N - 1 non-master member ``Device`` entities, each carrying ``vc_position``
     and an inline ``virtual_chassis`` whose master is the same matcher block
     (also non-recursive)
  4. ``Interface`` / ``IPAddress`` entities, each routed to the correct member
     by ``parse_member_id``.

Logical master is pinned to the lowest member id so live StackWise role
failovers do not change the VC's master Device on re-runs (Diode resolves
existing VCs via the ``unique_master`` matcher).
"""

import copy
import logging

from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb
from netboxlabs.diode.sdk.ingester import Entity

from device_discovery.interface import build_interface_entities
from device_discovery.policy.models import Defaults, Options
from device_discovery.proto_presence import copy_scalar_if_set
from device_discovery.stack_naming import render_stack_member_name
from device_discovery.translate_modules import emit_modules_if_requested

logger = logging.getLogger(__name__)


def _is_valid_chassis_member(m: object) -> bool:
    """Return True iff ``m`` is a chassis member dict with safe types and core fields set."""
    if not isinstance(m, dict):
        return False
    mid = m.get("id")
    if not isinstance(mid, int) or isinstance(mid, bool) or mid < 0:
        return False
    serial = m.get("serial")
    if not isinstance(serial, str) or not serial:
        return False
    if not all(isinstance(m.get(k), (str, type(None))) for k in ("model", "mac", "state", "role")):
        logger.warning("chassis_members: dropping member %r — non-string optional field", mid)
        return False
    prio = m.get("priority")
    if prio is not None and (not isinstance(prio, int) or isinstance(prio, bool)):
        logger.warning("chassis_members: dropping member %r — non-int priority", mid)
        return False
    return True


def validate_chassis_payload(payload) -> list[dict] | None:
    """
    Confirm chassis_members payload is usable. Returns sorted-by-id member list or None.

    Defensive — a malformed payload (non-dict, missing/empty members list, or members
    without non-negative int ids — Junos FPC numbering starts at 0, e.g. ``et-0/0/0`` —
    and non-empty serials) falls through to the single-Device
    path. Members with duplicate ids or duplicate serials are dropped after the first
    occurrence (with a warning). Optional fields (``model``, ``mac``, ``state``,
    ``role``) must be str or None; ``priority`` must be int or None — bad types drop
    the member rather than crashing translate. Two or more valid members are required
    to emit VC.
    """
    if not isinstance(payload, dict):
        return None
    members_raw = payload.get("members")
    if not isinstance(members_raw, list):
        return None
    valid: list[dict] = []
    seen_ids: set[int] = set()
    seen_serials: set[str] = set()
    for m in members_raw:
        if not _is_valid_chassis_member(m):
            continue
        mid = m["id"]
        serial = m["serial"]
        if mid in seen_ids:
            logger.warning("chassis_members: dropping duplicate member id %r", mid)
            continue
        if serial in seen_serials:
            logger.warning("chassis_members: dropping duplicate serial %r", serial)
            continue
        seen_ids.add(mid)
        seen_serials.add(serial)
        valid.append(m)
    if len(valid) < 2:
        return None
    valid.sort(key=lambda m: m["id"])
    return valid


def _master_device_ref(master_dev: pb.Device) -> pb.Device:
    """
    Build an inline master Device matcher block from the emitted master Device proto.

    Used for both the top-level VirtualChassis.master field and each non-master
    member Device's virtual_chassis.master field. The plugin resolves the existing
    VC via unique_master, so this carries the matcher fields the emitted master
    Device carries — name, serial, site, tenant, role, device_type, asset_tag,
    and metadata.source_match — so the VC ref resolves through the same matcher
    path as the top-level master.

    Strips ``virtual_chassis``, ``config``, and annotation-only metadata so the
    inline ref does not nest another VC (circular reference) or carry config.
    Also strips ``primary_ip4``/``primary_ip6``: this ref is not a cycle-closer,
    and device.primary_ip4 is a circular reference the plugin can only resolve in
    the single change set that also assigns the IP to its interface.
    """
    # Defensive: the master name is currently always non-empty (hostname or
    # target_hostname or "unknown") and member serials are validated non-empty, so
    # neither field can be blank today. Routed through copy_scalar_if_set anyway so
    # this stub cannot regress into emitting an explicit empty matcher value.
    stub = pb.Device()
    copy_scalar_if_set(stub, master_dev, "name", "serial")
    _copy_master_ref_fields(stub, master_dev)
    if master_dev.asset_tag:
        stub.asset_tag = master_dev.asset_tag
    if "source_match" in master_dev.metadata:
        stub.metadata["source_match"] = master_dev.metadata["source_match"]
    return stub


def _copy_master_ref_fields(stub: pb.Device, master_dev: pb.Device) -> None:
    """Copy site/tenant/role/device_type onto a master matcher stub."""
    if master_dev.HasField("site"):
        stub.site.CopyFrom(pb.Site(name=master_dev.site.name))
    if master_dev.HasField("tenant"):
        t = master_dev.tenant
        tenant_stub = pb.Tenant(name=t.name)
        if t.HasField("group"):
            tenant_stub.group.CopyFrom(pb.TenantGroup(name=t.group.name))
        stub.tenant.CopyFrom(tenant_stub)
    if master_dev.HasField("role"):
        stub.role.CopyFrom(pb.DeviceRole(name=master_dev.role.name))
    if master_dev.HasField("device_type"):
        dt = master_dev.device_type
        stub_dt = pb.DeviceType(model=dt.model)
        if dt.HasField("manufacturer"):
            stub_dt.manufacturer.CopyFrom(pb.Manufacturer(name=dt.manufacturer.name))
        stub.device_type.CopyFrom(stub_dt)
    # primary_ip4/6 are intentionally NOT copied onto the VC-master ref: it is not
    # a cycle-closer. device.primary_ip4 is a circular reference the plugin can only
    # resolve inside a single change set, and this ref does not perform the
    # IP→interface assignment. The VC resolves via name+serial+site+tenant+role+
    # device_type. Only the top-level master Device entity (set by assign_primary_ip)
    # keeps its rich primary_ip4; the master's own ipam.ipaddress entity is the single
    # cycle-closer that validly sets it.


def _route_interfaces_by_member(
    interfaces: dict,
    interfaces_ip: dict,
    valid_ids: set[int],
    master_id: int,
    vc_name: str,
) -> tuple[dict[int, dict], dict[int, dict]]:
    """
    Group interface and interface_ip entries by chassis member id.

    Routing rules:

    - No parseable member id (``Vlan``, ``Loopback``, ``Port-channel``, etc.) → master.
    - Parseable member id that matches a validated member → that member.
    - Parseable member id that does NOT match any validated member → SKIPPED with a
      WARNING. This case fires when a physical member was dropped during validation
      (missing serial, duplicate id, etc.) but the device still reported its ports
      via ``show interfaces``. Routing those ports to master would silently
      misattribute member-1 interfaces to member-2 — a worse outcome than a NetBox
      record missing the orphaned ports, which an operator can spot via the warning.

    Interfaces present only in ``interface_ip`` (typical for loopbacks / mgmt SVIs
    not enumerated by ``get_interfaces``) are routed by the same rule so they are
    not silently dropped from valid members.
    """
    from custom_napalm._chassis import parse_member_id

    grouped_interfaces: dict[int, dict] = {mid: {} for mid in valid_ids}
    grouped_ips: dict[int, dict] = {mid: {} for mid in valid_ids}

    def _route(if_name: str, kind: str) -> int | None:
        mid = parse_member_id(if_name)
        if mid is None:
            return master_id
        if mid in valid_ids:
            return mid
        logger.warning(
            "chassis stack %r: %s %r references unknown member id %d "
            "(member dropped during validation or absent from chassis_members); "
            "skipping rather than misattributing to master",
            vc_name, kind, if_name, mid,
        )
        return None

    for if_name, if_data in interfaces.items():
        target = _route(if_name, "interface")
        if target is not None:
            grouped_interfaces[target][if_name] = if_data
    for if_name, ip_data in interfaces_ip.items():
        target = _route(if_name, "interface_ip")
        if target is not None:
            grouped_ips[target][if_name] = ip_data
    return grouped_interfaces, grouped_ips


def _build_member_devices(
    members: list[dict],
    master: dict,
    vc_name: str,
    device_info: dict,
    defaults: Defaults,
    options: Options,
    config_info: dict,
    netbox_id: int | None,
) -> dict[int, pb.Device]:
    """Build per-member rich Device protos. Non-master members get vc_position; virtual_chassis is filled later."""
    # Local import avoids a circular dep — translate.py imports translate_as_stack
    # from this module, and translate_device lives in translate.py.
    from device_discovery.translate import translate_device

    def _one(m: dict, *, is_master: bool) -> pb.Device:
        member_info = dict(device_info)
        member_info["hostname"] = render_stack_member_name(
            defaults.stack_member_name_template, vc_name, m["id"]
        )
        member_info["serial_number"] = m["serial"]
        if m.get("model"):
            member_info["model"] = m["model"]
        elif not is_master:
            # Non-master members must NOT silently inherit the chassis-level
            # model from device_info (which came from get_facts() on the
            # master/management plane). On mixed-model stacks the inherited
            # value would be wrong for every non-master member. When the
            # driver couldn't determine a per-member model we emit it as
            # empty so NetBox surfaces the gap rather than the lie. The
            # master keeps the chassis-reported model because get_facts()
            # describes the management entity — i.e., the master itself.
            member_info["model"] = None
        return translate_device(
            member_info,
            defaults,
            config_info if is_master else None,
            options if is_master else None,
            netbox_id=netbox_id if is_master else None,
        )

    member_devices: dict[int, pb.Device] = {master["id"]: _one(master, is_master=True)}
    for m in members[1:]:
        member_dev = _one(m, is_master=False)
        # asset_tag is a high-precedence matcher in Diode — copying the
        # defaults.device.asset_tag onto every member would collide.
        member_dev.ClearField("asset_tag")
        member_dev.vc_position = m["id"]
        member_devices[m["id"]] = member_dev
    return member_devices


def _build_per_member_interfaces(
    member_ids: list[int],
    member_devices: dict[int, pb.Device],
    grouped_interfaces: dict[int, dict],
    grouped_ips: dict[int, dict],
    defaults: Defaults,
    iface_module_map: dict[str, pb.Module] | None = None,
    options: "Options | None" = None,
    iface_vrf_map: dict[str, pb.VRF] | None = None,
) -> dict[int, list[Entity]]:
    """
    Run build_interface_entities once per member and return the per-member entity lists.

    Iterates ``member_ids`` in the caller-provided order (already sorted ascending in
    validate_chassis_payload) so per-member emission is deterministic across runs.
    When ``iface_module_map`` is provided, each member's interface builder
    threads it in so an Interface entity carries ``module=`` whenever its
    ifname appears in the map (populated by emit_modules_if_requested).
    """
    out: dict[int, list[Entity]] = {mid: [] for mid in member_ids}
    for mid in member_ids:
        sub_interfaces = grouped_interfaces[mid]
        sub_ips = grouped_ips[mid]
        if not sub_interfaces and not sub_ips:
            continue
        device_for_iface = copy.deepcopy(member_devices[mid])
        device_for_iface.ClearField("config")
        out[mid] = build_interface_entities(
            device_for_iface, sub_interfaces, sub_ips, defaults,
            iface_module_map=iface_module_map,
            options=options,
            iface_vrf_map=iface_vrf_map,
        )
    return out


def translate_as_stack(
    data: dict,
    members: list[dict],
    defaults: Defaults,
    options: Options,
    iface_vrf_map: dict[str, pb.VRF] | None = None,
) -> list[Entity]:
    """
    Emit master Device + VirtualChassis + member Devices (+ modules) + interfaces.

    Emission order, top-down:
      1. Master Device — PLAIN (no vc_position, no virtual_chassis ref).
      2. Top-level VirtualChassis with inline master ref.
      3. Non-master member Devices.
      4. Module / ModuleBay entities (when ``discover_modules`` is on)
         attached per-member to their owning Device.
      5. Interface entities, grouped per member, in ascending member-id
         order.

    Routes every interface / interface_ip entity to the correct member
    by parse_member_id. Mirrors the emission shape required by the
    netbox-diode-plugin for VC ingestion via the unique_master matcher.
    """
    from device_discovery.translate import assign_primary_ip

    device_info = data.get("device") or {}
    interfaces = data.get("interface") or {}
    interfaces_ip = data.get("interface_ip") or {}
    config_info = data.get("config") or {}
    netbox_id = data.get("netbox_id")
    target_hostname = data.get("target_hostname")

    base_hostname = device_info.get("hostname") or target_hostname or "unknown"
    vc_name = base_hostname
    master = members[0]  # already sorted ascending by id
    master_id = master["id"]

    # Build per-member Device protos. The master is built first so the inline
    # VC master ref can be derived from the same proto, guaranteeing matcher
    # fields stay in sync with whatever translate_device chose (defaults
    # overrides, etc.). Non-master members defer virtual_chassis assignment —
    # vc_master_ref must be derived AFTER assign_primary_ip mutates master_dev,
    # otherwise primary_ip4/6 would be missing from the inline VC master ref.
    member_devices = _build_member_devices(
        members, master, vc_name, device_info, defaults, options, config_info, netbox_id,
    )
    master_dev = member_devices[master_id]

    # Build interface entities — primary-IP assignment must mutate the master
    # Device proto BEFORE that proto is wrapped into Entity(device=...) and
    # BEFORE vc_master_ref is derived from it.
    # member_ids is a list (not a set) so per-member iteration order is stable
    # and emission is deterministic across runs. members is already sorted
    # ascending by id in validate_chassis_payload.
    member_ids = [m["id"] for m in members]
    grouped_interfaces, grouped_ips = _route_interfaces_by_member(
        interfaces, interfaces_ip, set(member_ids), master_id, vc_name,
    )

    # Emit per-member module / module-bay entities into a SEPARATE list so
    # the documented emission order (master Device → VirtualChassis →
    # non-master member Devices → interfaces) is preserved when modules
    # are later interleaved. The translate_modules helper appends Module
    # and ModuleBay entries to whatever list we hand it; collecting them
    # apart from `entities` lets us flush them after the Device / VC
    # / member-Device entries without changing their relative order or
    # the iface_module_map the per-member interface builder consumes.
    # Mirror the per-member interface path: hand emit_modules deep copies
    # with config cleared so the master's captured config isn't CopyFrom'd
    # into every ModuleBay/Module entity. prune_nested_refs would strip it
    # later, but clearing here avoids the in-memory bloat at emission time
    # (relevant on linecards with dozens of transceiver sub-bays).
    module_devices: dict[int | None, pb.Device] = {}
    for mid, dev in member_devices.items():
        dev_copy = copy.deepcopy(dev)
        dev_copy.ClearField("config")
        module_devices[mid] = dev_copy
    module_entities: list[Entity] = []
    iface_module_map = emit_modules_if_requested(
        data, options, module_devices, module_entities,
    )

    interface_entities_by_member = _build_per_member_interfaces(
        member_ids, member_devices, grouped_interfaces, grouped_ips, defaults,
        iface_module_map=iface_module_map,
        options=options,
        iface_vrf_map=iface_vrf_map,
    )

    # Primary-IP back-pointer is only meaningful on the master (mgmt IP).
    master_iface_entities = interface_entities_by_member[master_id]
    if master_iface_entities:
        assign_primary_ip(master_dev, master_iface_entities, target_hostname)

    # NOW derive vc_master_ref — captures master's primary_ip4/6 if assigned.
    vc_master_ref = _master_device_ref(master_dev)

    # Backfill virtual_chassis on each non-master member.
    for m in members[1:]:
        member_devices[m["id"]].virtual_chassis.CopyFrom(
            pb.VirtualChassis(name=vc_name, master=vc_master_ref)
        )

    entities: list[Entity] = []

    # 1) Master Device — PLAIN (no vc_position, no virtual_chassis ref).
    entities.append(Entity(device=master_dev))

    # 2) Top-level VirtualChassis with inline master ref.
    vc = pb.VirtualChassis(name=vc_name, master=vc_master_ref)
    domain = (data.get("chassis_members") or {}).get("domain")
    if domain:
        vc.domain = str(domain)
    entities.append(Entity(virtual_chassis=vc))

    # 3) Non-master member Devices.
    for m in members[1:]:
        entities.append(Entity(device=member_devices[m["id"]]))

    # 4) Module / ModuleBay entities (attached to each member's Device).
    entities.extend(module_entities)

    # 5) Interface entities, grouped per member, in ascending member-id order.
    for mid in member_ids:
        entities.extend(interface_entities_by_member[mid])

    return entities
