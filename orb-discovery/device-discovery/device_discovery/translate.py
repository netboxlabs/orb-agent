#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""Translate from NAPALM output format to Diode SDK entities."""

import copy
import ipaddress
import logging
from collections.abc import Iterable, Mapping
from typing import Any

from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb
from netboxlabs.diode.sdk.ingester import (
    VLAN,
    VRF,
    Device,
    DeviceConfig,
    DeviceType,
    Entity,
    Location,
    Platform,
    Rack,
    Tenant,
    TenantGroup,
    VLANGroup,
    slugify,
)

from device_discovery.interface import build_interface_entities
from device_discovery.policy.models import Defaults, Options, TenantParameters, VrfParameters
from device_discovery.translate_chassis import (
    translate_as_stack,
    validate_chassis_payload,
)

logger = logging.getLogger(__name__)


def translate_tenant(
    tenant: str | TenantParameters | pb.Tenant | None,
) -> pb.Tenant | None:
    """Convert tenant input into a Diode Tenant message."""
    if tenant is None or isinstance(tenant, pb.Tenant):
        return tenant

    if isinstance(tenant, TenantParameters):
        tenant_group = TenantGroup(name=tenant.group) if tenant.group else None
        return Tenant(
            name=tenant.name,
            group=tenant_group,
            comments=tenant.comments,
            description=tenant.description,
            tags=tenant.tags,
        )

    return Tenant(name=tenant)


def translate_vrf(
    vrf: str | VrfParameters | pb.VRF | None,
) -> pb.VRF | None:
    """Convert vrf input into a Diode VRF message."""
    if vrf is None or isinstance(vrf, pb.VRF):
        return vrf

    if isinstance(vrf, VrfParameters):
        return VRF(
            name=vrf.name,
            rd=vrf.rd,
            comments=vrf.comments,
            description=vrf.description,
            tags=vrf.tags,
        )

    return VRF(name=vrf)


def translate_device(
    device_info: dict,
    defaults: Defaults,
    config_info: dict | None = None,
    options: Options | None = None,
    netbox_id: int | None = None,
) -> Device:
    """
    Translate device information from NAPALM format to Diode SDK Device entity.

    Args:
    ----
        device_info (dict): Dictionary containing device information.
        defaults (Defaults): Default configuration.
        config_info (dict | None): Dictionary containing configuration data from NAPALM.
        options (Options | None): Discovery options.
        netbox_id (int | None): NetBox device primary key for PK-based matching.
            When set, writes ``source_match.netbox_id`` to device metadata.
            Ignored when None.

    Returns:
    -------
        Device: Translated Device entity.

    """
    tags = list(defaults.tags) if defaults.tags else []
    model = device_info.get("model")
    manufacturer = device_info.get("vendor")
    platform = device_info.get("platform")
    description = None
    comments = None
    location = None

    if defaults.device:
        tags.extend(defaults.device.tags or [])
        description = defaults.device.description
        comments = defaults.device.comments
        model = defaults.device.model or model
        manufacturer = defaults.device.manufacturer or manufacturer
        platform = defaults.device.platform or platform

    if defaults.location:
        location = Location(name=defaults.location, site=defaults.site)

    serial_number = device_info.get("serial_number")
    if isinstance(serial_number, list | tuple):
        if not serial_number:
            serial_number = None
        else:
            string_values = [
                value
                for value in serial_number
                if isinstance(value, str | bytes) and value
            ]
            if string_values:
                serial_number = string_values[0]
            else:
                serial_number = str(serial_number[0])
    elif serial_number is not None and not isinstance(serial_number, str | bytes):
        serial_number = str(serial_number)

    device_config = None
    if config_info and options:
        device_config = translate_device_config(config_info, options)

    # Build Device parameters
    device_params = {
        "name": device_info.get("hostname"),
        "device_type": DeviceType(model=model, manufacturer=manufacturer),
        "platform": Platform(name=platform, manufacturer=manufacturer),
        "role": defaults.role,
        "serial": serial_number,
        "asset_tag": defaults.device.asset_tag if defaults.device else None,
        "status": "active",
        "site": defaults.site,
        "tags": tags,
        "location": location,
        "rack": Rack(name=defaults.rack, site=defaults.site) if defaults.rack else None,
        "tenant": translate_tenant(defaults.tenant),
        "description": description,
        "comments": comments,
    }

    if device_config is not None:
        device_params["config"] = device_config
    device = Device(**device_params)
    if netbox_id is not None:
        device.metadata.update({"source_match": {"netbox_id": netbox_id}})
    return device


def translate_vlan(vid: str, vlan_name: str, defaults: Defaults) -> VLAN | None:
    """
    Translate VLAN information for a given VLAN ID.

    Args:
    ----
        vid (str): VLAN ID.
        vlan_name (str): VLAN name.
        defaults (Defaults): Default configuration.

    """
    try:
        vid_int = int(vid)
    except (ValueError, TypeError):
        return None
    tags = list(defaults.tags) if defaults.tags else []
    comments = None
    description = None
    group = None
    tenant = None
    role = None

    if defaults.vlan:
        tags.extend(defaults.vlan.tags or [])
        comments = defaults.vlan.comments
        description = defaults.vlan.description
        group = defaults.vlan.group
        tenant = translate_tenant(defaults.vlan.tenant)
        role = defaults.vlan.role
        if group:
            group = VLANGroup(
                name=group, slug=slugify(group), scope_site=defaults.site
            )

    clean_name = " ".join(vlan_name.strip().split())
    vlan = VLAN(
        vid=vid_int,
        name=clean_name,
        group=group,
        tenant=tenant,
        role=role,
        tags=tags,
        comments=comments,
        description=description,
    )

    return vlan


def _build_vlan_cache(
    raw_vlans: dict | None,
    defaults: Defaults,
) -> dict[int, pb.VLAN]:
    """Build vid -> pb.VLAN cache using the same rules as translate_vlan()."""
    cache: dict[int, pb.VLAN] = {}
    for vid_str, info in (raw_vlans or {}).items():
        vlan = translate_vlan(vid_str, (info or {}).get("name", ""), defaults)
        if vlan is not None:
            cache[vlan.vid] = vlan
    return cache


def _ensure_vlan(
    vid: int,
    cache: dict[int, pb.VLAN],
    defaults: Defaults,
    options: Options,
    new_stubs: list[pb.VLAN],
) -> pb.VLAN | None:
    """
    Return the cached VLAN for ``vid``, or synthesize a stub when allowed.

    Stubs use the placeholder name ``"VLAN<vid>"`` because NetBox's
    ipam.vlan.name field is required (non-blank). Operators or sibling
    switches can later overwrite the placeholder with a real name via the
    same vid+group matcher.
    """
    if vid in cache:
        return cache[vid]
    if not getattr(options, "create_unknown_vlans", True):
        return None
    stub = translate_vlan(str(vid), f"VLAN{vid}", defaults)
    if stub is None:
        return None
    cache[vid] = stub
    new_stubs.append(stub)
    return stub


_NAPALM_TO_NETBOX_MODE = {
    "access": "access",
    "trunk": "tagged",
    "trunk-all": "tagged-all",
}


def _safe_vid(value: object) -> int | None:
    """
    Coerce a driver-supplied VID to an int in [1, 4094], or return None.

    Drivers occasionally emit malformed values; clamping/coercing here keeps
    discovery resilient instead of aborting on a bad row. Booleans are
    rejected explicitly because ``bool`` is a subclass of ``int`` in Python
    (``int(True) == 1``) — without this guard a driver accidentally emitting
    ``True``/``False`` for a VID would silently map to VLAN 1.
    """
    if isinstance(value, bool):
        return None
    try:
        vid = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if vid < 1 or vid > 4094:
        return None
    return vid


def _apply_iface_vlan_mutation(
    iface: pb.Interface,
    info: dict,
    netbox_mode: str,
    vlan_cache: dict[int, pb.VLAN],
    defaults: Defaults,
    options: Options,
    new_stubs: list[pb.VLAN],
) -> None:
    """Apply a single interface's VLAN association based on driver-supplied info."""
    iface.mode = netbox_mode

    untagged = info.get("untagged")

    # Defensive: ``tagged`` may not be a list when a custom driver
    # returns malformed data — coerce to an iterable.
    raw_tagged = info.get("tagged")
    if not isinstance(raw_tagged, (list, tuple)):
        raw_tagged = []

    # Defensive: filter unparseable VIDs (and out-of-range) silently.
    untagged_vid = _safe_vid(untagged) if untagged is not None else None
    tagged_vids = []
    for v in raw_tagged:
        vid = _safe_vid(v)
        if vid is not None and vid != untagged_vid:
            tagged_vids.append(vid)

    # Defensive idempotency: clear any pre-existing untagged_vlan up front.
    # We then re-set it only if (a) the new payload supplies a VID and
    # (b) _ensure_vlan returns a usable VLAN (which honors
    # `Options.create_unknown_vlans` for unknown VIDs).
    # NOTE: at the Diode/NetBox layer this clear is currently cosmetic
    # because the plugin uses PATCH semantics on omitted fields — the
    # proto state is correct but won't propagate as a clear to NetBox.
    # See the Round 9 limitation note in the routed branch and the PR
    # description.
    iface.ClearField("untagged_vlan")
    if untagged_vid is not None:
        vlan = _ensure_vlan(untagged_vid, vlan_cache, defaults, options, new_stubs)
        if vlan is not None:
            iface.untagged_vlan.CopyFrom(vlan)

    # Defensive idempotency: clear any pre-existing tagged VLANs before
    # rebuilding the list. Without this, calling apply_interface_vlans()
    # twice on the same Interface entity (or handing in an entity that
    # already has tagged_vlans set) would accumulate duplicates.
    del iface.tagged_vlans[:]
    for vid in tagged_vids:
        vlan = _ensure_vlan(vid, vlan_cache, defaults, options, new_stubs)
        if vlan is not None:
            iface.tagged_vlans.append(vlan)


def _apply_interface_vlan_associations(
    data: dict,
    interface_related_entities: list[Entity],
    defaults: Defaults,
    options: Options,
    new_stubs: list[pb.VLAN],
) -> None:
    """
    Apply interface↔VLAN associations from custom-driver method, if available.

    Builds a vid→VLAN cache from ``data["vlan"]`` and mutates Interface entities
    in ``interface_related_entities`` to set mode/untagged_vlan/tagged_vlans
    when ``data["interfaces_vlans"]`` is present. Stubs are appended to
    ``new_stubs`` for VIDs not in the cache when ``options.create_unknown_vlans``
    is True.
    """
    ifaces_vlans = data.get("interfaces_vlans") or {}
    if not ifaces_vlans:
        return
    vlan_cache = _build_vlan_cache(data.get("vlan") or {}, defaults)
    apply_interface_vlans(
        interface_related_entities,
        ifaces_vlans,
        vlan_cache,
        defaults,
        options,
        new_stubs,
    )


def apply_interface_vlans(
    entities: list[Entity],
    interfaces_vlans: Mapping[str, Any] | object,
    vlan_cache: dict[int, pb.VLAN],
    defaults: Defaults,
    options: Options,
    new_stubs: list[pb.VLAN],
) -> None:
    """Mutate Interface entities in place with mode/untagged_vlan/tagged_vlans."""
    if not interfaces_vlans:
        return
    if not isinstance(interfaces_vlans, dict):
        # A custom driver may return a non-dict (list, None, str, etc.) when
        # its parser hits an unexpected shape. Skip silently rather than
        # aborting the whole device's ingestion with an AttributeError.
        logger.warning(
            "interfaces_vlans payload is not a dict (got %s); skipping interface↔VLAN mapping",
            type(interfaces_vlans).__name__,
        )
        return

    by_name: dict[str, pb.Interface] = {
        entity.interface.name: entity.interface
        for entity in entities
        if entity.HasField("interface")
    }

    for if_name, info in interfaces_vlans.items():
        iface = by_name.get(if_name)
        if iface is None:
            logger.debug(
                "interfaces_vlans: skipping %r — not present among emitted Interface entities",
                if_name,
            )
            continue

        if not isinstance(info, dict):
            logger.warning(
                "interfaces_vlans[%r] is not a dict (got %s); skipping interface VLAN mapping",
                if_name,
                type(info).__name__,
            )
            continue

        netbox_mode = _NAPALM_TO_NETBOX_MODE.get(info.get("mode"))
        if netbox_mode is None:
            # routed / unknown / disabled — leave the Interface entity
            # untouched. Note: ClearField()-ing mode/untagged_vlan/
            # tagged_vlans here would NOT propagate to NetBox: the Diode
            # plugin's apply-change-set endpoint uses PATCH semantics on
            # the diff `data` payload, and proto3 default-value fields
            # are omitted from serialization, so they get treated as
            # "no change" rather than "clear". Operators converting a
            # switchport to L3 must currently clear the stale VLAN
            # association in NetBox manually, or wait for Diode-plugin
            # support for explicit field clearing.
            continue

        _apply_iface_vlan_mutation(
            iface, info, netbox_mode, vlan_cache, defaults, options, new_stubs
        )


def translate_device_config(config_info: dict, options: Options) -> DeviceConfig | None:
    """
    Translate device configuration from NAPALM format to Diode SDK DeviceConfig entity.

    Args:
    ----
        config_info (dict): Dictionary containing configuration data from NAPALM.
        options (Options): Discovery options with config capture flags.

    Returns:
    -------
        DeviceConfig | None: Translated DeviceConfig entity or None if no config data.

    """
    if not config_info:
        return None

    # Check if any config capture is enabled
    if not (options.capture_running_config or options.capture_startup_config):
        return None

    # Extract only the requested config components
    startup = None
    running = None

    if options.capture_startup_config:
        startup = config_info.get("startup")
        # Convert strings to bytes if needed (DeviceConfig expects bytes)
        # Check isinstance first to handle empty strings correctly
        if isinstance(startup, str):
            startup = startup.encode("utf-8")

    if options.capture_running_config:
        running = config_info.get("running")
        # Convert strings to bytes if needed (DeviceConfig expects bytes)
        # Check isinstance first to handle empty strings correctly
        if isinstance(running, str):
            running = running.encode("utf-8")

    # Skip if no actual config data present
    if startup is None and running is None:
        return None

    # Metadata is not captured for device configs - device association is via
    # the Device entity's device_config field when SDK support is enabled
    return DeviceConfig(
        startup=startup,
        running=running,
        candidate=None,
        metadata=None,
    )


def _target_ipv4_candidate(hostname: str | None) -> str | None:
    """
    Return the IPv4 literal candidate for the NAPALM target host.

    Only IPv4 literals are matched for primary-IP assignment. Hostnames are
    deliberately NOT re-resolved here: re-resolving can pick a different
    address than the one NAPALM actually connected to (DNS load-balancing,
    address-family preference), and in practice NAPALM inventories are
    overwhelmingly keyed by IP. Users who need primary-IP populated for
    name-keyed devices should set it through another source.

    Args:
    ----
        hostname: The sanitized target host as configured on the policy.

    Returns:
    -------
        The canonicalized IPv4 address, or ``None`` if the host is empty,
        an IPv6 literal, or a DNS name.

    """
    if not hostname:
        return None
    hostname = hostname.strip()
    if not hostname:
        return None
    try:
        parsed = ipaddress.ip_address(hostname)
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv4Address):
        return str(parsed)
    return None


def _strip_prefix(address: str) -> str:
    """Return the IP portion of a CIDR or plain IP string."""
    return address.split("/", 1)[0]


def assign_primary_ip(
    device: Device,
    entities: list[Entity],
    target_hostname: str | None,
) -> None:
    """
    Set ``device.primary_ip4`` when the target host matches a discovered IP.

    The target host must be an IPv4 literal — DNS names are not re-resolved
    here because re-resolution can pick a different address than the one
    NAPALM actually connected to, and NAPALM inventories are predominantly
    IP-keyed. Scans the emitted ``ip_address`` entities and picks the
    IPAddress whose address matches the target IPv4, restricted to entities
    whose ``assigned_object_interface`` is set.

    Args:
    ----
        device: The Device entity to mutate in place.
        entities: The list of translated entities; only IPAddress entities
            whose ``assigned_object_interface`` is set are eligible.
        target_hostname: The scan target host (policy's ``scope.hostname``),
            distinct from the device's own name reported in NAPALM facts.
            Only IPv4 literals produce a match.

    """
    if device is None:
        return
    target_ipv4 = _target_ipv4_candidate(target_hostname)
    if target_ipv4 is None:
        return

    hits = []
    for entity in entities:
        if not entity.HasField("ip_address"):
            continue
        ip = entity.ip_address
        if not ip.address:
            continue
        if not ip.HasField("assigned_object_interface"):
            continue
        if _strip_prefix(ip.address) != target_ipv4:
            continue
        iface_name = ip.assigned_object_interface.name or ""
        # Primary sort key is ``<address>|<interface-name>``; content key is
        # the full IPAddress serialization as a stable, data-derived
        # tiebreaker when two entries share a primary key.
        primary_key = f"{ip.address}|{iface_name}"
        content_key = ip.SerializeToString(deterministic=True)
        hits.append((primary_key, content_key, ip))

    if not hits:
        return

    hits.sort(key=lambda h: (h[0], h[1]))
    if len(hits) > 1:
        logger.warning(
            "Primary-IP: multiple candidates match target; picking deterministic first",
            extra={
                "target": target_hostname,
                "candidates": [h[0] for h in hits],
            },
        )

    device.primary_ip4.CopyFrom(hits[0][2])


def _resolve_platform(data: dict, options: Options) -> None:
    """
    Mutate data['device']['platform'] to the resolved platform string.

    Format is ``"<DRIVER> <os_version>"`` (or just ``<driver>`` when
    ``platform_omit_version`` is set). Long platform strings are truncated to 100 chars
    while preserving the format — the previous behaviour replaced the whole string
    with ``os_version[:100]`` on overflow, which dropped the driver prefix and
    crashed when ``os_version`` was ``None``.
    """
    device_info = data.get("device") or {}
    if not device_info:
        return
    if options.platform_omit_version:
        device_info["platform"] = data.get("driver")
        return
    driver = (data.get("driver") or "").upper()
    os_version = device_info.get("os_version") or ""
    platform = f"{driver} {os_version}".strip()
    device_info["platform"] = platform[:100]


def _emit_vlans_and_stubs(
    entities: list[Entity],
    raw_vlans: dict | None,
    defaults: Defaults,
    new_stubs: list[pb.VLAN],
) -> None:
    """Append VLAN entities (from get_vlans()) plus any auto-stubbed VLANs not already emitted."""
    if raw_vlans:
        for vid, vlan_info in raw_vlans.items():
            vlan = translate_vlan(vid, vlan_info.get("name"), defaults)
            if vlan:
                entities.append(Entity(vlan=vlan))
    if new_stubs:
        already_emitted = {e.vlan.vid for e in entities if e.HasField("vlan")}
        for stub in new_stubs:
            if stub.vid not in already_emitted:
                entities.append(Entity(vlan=stub))
                already_emitted.add(stub.vid)


def translate_data(data: dict) -> Iterable[Entity]:
    """
    Translate data from NAPALM format to Diode SDK entities.

    Args:
    ----
        data (dict): Dictionary containing device, interface and VLAN data from NAPALM.

    Returns:
    -------
        Iterable[Entity]: Iterable of translated Diode SDK entities.

    """
    entities: list[Entity] = []
    new_stubs: list[pb.VLAN] = []

    defaults = data.get("defaults") or Defaults()
    options = data.get("options") or Options()
    device_info = data.get("device", {})
    config_info = data.get("config") or {}
    interfaces = data.get("interface") or {}
    interfaces_ip = data.get("interface_ip") or {}
    netbox_id = data.get("netbox_id")
    # ``target_hostname`` is the policy's scan target; device_info["hostname"]
    # is the device's own name reported by NAPALM — the two concepts must
    # not be conflated.
    target_hostname = data.get("target_hostname")

    _resolve_platform(data, options)

    chassis_members = validate_chassis_payload(data.get("chassis_members"))
    if device_info and chassis_members is not None:
        entities.extend(translate_as_stack(data, chassis_members, defaults, options))
        _apply_interface_vlan_associations(
            data, [e for e in entities if e.HasField("interface")], defaults, options, new_stubs,
        )
        _emit_vlans_and_stubs(entities, data.get("vlan"), defaults, new_stubs)
        return entities

    if device_info:
        device = translate_device(device_info, defaults, config_info, options, netbox_id=netbox_id)
        device_for_interfaces = copy.deepcopy(device)
        device_for_interfaces.ClearField("config")
        interface_related_entities = build_interface_entities(
            device_for_interfaces, interfaces, interfaces_ip, defaults
        )
        # assign_primary_ip must run before the Device is wrapped into Entity
        # because Entity(device=...) copies the message; subsequent mutations
        # on `device` would not propagate to the wrapped copy.
        assign_primary_ip(device, interface_related_entities, target_hostname)
        _apply_interface_vlan_associations(
            data, interface_related_entities, defaults, options, new_stubs,
        )
        entities.append(Entity(device=device))
        entities.extend(interface_related_entities)

    _emit_vlans_and_stubs(entities, data.get("vlan"), defaults, new_stubs)
    return entities
