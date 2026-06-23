#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Discovered-VRF translation from NAPALM network instances."""

import logging

from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb
from netboxlabs.diode.sdk.ingester import VRF

from device_discovery.policy.models import Defaults

logger = logging.getLogger(__name__)

# NAPALM network-instance types that translate to a NetBox VRF.
# DEFAULT_INSTANCE is the global routing table (not a VRF) and L2 instance
# types (L2VSI, L2EVPN, ...) have no VRF equivalent. "virtual-router" is
# Junos' VRF-lite instance type, passed through raw by the junos driver
# because OpenConfig has no mapping for it — it's how Junos models the
# management VRF (mgmt_junos) and plain L3 separation. The empty string is
# accepted so drivers that omit the type still produce VRFs.
_VRF_INSTANCE_TYPES = frozenset({"L3VRF", "virtual-router", ""})

# Well-known names of the global routing table. Drivers that omit the
# instance type can't flag it as DEFAULT_INSTANCE, so these names are
# treated as the default table when no explicit L3VRF type vouches for them.
_DEFAULT_INSTANCE_NAMES = frozenset({"default", "global"})

# RD strings some drivers emit when no RD is configured: NX-OS stringifies
# a missing rd field ("None"), its JSON API reports unset as "0:0", and raw
# CLI passthroughs show "<not set>". Compared lowercase.
_RD_UNSET_SENTINELS = frozenset({"none", "0:0", "<not set>", "not set"})


def _instance_rd(instance: dict) -> str | None:
    """
    Return the instance's route distinguisher, or None when absent/empty.

    Devices without MPLS routinely report an empty-string RD, and several
    drivers emit unset-RD sentinels instead (see _RD_UNSET_SENTINELS).
    Returning None keeps ``rd`` off the wire entirely, so the VRF matches
    NetBox records with a NULL rd instead of creating one with a bogus rd.
    """
    state = instance.get("state")
    if not isinstance(state, dict):
        return None
    rd = state.get("route_distinguisher")
    if not isinstance(rd, str):
        return None
    rd = rd.strip()
    if not rd or rd.lower() in _RD_UNSET_SENTINELS:
        return None
    return rd


def _resolve_vrf_name(key: object, instance: dict) -> str | None:
    """
    Return the instance's VRF name, or None when it should not become a VRF.

    Free helper (not inlined in build_discovered_vrfs) so the parent
    function stays under the McCabe complexity limit. Skips instances
    with missing/non-string names, non-VRF or malformed types, untyped
    instances carrying a well-known default-table name, and
    platform-internal ``__``-prefixed names.
    """
    name = instance.get("name") or key
    if not isinstance(name, str) or not name:
        logger.debug("Skipping network instance %r: missing or non-string name", key)
        return None
    instance_type = instance.get("type")
    if instance_type is not None and not isinstance(instance_type, str):
        logger.debug(
            "Skipping network instance %r of non-string type %r", name, instance_type
        )
        return None
    instance_type = instance_type or ""
    if instance_type not in _VRF_INSTANCE_TYPES:
        logger.debug("Skipping network instance %r of type %r", name, instance_type)
        return None
    if not instance_type and name.lower() in _DEFAULT_INSTANCE_NAMES:
        logger.debug(
            "Skipping network instance %r: well-known default-table name "
            "with no explicit type",
            name,
        )
        return None
    if name.startswith("__"):
        logger.debug("Skipping platform-internal network instance %r", name)
        return None
    return name


def _instance_interfaces(instance: dict) -> list[str]:
    """Return the interface names of a network instance (OC nested shape)."""
    interfaces = instance.get("interfaces")
    if not isinstance(interfaces, dict):
        return []
    by_name = interfaces.get("interface")
    if not isinstance(by_name, dict):
        return []
    return [name for name in by_name if isinstance(name, str) and name]


def build_discovered_vrfs(
    network_instances: object,
    defaults: Defaults,
) -> tuple[list[pb.VRF], dict[str, pb.VRF]]:
    """
    Build VRF messages and an interface→VRF map from get_network_instances().

    Filters out the default instance (global routing table), L2 instance
    types, and platform-internal instances whose names start with ``__``
    (e.g. Cisco's ``__Platform_iVRF:_ID00_``). Malformed payloads are
    skipped with a warning rather than aborting the device's ingestion.

    Args:
    ----
        network_instances: Raw get_network_instances() payload, keyed by
            instance name in the OpenConfig shape NAPALM standardizes.
        defaults: Default configuration; top-level tags are applied to
            the emitted VRFs.

    Returns:
    -------
        A (vrfs, iface_vrf_map) tuple: the VRF messages to emit, ordered
        by name for deterministic output, and a map of interface name to
        the VRF that interface belongs to.

    """
    if not network_instances:
        return [], {}
    if not isinstance(network_instances, dict):
        logger.warning(
            "network_instances payload is not a dict (got %s); skipping VRF discovery",
            type(network_instances).__name__,
        )
        return [], {}

    tags = list(defaults.tags) if defaults.tags else []
    vrfs: dict[str, pb.VRF] = {}
    iface_vrf_map: dict[str, pb.VRF] = {}

    for key, instance in network_instances.items():
        if not isinstance(instance, dict):
            logger.warning(
                "network_instances[%r] is not a dict (got %s); skipping instance",
                key,
                type(instance).__name__,
            )
            continue
        name = _resolve_vrf_name(key, instance)
        if name is None:
            continue
        # First occurrence wins on duplicate resolved names so the iface map
        # always points at the VRF message that is actually emitted.
        vrf = vrfs.get(name)
        if vrf is None:
            vrf = VRF(name=name, rd=_instance_rd(instance), tags=tags)
            vrfs[name] = vrf
        else:
            logger.warning(
                "Duplicate network instance name %r; keeping the first occurrence",
                name,
            )
        for if_name in _instance_interfaces(instance):
            iface_vrf_map[if_name] = vrf

    ordered = [vrfs[name] for name in sorted(vrfs)]
    return ordered, iface_vrf_map
