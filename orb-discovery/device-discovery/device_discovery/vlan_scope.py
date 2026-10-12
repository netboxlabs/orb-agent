#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Device Discovery - VLAN scope reporting."""

from collections.abc import Iterable

from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb

from device_discovery.policy.models import UNDEFINED_PLACEHOLDER

# NetBox stores unlimited same-VID VLANs when group is NULL: its (group, vid)
# constraint does not enforce uniqueness there. The Diode plugin fills that gap
# with a matcher keyed on VID among rows carrying no group, no site and no
# Q-in-Q service VLAN. Such a VLAN never matches the group-scoped VLANs an
# operator curated by hand, so ingestion duplicates them, and across a
# multi-site estate every device's VLAN 101 resolves to one record, so the rows
# collide and the last writer's name wins.
#
# A group alone is not the whole remedy. With no defaults.site the group is
# scoped to the "undefined" placeholder, and a group scoped there cannot match
# the same group scoped to a real site: Diode matches a VLAN group by
# (scope_type, scope_id, name). Following "set a group" without also setting a
# site therefore buys a second group under a junk site plus the same duplicate
# VLANs, and would silence this warning while doing it. Hence both options are
# named, and a placeholder-scoped group still counts as unscoped.
#
# Why a group and not a site on the VLAN itself: NetBox has deprecated assigning
# a VLAN directly to a site and will remove it in a future release.
UNSCOPED_VLAN_WARNING = (
    "%d discovered VLAN(s) on %s (policy %s) were sent with no VLAN group, or "
    "with a group whose scope is missing, is a location with no site, or "
    "rests on the '" + UNDEFINED_PLACEHOLDER + "' placeholder site. "
    "Diode cannot match these against VLANs already "
    "scoped to a group in NetBox, so ingestion duplicates them, and the same "
    "VID discovered on devices at different sites collides on one record. Set "
    "defaults.site, and defaults.vlan.group if it is not already set."
)


# Scopes the agent never substitutes anything into: whatever the operator wrote
# is what NetBox matches on. Derived from the proto rather than listed, so a
# scope added to VlanGroupParameters later is treated as a real scope here, as
# the Go backends' type switch already does by falling through.
_AGENT_SUBSTITUTED_SCOPES = frozenset({"scope_site", "scope_location"})
_OPERATOR_SCOPES = tuple(
    field.name
    for field in pb.VLANGroup.DESCRIPTOR.fields
    if field.name.startswith("scope_") and field.name not in _AGENT_SUBSTITUTED_SCOPES
)


def _group_scope_separates(group: pb.VLANGroup) -> bool:
    """
    Report whether a VLAN group's scope tells one estate from another.

    A scope resting on the "undefined" placeholder does not: every policy
    without a ``defaults.site`` produces the same one, so it cannot match the
    operator's group of the same name under a real site. Nor does a group with
    no scope at all, or a location with no site, which NetBox cannot resolve.

    A location scope is the easier placeholder to hit: the docs recommend it
    for VLANs shared across sites, and ``translate_vlan_group`` hangs the
    location off ``defaults.site``.
    """
    if group.HasField("scope_location"):
        return group.scope_location.site.name not in ("", UNDEFINED_PLACEHOLDER)
    if group.HasField("scope_site"):
        return group.scope_site.name not in ("", UNDEFINED_PLACEHOLDER)
    return any(group.HasField(field) for field in _OPERATOR_SCOPES)


def count_unscoped_vlans(entities: Iterable[pb.Entity]) -> int:
    """
    Count emitted VLANs Diode cannot usefully separate.

    That is: no group, or a group whose scope separates nothing.

    A site on the VLAN itself is deliberately not treated as a scope, even
    though Diode will match on ``(vid, site)``. It leaves the duplication
    against the operator's group-scoped VLANs untouched, and NetBox has
    deprecated assigning a VLAN directly to a site. This backend never sets one
    in any case; the rule is shared with the other two so a policy that warns
    on one warns on all.

    Only top-level VLAN entities are counted. Every VLAN referenced from an
    interface also has a top-level entity for the same VID, so counting the
    nested copies too would report each VLAN many times over.
    """
    total = 0
    for entity in entities:
        if not entity.HasField("vlan"):
            continue
        group = entity.vlan.group
        if not entity.vlan.HasField("group") or not _group_scope_separates(group):
            total += 1
    return total
