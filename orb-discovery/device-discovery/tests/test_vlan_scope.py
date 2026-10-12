#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Device Discovery - VLAN scope reporting tests."""

from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb

from device_discovery.policy.models import UNDEFINED_PLACEHOLDER
from device_discovery.vlan_scope import (
    UNSCOPED_VLAN_WARNING,
    count_unscoped_vlans,
)


def _entity(**vlan_kwargs) -> pb.Entity:
    """Build a top-level VLAN entity, scoped by whatever kwargs are passed."""
    return pb.Entity(vlan=pb.VLAN(vid=101, name="Voice", **vlan_kwargs))


def test_counts_a_vlan_with_neither_group_nor_site():
    """A VLAN with no group and no site is the unscoped case we warn about."""
    assert count_unscoped_vlans([_entity()]) == 1


def test_a_group_with_no_scope_counts():
    """A group the builder emitted with no scope separates nothing."""
    group = pb.VLANGroup(name="Site A VLANs", slug="site-a-vlans")
    assert count_unscoped_vlans([_entity(group=group)]) == 1


def test_a_group_scoped_to_a_real_site_takes_it_out_of_the_matcher():
    """A real scope is what lets Diode find the operator's own group."""
    group = pb.VLANGroup(
        name="Site A VLANs", slug="site-a-vlans", scope_site=pb.Site(name="Site A")
    )
    assert count_unscoped_vlans([_entity(group=group)]) == 0


def test_a_site_on_the_vlan_is_not_a_scope():
    """
    A site on the VLAN is deliberately not treated as a scope.

    Diode would match it on (vid, site), but that leaves the duplication
    against the operator's group-scoped VLANs untouched, and NetBox has
    deprecated assigning a VLAN directly to a site. All three backends apply
    the same rule, so a policy that warns on one warns on all.
    """
    assert count_unscoped_vlans([_entity(site=pb.Site(name="Site A"))]) == 1


def test_counts_every_unscoped_vlan():
    """The count is per VLAN, so the warning can report how many."""
    scoped = pb.VLANGroup(name="g", slug="g", scope_site=pb.Site(name="Site A"))
    entities = [_entity(), _entity(), _entity(group=scoped)]
    assert count_unscoped_vlans(entities) == 2


def test_ignores_non_vlan_entities():
    """Other entity types never contribute to the count."""
    entities = [pb.Entity(device=pb.Device(name="rtr1")), _entity()]
    assert count_unscoped_vlans(entities) == 1


def test_a_vlan_nested_on_an_interface_is_not_counted_again():
    """Every nested VLAN has a top-level entity for the same VID; count that one only."""
    iface = pb.Interface(name="Gi0/1", untagged_vlan=pb.VLAN(vid=101, name="Voice"))
    assert count_unscoped_vlans([pb.Entity(interface=iface)]) == 0


def test_the_warning_names_count_host_policy_and_both_options():
    """
    The message takes all three args and names both options.

    The host matters because the count is one device's, not the policy's. The
    policy name matters because one Client is shared by every policy. Naming
    only vlan.group would send an operator to a fix that silences the warning
    without resolving the duplication.
    """
    message = UNSCOPED_VLAN_WARNING % (3, "sw1.example.net", "site-a")
    assert message.startswith("3 discovered VLAN(s) on sw1.example.net (policy site-a) ")
    assert "defaults.site" in message
    assert "defaults.vlan.group" in message
    assert UNDEFINED_PLACEHOLDER in message
    assert "%" not in message


def test_a_group_scoped_to_the_placeholder_site_still_counts():
    """
    The remedy must not be able to silence the warning without fixing anything.

    With no defaults.site a configured vlan.group is scoped to the "undefined"
    placeholder. Diode matches a group by (scope_type, scope_id, name), so that
    group cannot match the operator's group of the same name under a real site:
    they get a second group and the same duplicate VLANs. Counting it keeps the
    warning up until a real site is set too.
    """
    group = pb.VLANGroup(
        name="Site A VLANs",
        slug="site-a-vlans",
        scope_site=pb.Site(name=UNDEFINED_PLACEHOLDER),
    )
    assert count_unscoped_vlans([_entity(group=group)]) == 1


def test_a_group_scoped_to_a_real_site_is_scoped():
    """A real site scope separates one estate's VLANs from another's."""
    group = pb.VLANGroup(
        name="Site A VLANs", slug="site-a-vlans", scope_site=pb.Site(name="Site A")
    )
    assert count_unscoped_vlans([_entity(group=group)]) == 0


def test_a_group_scoped_to_something_other_than_a_site_is_scoped():
    """A region or site-group scope separates estates just as well as a site."""
    group = pb.VLANGroup(
        name="Brussels VLANs",
        slug="brussels-vlans",
        scope_region=pb.Region(name="Brussels"),
    )
    assert count_unscoped_vlans([_entity(group=group)]) == 0
