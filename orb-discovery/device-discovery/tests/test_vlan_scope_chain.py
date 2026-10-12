#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
Device Discovery - unscoped-VLAN counting over the real translation path.

Hand-built VLAN entities cannot catch a scope the builder produces but the
counter does not recognise: both halves pass their own unit tests and the
composition is still broken. That is how the location-under-placeholder gap
survived two review rounds, so this walks the matrix through translate_vlan.
"""

import pytest
from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb

from device_discovery.policy.models import (
    UNDEFINED_PLACEHOLDER,
    Defaults,
    VlanGroupParameters,
    VlanParameters,
)
from device_discovery.translate import translate_vlan
from device_discovery.vlan_scope import count_unscoped_vlans

REAL_SITE = "Site A"

#: Distinct from None, which means "omit the key and take the pydantic default".
OMIT = object()


def _count(defaults: Defaults) -> int:
    vlan = translate_vlan("101", "Voice", defaults)
    return count_unscoped_vlans([pb.Entity(vlan=vlan)])


@pytest.mark.parametrize(
    ("site", "group", "expected", "why"),
    [
        (OMIT, None, 1, "no site and no group is the plain unscoped case"),
        (REAL_SITE, None, 1, "a site alone is not a scope: it never reaches the VLAN"),
        (
            OMIT,
            VlanGroupParameters(name="Campus VLANs"),
            1,
            "a bare group without a site is scoped to the placeholder",
        ),
        (
            OMIT,
            VlanGroupParameters(name="Campus VLANs", scope_location="Floor 3"),
            1,
            "a location scope hangs off defaults.site, so it is under the placeholder too",
        ),
        (
            REAL_SITE,
            VlanGroupParameters(name="Campus VLANs"),
            0,
            "a real site plus a group is the documented remedy",
        ),
        (
            REAL_SITE,
            VlanGroupParameters(name="Campus VLANs", scope_location="Floor 3"),
            0,
            "a location under a real site separates estates",
        ),
        (
            OMIT,
            VlanGroupParameters(name="Campus VLANs", scope_region="Brussels"),
            0,
            "a region comes from operator config, with no placeholder substitution",
        ),
        (
            OMIT,
            VlanGroupParameters(name="Campus VLANs", scope_site_group="Brussels"),
            0,
            "a site group likewise",
        ),
        (
            OMIT,
            VlanGroupParameters(name="Campus VLANs", scope_site=REAL_SITE),
            0,
            "an explicit scope_site wins over the placeholder default",
        ),
        (
            None,
            VlanGroupParameters(name="Campus VLANs"),
            1,
            "an explicit null site emits a group with no scope at all, which "
            "cannot match the operator's site-scoped group",
        ),
        (
            "",
            VlanGroupParameters(name="Campus VLANs"),
            1,
            "an empty site is the same as a null one here",
        ),
        (
            None,
            VlanGroupParameters(name="Campus VLANs", scope_location="Floor 3"),
            1,
            "a location with no site cannot be resolved by NetBox at all",
        ),
        (
            REAL_SITE,
            VlanGroupParameters(name="Campus VLANs", scope_region="Brussels"),
            0,
            "an operator-supplied region is a real scope regardless of site",
        ),
    ],
)
def test_scope_matrix(site, group, expected, why):
    """Each configuration either leaves Diode something to match on, or does not."""
    kwargs = {"vlan": VlanParameters(group=group)} if group else {}
    if site is not OMIT:
        kwargs["site"] = site
    assert _count(Defaults(**kwargs)) == expected, why


def test_the_default_site_really_is_the_placeholder():
    """The matrix above is only meaningful while this holds."""
    assert Defaults().site == UNDEFINED_PLACEHOLDER
