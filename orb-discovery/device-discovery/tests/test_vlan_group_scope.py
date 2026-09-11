"""Tests for the scope of the VLAN group that discovered VLANs are attached to."""

import pytest
from pydantic import ValidationError

from device_discovery.policy.models import Defaults, VlanGroupParameters, VlanParameters
from device_discovery.policy.runner import merge_override_defaults
from device_discovery.translate import translate_vlan


def test_group_accepts_bare_name():
    """A bare string is the group name."""
    assert VlanParameters(group="campus-vlans").group == "campus-vlans"


def test_group_accepts_map_with_scope():
    """The map form carries the name and one scope."""
    params = VlanParameters.model_validate(
        {"group": {"name": "Brussels VLAN Group", "scope_site_group": "Brussels"}}
    )
    assert params.group == VlanGroupParameters(
        name="Brussels VLAN Group", scope_site_group="Brussels"
    )


def test_group_map_rejects_two_scopes():
    """Two scopes at once is a validation error."""
    with pytest.raises(ValidationError, match="only one scope"):
        VlanParameters.model_validate(
            {"group": {"name": "g", "scope_site": "s", "scope_site_group": "sg"}}
        )


def test_group_map_requires_name():
    """The map form needs a name."""
    with pytest.raises(ValidationError, match="name"):
        VlanParameters.model_validate({"group": {"scope_site_group": "sg"}})


def _defaults(group) -> Defaults:
    return Defaults(site="NYC", vlan=VlanParameters(group=group))


def test_translate_site_group_scope():
    """scope_site_group is emitted as a SiteGroup scope, with no site."""
    vlan = translate_vlan("10", "V10", _defaults(VlanGroupParameters(name="g", scope_site_group="Brussels")))

    assert vlan.group.slug == "g"
    assert vlan.group.scope_site_group.name == "Brussels"
    assert vlan.group.scope_site.name == ""


def test_translate_region_scope():
    """scope_region is emitted as a Region scope, with no site."""
    vlan = translate_vlan("10", "V10", _defaults(VlanGroupParameters(name="g", scope_region="Benelux")))

    assert vlan.group.scope_region.name == "Benelux"
    assert vlan.group.scope_site.name == ""


def test_translate_explicit_site_wins_over_defaults_site():
    """An explicit scope_site replaces defaults.site."""
    vlan = translate_vlan("10", "V10", _defaults(VlanGroupParameters(name="g", scope_site="other")))

    assert vlan.group.scope_site.name == "other"


def test_translate_location_scope_carries_defaults_site():
    """A location scope carries defaults.site, as NetBox locations are per site."""
    vlan = translate_vlan("10", "V10", _defaults(VlanGroupParameters(name="g", scope_location="Floor 2")))

    assert vlan.group.scope_location.name == "Floor 2"
    assert vlan.group.scope_location.site.name == "NYC"
    assert vlan.group.scope_site.name == ""


def test_translate_location_scope_without_site():
    """A location scope with no site anywhere is emitted without one."""
    defaults = Defaults(site=None, vlan=VlanParameters(group=VlanGroupParameters(name="g", scope_location="Floor 2")))
    vlan = translate_vlan("10", "V10", defaults)

    assert vlan.group.scope_location.name == "Floor 2"
    assert vlan.group.scope_location.site.name == ""


def test_translate_map_without_scope_falls_back_to_defaults_site():
    """A map with no scope behaves like the bare name."""
    vlan = translate_vlan("10", "V10", _defaults(VlanGroupParameters(name="g")))

    assert vlan.group.scope_site.name == "NYC"


def test_override_replaces_group_as_a_whole():
    """An override group replaces the policy group; the policy scope must not leak in."""
    base = Defaults(vlan=VlanParameters(group=VlanGroupParameters(name="policy", scope_site_group="sg")))

    as_name = merge_override_defaults(base, Defaults(vlan=VlanParameters(group="override")))
    assert as_name.vlan.group == "override"

    as_map = merge_override_defaults(base, Defaults(vlan=VlanParameters(group=VlanGroupParameters(name="override"))))
    assert as_map.vlan.group == VlanGroupParameters(name="override")


def test_override_without_group_keeps_policy_group():
    """An override that does not name a group keeps the policy group intact."""
    base = Defaults(vlan=VlanParameters(group=VlanGroupParameters(name="policy", scope_site_group="sg")))

    merged = merge_override_defaults(base, Defaults(vlan=VlanParameters(tenant="t")))

    assert merged.vlan.group == VlanGroupParameters(name="policy", scope_site_group="sg")
    assert merged.vlan.tenant == "t"
