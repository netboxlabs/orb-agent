#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""NetBox Labs - Policy Models Unit Tests."""

import logging

import pytest
import yaml
from pydantic import ValidationError

from device_discovery.policy.models import Options


def test_options_create_unknown_vlans_default_true():
    """Options.create_unknown_vlans defaults to True."""
    opts = Options()
    assert opts.create_unknown_vlans is True


def test_options_create_unknown_vlans_overridable():
    """Options.create_unknown_vlans accepts an explicit False override."""
    opts = Options(create_unknown_vlans=False)
    assert opts.create_unknown_vlans is False


def test_options_discover_modules_default_off():
    """Options.discover_modules defaults to 'off' (backwards compatibility)."""
    opts = Options()
    assert opts.discover_modules == "off"


@pytest.mark.parametrize("value", ["off", "linecards", "full"])
def test_options_discover_modules_accepts_enum_values(value):
    """Options.discover_modules accepts each documented enum value."""
    opts = Options(discover_modules=value)
    assert opts.discover_modules == value


def test_options_discover_modules_rejects_unknown_value():
    """Options.discover_modules rejects values outside the enum."""
    with pytest.raises(ValidationError):
        Options(discover_modules="bogus")


def test_prefix_parameters_accepts_scope_fields():
    """PrefixParameters carries scope_site and scope_location."""
    from device_discovery.policy.models import PrefixParameters

    p = PrefixParameters(
        scope_site="DC-East",
        scope_location="Floor-3",
    )
    assert p.scope_site == "DC-East"
    assert p.scope_location == "Floor-3"


def test_prefix_parameters_scope_fields_default_to_none():
    """Both scope fields default to None — back-compat for existing configs."""
    from device_discovery.policy.models import PrefixParameters

    p = PrefixParameters()
    assert p.scope_site is None
    assert p.scope_location is None


def test_prefix_parameters_inherits_ipam_fields():
    """PrefixParameters keeps the inherited tenant / role / vrf / comments / tags."""
    from device_discovery.policy.models import PrefixParameters

    p = PrefixParameters(role="customer-edge", tenant="acme")
    assert p.role == "customer-edge"
    assert p.tenant == "acme"
    # Inherited from ObjectParameters via IpamParameters
    assert p.tags is None
    assert p.comments is None


def test_defaults_prefix_field_accepts_prefix_parameters():
    """Defaults.prefix accepts a PrefixParameters payload with scope fields."""
    from device_discovery.policy.models import Defaults

    d = Defaults(prefix={"scope_site": "DC-East", "role": "customer-edge"})
    assert d.prefix is not None
    assert d.prefix.scope_site == "DC-East"
    assert d.prefix.role == "customer-edge"


def test_defaults_prefix_back_compat_no_scope():
    """A Defaults payload without scope_* still validates (back-compat)."""
    from device_discovery.policy.models import Defaults

    d = Defaults(prefix={"role": "customer-edge"})
    assert d.prefix is not None
    assert d.prefix.role == "customer-edge"
    assert d.prefix.scope_site is None


def test_defaults_prefix_coerces_legacy_ipam_parameters_at_construction():
    """Back-compat for callers passing a bare IpamParameters (the previous public shape)."""
    from device_discovery.policy.models import Defaults, IpamParameters, PrefixParameters

    # Pre-PrefixParameters callers built defaults like this:
    d = Defaults(prefix=IpamParameters(role="customer-edge", tags=["legacy"]))
    # Coerced to PrefixParameters via the field validator; matching fields land.
    assert isinstance(d.prefix, PrefixParameters)
    assert d.prefix.role == "customer-edge"
    assert d.prefix.tags == ["legacy"]
    # scope_* default to None — IpamParameters carries no scope state to copy.
    assert d.prefix.scope_site is None
    assert d.prefix.scope_location is None


def test_options_propagate_defaults_to_prefix_scope_defaults_false():
    """The new Options flag defaults to False (no cascade)."""
    from device_discovery.policy.models import Options

    o = Options()
    assert o.propagate_defaults_to_prefix_scope is False


def test_options_propagate_defaults_to_prefix_scope_accepts_true():
    """The flag accepts True to opt into the cascade."""
    from device_discovery.policy.models import Options

    o = Options(propagate_defaults_to_prefix_scope=True)
    assert o.propagate_defaults_to_prefix_scope is True


def test_options_emit_prefix_vlan_defaults_off():
    """emit_prefix_vlan defaults to the 'off' mode string."""
    assert Options().emit_prefix_vlan == "off"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # The literal the README tells operators to write. YAML 1.1 parses a
        # bare `off` as the boolean False, so the option must survive that.
        ("emit_prefix_vlan: off", "off"),
        ("emit_prefix_vlan: 'off'", "off"),
        ("emit_prefix_vlan: svi-name", "svi-name"),
        # Case and surrounding whitespace are normalised at the model
        # boundary, exactly as the snmp-discovery twin does.
        ("emit_prefix_vlan: SVI-Name", "svi-name"),
        ("emit_prefix_vlan: SVI-NAME", "svi-name"),
        ("emit_prefix_vlan: '  svi-name  '", "svi-name"),
        # The mode was called `corroborated` while this was in review. It never
        # shipped, so the old spelling is simply not a mode: it disables the
        # feature with a warning rather than silently keeping the old meaning.
        ("emit_prefix_vlan: corroborated", "off"),
        ("emit_prefix_vlan: Off", "off"),
        # An explicit null is the same as omitting the option.
        ("emit_prefix_vlan:", "off"),
    ],
)
def test_options_emit_prefix_vlan_from_policy_yaml(text, expected):
    """The option loads from the literal policy YAML text, not just a dict."""
    opts = Options(**yaml.safe_load(text))
    assert opts.emit_prefix_vlan == expected


@pytest.mark.parametrize(
    "text",
    ["emit_prefix_vlan: on", "emit_prefix_vlan: yes", "emit_prefix_vlan: true"],
)
def test_options_emit_prefix_vlan_boolean_true_disables_rather_than_raising(text, caplog):
    """
    A bare on/yes/true names no mode, so it disables the feature.

    It must not raise. The snmp-discovery twin's decoder hands these to
    PrefixVlanMode as the string they were written as, and anything
    unrecognized there resolves to 'off'. Raising here would make one policy
    text valid for that backend and fatal for this one.
    """
    with caplog.at_level(logging.WARNING):
        opts = Options(**yaml.safe_load(text))
    assert opts.emit_prefix_vlan == "off"
    assert any("names no mode" in r.getMessage() for r in caplog.records), (
        "a value that silently disables the feature must be discoverable in the log"
    )
