#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Rack placement in policy defaults and per-target override_defaults."""

import pytest
from pydantic import ValidationError

from device_discovery.policy.manager import PolicyManager
from device_discovery.policy.models import Config, Defaults, Napalm, Policy
from device_discovery.policy.runner import merge_override_defaults


def _scope(hostname="192.0.2.10", **override):
    return Napalm(
        hostname=hostname,
        username="admin",
        password="secret",
        override_defaults=Defaults(**override) if override else None,
    )


def _policy(scope, **defaults):
    return Policy(config=Config(defaults=Defaults(**defaults)), scope=scope)


def test_position_and_face_per_target_are_accepted():
    """A single-host target places its device at a U and face of a rack."""
    policy = _policy([_scope(rack="R12", position=40, face="front")])
    merged = merge_override_defaults(policy.config.defaults, policy.scope[0].override_defaults)
    assert merged.rack == "R12"
    assert merged.position == 40
    assert merged.face == "front"


def test_rack_from_the_policy_defaults_serves_a_target_position():
    """The rack may come from the policy defaults; the position and face from the target."""
    policy = _policy([_scope(position=40.5, face="REAR")], rack="R12")
    merged = merge_override_defaults(policy.config.defaults, policy.scope[0].override_defaults)
    assert merged.rack == "R12"
    assert merged.position == 40.5
    assert merged.face == "rear"


def test_target_rack_replaces_the_policy_rack():
    """A target's rack replaces the policy's."""
    policy = _policy([_scope(rack="R13")], rack="R12")
    merged = merge_override_defaults(policy.config.defaults, policy.scope[0].override_defaults)
    assert merged.rack == "R13"


@pytest.mark.parametrize("field", [{"position": 40, "face": "front"}, {"position": 40}, {"face": "front"}])
def test_position_and_face_in_policy_defaults_are_refused(field):
    """One U for every device in the policy cannot be right."""
    with pytest.raises(ValidationError, match="set per target, in override_defaults"):
        _policy([_scope()], rack="R12", **field)


@pytest.mark.parametrize("field", [{"position": 40}, {"face": "front"}])
def test_position_and_face_go_together(field):
    """NetBox requires a face for any position, and a face means nothing without one."""
    with pytest.raises(ValidationError, match="192.0.2.10: position and face go together"):
        _policy([_scope(rack="R12", **field)])


def test_position_needs_a_rack():
    """A position without a rack anywhere cannot be placed."""
    with pytest.raises(ValidationError, match="192.0.2.10: position and face need a rack"):
        _policy([_scope(position=40, face="front")])


@pytest.mark.parametrize("hostname", ["192.0.2.0/30", "192.0.2.1-3"])
def test_position_needs_a_single_host(hostname):
    """A range or subnet would put every device at the same U."""
    with pytest.raises(ValidationError, match="need a single host"):
        _policy([_scope(hostname, rack="R12", position=40, face="front")])


@pytest.mark.parametrize("hostname", ["192.0.2.0/30", "192.0.2.1-3"])
def test_rack_alone_is_fine_on_a_range(hostname):
    """Every device of a range may share a rack."""
    policy = _policy([_scope(hostname, rack="R12")])
    assert policy.scope[0].override_defaults.rack == "R12"


@pytest.mark.parametrize("face", ["side", "front-ish"])
def test_face_must_be_front_or_rear(face):
    """NetBox's rack faces are front and rear."""
    with pytest.raises(ValidationError, match="face must be front or rear"):
        Defaults(face=face)


@pytest.mark.parametrize("position", [0, 0.5, -1, 40.25, 40.3])
def test_position_is_a_u_from_one_in_half_steps(position):
    """NetBox positions start at U1 and move in half-U steps."""
    with pytest.raises(ValidationError, match="position must be at least 1, in steps of 0.5"):
        Defaults(position=position)


@pytest.mark.parametrize("position", [1, 40, 40.5, 99.5])
def test_valid_positions(position):
    """Whole and half Us from U1 up are accepted; the rack's height is NetBox's to check."""
    assert Defaults(position=position).position == position


@pytest.mark.parametrize(("rack", "want"), [(" R12 ", "R12"), ("   ", ""), ("", "")])
def test_rack_name_is_trimmed(rack, want):
    """A rack name is trimmed, and kept blank when blank."""
    assert Defaults(rack=rack).rack == want


@pytest.mark.parametrize("rack", [1, 8, 12.0, True])
def test_numeric_rack_name_must_be_quoted(rack):
    """YAML reads an unquoted 01 as 1 and 010 as 8, so the name it meant is lost."""
    with pytest.raises(ValidationError, match='quote a numeric rack name'):
        Defaults(rack=rack)


def test_blank_rack_does_not_serve_a_position():
    """Whitespace is not a rack."""
    with pytest.raises(ValidationError, match="need a rack"):
        _policy([_scope(rack="  ", position=40, face="front")])


def test_blank_target_rack_opts_out_of_the_policy_rack():
    """A target's empty rack keeps its device out of the policy's rack, as before."""
    policy = _policy([_scope(rack="")], rack="R12")
    merged = merge_override_defaults(policy.config.defaults, policy.scope[0].override_defaults)
    assert not merged.rack


def test_blank_target_rack_does_not_serve_a_position():
    """A target that opted out of the policy rack has no rack to be placed in."""
    with pytest.raises(ValidationError, match="need a rack"):
        _policy([_scope(rack="", position=40, face="front")], rack="R12")


def test_two_targets_at_the_same_u_are_refused():
    """Diode would match the second, new device to the first device's record."""
    with pytest.raises(ValidationError, match="192.0.2.10 and 192.0.2.11 are both placed at R12 U40 front"):
        _policy([
            _scope("192.0.2.10", rack="R12", position=40, face="front"),
            _scope("192.0.2.11", rack="R12", position=40, face="front"),
        ])


def test_two_targets_at_the_same_u_through_the_policy_rack_are_refused():
    """The rack each target is placed in is the effective one."""
    with pytest.raises(ValidationError, match="both placed at R12 U40 front"):
        _policy([
            _scope("192.0.2.10", position=40, face="front"),
            _scope("192.0.2.11", position=40, face="front"),
        ], rack="R12")


@pytest.mark.parametrize("other", [
    {"rack": "R12", "position": 40, "face": "rear"},
    {"rack": "R13", "position": 40, "face": "front"},
    {"rack": "R12", "position": 41, "face": "front"},
    {"rack": "R12", "position": 40, "face": "front", "site": "DC2"},
])
def test_targets_at_different_slots_are_accepted(other):
    """Another face, rack, U or site is another slot."""
    _policy([_scope("192.0.2.10", rack="R12", position=40, face="front"), _scope("192.0.2.11", **other)])


def test_targets_in_different_locations_are_accepted():
    """Same-named racks in two locations are two racks."""
    _policy([
        _scope("192.0.2.10", location="Hall A", rack="R12", position=40, face="front"),
        _scope("192.0.2.11", location="Hall B", rack="R12", position=40, face="front"),
    ])


@pytest.mark.parametrize("unlocated", [{}, {"location": ""}])
def test_a_target_without_a_location_clashes_with_any_location(unlocated):
    """A rack sent without a location binds a same-named rack in any location of the site."""
    for first, second in ((unlocated, {"location": "Hall B"}), ({"location": "Hall B"}, unlocated)):
        with pytest.raises(ValidationError, match="both placed at R12 U40 front"):
            _policy([
                _scope("192.0.2.10", rack="R12", position=40, face="front", **first),
                _scope("192.0.2.11", rack="R12", position=40, face="front", **second),
            ])


def test_a_target_restating_the_policy_rack_is_the_same_slot():
    """A rack set on one target and inherited by the other is still one rack."""
    with pytest.raises(ValidationError, match="both placed at R12 U40 front"):
        _policy([
            _scope("192.0.2.10", rack="R12", position=40, face="front"),
            _scope("192.0.2.11", position=40, face="front"),
        ], rack="R12")


def test_a_null_target_rack_falls_back_to_the_policy_rack():
    """A null override is no override, as in the merge."""
    policy = _policy([_scope(rack=None, position=40, face="front")], rack="R12")
    merged = merge_override_defaults(policy.config.defaults, policy.scope[0].override_defaults)
    assert merged.rack == "R12"


@pytest.mark.parametrize("position", [True, False])
def test_boolean_position_is_refused(position):
    """YAML's yes/true would otherwise read as U1."""
    with pytest.raises(ValidationError, match="position must be a number"):
        Defaults(position=position)


def test_numeric_string_position_is_accepted():
    """A ${VAR} substitution yields a string."""
    assert Defaults(position="40.5").position == 40.5


def test_face_is_trimmed_and_lowercased():
    """Surrounding spaces and case are not part of the face."""
    assert Defaults(face=" Front ").face == "front"


@pytest.mark.parametrize("face", ["", "  "])
def test_blank_face_means_no_face(face):
    """As in the other backends, a blank face is unset."""
    assert Defaults(face=face).face is None


def test_policy_yaml_with_position_in_defaults_is_refused():
    """The API's YAML path applies the same rules."""
    config_data = b"""
    policies:
      p1:
        config:
          defaults:
            site: DC1
            rack: R12
            position: 40
            face: front
        scope:
          - hostname: 192.0.2.10
            username: admin
            password: secret
    """
    with pytest.raises(ValidationError, match="set per target, in override_defaults"):
        PolicyManager().parse_policy(config_data)


def test_a_target_restating_the_policy_site_is_the_same_slot():
    """A site set on one target and inherited by the other is still one site."""
    with pytest.raises(ValidationError, match="both placed at R12 U40 front"):
        _policy([
            _scope("192.0.2.10", site="DC1", rack="R12", position=40, face="front"),
            _scope("192.0.2.11", rack="R12", position=40, face="front"),
        ], site="DC1")


def test_no_site_and_the_undefined_site_are_one_site():
    """A device without a site lands in the "undefined" site, so the two clash."""
    with pytest.raises(ValidationError, match="both placed at R12 U40 front"):
        Policy(scope=[
            _scope("192.0.2.10", site="undefined", rack="R12", position=40, face="front"),
            _scope("192.0.2.11", rack="R12", position=40, face="front"),
        ])


def _pinned(hostname="192.0.2.10", **override):
    return Napalm(hostname=hostname, username="admin", password="secret", netbox_id=42,
                  override_defaults=Defaults(**override))


def test_netbox_id_placement_needs_a_site():
    """With netbox_id and no site, no site is sent, so the rack could not be looked up."""
    with pytest.raises(ValidationError, match="192.0.2.10: position and face need a site when netbox_id is set"):
        Policy(config=Config(defaults=Defaults(rack="R12")), scope=[_pinned(position=40, face="front")])


@pytest.mark.parametrize("where", ["policy", "target"])
def test_netbox_id_placement_with_a_site_is_accepted(where):
    """A configured site is sent, and the rack is looked up in it."""
    defaults = Defaults(rack="R12", site="DC1") if where == "policy" else Defaults(rack="R12")
    override = {"site": "DC1"} if where == "target" else {}
    Policy(config=Config(defaults=defaults), scope=[_pinned(position=40, face="front", **override)])


@pytest.mark.parametrize("site", ["", "   "])
def test_netbox_id_placement_with_a_blank_site_is_refused(site):
    """A blank site, such as an empty ${SITE}, is no site to look the rack up in."""
    with pytest.raises(ValidationError, match="need a site when netbox_id is set"):
        Policy(config=Config(defaults=Defaults(rack="R12", site=site)), scope=[_pinned(position=40, face="front")])


def test_one_netbox_id_at_two_slots_is_refused():
    """Both entries update the same device, which would move between the slots every run."""
    with pytest.raises(ValidationError, match="192.0.2.10 and 192.0.2.11 place netbox_id 42 at different slots"):
        Policy(config=Config(defaults=Defaults(rack="R12", site="DC1")), scope=[
            _pinned("192.0.2.10", position=40, face="front"),
            _pinned("192.0.2.11", position=41, face="front"),
        ])


def test_one_netbox_id_at_one_slot_is_accepted():
    """Two entries for one device, both placing it at the same U, describe one placement."""
    Policy(config=Config(defaults=Defaults(rack="R12", site="DC1")), scope=[
        _pinned("192.0.2.10", position=40, face="front"),
        _pinned("192.0.2.11", position=40, face="front"),
    ])


def test_an_oversized_policy_is_refused_before_placement_is_checked():
    """The expansion budget runs first, so an oversized policy costs no placement work."""
    with pytest.raises(ValidationError, match="more than the limit") as exc:
        _policy([_scope("10.0.0.0/8", rack="R12", position=40, face="front")])
    assert "single host" not in str(exc.value)


@pytest.mark.parametrize("second", [{"rack": "R13"}, {"rack": "R12"}])
def test_one_netbox_id_in_two_placements_is_refused(second):
    """A rack sent without a position is a placement too: one device cannot have two."""
    with pytest.raises(ValidationError, match="place netbox_id 42 at different slots"):
        Policy(config=Config(defaults=Defaults(site="DC1")), scope=[
            _pinned("192.0.2.10", rack="R12", position=40, face="front"),
            _pinned("192.0.2.11", **second),
        ])


def test_one_netbox_id_in_two_racks_is_refused():
    """Rack-only entries for one device must agree on the rack."""
    with pytest.raises(ValidationError, match="place netbox_id 42 at different slots"):
        Policy(config=Config(defaults=Defaults(site="DC1")), scope=[
            _pinned("192.0.2.10", rack="R12"),
            _pinned("192.0.2.11", rack="R13"),
        ])


def test_one_netbox_id_in_one_rack_is_accepted():
    """Two rack-only entries for one device in the same rack agree."""
    Policy(config=Config(defaults=Defaults(site="DC1", rack="R12")), scope=[
        _pinned("192.0.2.10"), _pinned("192.0.2.11"),
    ])


def test_a_netbox_id_entry_that_sends_no_rack_does_not_conflict():
    """An entry opting out of the rack sends none, so NetBox keeps the other's."""
    Policy(config=Config(defaults=Defaults(site="DC1")), scope=[
        _pinned("192.0.2.10", rack="R12"),
        _pinned("192.0.2.11", rack=""),
    ])


def test_netbox_id_on_a_range_pins_nothing():
    """netbox_id is ignored on a range, so it cannot conflict with a single host."""
    Policy(config=Config(defaults=Defaults(site="DC1")), scope=[
        _pinned("192.0.2.10", rack="R12"),
        _pinned("192.0.2.16/29", rack="R13"),
    ])


@pytest.mark.parametrize("syntax", ["{}/32", "{}-{}"])
def test_netbox_id_on_single_address_range_syntax_pins_nothing(syntax):
    """A /32 or one-address range is still a range: netbox_id is dropped, so each is its own device."""
    with pytest.raises(ValidationError, match="are both placed at R12 U40 front"):
        Policy(config=Config(defaults=Defaults(rack="R12", site="DC1")), scope=[
            _pinned(syntax.format("192.0.2.10", "10"), position=40, face="front"),
            _pinned(syntax.format("192.0.2.11", "11"), position=40, face="front"),
        ])


def test_netbox_id_on_single_address_range_syntax_keeps_its_own_rack():
    """The /32 is not the netbox_id device, so its rack cannot conflict with that device's."""
    Policy(config=Config(defaults=Defaults(site="DC1")), scope=[
        _pinned("192.0.2.10", rack="R12"),
        _pinned("192.0.2.11/32", rack="R13"),
    ])


def test_netbox_id_placement_on_single_address_range_syntax_needs_no_site():
    """netbox_id is dropped there, so the device is sent with the undefined site and the rack with it."""
    Policy(config=Config(defaults=Defaults(rack="R12")), scope=[_pinned("192.0.2.10/32", position=40, face="front")])
