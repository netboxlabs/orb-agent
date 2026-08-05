#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Tests for the emit_device_name option."""

import logging

import pytest

from device_discovery.device_name import (
    apply_device_name_emission,
    device_has_alternative_matcher,
)
from device_discovery.policy.models import Defaults, DeviceParameters, Options
from device_discovery.translate import translate_data, translate_device


@pytest.fixture
def device_info():
    """NAPALM get_facts output for a device whose hostname differs from NetBox."""
    return {
        "hostname": "discovered-name",
        "vendor": "Cisco",
        "model": "C9300-24T",
        "os_version": "17.9.4",
        "serial_number": "FOC1111111",
        "uptime": 1000.0,
        "fqdn": "discovered-name.example.net",
        "interface_list": ["GigabitEthernet1/0/1"],
    }


def _defaults(**kw):
    return Defaults(site="site-a", role="switch", **kw)


# --- the matcher guard -------------------------------------------------------


def test_netbox_id_counts_as_an_alternative_matcher(device_info):
    """A scope netbox_id becomes metadata.source_match, which survives onto stubs."""
    dev = translate_device(device_info, _defaults(), netbox_id=42)
    assert device_has_alternative_matcher(dev) is True


def test_asset_tag_counts_as_an_alternative_matcher(device_info):
    """asset_tag is the highest-precedence NetBox device matcher."""
    dev = translate_device(
        device_info, _defaults(device=DeviceParameters(asset_tag="AT-0001"))
    )
    assert device_has_alternative_matcher(dev) is True


def test_serial_alone_is_not_an_alternative_matcher(device_info):
    """
    NetBox Device.serial is not unique and generates no matcher.

    The fixture always carries a serial, so this pins that serial alone does
    not unlock suppression — otherwise every device would qualify and clearing
    the name would emit something NetBox cannot resolve.
    """
    dev = translate_device(device_info, _defaults())
    assert dev.serial == "FOC1111111"
    assert device_has_alternative_matcher(dev) is False


# --- the transform -----------------------------------------------------------


def test_default_emits_the_name(device_info):
    """Defaults are unchanged: the discovered hostname is emitted."""
    assert Options().emit_device_name is True
    dev = translate_device(device_info, _defaults(), netbox_id=42)
    assert apply_device_name_emission(dev, Options().emit_device_name, "10.0.0.5") is False
    assert dev.name == "discovered-name"


def test_disabled_with_a_matcher_unsets_the_name(device_info):
    """
    Suppression must UNSET the field, not assign "".

    Device.name declares proto presence and the Diode plugin treats an explicit
    empty string as a deliberate clear, which would wipe the hostname in NetBox
    instead of leaving it alone. HasField is the assertion that catches that.
    """
    dev = translate_device(device_info, _defaults(), netbox_id=42)
    assert apply_device_name_emission(dev, False, "10.0.0.5") is True
    assert dev.HasField("name") is False


def test_disabled_without_a_matcher_keeps_the_name_and_warns(device_info, caplog):
    """Name is a primary matcher; dropping it unguarded emits an unresolvable device."""
    dev = translate_device(device_info, _defaults())
    with caplog.at_level(logging.DEBUG, logger="device_discovery.device_name"):
        assert apply_device_name_emission(dev, False, "10.0.0.5") is False
    assert dev.name == "discovered-name"
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1
    assert "no alternative matcher" in warnings[0].getMessage()


def test_virtual_chassis_member_is_never_suppressed(device_info):
    """Suppression is master-only, matching snmp-discovery."""
    dev = translate_device(device_info, _defaults(), netbox_id=42)
    dev.vc_position = 2
    assert apply_device_name_emission(dev, False, "10.0.0.5") is False
    assert dev.name == "discovered-name"


def test_a_device_with_no_name_is_a_no_op(device_info):
    """A driver that discovered no hostname leaves nothing to suppress."""
    info = dict(device_info, hostname="")
    dev = translate_device(info, _defaults(), netbox_id=42)
    assert dev.HasField("name") is False
    assert apply_device_name_emission(dev, False, "10.0.0.5") is False


# --- end to end through translate_data --------------------------------------


def _stack_payload(device_info, options):
    return {
        "device": device_info,
        "interface": {
            "GigabitEthernet1/0/1": {
                "is_enabled": True, "mtu": 1500, "mac_address": "",
                "speed": 1000, "description": "",
            },
            "GigabitEthernet2/0/1": {
                "is_enabled": True, "mtu": 1500, "mac_address": "",
                "speed": 1000, "description": "",
            },
        },
        "interface_ip": {},
        "driver": "ios",
        "defaults": _defaults(),
        "options": options,
        "netbox_id": 42,
        "chassis_members": {
            "members": [
                {"id": 1, "serial": "FOC1111111", "model": "C9300-24T", "role": "active"},
                {"id": 2, "serial": "FOC2222222", "model": "C9300-24T", "role": "standby"},
            ],
            "domain": None,
        },
    }


def test_standalone_end_to_end_suppresses_and_keeps_nothing_empty(device_info):
    """The emitted Device carries no name, and no entity carries an empty one."""
    data = {
        "device": device_info,
        "interface": {},
        "interface_ip": {},
        "driver": "ios",
        "defaults": _defaults(),
        "options": Options(emit_device_name=False),
        "netbox_id": 42,
    }
    entities = list(translate_data(data))
    devices = [e.device for e in entities if e.HasField("device")]
    assert devices, "expected a Device entity"
    for d in devices:
        assert d.HasField("name") is False, "name must be unset, never empty"


def test_stack_master_suppressed_but_members_keep_their_names(device_info):
    """Master and the shared VC master ref lose the name; members do not."""
    data = _stack_payload(device_info, Options(emit_device_name=False))
    entities = list(translate_data(data))

    devices = [e.device for e in entities if e.HasField("device")]
    masters = [d for d in devices if not d.HasField("vc_position")]
    members = [d for d in devices if d.HasField("vc_position")]

    assert len(masters) == 1
    assert masters[0].HasField("name") is False, "master name must be suppressed"

    assert members, "expected non-master member devices"
    for m in members:
        assert m.HasField("name") is True, "member names come from the template"
        assert m.name

    vcs = [e.virtual_chassis for e in entities if e.HasField("virtual_chassis")]
    assert len(vcs) == 1
    assert vcs[0].name, "the VirtualChassis name itself is not suppressed"
    assert vcs[0].master.HasField("name") is False, (
        "the shared VC master ref must inherit the suppression, or it "
        "resurrects the name _master_device_ref exists to keep in sync"
    )
    for m in members:
        if m.HasField("virtual_chassis") and m.virtual_chassis.HasField("master"):
            assert m.virtual_chassis.master.HasField("name") is False


def test_stack_default_keeps_every_name(device_info):
    """With the option at its default, stack emission is byte-identical to before."""
    data = _stack_payload(device_info, Options())
    entities = list(translate_data(data))
    devices = [e.device for e in entities if e.HasField("device")]
    assert all(d.HasField("name") for d in devices)
    vcs = [e.virtual_chassis for e in entities if e.HasField("virtual_chassis")]
    assert vcs[0].master.HasField("name") is True


def test_standalone_suppression_precedes_the_nested_ref_deepcopy(device_info):
    """
    Suppression must run BEFORE translate.py's copy.deepcopy(device).

    Every nested interface / IP device reference is derived from that copy, so
    suppressing after it leaves them carrying the name that was just dropped.
    This asserts on the pre-pruning shape deliberately: prune_nested_refs
    regenerates nested refs at ingest and would mask the ordering.
    """
    data = {
        "device": device_info,
        "interface": {
            "GigabitEthernet1/0/1": {
                "is_enabled": True, "mtu": 1500, "mac_address": "",
                "speed": 1000, "description": "",
            },
        },
        "interface_ip": {},
        "driver": "ios",
        "defaults": _defaults(),
        "options": Options(emit_device_name=False),
        "netbox_id": 42,
    }
    entities = list(translate_data(data))
    nested = [
        e.interface.device for e in entities
        if e.HasField("interface") and e.interface.HasField("device")
    ]
    assert nested, "expected interface entities carrying a nested device ref"
    for ref in nested:
        assert ref.HasField("name") is False, (
            "a nested device ref still carries the suppressed name — suppression "
            "ran after copy.deepcopy(device)"
        )


def test_suppressed_name_without_a_serial_still_prunes(device_info, caplog):
    """
    A suppressed device with no serial must still resolve during pruning.

    prune_nested_refs resolves nested refs by name, then serial. Suppression is
    permitted on the strength of source_match / asset_tag, so a device with a
    netbox_id but no driver-reported serial would otherwise resolve to nothing:
    every nested ref left un-pruned, with one WARNING per interface on every
    discovery cycle.
    """
    from device_discovery.stubs import prune_nested_refs

    info = dict(device_info)
    del info["serial_number"]
    data = {
        "device": info,
        "interface": {
            f"GigabitEthernet1/0/{i}": {
                "is_enabled": True, "mtu": 1500, "mac_address": "",
                "speed": 1000, "description": "",
            }
            for i in (1, 2, 3)
        },
        "interface_ip": {},
        "driver": "ios",
        "defaults": _defaults(),
        "options": Options(emit_device_name=False),
        "netbox_id": 42,
    }
    entities = list(translate_data(data))
    with caplog.at_level(logging.DEBUG, logger="device_discovery.stubs"):
        prune_nested_refs(entities)

    unresolved = [r for r in caplog.records if "could not resolve" in r.getMessage()]
    assert unresolved == [], (
        "nested refs failed to resolve for a suppressed, serial-less device"
    )
    nested = [
        e.interface.device for e in entities
        if e.HasField("interface") and e.interface.HasField("device")
    ]
    assert nested
    for ref in nested:
        # platform and status are stripped by _device_match_stub, so their
        # presence proves the ref was left un-pruned.
        assert not ref.HasField("platform")
        assert not ref.HasField("status")
