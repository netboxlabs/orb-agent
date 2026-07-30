#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
NetBox Labs - presence tests for nested entity stubs.

Most optional scalars on the ingester protos declare explicit proto presence (including
``Device.name``), so "unset" and "set to the empty string" are distinct on the wire. The Diode NetBox plugin reads an
explicit empty value as a real value: on plugin v1.13.0 it counted as a change but was
stripped from the payload actually written (a deviation claiming one change with an
empty diff, applying with no effect, recreated on every discovery), and on v1.14.1 it
is written as a deliberate field clear.

Reading an unset scalar yields the proto3 default ``""``, so ``pb.Device(name=d.name)``
laundered absence into presence. These tests pin that down.
"""

from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb

from device_discovery.policy.models import Defaults
from device_discovery.proto_presence import copy_scalar_if_set
from device_discovery.stubs import _device_match_stub, prune_nested_refs
from device_discovery.translate import translate_data


def test_device_match_stub_does_not_launder_unset_name():
    """An unset name on the rich Device stays unset on the stub instead of becoming ""."""
    rich = pb.Device(serial="ABC123")
    rich.site.CopyFrom(pb.Site(name="site-1"))
    assert not rich.HasField("name")

    stub = _device_match_stub(rich)

    assert not stub.HasField("name"), "unset device name laundered into an empty string"


def test_device_match_stub_preserves_a_real_name():
    """A set name is still copied onto the stub."""
    stub = _device_match_stub(pb.Device(name="rtr-1"))
    assert stub.HasField("name")
    assert stub.name == "rtr-1"


def test_nested_device_stub_omits_name_when_hostname_undiscovered():
    """Nested device refs must not carry name:"" when no hostname was discovered."""
    entities = list(
        translate_data(
            {
                "device": {
                    "hostname": None,
                    "vendor": "MikroTik",
                    "model": "CCR1036-8G-2S+",
                    "serial_number": "ABC123",
                    "interface_list": ["management"],
                },
                "interface": {
                    "management": {
                        "is_up": True,
                        "is_enabled": True,
                        "description": "uplink",
                        "mtu": 1500,
                        "speed": -1.0,
                        "mac_address": "08:55:31:10:47:8D",
                        "last_flapped": -1.0,
                    }
                },
                "defaults": Defaults(site="site-1", role="router"),
                "netbox_id": 1,
            }
        )
    )
    prune_nested_refs(entities)

    devices = [e.device for e in entities if e.HasField("device")]
    interfaces = [e.interface for e in entities if e.HasField("interface")]
    assert devices and interfaces

    assert not devices[0].HasField("name")
    for iface in interfaces:
        assert not iface.device.HasField(
            "name"
        ), "nested device stub laundered the absent hostname into name:''"


def test_copy_scalar_if_set_skips_unset_presence_field():
    """A presence-bearing field that is unset on the source is not copied."""
    dst = pb.Device()
    copy_scalar_if_set(dst, pb.Device(), "name", "serial")
    assert not dst.HasField("name")
    assert not dst.HasField("serial")


def test_copy_scalar_if_set_copies_explicit_empty_when_source_set_it():
    """An explicitly-set empty value is still copied — the helper only guards absence."""
    dst = pb.Device()
    copy_scalar_if_set(dst, pb.Device(name=""), "name")
    assert dst.HasField("name")
    assert dst.name == ""


def test_copy_scalar_if_set_handles_fields_without_presence():
    """Fields without explicit presence are copied unconditionally, not rejected."""
    dst = pb.Site()
    copy_scalar_if_set(dst, pb.Site(name="site-1"), "name")
    assert dst.name == "site-1"


def test_master_device_ref_does_not_launder_unset_name():
    """The virtual-chassis master ref must not launder an unset name/serial either."""
    from device_discovery.translate_chassis import _master_device_ref

    master = pb.Device()
    master.site.CopyFrom(pb.Site(name="site-1"))
    assert not master.HasField("name")
    assert not master.HasField("serial")

    ref = _master_device_ref(master)

    assert not ref.HasField("name")
    assert not ref.HasField("serial")
    assert ref.site.name == "site-1"
