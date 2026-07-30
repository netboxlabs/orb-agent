#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
NetBox Labs - tests that blank NAPALM values are omitted, not sent empty.

NAPALM uses ``""`` to mean "this value is not available". Several presence-bearing
proto fields are fed directly from NAPALM getters, so passing a blank value through
sets the field to an explicit empty string — which the Diode NetBox plugin reads as a
real value rather than an omission.
"""

import pytest
from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb
from netboxlabs.diode.sdk.ingester import Entity

from device_discovery.policy.models import Defaults, ObjectParameters
from device_discovery.proto_presence import blank_to_none
from device_discovery.stubs import prune_nested_refs
from device_discovery.translate import translate_data

BASE_DEVICE = {
    "hostname": "rtr-1",
    "vendor": "MikroTik",
    "model": "CCR1036-8G-2S+",
    "serial_number": "ABC123",
    "os_version": "7.1",
    "interface_list": ["management"],
}
BASE_INTERFACE = {
    "is_up": True,
    "is_enabled": True,
    "description": "uplink to core",
    "mtu": 1500,
    "speed": -1.0,
    "mac_address": "08:55:31:10:47:8D",
    "last_flapped": -1.0,
}


def _is_repeated(field) -> bool:
    """
    Report whether a field is repeated, portably across protobuf versions.

    ``FieldDescriptor.is_repeated`` landed in protobuf 5.27; ``.label`` was removed in
    protobuf 6. protobuf is unpinned here (transitively via grpcio-status), so probe for
    the modern attribute and fall back to the legacy one.
    """
    if hasattr(field, "is_repeated"):
        return field.is_repeated
    return field.label == field.LABEL_REPEATED


def _present_but_blank(msg: pb.Device, path: str = "") -> list[str]:
    """
    Return dotted paths of every presence-bearing string field that is present but blank.

    Blank means empty OR whitespace-only: a field set to "   " is just as much a real
    value to the plugin as one set to "", so both must be caught.
    """
    found: list[str] = []
    for field, value in msg.ListFields():
        where = f"{path}.{field.name}" if path else field.name
        repeated = _is_repeated(field)
        if field.type == field.TYPE_STRING and not repeated:
            if field.has_presence and not value.strip():
                found.append(where)
        elif field.type == field.TYPE_MESSAGE and repeated:
            for i, item in enumerate(value):
                if hasattr(item, "ListFields"):
                    found.extend(_present_but_blank(item, f"{where}[{i}]"))
        elif field.type == field.TYPE_MESSAGE and hasattr(value, "ListFields"):
            found.extend(_present_but_blank(value, where))
    return found


def _emit(device_overrides=None, interface_overrides=None, defaults=None) -> list[Entity]:
    """Translate + prune a single-device payload, returning the emitted entities."""
    entities = list(
        translate_data(
            {
                "device": {**BASE_DEVICE, **(device_overrides or {})},
                "interface": {
                    "management": {**BASE_INTERFACE, **(interface_overrides or {})}
                },
                "defaults": defaults or Defaults(site="site-1", role="router"),
                "netbox_id": 1,
            }
        )
    )
    prune_nested_refs(entities)
    return entities


@pytest.mark.parametrize(
    ("label", "device_overrides", "interface_overrides"),
    [
        ("hostname undiscovered", {"hostname": None}, None),
        ("hostname empty", {"hostname": ""}, None),
        ("hostname whitespace", {"hostname": "   "}, None),
        ("serial empty", {"serial_number": ""}, None),
        ("serial whitespace", {"serial_number": " "}, None),
        ("serial blank in a list", {"serial_number": [""]}, None),
        ("serial bytes blank", {"serial_number": b""}, None),
        ("description empty", None, {"description": ""}),
        ("description whitespace", None, {"description": "  "}),
        ("mac empty", None, {"mac_address": ""}),
        (
            "everything blank",
            {"hostname": "", "serial_number": ""},
            {"description": "", "mac_address": ""},
        ),
    ],
)
def test_no_present_but_blank_fields_on_the_wire(
    label, device_overrides, interface_overrides
):
    """No emitted entity may carry a presence-bearing string field that is blank."""
    offenders: list[str] = []
    for entity in _emit(device_overrides, interface_overrides):
        which = entity.WhichOneof("entity")
        offenders.extend(
            f"{which}.{p}" for p in _present_but_blank(getattr(entity, which))
        )
    assert offenders == [], f"{label}: present-but-blank fields emitted: {offenders}"


def test_baseline_payload_still_carries_real_values():
    """The blank-value handling must not strip genuinely discovered values."""
    entities = _emit()
    device = next(e.device for e in entities if e.HasField("device"))
    iface = next(e.interface for e in entities if e.HasField("interface"))

    assert device.name == "rtr-1"
    assert device.serial == "ABC123"
    assert iface.description == "uplink to core"
    assert iface.primary_mac_address.mac_address == "08:55:31:10:47:8D"
    assert iface.device.name == "rtr-1"


def test_blank_driver_description_falls_back_to_policy_default():
    """A blank driver description must not override a policy-supplied default."""
    entities = _emit(
        interface_overrides={"description": ""},
        defaults=Defaults(
            site="site-1",
            role="router",
            interface=ObjectParameters(description="from policy"),
        ),
    )
    iface = next(e.interface for e in entities if e.HasField("interface"))
    assert iface.description == "from policy"


def test_real_driver_description_still_overrides_policy_default():
    """A non-blank driver description keeps precedence over the policy default."""
    entities = _emit(
        interface_overrides={"description": "from device"},
        defaults=Defaults(
            site="site-1",
            role="router",
            interface=ObjectParameters(description="from policy"),
        ),
    )
    iface = next(e.interface for e in entities if e.HasField("interface"))
    assert iface.description == "from device"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", None),
        ("   ", None),
        ("\t\n", None),
        ("x", "x"),
        (" padded ", " padded "),
        (None, None),
        (0, 0),
        (False, False),
    ],
)
def test_blank_to_none(value, expected):
    """Blank strings become None; every other value passes through untouched."""
    assert blank_to_none(value) == expected


def test_blank_policy_asset_tag_is_omitted():
    """A policy asset_tag of "" must not reach the wire: it is the top device matcher."""
    from device_discovery.policy.models import DeviceParameters

    entities = _emit(
        defaults=Defaults(
            site="site-1", role="router", device=DeviceParameters(asset_tag="")
        )
    )
    device = next(e.device for e in entities if e.HasField("device"))
    assert not device.HasField("asset_tag")


def test_blank_policy_asset_tag_keeps_rich_entity_and_stub_consistent():
    """The rich Device and its nested stub must agree on whether asset_tag is set."""
    from device_discovery.policy.models import DeviceParameters

    entities = _emit(
        defaults=Defaults(
            site="site-1", role="router", device=DeviceParameters(asset_tag="")
        )
    )
    device = next(e.device for e in entities if e.HasField("device"))
    iface = next(e.interface for e in entities if e.HasField("interface"))
    assert device.HasField("asset_tag") == iface.device.HasField("asset_tag")


def test_blank_policy_vrf_rd_is_omitted():
    """A policy VRF rd of "" must not reach the wire."""
    from device_discovery.policy.models import IpamParameters, VrfParameters

    entities = list(
        translate_data(
            {
                "device": BASE_DEVICE,
                "interface": {"management": BASE_INTERFACE},
                "interface_ip": {
                    "management": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}
                },
                "defaults": Defaults(
                    site="site-1",
                    role="router",
                    ipaddress=IpamParameters(vrf=VrfParameters(name="mgmt", rd="")),
                ),
            }
        )
    )
    prune_nested_refs(entities)
    vrf_bearing = [
        e.ip_address
        for e in entities
        if e.HasField("ip_address") and e.ip_address.HasField("vrf")
    ]
    assert vrf_bearing, "expected at least one IP carrying a VRF"
    for ip in vrf_bearing:
        assert not ip.vrf.HasField("rd")


@pytest.mark.parametrize("field", ["model", "vendor"])
def test_non_presence_fields_are_untouched(field):
    """Fields without proto presence are unaffected: empty and unset are the same wire."""
    entities = _emit({field: None})
    device = next(e.device for e in entities if e.HasField("device"))
    assert device.HasField("device_type")
