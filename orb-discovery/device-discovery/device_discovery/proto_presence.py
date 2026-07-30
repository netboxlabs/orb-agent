#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
Presence-safe helpers for populating Diode ingester protos.

MOST optional scalars on the ingester protos declare explicit presence (``optional`` in
proto3) — as a rule, everything except the fields NetBox requires. ``Device`` alone has
eight such string fields (``name``, ``serial``, ``asset_tag``, ``face``, ``status``,
``airflow``, ``description``, ``comments``), and ``Interface``, ``IPAddress``,
``Prefix``, ``VRF``, ``Module`` and ``ModuleBay`` all carry their own. Do NOT work from
a memorised list: check ``DESCRIPTOR.fields_by_name[name].has_presence``.

For a presence-bearing field, "unset" and "set to the empty string" are DISTINCT on the
wire, and the Diode NetBox plugin treats them very differently. Unset means "leave this
field alone"; an explicit empty value is a real value the plugin diffs against NetBox
and — from plugin v1.14.1 on — writes as a deliberate clear.

The exceptions are the required matcher fields (``Site.name``, ``Interface.name``,
``DeviceType.model``, ``Manufacturer.name``, ``MACAddress.mac_address``,
``IPAddress.address``, ``VRF.name``, ...), which have no presence: for them empty and
unset serialize identically and neither helper here changes anything.

Reading an unset scalar through the normal attribute accessor yields the proto3 default
(``""``), so the natural-looking ``pb.Device(name=d.name)`` silently launders absence
into an explicit empty string. See ``copy_scalar_if_set``.
"""

from typing import Any

from google.protobuf.message import Message


def copy_scalar_if_set(dst: Message, src: Message, *fields: str) -> None:
    """
    Copy scalar ``fields`` from ``src`` to ``dst`` without laundering absence into presence.

    Use this instead of passing accessor reads into a message constructor
    (``pb.Device(name=d.name)``). When ``d.name`` is unset that expression yields ``""``
    and the constructor marks the field PRESENT, turning "we discovered no hostname"
    into "the hostname is empty".

    That laundering is a real reported failure: nested device stubs built by
    ``prune_nested_refs`` carried ``name: ""`` even when discovery had correctly reported
    no hostname. On diode plugin v1.13.0 the plugin counted the empty value as a change
    but stripped it from the payload it actually wrote, so Assurance raised a deviation
    claiming one change with an empty diff — it applied with no effect and came back on
    the next discovery. On v1.14.1 the same payload instead erases the device name.

    Fields that declare explicit presence are copied only when set on ``src``. Fields
    without presence are copied unconditionally, since for them empty and unset are
    indistinguishable on the wire; they are accepted here so callers need not track
    which is which.

    Args:
    ----
        dst: Message to copy onto.
        src: Message to copy from.
        *fields: Names of scalar fields to copy.

    """
    descriptor = src.DESCRIPTOR
    for field in fields:
        if descriptor.fields_by_name[field].has_presence and not src.HasField(field):
            continue
        setattr(dst, field, getattr(src, field))


def blank_to_none(value: Any) -> Any:
    """
    Map a blank NAPALM string to ``None`` so the field is omitted rather than sent empty.

    NAPALM's getter contract uses ``""`` for "this value is not available", not for
    "this value is empty on the device" — 17 of the custom drivers hardcode
    ``"description": ""`` in ``get_interfaces`` without ever reading a description off
    the box. Passing that straight through sets a presence-bearing proto field to an
    explicit empty string, which the plugin reads as a real value: a no-op deviation
    that reapplies forever on plugin v1.13.0, and an actual field clear on v1.14.1.

    Whitespace-only values are treated as blank too, since they only ever come from a
    parser that matched nothing. Non-blank values are returned unchanged and unstripped,
    so genuine content is never rewritten. ``str`` and ``bytes`` are both handled; any
    other type passes straight through.

    Args:
    ----
        value: A value from a NAPALM getter, or anything else (returned unchanged).

    Returns:
    -------
        ``None`` when ``value`` is a blank string, otherwise ``value`` unchanged.

    """
    # bytes as well as str: translate_device deliberately lets a bytes serial through
    # its type normalisation, so b"" must be blanked too.
    if isinstance(value, str | bytes) and not value.strip():
        return None
    return value
