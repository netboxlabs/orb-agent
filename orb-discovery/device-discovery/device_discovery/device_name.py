#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
The ``emit_device_name`` transform.

device-discovery always emits ``Device.name`` from the hostname the driver
reported. When a policy matches an existing NetBox device by ``netbox_id`` and
that device's discovered hostname differs from its NetBox name, the match
succeeds but the emitted name is a deviation — so continual discovery proposes
a hostname rename on every cycle and it never settles.

``emit_device_name: false`` suppresses the name while keeping the match. Mirrors
``mapping.ApplyDeviceNameEmission`` in snmp-discovery (see
``orb-discovery/snmp-discovery/mapping/device_name.py``), including its matcher
guard and its master-only scope on virtual-chassis stacks.
"""

import logging

from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb

logger = logging.getLogger(__name__)


def device_has_alternative_matcher(device: pb.Device) -> bool:
    """
    Report whether ``device`` can be matched without its name.

    Only matchers that also survive onto the nested device stubs built by
    ``stubs._device_match_stub`` count:

    - ``metadata["source_match"]`` (written from a scope's ``netbox_id``)
    - a non-empty ``asset_tag``

    ``serial`` is excluded because NetBox ``Device.serial`` is not unique and
    generates no matcher at all. ``primary_ip4``/``primary_ip6`` are excluded
    because, although ``unique_primary_ip4``/``ip6`` match a top-level device,
    the nested stubs drop primary_ip (setting it on a nested stub fails
    ingest), so clearing the name would leave every nested reference
    unmatchable.
    """
    if "source_match" in device.metadata:
        return True
    return bool(device.asset_tag and device.asset_tag.strip())


def apply_device_name_emission(
    device: pb.Device,
    emit: bool,
    target_hostname: str | None = None,
) -> bool:
    """
    Clear ``device.name`` when name emission is disabled. Returns True if cleared.

    No-op when emission is enabled (the default), when the device carries no
    name, or when the device is a virtual-chassis member — suppression is
    master-only, matching snmp-discovery. Member names come from
    ``stack_member_name_template``, which is their own lever.

    When disabled but the device carries no alternative matcher, the name is
    KEPT and a warning is logged: ``name`` is a primary device matcher, so
    dropping it without a ``source_match`` / ``asset_tag`` would emit a device
    NetBox cannot resolve.

    Uses ``ClearField`` rather than assigning ``""``. ``Device.name`` declares
    explicit presence, and the Diode plugin treats an explicit empty string as
    a deliberate clear — that would wipe the hostname in NetBox instead of
    leaving it untouched, which is the opposite of the intent.
    """
    if emit:
        return False
    if not device.HasField("name"):
        return False
    if device.HasField("vc_position"):
        return False
    if not device_has_alternative_matcher(device):
        logger.warning(
            "emit_device_name is disabled but %s has no alternative matcher "
            "(netbox_id/source_match, or defaults.device.asset_tag); keeping the "
            "name so the device stays resolvable in NetBox",
            target_hostname or device.name,
        )
        return False
    logger.debug(
        "emit_device_name: suppressing Device.name %r for %s",
        device.name,
        target_hostname or "target",
    )
    device.ClearField("name")
    return True
