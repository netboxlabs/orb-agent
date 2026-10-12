#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Link-aggregation membership: set Interface.lag from a driver's member map."""

import logging
from collections.abc import Iterable

from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb
from netboxlabs.diode.sdk.ingester import Entity

logger = logging.getLogger(__name__)

# NetBox refuses a LAG parent on a virtual interface ("Virtual interfaces
# cannot have a parent LAG interface"), and the refusal fails the whole
# interface. A bridge or a LAG as a LAG member is accepted by the model but
# offered by no NetBox form and is not something a discovered aggregate
# means, so those are skipped too, matching snmp-discovery.
_NO_LAG_PARENT_TYPES = frozenset({"virtual", "bridge", "lag"})


def _index_interfaces(entities: Iterable[Entity]) -> dict[str, list[pb.Interface]]:
    """Map interface name to every emitted Interface carrying that name."""
    by_name: dict[str, list[pb.Interface]] = {}
    for entity in entities:
        if entity.HasField("interface"):
            by_name.setdefault(entity.interface.name, []).append(entity.interface)
    return by_name


def _single(by_name: dict[str, list[pb.Interface]], name: str, role: str, member: str) -> pb.Interface | None:
    """
    Return the one emitted interface called ``name``, or None with a log line.

    A name carried by more than one interface (a stack repeating a
    management-port name per member) cannot be attributed, so it is refused
    rather than guessed.
    """
    matches = by_name.get(name) or []
    if len(matches) == 1:
        return matches[0]
    if not matches:
        if role == "member":
            # Usually an interface the policy excluded; nothing to attach to.
            logger.debug("lag membership: member %r is not among emitted interfaces; skipping", name)
        else:
            logger.warning(
                "lag membership: aggregate %r of member %r is not among emitted interfaces; leaving the member without a lag",
                name,
                member,
            )
        return None
    logger.warning(
        "lag membership: %s %r matches %d emitted interfaces; leaving %r without a lag",
        role,
        name,
        len(matches),
        member,
    )
    return None


def apply_interface_lags(entities: list[Entity], interfaces_lag: object) -> int:
    """
    Set ``Interface.lag`` on each member port named by ``interfaces_lag``.

    ``interfaces_lag`` maps a physical member interface name to its aggregate
    interface name, as returned by a driver's ``get_interfaces_lag()``. Both
    interfaces must already be among ``entities``: nothing is created, and a
    pair that cannot be honoured is skipped with a log line rather than sent.
    Skipped are a member that is its own aggregate, an aggregate not typed
    ``lag`` (NetBox's forms offer only LAG interfaces as a parent), and a
    member typed ``virtual`` (refused by NetBox), ``bridge`` or ``lag``.

    The reference carries the aggregate's own device, so on a Virtual Chassis
    a member port on one stack member can point at an aggregate the
    translator attributed to another. It is reduced to a matcher stub by
    ``prune_nested_refs`` like ``parent`` and ``bridge``.

    Returns the number of interfaces that received a lag reference.
    """
    if not interfaces_lag:
        return 0
    if not isinstance(interfaces_lag, dict):
        logger.warning(
            "interfaces_lag payload is not a dict (got %s); skipping lag membership",
            type(interfaces_lag).__name__,
        )
        return 0

    by_name = _index_interfaces(entities)
    applied = 0
    for member_name, lag_name in interfaces_lag.items():
        if not isinstance(member_name, str) or not isinstance(lag_name, str) or not member_name or not lag_name:
            logger.warning("lag membership: skipping malformed entry %r -> %r", member_name, lag_name)
            continue
        if member_name == lag_name:
            logger.warning("lag membership: %r is reported as a member of itself; skipping", member_name)
            continue
        member = _single(by_name, member_name, "member", member_name)
        if member is None:
            continue
        aggregate = _single(by_name, lag_name, "aggregate", member_name)
        if aggregate is None:
            continue
        if aggregate.type != "lag":
            logger.warning(
                "lag membership: aggregate %r of member %r is typed %r, not lag; leaving the member without a lag",
                lag_name,
                member_name,
                aggregate.type,
            )
            continue
        if member.type in _NO_LAG_PARENT_TYPES:
            logger.warning(
                "lag membership: member %r is typed %r, which cannot carry a lag; skipping",
                member_name,
                member.type,
            )
            continue
        member.lag.CopyFrom(pb.Interface(name=aggregate.name, type=aggregate.type))
        member.lag.device.CopyFrom(aggregate.device)
        applied += 1
    return applied
