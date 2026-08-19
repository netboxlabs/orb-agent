#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Parse the 802.1Q VLAN ID out of an SVI-style interface name."""

import re

# Whitelisted tokens whose trailing integer is the 802.1Q VLAN ID on the
# platforms that use them.
# Kept byte-identical in intent to the Go twin in
# orb-discovery/snmp-discovery/mapping/svi_vlan.go; the shared accept/reject
# tables in the tests are what keep the two from drifting.
#
# Deliberately absent: br, v, vgi, bvi, bdi, ve, irb, rvi. Those integers are
# bridge-group ids, bridge-domain ids, virtual-interface ids or operator
# labels.
#
# bdi is the sharpest of those. A Cisco bridge domain carries whatever
# encapsulation its service instances declare, so BDI100 can route
# `encapsulation dot1q 10`, and requiring the VLAN table to contain VLAN 100
# does not catch it: a device that happens to have VLAN 100 corroborates the
# wrong association instead. Typing a BDI as a virtual interface is correct and
# unaffected; reading its number as a VLAN ID is not.
_SVI_RE = re.compile(
    r"^(?:interface[\s_-]+)?"
    r"(?:vlan-interface|vlan[\s_-]?id|vlanif|vlan|svi|vl)"
    r"[\s_-]*0*(\d{1,5})$",
    re.IGNORECASE,
)


def svi_vlan_id(name: str) -> int | None:
    """
    Return the VLAN ID for an SVI-style interface name, or None.

    Any name containing a dot is refused: a dotted name cannot be told apart
    from stack.slot.port notation or a loopback unit, and no measured device
    reports the 802.1Q encapsulation of a routed subinterface, so such a guess
    could never be checked against anything.
    """
    if not name:
        return None
    name = name.strip()
    if not name or "." in name:
        return None
    m = _SVI_RE.match(name)
    if m is None:
        return None
    vid = int(m.group(1))
    if vid < 1 or vid > 4094:
        return None
    return vid
