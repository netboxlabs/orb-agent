# Copyright 2026 NetBox Labs Inc
"""
Generic, vendor-neutral helper for switch-stack / Virtual Chassis discovery.

Each driver's optional ``get_chassis_members()`` builds a list of
:class:`ChassisMember` (vendor-neutral intermediates), drops members
without a serial, and wraps the result with :func:`to_payload`. The
translate layer (``device_discovery.translate``) consumes the payload
and emits a NetBox VirtualChassis plus N member Devices.

Output payload shape (consumed by translate)::

    {
        "members": [
            {"id": 1, "serial": "FOC1", "model": "...", "role": "active",
             "priority": 15, "mac": "...", "state": "..."},
            ...
        ],
        "domain": "1" | None,
    }

Returning ``None`` (no valid members after validation) signals the
translate layer to keep the existing single-Device path.
"""

from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass

logger = logging.getLogger(__name__)


_ROLE_MAP = {
    "active": "active",
    "master": "active",
    "standby": "standby",
    "backup": "standby",
    "slave": "standby",      # Comware 5 / older IRF terminology
    "member": "member",
    "ready": "member",
    "provisioned": "member",
}


def normalize_role(raw: str | None) -> str:
    """
    Map a vendor-native role string to one of {"active","standby","member"}.

    Empty / None / unknown values default to "member" rather than raising —
    discovery should never fail because a vendor returned a role string we
    don't recognize.
    """
    if not raw:
        return "member"
    return _ROLE_MAP.get(raw.strip().lower(), "member")


@dataclass
class ChassisMember:
    """Vendor-neutral normalized stack/VC member. Built by drivers, consumed by translate."""

    id: int
    serial: str
    model: str | None = None
    role: str = "member"
    priority: int | None = None
    mac: str | None = None
    state: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def to_payload(members: list[ChassisMember], domain: str | None = None) -> dict | None:
    """
    Wrap a list of ChassisMember into the payload shape consumed by translate.

    Drops members whose ``serial`` is empty (Diode resolves member Devices via
    the serial matcher; a member without one cannot be represented). Returns
    ``None`` when no valid members remain — translate then falls through to
    the existing single-Device path.
    """
    valid: list[dict] = []
    for m in members:
        if not m.serial:
            logger.warning(
                "_chassis.to_payload: dropping chassis member with no serial (id=%s, model=%r)",
                m.id, m.model,
            )
            continue
        valid.append(m.to_dict())
    if not valid:
        return None
    return {"members": valid, "domain": domain}


# Module-level compiled regexes — defined once at import.

# 1) Cisco IOS / IOS-XE: canonical long form (and short form for defense in depth).
#    Captures the leading switch id from "<word><digits>/<digits>/<digits>[.<sub>]".
#    Allows 3-tuple (Catalyst stack) and rejects 4-tuple (FEX-style 101/1/0/1).
_CISCO_IOS_RE = re.compile(
    r"""
    ^                                       # anchor
    (?:Gi(?:gabitEthernet)?                 # Gi or GigabitEthernet
       | Te(?:nGigabitEthernet)?            # Te or TenGigabitEthernet
       | Fo(?:rtyGigabitEthernet)?          # Fo or FortyGigabitEthernet
       | Hu(?:ndredGigE|ndredGigabitEthernet)?  # Hu, HundredGigE, or HundredGigabitEthernet
       | TwentyFiveGigE | Twe               # 25G mGig
       | TwoGigabitEthernet | Tw            # 2.5G mGig (Catalyst 9300/9400)
       | FiveGigabitEthernet | Fi           # 5G mGig
    )
    (\d+)                                   # member id
    /\d+/\d+                                # slot/port — exactly two more
    (?:\.\d+)?                              # optional subinterface suffix
    $                                       # anchor — rejects 4-tuples like 101/1/0/1
    """,
    re.VERBOSE,
)

# 2) NX-OS FEX-style 4-tuple (Eth101/1/0/1) — explicit reject so the Cisco
#    regex doesn't leak into a permissive match. FEX is NX-OS only and uses
#    the bare ``Ethernet``/``Eth`` prefix; IOS / IOS-XE never carry FEX, so
#    ``Gi``/``GigabitEthernet`` 4-tuples are NOT FEX and must not be rejected
#    here (Cat 9500 SVL with 1G FRU uplinks emits e.g.
#    ``GigabitEthernet1/2/0/43`` — leading digit is the SVL switch id).
_FEX_4TUPLE_RE = re.compile(r"^(?:Ethernet|Eth)\d+/\d+/\d+/\d+(?:\.\d+)?$")

# 2b) Cisco IOS / IOS-XE 4-tuple — Catalyst 9400/9500 StackWise Virtual.
#     Captures the leading switch id from "<word><digits>/<digits>/<digits>/<digits>".
#     Includes ``Gi``/``GigabitEthernet`` for Cat 9500 SVL with 1G FRU
#     uplinks — those interfaces are 4-tuple, leading digit is the switch
#     (member) id. No collision with FEX: FEX uses ``Ethernet``/``Eth``
#     only (NX-OS), and ``_FEX_4TUPLE_RE`` rejects those before this regex
#     runs.
_CISCO_IOS_4TUPLE_RE = re.compile(
    r"""
    ^                                       # anchor
    (?:Te(?:nGigabitEthernet)?              # Te or TenGigabitEthernet
       | Fo(?:rtyGigabitEthernet)?          # Fo or FortyGigabitEthernet
       | Hu(?:ndredGigE|ndredGigabitEthernet)?  # Hu, HundredGigE, or HundredGigabitEthernet
       | TwentyFiveGigE | Twe               # 25G mGig
       | TwoGigabitEthernet | Tw            # 2.5G mGig
       | FiveGigabitEthernet | Fi           # 5G mGig
       | GigabitEthernet | Gi               # 1G — Cat 9500 SVL FRU uplinks
    )
    (\d+)                                   # switch (member) id
    /\d+/\d+/\d+                            # slot/subslot/port — exactly three more
    (?:\.\d+)?                              # optional subinterface
    $                                       # anchor
    """,
    re.VERBOSE,
)

# 3) Junos / Aruba CX — leading digit-cluster followed by /<digit>/<digit>.
_JUNOS_RE = re.compile(r"^(?:[a-z]{2}-)?(\d+)/\d+/\d+(?:\.\d+)?$")

# 4) HP / H3C Comware expanded interface names — the hp_comware driver expands
#    `XGE1/0/49` → `Ten-GigabitEthernet1/0/49` and similar in get_interfaces(),
#    so translate sees the hyphenated full forms. These do not match the Cisco
#    regex (which expects `Te`/`TenGigabitEthernet` / `Fo`/`FortyGigabitEthernet`
#    without hyphens), so we cover them explicitly. `GigabitEthernet1/0/1` and
#    `HundredGigE3/0/1` already match the Cisco regex via the `Gi` / `Hu`
#    short-prefix branches and are intentionally NOT duplicated here.
#    `M-GigabitEthernet` is the Comware management interface — left as None.
_COMWARE_RE = re.compile(
    r"""
    ^
    (?:Ten-GigabitEthernet
     | Twenty-FiveGigE
     | FortyGigE
     | FiftyGigE
     | TwoHundredGigE
     | FourHundredGigE
    )
    (\d+)/\d+/\d+(?:\.\d+)?
    $
    """,
    re.VERBOSE,
)

# 5) Huawei VRP-specific Ethernet prefixes (batch 6 — iStack support).
#    Covers `XGigabitEthernet` (Huawei full-form 10G — NOT matched by the
#    Cisco `Te`/`TenGigabitEthernet` branch) and the Huawei numeric-speed
#    abbreviations (`10GE`, `25GE`, `40GE`, `50GE`, `100GE`, `200GE`, `400GE`)
#    that VRP may emit in `display interface brief`. `GigabitEthernet1/0/1`
#    already resolves via the Cisco `Gi` short-prefix branch.
_HUAWEI_RE = re.compile(
    r"""
    ^
    (?:XGigabitEthernet
     | (?:10|25|40|50|100|200|400)GE
    )
    (\d+)/\d+/\d+(?:\.\d+)?
    $
    """,
    re.VERBOSE,
)


def parse_member_id(if_name: str) -> int | None:
    """
    Extract the stack member id from an interface name. Return None when there is none.

    Supported (positive matches):
      - Cisco IOS canonical and short forms: GigabitEthernet1/0/1 -> 1, Gi2/0/1 -> 2
      - mGig families on Catalyst 9300/9400: TwoGigabitEthernet, FiveGigabitEthernet,
        TwentyFiveGigE (and Tw/Fi/Twe short aliases)
      - Subinterfaces: GigabitEthernet1/0/1.100 -> 1
      - Junos FPC-style: et-0/0/0 -> 0, ge-1/0/0 -> 1
      - Aruba CX bare digits: 1/1/1 -> 1
      - HP / H3C Comware hyphenated speed prefixes (batch 4 — IRF):
        Ten-GigabitEthernet1/0/49 -> 1, Twenty-FiveGigE2/0/1 -> 2,
        FortyGigE1/0/1 -> 1, FiftyGigE2/0/1 -> 2,
        TwoHundredGigE1/0/1 -> 1, FourHundredGigE2/0/1 -> 2
      - Huawei VRP (batch 6 — iStack): XGigabitEthernet1/0/49 -> 1,
        10GE1/0/1 -> 1, 25GE2/0/1 -> 2, 40GE/50GE/100GE/200GE/400GE

    Returns None for SVIs / loopback / tunnel / mgmt, LAG / bundle members,
    FEX 3/4-tuples, NX-OS ``Ethernet``/``Eth`` (out of scope for batch 1),
    ProCurve / ArubaOS-Switch port shorthand, and malformed input.
    """
    if not if_name:
        return None

    # Reject FEX 4-tuple before any positive match.
    if _FEX_4TUPLE_RE.match(if_name):
        return None

    # Cisco SVL 4-tuple BEFORE the 3-tuple Cisco regex — the 4-tuple regex
    # is anchored on the slash count, so the 3-tuple regex would not match
    # a 4-tuple name anyway, but ordering this match first keeps the
    # match-by-specificity convention obvious to readers.
    m = _CISCO_IOS_4TUPLE_RE.match(if_name)
    if m:
        return int(m.group(1))

    m = _CISCO_IOS_RE.match(if_name)
    if m:
        return int(m.group(1))

    m = _COMWARE_RE.match(if_name)
    if m:
        return int(m.group(1))

    m = _HUAWEI_RE.match(if_name)
    if m:
        return int(m.group(1))

    m = _JUNOS_RE.match(if_name)
    if m:
        return int(m.group(1))

    return None
