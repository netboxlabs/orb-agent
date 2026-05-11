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
       | Hu(?:ndredGigE)?                   # Hu or HundredGigE
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

# 2) FEX-style 4-tuple (Eth101/1/0/1) — explicit reject so the Cisco regex doesn't
#    leak into a permissive match if someone changes it later.
_FEX_4TUPLE_RE = re.compile(r"^(?:Ethernet|Eth|GigabitEthernet|Gi)\d+/\d+/\d+/\d+(?:\.\d+)?$")

# 3) Junos / Aruba CX — leading digit-cluster followed by /<digit>/<digit>.
_JUNOS_RE = re.compile(r"^(?:[a-z]{2}-)?(\d+)/\d+/\d+(?:\.\d+)?$")


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

    Returns None for SVIs / loopback / tunnel / mgmt, LAG / bundle members,
    FEX 3/4-tuples, NX-OS ``Ethernet``/``Eth`` (out of scope for batch 1),
    ProCurve / ArubaOS-Switch port shorthand, and malformed input.
    """
    if not if_name:
        return None

    # Reject FEX 4-tuple before any positive match.
    if _FEX_4TUPLE_RE.match(if_name):
        return None

    m = _CISCO_IOS_RE.match(if_name)
    if m:
        return int(m.group(1))

    m = _JUNOS_RE.match(if_name)
    if m:
        return int(m.group(1))

    return None
