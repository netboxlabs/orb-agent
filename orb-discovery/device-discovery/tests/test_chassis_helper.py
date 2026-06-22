"""Tests for custom_napalm/_chassis.py helper module."""

import pytest

from custom_napalm._chassis import ChassisMember, normalize_role, parse_member_id, to_payload


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("active", "active"),
        ("Active", "active"),
        ("master", "active"),    # Cisco StackWise legacy term
        ("Master", "active"),
        ("standby", "standby"),
        ("Standby", "standby"),
        ("backup", "standby"),
        ("slave", "standby"),     # Comware 5 / older IRF terminology
        ("Slave", "standby"),
        ("member", "member"),
        ("ready", "member"),
        ("provisioned", "member"),
        ("", "member"),          # empty string defaults to member
        (None, "member"),
        ("WhoKnows", "member"),  # unknown defaults to member
    ],
)
def test_normalize_role(raw, expected):
    """Vendor role strings normalize to {active, standby, member}; unknowns default to member."""
    assert normalize_role(raw) == expected


def test_chassis_member_to_dict_minimal():
    """ChassisMember.to_dict round-trips a minimal dataclass instance."""
    m = ChassisMember(id=1, serial="FOC1234")
    assert m.to_dict() == {
        "id": 1,
        "serial": "FOC1234",
        "model": None,
        "role": "member",
        "priority": None,
        "mac": None,
        "state": None,
    }


def test_chassis_member_to_dict_full():
    """ChassisMember.to_dict serializes every field including optional ones."""
    m = ChassisMember(
        id=2, serial="FOC5678", model="WS-C3850-12XS",
        role="active", priority=15, mac="aa:bb:cc:dd:ee:ff", state="ready",
    )
    assert m.to_dict() == {
        "id": 2, "serial": "FOC5678", "model": "WS-C3850-12XS",
        "role": "active", "priority": 15, "mac": "aa:bb:cc:dd:ee:ff", "state": "ready",
    }


def test_to_payload_drops_members_without_serial(caplog):
    """Members without a serial are dropped (and a warning logged) before payload is built."""
    members = [
        ChassisMember(id=1, serial="FOC1"),
        ChassisMember(id=2, serial=""),    # dropped
        ChassisMember(id=3, serial="FOC3"),
    ]
    with caplog.at_level("WARNING", logger="custom_napalm._chassis"):
        payload = to_payload(members)
    assert [m["id"] for m in payload["members"]] == [1, 3]
    assert any("dropping chassis member with no serial" in r.message.lower() for r in caplog.records)


def test_to_payload_returns_none_when_no_valid_members():
    """Returns None when no member has a serial — translate falls through to single-Device path."""
    assert to_payload([ChassisMember(id=1, serial="")]) is None
    assert to_payload([]) is None


def test_to_payload_preserves_domain():
    """The optional domain field round-trips into the payload dict."""
    members = [ChassisMember(id=1, serial="FOC1"), ChassisMember(id=2, serial="FOC2")]
    payload = to_payload(members, domain="vc-1")
    assert payload["domain"] == "vc-1"


@pytest.mark.parametrize(
    "ifname, expected",
    [
        # Cisco IOS canonical (the IOS driver canonicalizes Gi → GigabitEthernet)
        ("GigabitEthernet1/0/1",     1),
        ("GigabitEthernet2/0/12",    2),
        ("TenGigabitEthernet1/0/1",  1),
        ("TenGigabitEthernet3/1/0",  3),
        ("FortyGigabitEthernet2/0/1", 2),

        # Cisco short forms (defensive — drivers should canonicalize, but be tolerant)
        ("Gi1/0/1",                  1),
        ("Te2/0/1",                  2),

        # Cisco mGig families on Catalyst 9300/9400 stacks
        ("TwoGigabitEthernet1/0/1",  1),
        ("FiveGigabitEthernet2/0/3", 2),
        ("Tw1/0/1",                  1),
        ("Fi2/0/1",                  2),
        ("Twe3/0/1",                 3),

        # Subinterface — strip the .NNN suffix and resolve to the parent's member id
        ("GigabitEthernet1/0/1.100", 1),
        ("TenGigabitEthernet2/0/12.4094", 2),

        # Junos FPC-style — full coverage for batch-2 Junos VirtualChassis support.
        # The Junos canonical name format is "<media>-<fpc>/<pic>/<port>[.<unit>]" where
        # <fpc> is the Flexible PIC Concentrator slot — the stack member id.
        ("et-0/0/0",                 0),
        ("ge-1/0/0",                 1),
        ("xe-2/1/0",                 2),
        ("ge-1/0/0.0",               1),    # logical subinterface (default unit)
        ("ge-1/0/0.100",             1),    # tagged subinterface
        ("xe-2/1/0.4094",            2),    # max VLAN id
        ("et-0/0/0.0",               0),    # member 0 with subif (Junos FPC starts at 0)
        # Junos non-stack interfaces (must NOT be parsed as member ids):
        ("ae0",                      None),  # aggregated Ethernet (bundle)
        ("ae0.100",                  None),  # AE subinterface
        ("lo0",                      None),  # loopback
        ("lo0.0",                    None),  # loopback unit
        ("irb",                      None),  # Integrated Routing/Bridging (no member)
        ("irb.100",                  None),  # IRB unit (acts like SVI)
        ("vlan",                     None),
        ("vlan.50",                  None),
        ("me0",                      None),  # management
        ("me0.0",                    None),
        ("fxp0",                     None),  # mgmt (older Junos)

        # Aruba CX bare 3-tuple (batch 3 — AOS-CX VSF)
        ("1/1/1",                    1),
        ("2/1/12",                   2),

        # HP / H3C Comware expanded interface names (batch 4 — IRF).
        # The hp_comware driver expands `XGE1/0/49` → `Ten-GigabitEthernet1/0/49`
        # and similar; translate sees the hyphenated full forms.
        ("Ten-GigabitEthernet1/0/49", 1),
        ("Ten-GigabitEthernet2/0/49", 2),
        ("Twenty-FiveGigE1/0/1",     1),
        ("FortyGigE2/0/1",           2),
        ("FiftyGigE3/0/1",           3),
        ("TwoHundredGigE1/0/1",      1),
        ("FourHundredGigE4/0/1",     4),
        ("Ten-GigabitEthernet1/0/49.100", 1),    # subif
        # GigabitEthernet1/0/1 + HundredGigE3/0/1 are exercised by the
        # Cisco rows above; Comware uses the same canonical forms for those.
        # M-GigabitEthernet is the Comware management interface — no member id.
        ("M-GigabitEthernet0/0/0",   None),
        # Comware aggregations / SVIs (must NOT extract a member id):
        ("Bridge-Aggregation1",      None),
        ("Bridge-Aggregation99",     None),
        ("Route-Aggregation1",       None),
        ("Vlan-interface100",        None),
        ("Vlan-interface4094",       None),
        ("NULL0",                    None),

        # Huawei VRP (batch 6 — iStack):
        ("XGigabitEthernet1/0/49",   1),    # Huawei full-form 10G
        ("XGigabitEthernet2/0/1",    2),
        ("10GE1/0/1",                1),    # Huawei abbreviated speed-N-GE
        ("25GE2/0/1",                2),
        ("40GE3/0/1",                3),
        ("50GE1/0/1",                1),
        ("100GE2/0/1",               2),
        ("200GE1/0/1",               1),
        ("400GE4/0/1",               4),
        ("XGigabitEthernet1/0/49.100", 1),  # subif
        # Huawei aggregations / management interfaces — no member id:
        ("Eth-Trunk1",               None),
        ("Vlanif100",                None),

        # SVIs / loopback / tunnel / management — no embedded member id
        ("Vlan10",                   None),
        ("Vlan1",                    None),
        ("Loopback0",                None),
        ("Tunnel0",                  None),
        ("mgmt0",                    None),
        ("Management1",              None),

        # LAG / bundle members — explicitly NOT a stack member id
        # (Junos `ae0` is covered in the Junos non-stack section above.)
        ("Port-channel1",            None),
        ("Port-channel99",           None),
        ("Bundle-Ether1",            None),
        ("Trk1",                     None),
        ("lag1",                     None),

        # NX-OS FEX 3/4-tuple — must NOT extract 101 as a member id.
        # FEX is NX-OS-only and always uses bare Ethernet/Eth.
        ("Eth101/1/1",               None),
        ("Ethernet101/1/1",          None),
        ("Ethernet101/1/0/1",        None),
        ("Eth101/1/0/1",             None),

        # Cisco IOS 4-tuple — Catalyst 9400/9500 StackWise Virtual. The
        # leading integer is the switch (member) id, followed by
        # slot/subslot/port. The FEX reject pattern fires first on the
        # bare ``Ethernet``/``Eth`` prefixes (NX-OS-only) so all other
        # Cisco IOS prefixes are valid SVL — including ``Gi``/
        # ``GigabitEthernet`` for Cat 9500 SVL with 1G FRU uplinks.
        ("HundredGigE1/2/0/1",       1),
        ("HundredGigE2/3/0/24",      2),
        ("Hu1/2/0/1",                1),
        ("Hu2/3/0/24",               2),
        # Canonical long form — the canonicalizer expands Hu*/HundredGigE*
        # to HundredGigabitEthernet* on entry, so parse_member_id MUST
        # accept that spelling too or SVL uplinks lose member attribution.
        ("HundredGigabitEthernet1/2/0/1", 1),
        ("HundredGigabitEthernet2/3/0/24", 2),
        ("HundredGigabitEthernet1/0/1",   1),   # 3-tuple long form too
        ("HundredGigabitEthernet2/0/1.100", 2),
        ("FortyGigabitEthernet1/2/0/1",  1),
        ("Fo2/3/0/4",                2),
        ("TenGigabitEthernet1/2/0/1",    1),
        ("Te1/2/0/1",                1),
        ("HundredGigE1/2/0/1.100",   1),   # SVL subinterface
        ("Hu2/3/0/24.4094",          2),
        # Cat 9500 SVL with 1G FRU uplinks — bare Gi/GigabitEthernet 4-tuple
        # IS valid SVL (FEX never uses Gi prefix), leading digit is the
        # SVL switch id.
        ("GigabitEthernet1/2/0/43",  1),
        ("GigabitEthernet2/3/0/1",   2),
        ("Gi1/2/0/43",               1),
        ("Gi2/3/0/1",                2),
        ("GigabitEthernet2/3/0/1.100", 2),

        # ProCurve / ArubaOS-Switch port shorthand — deferred to batch 3, return None
        ("A1",                       None),
        ("B12",                      None),
        ("1",                        None),
        ("24",                       None),

        # Junk
        ("",                         None),
        ("not-an-interface",         None),
    ],
)
def test_parse_member_id(ifname, expected):
    """parse_member_id extracts the leading switch id for stack-style names; None otherwise."""
    assert parse_member_id(ifname) == expected
