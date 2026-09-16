#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""NetBox Labs - Junos Virtual Address Suppression Unit Tests."""

import logging

import pytest
from lxml import etree

from custom_napalm import junos as junos_mod
from custom_napalm.junos import (
    _is_virtual_address_tag,
    _normalise_ip,
    _suppress_virtual,
    _virtual_addresses_from_reply,
)

REPLY = (
    "<vrrp-information><vrrp-interface><interface>ae0.100</interface>"
    "<group>1</group><virtual-ip-address>192.0.2.1</virtual-ip-address>"
    "</vrrp-interface></vrrp-information>"
)


@pytest.fixture(autouse=True)
def _clear_seen_tags():
    """Clear the module-level seen-tags set around every test."""
    junos_mod._UNEXPECTED_TAGS_SEEN.clear()
    yield
    junos_mod._UNEXPECTED_TAGS_SEEN.clear()


def test_loopback_addresses_survive():
    """
    Junos reports every loopback address without a mask too.

    They are not virtual, so nothing about them is suppressed. Keying on the
    missing mask would have deleted the router loopback fleet-wide.
    """
    interfaces_ip = {"lo0.0": {"ipv4": {
        "198.51.100.1": {"prefix_length": 32},
        "203.0.113.1": {"prefix_length": 32},
    }}}
    result, dropped = _suppress_virtual(interfaces_ip, {})
    assert sorted(result["lo0.0"]["ipv4"]) == ["198.51.100.1", "203.0.113.1"]
    assert dropped == []


def test_deliberate_host_address_inside_a_sibling_subnet_survives():
    """
    An anycast or service /32 alongside its gateway is not virtual.

    This is the case that disqualified keying on "covered by a sibling subnet":
    the device reports it exactly like a virtual address.
    """
    interfaces_ip = {"irb.100": {"ipv4": {
        "198.51.100.10": {"prefix_length": 24},
        "198.51.100.250": {"prefix_length": 32},
    }}}
    result, dropped = _suppress_virtual(interfaces_ip, {})
    assert sorted(result["irb.100"]["ipv4"]) == ["198.51.100.10", "198.51.100.250"]
    assert dropped == []


def test_virtual_address_the_device_masked_is_still_suppressed():
    """Suppression keys on the device calling it virtual, not on the mask."""
    interfaces_ip = {"ae0.100": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}}
    _, dropped = _suppress_virtual(interfaces_ip, {("ae0.100", "192.0.2.1"): "1"})
    assert len(dropped) == 1


def test_virtual_address_equal_to_the_subnet_router_anycast_is_suppressed():
    """A VRRPv3 VIP can be the all-zeros host of the prefix."""
    interfaces_ip = {"ae0.100": {"ipv6": {
        "2001:db8::": {"prefix_length": 128},
        "2001:db8::3": {"prefix_length": 64},
    }}}
    _, dropped = _suppress_virtual(interfaces_ip, {("ae0.100", "2001:db8::"): "7"})
    assert [d[1] for d in dropped] == ["2001:db8::"]


def test_virtual_address_on_another_interface_is_not_suppressed():
    """The match is per interface, not global."""
    interfaces_ip = {"ae0.200": {"ipv4": {"192.0.2.1": {"prefix_length": 32}}}}
    _, dropped = _suppress_virtual(interfaces_ip, {("ae0.100", "192.0.2.1"): "1"})
    assert dropped == []


def test_reported_shape_drops_only_the_vip():
    """The VIP goes; the real address keeps its own mask."""
    interfaces_ip = {"ae0.100": {"ipv4": {
        "192.0.2.1": {"prefix_length": 32},
        "192.0.2.3": {"prefix_length": 24},
    }}}
    result, dropped = _suppress_virtual(
        interfaces_ip, {("ae0.100", "192.0.2.1"): "1"}
    )
    assert list(result["ae0.100"]["ipv4"]) == ["192.0.2.3"]
    assert result["ae0.100"]["ipv4"]["192.0.2.3"]["prefix_length"] == 24
    assert dropped == [("ae0.100", "192.0.2.1", "1")]


def test_suppression_never_removes_a_family_or_interface_key():
    """
    An interface known only through interfaces_ip must not vanish.

    Interface entities are created for names present only there, so dropping a
    key would drop the interface.
    """
    interfaces_ip = {"ae0.100": {"ipv4": {"192.0.2.1": {"prefix_length": 32}}}}
    result, _ = _suppress_virtual(interfaces_ip, {("ae0.100", "192.0.2.1"): "1"})
    assert "ae0.100" in result and "ipv4" in result["ae0.100"]
    assert result["ae0.100"]["ipv4"] == {}


def test_suppression_does_not_rely_on_napalm_compressing_its_keys():
    """
    Do not rely on napalm compressing its own keys.

    Napalm compresses today; this must not silently break if it stops. The key
    here is deliberately un-compressed, which its helper would never produce, so
    it exercises the normalisation inside _suppress_virtual.
    """
    interfaces_ip = {"ae0.100": {"ipv6": {"2001:0db8:0001::1": {"prefix_length": 128}}}}
    _, dropped = _suppress_virtual(interfaces_ip, {("ae0.100", "2001:db8:1::1"): "7"})
    assert [d[1] for d in dropped] == ["2001:0db8:0001::1"]


def test_virtual_address_is_parsed():
    """The reported shape yields one (interface, address) pair."""
    assert _virtual_addresses_from_reply(etree.fromstring(REPLY)) == {
        ("ae0.100", "192.0.2.1"): "1"
    }


def test_a_device_without_vrrp_yields_no_virtual_addresses():
    """
    PyEZ returns the boolean True, not an element, for this case.

    ignoreWarnDecorator strips the rpc-error, leaving an empty rpc-reply, after
    which Device.execute indexes its first child, raises IndexError and returns
    True. This is the common case, so it belongs on the normal path.
    """
    assert _virtual_addresses_from_reply(True) == {}
    assert _virtual_addresses_from_reply(None) == {}


def test_multi_re_wrapped_reply_is_handled():
    """
    show-vrrp.yang declares multi-routing-engine-results as an output case.

    No unwrapping step is needed because the parser walks every descendant, but
    that is worth pinning rather than assuming: an earlier revision added an
    unwrap helper for this and it turned out to be dead code.
    """
    reply = etree.fromstring(
        "<multi-routing-engine-results><multi-routing-engine-item>"
        "<re-name>fpc0</re-name><vrrp-information><vrrp-interface>"
        "<interface>ae0.100</interface><group>1</group>"
        "<virtual-ip-address>192.0.2.1</virtual-ip-address>"
        "</vrrp-interface></vrrp-information>"
        "</multi-routing-engine-item></multi-routing-engine-results>"
    )
    assert _virtual_addresses_from_reply(reply) == {("ae0.100", "192.0.2.1"): "1"}


@pytest.mark.parametrize(
    "tag",
    ["virtual-ip-address", "virtual-inet6-address", "virtual-address", "vip"],
)
def test_the_virtual_address_element_is_matched_by_shape(tag):
    """
    The element name is not corroborated by any source, so match its shape.

    Local name containing "virtual" and ending in "address", or exactly "vip",
    with text that parses as an IP.
    """
    reply = etree.fromstring(
        f"<vrrp-information><vrrp-interface><interface>ae0.100</interface>"
        f"<group>1</group><{tag}>192.0.2.1</{tag}></vrrp-interface></vrrp-information>"
    )
    assert _virtual_addresses_from_reply(reply) == {("ae0.100", "192.0.2.1"): "1"}


def test_an_unexpected_element_name_is_logged(caplog):
    """
    A match on an unexpected element name must be visible, not silent.

    The case it uniquely catches is a match on an address napalm never reported:
    nothing is suppressed then, so the suppression line never fires and a wrong
    match would leave no trace at all.
    """
    reply = etree.fromstring(
        "<vrrp-information><vrrp-interface><interface>ae0.100</interface>"
        "<group>1</group><virtual-address>10.0.0.1</virtual-address>"
        "</vrrp-interface></vrrp-information>"
    )
    with caplog.at_level(logging.INFO):
        _virtual_addresses_from_reply(reply)
    assert "virtual-address" in " ".join(r.getMessage() for r in caplog.records)


def test_the_expected_element_name_logs_nothing(caplog):
    """The common case must not emit a line per virtual address."""
    with caplog.at_level(logging.INFO):
        _virtual_addresses_from_reply(etree.fromstring(REPLY))
    assert [r for r in caplog.records if "unexpected" in r.getMessage()] == []


def test_an_unexpected_element_name_is_logged_once(caplog):
    """
    Repeats of the same name log once per process, not once per address.

    The expected name is uncorroborated, so on a device using a different one an
    unbounded line would be permanent noise.
    """
    reply = etree.fromstring(
        "<vrrp-information><vrrp-interface><interface>ae0.100</interface>"
        "<group>1</group><virtual-address>10.0.0.1</virtual-address>"
        "<virtual-address>10.0.0.2</virtual-address>"
        "</vrrp-interface></vrrp-information>"
    )
    with caplog.at_level(logging.INFO):
        _virtual_addresses_from_reply(reply)
    assert len([r for r in caplog.records if "unexpected" in r.getMessage()]) == 1


def test_local_and_master_addresses_are_never_collected():
    """
    VRRP output also carries the local and master addresses.

    Collecting either would suppress the interface's own real address.
    """
    reply = etree.fromstring(
        "<vrrp-information><vrrp-interface><interface>ae0.100</interface>"
        "<group>1</group><lcl>192.0.2.3</lcl><mas>192.0.2.2</mas>"
        "<virtual-ip-address>192.0.2.1</virtual-ip-address>"
        "</vrrp-interface></vrrp-information>"
    )
    assert _virtual_addresses_from_reply(reply) == {("ae0.100", "192.0.2.1"): "1"}


def test_a_comment_in_the_reply_does_not_break_the_parse():
    """
    element.iter() yields comments, whose tag is a callable.

    _localname raises ValueError on one, and ncclient's Junos transform copies
    comments through from real devices, so an unguarded walk is silently inert
    in production. A comment sits in both positions here because each walk sees
    only one of them.
    """
    reply = etree.fromstring(
        "<vrrp-information><!-- values are synthetic -->"
        "<vrrp-interface><interface>ae0.100</interface><group>1</group>"
        "<!-- the virtual address follows -->"
        "<virtual-ip-address>192.0.2.1</virtual-ip-address>"
        "</vrrp-interface></vrrp-information>"
    )
    assert ("ae0.100", "192.0.2.1") in _virtual_addresses_from_reply(reply)


def test_a_nested_entry_keeps_its_own_addresses():
    """
    An outer entry must not absorb an inner entry's addresses.

    Absorbing them would suppress an address on the wrong interface. The
    trailing address pins the ownership predicate against a plain break: iter()
    is document-order depth-first, so breaking at the nested entry would abandon
    this one too.
    """
    reply = etree.fromstring(
        "<vrrp-information><vrrp-interface><interface>ae0.100</interface>"
        "<group>1</group><virtual-ip-address>10.0.0.1</virtual-ip-address>"
        "<vrrp-interface><interface>ae0.200</interface><group>2</group>"
        "<virtual-ip-address>10.0.0.2</virtual-ip-address></vrrp-interface>"
        "<virtual-ip-address>10.0.0.3</virtual-ip-address>"
        "</vrrp-interface></vrrp-information>"
    )
    got = _virtual_addresses_from_reply(reply)
    assert ("ae0.100", "10.0.0.2") not in got, "outer entry absorbed an inner address"
    assert set(got) == {
        ("ae0.100", "10.0.0.1"),
        ("ae0.100", "10.0.0.3"),
        ("ae0.200", "10.0.0.2"),
    }


def test_a_group_in_its_own_container_is_still_attributed():
    """
    The group can sit above the address rather than beside the interface.

    A direct-child lookup on the entry would report every group as unknown,
    making the log line useless on that shape.
    """
    reply = etree.fromstring(
        "<vrrp-information><vrrp-interface><interface>ae0.100</interface>"
        "<vrrp-group><group>7</group>"
        "<virtual-ip-address>10.0.0.1</virtual-ip-address></vrrp-group>"
        "</vrrp-interface></vrrp-information>"
    )
    assert _virtual_addresses_from_reply(reply)[("ae0.100", "10.0.0.1")] == "7"


def test_physical_interface_and_unit_are_joined():
    """
    VRRP output can report the interface and its unit separately.

    A key of "ae0" could never match napalm's "ae0.100".
    """
    reply = etree.fromstring(
        "<vrrp-information><vrrp-interface><interface>ge-0/0/2</interface>"
        "<unit>0</unit><group>1</group>"
        "<virtual-ip-address>10.0.0.1</virtual-ip-address>"
        "</vrrp-interface></vrrp-information>"
    )
    assert _virtual_addresses_from_reply(reply) == {("ge-0/0/2.0", "10.0.0.1"): "1"}


def test_a_virtual_address_carrying_a_mask_still_matches():
    """Napalm keys are bare addresses, so any mask must be stripped."""
    reply = etree.fromstring(
        "<vrrp-information><vrrp-interface><interface>ae0.100</interface>"
        "<group>1</group><virtual-ip-address>192.0.2.1/24</virtual-ip-address>"
        "</vrrp-interface></vrrp-information>"
    )
    assert _virtual_addresses_from_reply(reply) == {("ae0.100", "192.0.2.1"): "1"}


def test_an_uncompressed_ipv6_virtual_address_is_normalised():
    """The parser side must normalise too, not just the suppression side."""
    reply = etree.fromstring(
        "<vrrp-information><vrrp-interface><interface>ae0.100</interface>"
        "<group>7</group>"
        "<virtual-inet6-address>2001:0db8:0001::0001</virtual-inet6-address>"
        "</vrrp-interface></vrrp-information>"
    )
    assert _virtual_addresses_from_reply(reply) == {("ae0.100", "2001:db8:1::1"): "7"}


def test_parse_handles_multiple_groups_on_one_interface():
    """Two groups on one ifl contribute two addresses."""
    reply = etree.fromstring(
        "<vrrp-information>"
        "<vrrp-interface><interface>ae0.100</interface><group>1</group>"
        "<virtual-ip-address>192.0.2.1</virtual-ip-address></vrrp-interface>"
        "<vrrp-interface><interface>ae0.100</interface><group>2</group>"
        "<virtual-ip-address>192.0.2.9</virtual-ip-address></vrrp-interface>"
        "</vrrp-information>"
    )
    assert _virtual_addresses_from_reply(reply) == {
        ("ae0.100", "192.0.2.1"): "1",
        ("ae0.100", "192.0.2.9"): "2",
    }


def test_parse_skips_an_entry_with_no_interface_or_no_address():
    """Malformed entries are ignored rather than raising."""
    reply = etree.fromstring(
        "<vrrp-information>"
        "<vrrp-interface><group>1</group>"
        "<virtual-ip-address>10.0.0.1</virtual-ip-address></vrrp-interface>"
        "<vrrp-interface><interface>ae0.200</interface><group>2</group>"
        "</vrrp-interface></vrrp-information>"
    )
    assert _virtual_addresses_from_reply(reply) == {}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2001:0db8:0001::1", "2001:db8:1::1"),
        ("10.0.0.1", "10.0.0.1"),
        ("192.0.2.1/24", "192.0.2.1"),
        ("not-an-ip", "not-an-ip"),
    ],
)
def test_normalise_ip(raw, expected):
    """IPv6 is compressed, a mask is stripped, unparseable input passes through."""
    assert _normalise_ip(raw) == expected


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("virtual-ip-address", True),
        ("virtual-inet6-address", True),
        ("vip", True),
        ("lcl", False),
        ("mas", False),
        ("interface-address", False),
    ],
)
def test_is_virtual_address_tag(name, expected):
    """Match by shape, without collecting the local or master address."""
    assert _is_virtual_address_tag(name) is expected


def test_driver_suppresses_the_virtual_address(monkeypatch, caplog):
    """End to end through the override: the VIP goes, the real address stays."""
    from custom_napalm.junos import JunOSDriver

    driver = JunOSDriver.__new__(JunOSDriver)
    upstream = {"ae0.100": {"ipv4": {
        "192.0.2.1": {"prefix_length": 32},
        "192.0.2.3": {"prefix_length": 24},
    }}}
    monkeypatch.setattr(
        "napalm.junos.junos.JunOSDriver.get_interfaces_ip", lambda self: upstream
    )
    monkeypatch.setattr(
        JunOSDriver, "_virtual_addresses",
        lambda self: {("ae0.100", "192.0.2.1"): "1"},
    )
    with caplog.at_level(logging.INFO):
        result = driver.get_interfaces_ip()
    assert list(result["ae0.100"]["ipv4"]) == ["192.0.2.3"]
    joined = " ".join(r.getMessage() for r in caplog.records)
    assert "192.0.2.1" in joined and "ae0.100" in joined


def test_driver_returns_upstream_unchanged_when_the_probe_raises(monkeypatch):
    """
    A probe failure must never make IP discovery worse than not having this.

    Compared against a deepcopy: asserting against the same object would pass
    even if the implementation had emptied it.
    """
    import copy

    from custom_napalm.junos import JunOSDriver

    driver = JunOSDriver.__new__(JunOSDriver)
    upstream = {"ae0.100": {"ipv4": {"192.0.2.1": {"prefix_length": 32}}}}
    expected = copy.deepcopy(upstream)
    monkeypatch.setattr(
        "napalm.junos.junos.JunOSDriver.get_interfaces_ip", lambda self: upstream
    )

    def boom(self):
        raise RuntimeError("rpc exploded")

    monkeypatch.setattr(JunOSDriver, "_virtual_addresses", boom)
    assert driver.get_interfaces_ip() == expected


def test_probe_passes_ignore_warning_for_a_device_without_vrrp():
    """
    A device with no VRRP answers with a warning, not data.

    PyEZ documents ignore_warning for this RPC family; without it the call
    raises and suppression silently never happens.
    """
    from custom_napalm.junos import JunOSDriver

    seen = {}

    class FakeRpc:
        def get_vrrp_information(self, **kwargs):
            seen.update(kwargs)
            # PyEZ returns the boolean True for a device with no VRRP:
            # ignoreWarnDecorator strips the rpc-error, leaving an empty
            # rpc-reply, and Device.execute then returns True.
            return True

    class FakeDevice:
        rpc = FakeRpc()

    driver = JunOSDriver.__new__(JunOSDriver)
    driver.device = FakeDevice()
    assert driver._virtual_addresses() == {}
    assert "ignore_warning" in seen


def test_a_typed_row_carries_the_virtual_address():
    """
    The role can be a sibling value beside a generic address element.

    Junos output distinguishes vip, lcl and mas as row types, and in XML that
    can be a value rather than the element name. On this shape a name-only
    match collects nothing and the virtual address keeps being emitted.
    """
    reply = etree.fromstring(
        "<vrrp-information><vrrp-interface>"
        "<interface>ae0.100</interface><group>1</group>"
        "<vrrp-address-info>"
        "<address-type>vip</address-type><address>192.0.2.1</address>"
        "</vrrp-address-info>"
        "</vrrp-interface></vrrp-information>"
    )
    assert _virtual_addresses_from_reply(reply) == {("ae0.100", "192.0.2.1"): "1"}


def test_typed_rows_for_local_and_master_are_not_collected():
    """
    Only the vip row may be suppressed.

    The lcl row is this router's own interface address and the mas row is the
    peer's. Collecting either would delete a real address from NetBox.
    """
    reply = etree.fromstring(
        "<vrrp-information><vrrp-interface>"
        "<interface>ae0.100</interface><group>1</group>"
        "<vrrp-address-info>"
        "<address-type>lcl</address-type><address>192.0.2.3</address>"
        "</vrrp-address-info>"
        "<vrrp-address-info>"
        "<address-type>mas</address-type><address>192.0.2.2</address>"
        "</vrrp-address-info>"
        "<vrrp-address-info>"
        "<address-type>vip</address-type><address>192.0.2.1</address>"
        "</vrrp-address-info>"
        "</vrrp-interface></vrrp-information>"
    )
    assert _virtual_addresses_from_reply(reply) == {("ae0.100", "192.0.2.1"): "1"}


def test_an_explicit_real_role_beats_a_matching_element_name():
    """
    A row declaring itself lcl is never collected, whatever it is called.

    Belt and braces: if a reply both names the element like a virtual address
    and declares the role as local, the declared role wins, because collecting
    it would remove a real address.
    """
    reply = etree.fromstring(
        "<vrrp-information><vrrp-interface>"
        "<interface>ae0.100</interface><group>1</group>"
        "<vrrp-address-info>"
        "<address-type>lcl</address-type>"
        "<virtual-ip-address>192.0.2.3</virtual-ip-address>"
        "</vrrp-address-info>"
        "</vrrp-interface></vrrp-information>"
    )
    assert _virtual_addresses_from_reply(reply) == {}


def test_a_generic_address_with_no_role_is_not_collected():
    """
    Without a role or a matching name there is no evidence it is virtual.

    An interface-address element on its own must not be suppressed; guessing
    here is what would delete real addresses.
    """
    reply = etree.fromstring(
        "<vrrp-information><vrrp-interface>"
        "<interface>ae0.100</interface><group>1</group>"
        "<interface-address>192.0.2.3</interface-address>"
        "</vrrp-interface></vrrp-information>"
    )
    assert _virtual_addresses_from_reply(reply) == {}


FLAT_ROWS = """
<vrrp-information><vrrp-interface>
  <interface>ae0.100</interface><group>1</group>
  <address-type>{first_type}</address-type><address>{first_addr}</address>
  <address-type>{second_type}</address-type><address>{second_addr}</address>
  <address-type>{third_type}</address-type><address>{third_addr}</address>
</vrrp-interface></vrrp-information>
"""


@pytest.mark.parametrize(
    "order",
    [
        ("lcl", "192.0.2.3", "mas", "192.0.2.2", "vip", "192.0.2.1"),
        ("vip", "192.0.2.1", "lcl", "192.0.2.3", "mas", "192.0.2.2"),
        ("mas", "192.0.2.2", "vip", "192.0.2.1", "lcl", "192.0.2.3"),
    ],
)
def test_flat_typed_rows_pair_each_address_with_its_own_role(order):
    """
    A flat run of type/address pairs must pair positionally.

    Taking any role found among the siblings makes every address inherit
    whichever came first: with lcl first the virtual address is missed, and with
    vip first the interface's own address and the master's are suppressed too,
    which deletes real addresses. The role that applies is the one declared
    immediately before the address, whatever the ordering.
    """
    reply = etree.fromstring(
        FLAT_ROWS.format(
            first_type=order[0], first_addr=order[1],
            second_type=order[2], second_addr=order[3],
            third_type=order[4], third_addr=order[5],
        )
    )
    assert _virtual_addresses_from_reply(reply) == {("ae0.100", "192.0.2.1"): "1"}


def test_an_address_with_no_role_before_it_is_left_alone():
    """
    Only label-before-value is supported, and the fallback is to suppress nothing.

    A run of type/address pairs cannot be read in both directions at once, and
    the output this was derived from puts the label first. An address with no
    role declared before it is therefore not collected, which is the safe
    direction: nothing is suppressed and the deviation stays visible. Guessing
    the other ordering would attach a virtual role to a real address.
    """
    reply = etree.fromstring(
        "<vrrp-information><vrrp-interface>"
        "<interface>ae0.100</interface><group>1</group>"
        "<address>192.0.2.1</address><address-type>vip</address-type>"
        "</vrrp-interface></vrrp-information>"
    )
    assert _virtual_addresses_from_reply(reply) == {}


@pytest.mark.parametrize(
    "trailing",
    [
        "<local-interface-address>192.0.2.3</local-interface-address>",
        "<master-router-address>192.0.2.2</master-router-address>",
        "<vrrp-interface-address>192.0.2.3</vrrp-interface-address>",
    ],
)
def test_an_unrecognised_element_after_a_vip_row_does_not_inherit_the_role(trailing):
    """
    A role pairs with one recognised element and is then spent.

    Otherwise an element merely following a vip row inherits the role, and a
    substring test on the name made that concrete: local-interface-address
    matched, so the interface's own address was suppressed. A name not on the
    allowlist is left alone even directly after a vip pair.
    """
    reply = etree.fromstring(
        "<vrrp-information><vrrp-interface>"
        "<interface>ae0.100</interface><group>1</group>"
        "<address-type>vip</address-type><address>192.0.2.1</address>"
        f"{trailing}"
        "</vrrp-interface></vrrp-information>"
    )
    assert _virtual_addresses_from_reply(reply) == {("ae0.100", "192.0.2.1"): "1"}


def test_a_second_address_after_one_pair_is_left_alone():
    """
    The role is spent by the first value, so a second address is not collected.

    A group can legitimately carry several virtual addresses, and this makes
    that a false negative rather than a guess. Failing closed is the right
    direction here: the deviation stays visible, and no real address is removed.
    """
    reply = etree.fromstring(
        "<vrrp-information><vrrp-interface>"
        "<interface>ae0.100</interface><group>1</group>"
        "<address-type>vip</address-type>"
        "<address>192.0.2.1</address><address>192.0.2.9</address>"
        "</vrrp-interface></vrrp-information>"
    )
    assert _virtual_addresses_from_reply(reply) == {("ae0.100", "192.0.2.1"): "1"}


def test_an_unrecognised_element_cannot_consume_the_role():
    """
    Only an allowlisted name may take a role, not anything address-shaped.

    Ordering is what makes this distinct from spending the role: here the
    unrecognised element sits between the role and the real address. A
    substring test on the name would let it consume the vip role, suppressing
    the interface's own address and leaving the actual virtual address unroled.
    """
    reply = etree.fromstring(
        "<vrrp-information><vrrp-interface>"
        "<interface>ae0.100</interface><group>1</group>"
        "<address-type>vip</address-type>"
        "<local-interface-address>192.0.2.3</local-interface-address>"
        "<address>192.0.2.1</address>"
        "</vrrp-interface></vrrp-information>"
    )
    assert _virtual_addresses_from_reply(reply) == {("ae0.100", "192.0.2.1"): "1"}


def test_a_spent_role_does_not_veto_a_later_name_based_address():
    """
    A completed row must not carry its role forward.

    In a reply mixing both shapes, an earlier lcl row would otherwise veto a
    later virtual-ip-address and the virtual address would keep being emitted.
    That direction is only a missed suppression rather than lost data, but the
    row is genuinely finished once its value is taken.
    """
    reply = etree.fromstring(
        "<vrrp-information><vrrp-interface>"
        "<interface>ae0.100</interface><group>1</group>"
        "<address-type>lcl</address-type><address>192.0.2.3</address>"
        "<virtual-ip-address>192.0.2.1</virtual-ip-address>"
        "</vrrp-interface></vrrp-information>"
    )
    assert _virtual_addresses_from_reply(reply) == {("ae0.100", "192.0.2.1"): "1"}


@pytest.mark.parametrize(
    "reply_xml",
    [
        # Before <interface>: breaks the interface-name lookup.
        "<vrrp-information><vrrp-interface><!-- c -->"
        "<interface>ae0.100</interface><group>1</group>"
        "<virtual-ip-address>192.0.2.1</virtual-ip-address>"
        "</vrrp-interface></vrrp-information>",
        # Between <interface> and <group>: breaks the group lookup.
        "<vrrp-information><vrrp-interface>"
        "<interface>ae0.100</interface><!-- c --><group>1</group>"
        "<virtual-ip-address>192.0.2.1</virtual-ip-address>"
        "</vrrp-interface></vrrp-information>",
        # Around the unit, which is only consulted when the name has no dot.
        "<vrrp-information><vrrp-interface>"
        "<interface>ae0</interface><!-- c --><unit>100</unit><group>1</group>"
        "<virtual-ip-address>192.0.2.1</virtual-ip-address>"
        "</vrrp-interface></vrrp-information>",
    ],
)
def test_a_comment_before_the_metadata_does_not_break_the_parse(reply_xml):
    """
    The name and group lookups must tolerate comments too, not just the walks.

    A comment ahead of the element being looked up made the shared child lookup
    raise, the outer handler swallowed it, and the virtual address was emitted
    again. Comments only after the matched element never reached that path,
    which is why the earlier test missed it.
    """
    assert _virtual_addresses_from_reply(etree.fromstring(reply_xml)) == {
        ("ae0.100", "192.0.2.1"): "1"
    }
