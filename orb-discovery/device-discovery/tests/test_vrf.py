#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Unit tests for discovered-VRF translation (vrf.build_discovered_vrfs)."""

import logging

from device_discovery.policy.models import Defaults
from device_discovery.vrf import build_discovered_vrfs


def _instances():
    """Sample get_network_instances() payload in the NAPALM OC shape."""
    return {
        "default": {
            "name": "default",
            "type": "DEFAULT_INSTANCE",
            "state": {"route_distinguisher": ""},
            "interfaces": {"interface": {"Ethernet1": {}, "Ethernet2": {}}},
        },
        "MGMT": {
            "name": "MGMT",
            "type": "L3VRF",
            "state": {"route_distinguisher": "123:456"},
            "interfaces": {"interface": {"Management1": {}}},
        },
        "CUST-A": {
            "name": "CUST-A",
            "type": "L3VRF",
            "state": {"route_distinguisher": ""},
            "interfaces": {"interface": {"Ethernet3": {}, "Ethernet4": {}}},
        },
        "__Platform_iVRF:_ID00_": {
            "name": "__Platform_iVRF:_ID00_",
            "type": "L3VRF",
            "state": {"route_distinguisher": ""},
            "interfaces": {"interface": {"Loopback0": {}}},
        },
        "evpn-vsi": {
            "name": "evpn-vsi",
            "type": "L2VSI",
            "state": {"route_distinguisher": "65000:99"},
            "interfaces": {"interface": {"Ethernet5": {}}},
        },
    }


def test_filters_default_instance_l2_and_platform_internal():
    """Only L3VRF instances with operator-meaningful names survive."""
    vrfs, iface_map = build_discovered_vrfs(_instances(), Defaults())
    assert [v.name for v in vrfs] == ["CUST-A", "MGMT"]
    assert set(iface_map) == {"Management1", "Ethernet3", "Ethernet4"}
    assert iface_map["Management1"].name == "MGMT"
    assert iface_map["Ethernet3"].name == "CUST-A"
    assert iface_map["Ethernet4"].name == "CUST-A"


def test_rd_set_only_when_non_empty():
    """Empty RD stays off the wire; non-empty RD is carried."""
    vrfs, _ = build_discovered_vrfs(_instances(), Defaults())
    by_name = {v.name: v for v in vrfs}
    assert by_name["MGMT"].rd == "123:456"
    assert by_name["MGMT"].HasField("rd")
    assert not by_name["CUST-A"].HasField("rd")


def test_rd_whitespace_treated_as_empty():
    """A whitespace-only RD is treated like an absent one."""
    payload = {
        "X": {
            "name": "X",
            "type": "L3VRF",
            "state": {"route_distinguisher": "   "},
            "interfaces": {"interface": {}},
        },
    }
    vrfs, _ = build_discovered_vrfs(payload, Defaults())
    assert not vrfs[0].HasField("rd")


def test_rd_unset_sentinels_treated_as_absent():
    """
    Driver unset-RD sentinels stay off the wire.

    NX-OS stringifies a missing rd ("None"), its JSON API reports unset
    as "0:0", and raw CLI passthroughs show "<not set>".
    """
    for sentinel in ("None", "none", "0:0", "<not set>", "Not Set", None, 7):
        payload = {
            "X": {
                "name": "X",
                "type": "L3VRF",
                "state": {"route_distinguisher": sentinel},
            },
        }
        vrfs, _ = build_discovered_vrfs(payload, Defaults())
        assert not vrfs[0].HasField("rd"), f"rd sentinel {sentinel!r} leaked"


def test_untyped_default_table_names_skipped():
    """Untyped instances named default/global are treated as the global table."""
    payload = {
        "default": {"name": "default", "interfaces": {"interface": {"Eth1": {}}}},
        "GLOBAL": {"name": "GLOBAL"},
        "CUST": {"name": "CUST"},
    }
    vrfs, iface_map = build_discovered_vrfs(payload, Defaults())
    assert [v.name for v in vrfs] == ["CUST"]
    assert iface_map == {}


def test_explicit_l3vrf_type_overrides_default_name_guard():
    """An instance the driver explicitly types L3VRF survives even if named default."""
    payload = {"default": {"name": "default", "type": "L3VRF"}}
    vrfs, _ = build_discovered_vrfs(payload, Defaults())
    assert [v.name for v in vrfs] == ["default"]


def test_junos_virtual_router_type_accepted():
    """Junos virtual-router instances (e.g. mgmt_junos) translate to VRFs."""
    payload = {
        "mgmt_junos": {
            "name": "mgmt_junos",
            "type": "virtual-router",
            "state": {"route_distinguisher": ""},
            "interfaces": {"interface": {"fxp0.0": {}}},
        },
    }
    vrfs, iface_map = build_discovered_vrfs(payload, Defaults())
    assert [v.name for v in vrfs] == ["mgmt_junos"]
    assert iface_map["fxp0.0"].name == "mgmt_junos"


def test_non_string_type_skipped_without_crash():
    """A non-string (unhashable) type skips the instance instead of raising."""
    payload = {
        "BAD": {"name": "BAD", "type": {"oc": "L3VRF"}},
        "ALSO-BAD": {"name": "ALSO-BAD", "type": 7},
        "GOOD": {"name": "GOOD", "type": "L3VRF"},
    }
    vrfs, _ = build_discovered_vrfs(payload, Defaults())
    assert [v.name for v in vrfs] == ["GOOD"]


def test_duplicate_names_first_wins_and_map_stays_consistent(caplog):
    """Duplicate resolved names warn; the iface map points at the emitted VRF."""
    payload = {
        "A": {
            "name": "X",
            "type": "L3VRF",
            "state": {"route_distinguisher": "1:1"},
            "interfaces": {"interface": {"Eth1": {}}},
        },
        "B": {
            "name": "X",
            "type": "L3VRF",
            "state": {"route_distinguisher": "2:2"},
            "interfaces": {"interface": {"Eth2": {}}},
        },
    }
    with caplog.at_level(logging.WARNING, logger="device_discovery.vrf"):
        vrfs, iface_map = build_discovered_vrfs(payload, Defaults())
    assert len(vrfs) == 1
    assert vrfs[0].rd == "1:1"
    assert iface_map["Eth1"].rd == "1:1"
    assert iface_map["Eth2"].rd == "1:1"
    assert any("Duplicate network instance name" in r.message for r in caplog.records)


def test_missing_type_is_accepted():
    """Instances without a type (custom drivers) still produce a VRF."""
    payload = {"PLAIN": {"name": "PLAIN", "interfaces": {"interface": {"Vlan10": {}}}}}
    vrfs, iface_map = build_discovered_vrfs(payload, Defaults())
    assert [v.name for v in vrfs] == ["PLAIN"]
    assert iface_map["Vlan10"].name == "PLAIN"


def test_name_falls_back_to_dict_key():
    """When the instance omits its name, the payload key is used."""
    payload = {"KEYED": {"type": "L3VRF", "interfaces": {"interface": {}}}}
    vrfs, _ = build_discovered_vrfs(payload, Defaults())
    assert vrfs[0].name == "KEYED"


def test_defaults_tags_applied():
    """Top-level defaults.tags land on discovered VRFs."""
    vrfs, _ = build_discovered_vrfs(_instances(), Defaults(tags=["orb"]))
    assert all([t.name for t in v.tags] == ["orb"] for v in vrfs)


def test_empty_or_none_payload():
    """None / empty payloads produce no VRFs and no map."""
    assert build_discovered_vrfs(None, Defaults()) == ([], {})
    assert build_discovered_vrfs({}, Defaults()) == ([], {})


def test_non_dict_payload_warns_and_skips(caplog):
    """A non-dict payload is skipped with a warning, not a crash."""
    with caplog.at_level(logging.WARNING, logger="device_discovery.vrf"):
        vrfs, iface_map = build_discovered_vrfs(["bogus"], Defaults())
    assert vrfs == [] and iface_map == {}
    assert any("not a dict" in r.message for r in caplog.records)


def test_non_dict_instance_warns_and_skips(caplog):
    """A malformed single instance is skipped; the rest still translate."""
    payload = {"BAD": "oops", "GOOD": {"name": "GOOD", "type": "L3VRF"}}
    with caplog.at_level(logging.WARNING, logger="device_discovery.vrf"):
        vrfs, _ = build_discovered_vrfs(payload, Defaults())
    assert [v.name for v in vrfs] == ["GOOD"]
    assert any("skipping instance" in r.message for r in caplog.records)


def test_malformed_state_and_interfaces_tolerated():
    """Non-dict state / interfaces shapes degrade to no-rd / no-map."""
    payload = {
        "X": {"name": "X", "type": "L3VRF", "state": "bogus", "interfaces": "bogus"},
    }
    vrfs, iface_map = build_discovered_vrfs(payload, Defaults())
    assert vrfs[0].name == "X"
    assert not vrfs[0].HasField("rd")
    assert iface_map == {}


def test_output_order_is_deterministic():
    """VRFs are emitted sorted by name regardless of payload order."""
    payload = {
        "zeta": {"name": "zeta", "type": "L3VRF"},
        "alpha": {"name": "alpha", "type": "L3VRF"},
    }
    vrfs, _ = build_discovered_vrfs(payload, Defaults())
    assert [v.name for v in vrfs] == ["alpha", "zeta"]
