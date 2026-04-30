"""Unit tests for batch-2 field mappers (vendor row → SwitchportInfo)."""

import pytest

from custom_napalm._vlan import classify_switchport
from custom_napalm.aruba_aoscx import (
    _aoscx_iface_to_switchport_info,
    _vlan_uri_to_vid,
)
from custom_napalm.aruba_osswitch import (
    _invert_vlan_port_rows,
    _osswitch_port_to_switchport_info,
)
from custom_napalm.cumulus_linux import _bridge_json_to_switchport_info
from custom_napalm.dell_sonic import _sonic_row_to_switchport_info
from custom_napalm.mellanox_mlnxos import _mlnx_row_to_switchport_info

# ----- Mellanox MLNX-OS -----------------------------------------------------


def test_mlnx_disabled_admin_returns_routed():
    """Disabled switchport classifies as routed."""
    info = _mlnx_row_to_switchport_info({"admin_mode": "disabled"})
    assert classify_switchport(info) == {"mode": "routed", "tagged": [], "untagged": None}


def test_mlnx_hybrid_collapses_to_trunk():
    """Hybrid mode collapses to trunk with native + tagged set."""
    row = {
        "admin_mode": "hybrid",
        "operational_mode": "hybrid",
        "native_vlan": "50",
        "hybrid_allowed_vlans": "100,200",
    }
    info = _mlnx_row_to_switchport_info(row)
    assert info.admin_mode == "trunk"
    assert info.native_vlan == 50
    assert info.allowed_vlans == [100, 200]


def test_mlnx_empty_allowed_yields_none():
    """Empty Allowed VLANs string maps to None (not wildcard)."""
    row = {"admin_mode": "trunk", "operational_mode": "trunk", "native_vlan": "1"}
    info = _mlnx_row_to_switchport_info(row)
    assert info.allowed_vlans is None


# ----- Dell SONiC -----------------------------------------------------------


def test_sonic_dash_untagged_yields_none():
    """Dash sentinel in untagged column maps to None native_vlan."""
    row = {"interface": "Eth0", "mode": "trunk", "untagged": "-", "tagged": "100"}
    info = _sonic_row_to_switchport_info(row)
    assert info.native_vlan is None
    assert info.allowed_vlans == [100]


def test_sonic_unknown_mode_routed():
    """Unrecognised mode value is treated as routed."""
    row = {"interface": "Eth0", "mode": "weird", "untagged": "1", "tagged": "-"}
    info = _sonic_row_to_switchport_info(row)
    assert info.enabled is False


def test_sonic_all_tagged_token_wildcard():
    """The literal 'all' token in tagged column is the SONiC wildcard."""
    row = {"interface": "Eth0", "mode": "trunk", "untagged": "-", "tagged": "all"}
    info = _sonic_row_to_switchport_info(row)
    assert info.allowed_vlans == "all"


def test_sonic_parse_drops_separator_rows():
    """Table separator rows (dashes with whitespace) must not become bogus interface entries."""
    from custom_napalm.dell_sonic import _parse_show_interface_switchport

    text = (
        "Interface     Mode    Untagged    Tagged\n"
        "---------     ----    --------    ------\n"
        "Ethernet0     access  10          -\n"
    )
    rows = _parse_show_interface_switchport(text)
    assert [r["interface"] for r in rows] == ["Ethernet0"]


# ----- Cumulus Linux --------------------------------------------------------


def test_cumulus_pvid_dedup_in_tagged():
    """A duplicate non-PVID row matching the PVID VID is deduped (still access)."""
    entry = {"ifname": "swp1", "vlans": [
        {"vlan": 10, "flags": ["PVID", "Egress Untagged"]},
        {"vlan": 10, "flags": []},
    ]}
    info = _bridge_json_to_switchport_info(entry)
    assert info.admin_mode == "access"
    assert info.access_vlan == 10


def test_cumulus_no_pvid_with_tagged_yields_trunk_no_native():
    """Tagged-only ports (no PVID) map to trunk with no native VID."""
    entry = {"ifname": "swp1", "vlans": [
        {"vlan": 100, "flags": []},
        {"vlan": 200, "flags": []},
    ]}
    info = _bridge_json_to_switchport_info(entry)
    assert info.admin_mode == "trunk"
    assert info.native_vlan is None
    assert info.allowed_vlans == [100, 200]


def test_cumulus_empty_vlans_yields_routed():
    """An interface with empty vlans list is treated as routed."""
    info = _bridge_json_to_switchport_info({"ifname": "swp1", "vlans": []})
    assert info.enabled is False


def test_cumulus_bad_vid_skipped():
    """Non-numeric VID rows are silently dropped."""
    entry = {"ifname": "swp1", "vlans": [
        {"vlan": "junk", "flags": []},
        {"vlan": 100, "flags": []},
    ]}
    info = _bridge_json_to_switchport_info(entry)
    assert info.allowed_vlans == [100]


def test_cumulus_bool_vid_rejected():
    """Bool VID is rejected before int() coercion (bool is a subclass of int)."""
    entry = {"ifname": "swp1", "vlans": [
        {"vlan": True, "flags": ["PVID"]},
        {"vlan": 100, "flags": []},
    ]}
    info = _bridge_json_to_switchport_info(entry)
    # PVID with bool=True must NOT become PVID=1; only the valid 100 survives.
    assert info.access_vlan is None
    assert info.native_vlan is None
    assert info.allowed_vlans == [100]


# ----- AOS-CX ---------------------------------------------------------------


@pytest.mark.parametrize("value,expected", [
    ("/rest/v10.04/system/vlans/10", 10),
    ("/system/vlans/100", 100),
    (42, 42),
    ("99", 99),
    ("not-a-uri", None),
    (None, None),
    (True, None),
    ({"/rest/v10.04/system/vlans/10": "/rest/v10.04/system/vlans/10"}, 10),
    ({"/rest/v10.04/system/vlans/200": {"id": 200, "name": "FOO"}}, 200),
    ({}, None),
])
def test_aoscx_vlan_uri_parsing(value, expected):
    """URI/int/string/bool/dict-reference inputs all reduce to int VID or None."""
    assert _vlan_uri_to_vid(value) == expected


def test_aoscx_vlan_trunks_dict_shape():
    """vlan_trunks can arrive as a dict (pyaoscx depth>=1 reference shape)."""
    info = _aoscx_iface_to_switchport_info({
        "routing": False,
        "vlan_mode": "native-untagged",
        "vlan_tag": {"/rest/v10.04/system/vlans/99": "/rest/v10.04/system/vlans/99"},
        "vlan_trunks": {
            "/rest/v10.04/system/vlans/100": "/rest/v10.04/system/vlans/100",
            "/rest/v10.04/system/vlans/200": "/rest/v10.04/system/vlans/200",
        },
    })
    assert info.native_vlan == 99
    assert sorted(info.allowed_vlans) == [100, 200]


def test_aoscx_trunk_dict_with_entries_is_not_wildcard():
    """Non-empty vlan_trunks dict under vlan_mode=trunk emits explicit list, not trunk-all."""
    info = _aoscx_iface_to_switchport_info({
        "routing": False,
        "vlan_mode": "trunk",
        "vlan_tag": None,
        "vlan_trunks": {"/rest/v10.04/system/vlans/100": "/rest/v10.04/system/vlans/100"},
    })
    assert info.allowed_vlans == [100]


def test_aoscx_routing_true_yields_routed():
    """routing=True ⇒ routed regardless of vlan_mode."""
    info = _aoscx_iface_to_switchport_info({"routing": True, "vlan_mode": "access"})
    assert info.enabled is False


def test_aoscx_trunk_empty_trunks_is_wildcard():
    """vlan_mode=trunk with empty vlan_trunks list is the AOS-CX wildcard."""
    info = _aoscx_iface_to_switchport_info({
        "routing": False,
        "vlan_mode": "trunk",
        "vlan_tag": None,
        "vlan_trunks": [],
    })
    assert info.allowed_vlans == "all"


def test_aoscx_native_tagged_no_untagged():
    """native-tagged places the native VID in the tagged list with no untagged."""
    info = _aoscx_iface_to_switchport_info({
        "routing": False,
        "vlan_mode": "native-tagged",
        "vlan_tag": "/rest/v10.04/system/vlans/99",
        "vlan_trunks": ["/rest/v10.04/system/vlans/100"],
    })
    assert info.native_vlan is None
    assert info.allowed_vlans == [100, 99]


# ----- ArubaOS-Switch -------------------------------------------------------


def test_osswitch_invert_lowercase_pom():
    """Lowercase POM_* values are normalised case-insensitively."""
    rows = [{"vlan_id": 10, "port_id": "1", "port_mode": "pom_untagged"}]
    result = _invert_vlan_port_rows(rows)
    assert result["1"]["untagged"] == 10


def test_osswitch_invert_skips_bool_vid():
    """Bool VIDs are explicitly rejected (bool is a subclass of int)."""
    rows = [
        {"vlan_id": True, "port_id": "1", "port_mode": "POM_UNTAGGED"},
        {"vlan_id": 10, "port_id": "1", "port_mode": "POM_UNTAGGED"},
    ]
    result = _invert_vlan_port_rows(rows)
    assert result["1"]["untagged"] == 10


def test_osswitch_forbidden_only_routed():
    """A bucket with only forbidden VIDs and no membership classifies as routed."""
    bucket = {"untagged": None, "tagged": [], "forbidden": [1, 2]}
    info = _osswitch_port_to_switchport_info(bucket)
    assert info.enabled is False


def test_osswitch_unknown_port_mode_skipped():
    """Unknown port_mode values are silently dropped."""
    rows = [
        {"vlan_id": 10, "port_id": "1", "port_mode": "POM_NEW_FANGLED_THING"},
        {"vlan_id": 100, "port_id": "1", "port_mode": "POM_TAGGED"},
    ]
    result = _invert_vlan_port_rows(rows)
    assert result["1"]["tagged"] == [100]
    assert result["1"]["untagged"] is None
