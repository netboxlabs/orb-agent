"""Unit tests for batch-3 field mappers (vendor row → SwitchportInfo)."""

from custom_napalm.aruba_aoscx_ssh import (
    _aoscx_ssh_row_to_switchport_info,
    _parse_aoscx_show_vlan_port_config,
)
from custom_napalm.dell_ftos import (
    _ftos_row_to_switchport_info,
    _parse_ftos_show_interfaces_switchport,
)
from custom_napalm.extreme_exos import (
    _exos_merge_to_switchport_info,
    _parse_exos_show_ports_membership,
)
from custom_napalm.hp_comware import (
    _comware_merge_to_switchport_info,
    _expand_comware_iface,
    _parse_comware_display_vlan_all,
    _parse_comware_interface_brief_modes,
)
from custom_napalm.huawei_vrp import _huawei_row_to_switchport_info

# ----- Huawei VRP -----------------------------------------------------------


def test_huawei_lnp_link_type_inferred_from_membership():
    """LNP link-types (auto/desirable) infer mode from VLAN membership shape."""
    # No tagged VLANs → access on PVID
    info = _huawei_row_to_switchport_info(
        {"link_type": "desirable", "vlan_id": "1", "trunk_vlan_list": []}
    )
    assert info.admin_mode == "access"
    assert info.access_vlan == 1
    # Tagged VLANs present → trunk with PVID as native
    info = _huawei_row_to_switchport_info(
        {"link_type": "auto", "vlan_id": "99", "trunk_vlan_list": ["100", "200"]}
    )
    assert info.admin_mode == "trunk"
    assert info.native_vlan == 99
    assert info.allowed_vlans == [100, 200]


def test_huawei_dot1q_tunnel_classifies_as_access():
    """dot1q-tunnel L2 ports keep VLAN data — classified as access on PVID."""
    info = _huawei_row_to_switchport_info(
        {"link_type": "dot1q-tunnel", "vlan_id": "100", "trunk_vlan_list": []}
    )
    assert info.admin_mode == "access"
    assert info.access_vlan == 100


def test_huawei_unknown_link_type_routed():
    """Blank / genuinely unknown link-types still map to routed."""
    info = _huawei_row_to_switchport_info({"link_type": "", "vlan_id": "1"})
    assert info.enabled is False
    info = _huawei_row_to_switchport_info({"link_type": "weird-mode", "vlan_id": "1"})
    assert info.enabled is False


def test_huawei_hybrid_collapses_to_trunk():
    """Hybrid maps to trunk classification with PVID as native."""
    info = _huawei_row_to_switchport_info({
        "link_type": "hybrid",
        "vlan_id": "50",
        "trunk_vlan_list": ["100", "200"],
    })
    assert info.admin_mode == "trunk"
    assert info.native_vlan == 50
    assert info.allowed_vlans == [100, 200]


def test_huawei_full_range_is_wildcard():
    """The 1-4094 trunk range collapses to the wildcard."""
    info = _huawei_row_to_switchport_info({
        "link_type": "trunk",
        "vlan_id": "1",
        "trunk_vlan_list": ["1-4094"],
    })
    assert info.allowed_vlans == "all"


def test_huawei_bool_pvid_rejected():
    """Bool PVID is rejected before int() coercion (bool is a subclass of int)."""
    info = _huawei_row_to_switchport_info({
        "link_type": "access",
        "vlan_id": True,
        "trunk_vlan_list": [],
    })
    assert info.access_vlan is None


# ----- Dell FTOS ------------------------------------------------------------


def test_ftos_general_mode_trunk():
    """FTOS `general` mode classifies as trunk with native + tagged."""
    info = _ftos_row_to_switchport_info({
        "switchport": "Enabled",
        "administrative_mode": "general",
        "native_vlan": "99",
        "trunking_vlans_enabled": "100,200",
    })
    assert info.admin_mode == "trunk"
    assert info.native_vlan == 99
    assert info.allowed_vlans == [100, 200]


def test_ftos_switchport_disabled_routed():
    """Switchport=Disabled → routed regardless of other fields."""
    info = _ftos_row_to_switchport_info({"switchport": "Disabled"})
    assert info.enabled is False


def test_ftos_bool_vid_rejected():
    """Bool fields in access/native VLAN positions are rejected before int() coercion."""
    info = _ftos_row_to_switchport_info({
        "switchport": "Enabled",
        "administrative_mode": "trunk",
        "trunking_native_mode_vlan": True,
        "trunking_vlans_enabled": "100",
    })
    assert info.native_vlan is None
    assert info.allowed_vlans == [100]


def test_ftos_os9_hybrid_collapses_to_trunk():
    """OS9 802.1QTagged=Hybrid with native + tagged classifies as trunk."""
    info = _ftos_row_to_switchport_info({
        "switchport": "Enabled",
        "802.1qtagged": "Hybrid",
        "os9_untagged": ["20"],
        "os9_tagged": ["100,200,300"],
    })
    assert info.admin_mode == "trunk"
    assert info.native_vlan == 20
    assert info.allowed_vlans == [100, 200, 300]


def test_ftos_os9_false_yields_access():
    """OS9 802.1QTagged=False with one untagged VID classifies as access."""
    info = _ftos_row_to_switchport_info({
        "switchport": "Enabled",
        "802.1qtagged": "False",
        "os9_untagged": ["10"],
        "os9_tagged": [],
    })
    assert info.admin_mode == "access"
    assert info.access_vlan == 10


def test_ftos_os9_parser_captures_membership_block():
    """OS9 Vlan-membership block lines (`U`/`T`) populate os9_* lists."""
    text = (
        "\nName: GigabitEthernet 0/1\n"
        "802.1QTagged: Hybrid\n"
        "Vlan membership:\n"
        "Q Vlans\n"
        "U  20\n"
        "T  100,200\n"
    )
    rows = _parse_ftos_show_interfaces_switchport(text)
    assert rows[0]["802.1qtagged"] == "Hybrid"
    assert rows[0]["os9_untagged"] == ["20"]
    assert rows[0]["os9_tagged"] == ["100,200"]


def test_ftos_os9_vlan_token_form_hybrid_uses_native():
    """Alt OS9 form `Vlan <vid>` + Hybrid + Native VlanId resolves native + tagged."""
    info = _ftos_row_to_switchport_info({
        "switchport": "Enabled",
        "802.1qtagged": "Hybrid",
        "os9_untagged": [],
        "os9_tagged": [],
        "os9_vlans": [1, 100, 200],
        "native_vlanid": "1.",
    })
    assert info.admin_mode == "trunk"
    assert info.native_vlan == 1
    assert info.allowed_vlans == [100, 200]


def test_ftos_os9_vlan_token_form_true_all_tagged():
    """Alt OS9 form + 802.1QTagged=True puts every VID in the tagged list."""
    info = _ftos_row_to_switchport_info({
        "switchport": "Enabled",
        "802.1qtagged": "True",
        "os9_untagged": [],
        "os9_tagged": [],
        "os9_vlans": [100, 200, 300],
    })
    assert info.admin_mode == "trunk"
    assert info.native_vlan is None
    assert info.allowed_vlans == [100, 200, 300]


def test_ftos_os9_vlan_token_form_false_single_vlan_access():
    """Alt OS9 form + 802.1QTagged=False with one VID classifies as access."""
    info = _ftos_row_to_switchport_info({
        "switchport": "Enabled",
        "802.1qtagged": "False",
        "os9_untagged": [],
        "os9_tagged": [],
        "os9_vlans": [10],
    })
    assert info.admin_mode == "access"
    assert info.access_vlan == 10


def test_ftos_os9_parser_captures_vlan_token_form():
    """Parser captures `Vlan <vid>, Vlan <vid>` tokens into `os9_vlans`."""
    text = (
        "\nName: GigabitEthernet 0/3\n"
        "802.1QTagged: Hybrid\n"
        "Vlan membership:\n"
        "Vlan 1, Vlan 100, Vlan 200\n"
        "Native VlanId: 1.\n"
    )
    rows = _parse_ftos_show_interfaces_switchport(text)
    assert rows[0]["os9_vlans"] == [1, 100, 200]
    assert rows[0]["native_vlanid"] == "1."


def test_ftos_section_parser_handles_multiple_ports():
    """Section parser separates ports correctly on `Name:` header."""
    text = (
        "\nName: GigabitEthernet 0/1\n"
        "Switchport: Enabled\n"
        "Administrative mode: access\n"
        "Access Mode VLAN: 10\n"
        "\n"
        "Name: GigabitEthernet 0/2\n"
        "Switchport: Disabled\n"
    )
    rows = _parse_ftos_show_interfaces_switchport(text)
    assert [r["interface"] for r in rows] == [
        "GigabitEthernet 0/1",
        "GigabitEthernet 0/2",
    ]


# ----- AOS-CX SSH -----------------------------------------------------------


def test_aoscx_ssh_native_tagged_no_untagged():
    """native-tagged folds the native VID into the tagged list with no untagged."""
    info = _aoscx_ssh_row_to_switchport_info({
        "port": "1/1/1",
        "mode": "native-tagged",
        "native": "99",
        "tagged": "100, 200",
    })
    assert info.native_vlan is None
    assert info.allowed_vlans == [100, 200, 99]


def test_aoscx_ssh_trunk_empty_tagged_is_wildcard():
    """Empty tagged list under trunk mode is the AOS-CX wildcard."""
    info = _aoscx_ssh_row_to_switchport_info({
        "port": "1/1/1",
        "mode": "trunk",
        "native": "--",
        "tagged": "--",
    })
    assert info.allowed_vlans == "all"


def test_aoscx_ssh_routed_yields_routed():
    """Routed mode classifies as routed regardless of other columns."""
    info = _aoscx_ssh_row_to_switchport_info({
        "port": "1/1/1",
        "mode": "routed",
        "native": "--",
        "tagged": "--",
    })
    assert info.enabled is False


def test_aoscx_ssh_bool_native_rejected():
    """Bool native VID is rejected; coerce_vid handles the bool guard."""
    info = _aoscx_ssh_row_to_switchport_info({
        "port": "1/1/1",
        "mode": "access",
        "native": True,
        "tagged": "--",
    })
    assert info.access_vlan is None


def test_aoscx_ssh_parser_skips_separator_rows():
    """Table separator rows must not produce bogus port entries."""
    text = (
        "Port    Mode             Native VLAN   Tagged VLAN(s)\n"
        "-----   --------------   -----------   ------------------\n"
        "1/1/1   access           10            --\n"
    )
    rows = _parse_aoscx_show_vlan_port_config(text)
    assert [r["port"] for r in rows] == ["1/1/1"]


# ----- HP Comware -----------------------------------------------------------


def test_comware_iface_expand_known_prefixes():
    """Abbreviated interface names expand to the full form `display interface` emits."""
    assert _expand_comware_iface("GE1/0/1") == "GigabitEthernet1/0/1"
    assert _expand_comware_iface("XGE1/0/49") == "Ten-GigabitEthernet1/0/49"
    assert _expand_comware_iface("BAGG1") == "Bridge-Aggregation1"


def test_comware_iface_expand_digit_leading_prefixes():
    """Digit-leading abbreviations (25GE/40GE/100GE/...) expand correctly."""
    assert _expand_comware_iface("25GE1/0/1") == "Twenty-FiveGigE1/0/1"
    assert _expand_comware_iface("40GE1/0/1") == "FortyGigE1/0/1"
    assert _expand_comware_iface("100GE1/0/1") == "HundredGigE1/0/1"
    assert _expand_comware_iface("200GE1/0/1") == "TwoHundredGigE1/0/1"
    assert _expand_comware_iface("400GE1/0/1") == "FourHundredGigE1/0/1"


def test_comware_iface_expand_no_false_positives():
    """A prefix without a digit suffix (or non-matching) is returned unchanged."""
    # 'GEORGE' starts with 'GE' but the next char is a letter, not a digit.
    assert _expand_comware_iface("GEORGE") == "GEORGE"
    # 'GE' alone — nothing after the prefix.
    assert _expand_comware_iface("GE") == "GE"


def test_comware_iface_expand_passthrough():
    """Names already in full form (or unknown prefixes) are returned unchanged."""
    assert _expand_comware_iface("GigabitEthernet1/0/1") == "GigabitEthernet1/0/1"
    assert _expand_comware_iface("Loopback0") == "Loopback0"
    assert _expand_comware_iface("notaport") == "notaport"


def test_comware_brief_modes_expands_iface_names():
    """Brief-mode rows get their abbreviated names expanded in the modes dict."""
    rows = [{"interface": "GE1/0/1", "type": "A", "vlan_id": "10"}]
    modes = _parse_comware_interface_brief_modes(rows)
    assert "GigabitEthernet1/0/1" in modes
    assert "GE1/0/1" not in modes


def test_comware_bool_pvid_rejected():
    """Bool PVID is rejected before int() coercion (uses coerce_vid)."""
    rows = [{"interface": "GE1/0/1", "type": "A", "vlan_id": True}]
    modes = _parse_comware_interface_brief_modes(rows)
    assert modes["GigabitEthernet1/0/1"]["pvid"] is None


def test_comware_brief_modes_skip_route_rows():
    """Route-mode rows (no Type letter) are skipped from the modes dict."""
    rows = [
        {"interface": "GE1/0/1", "type": "A", "vlan_id": "10"},
        {"interface": "Vlan-interface1", "type": "", "vlan_id": ""},
    ]
    modes = _parse_comware_interface_brief_modes(rows)
    assert "GigabitEthernet1/0/1" in modes
    assert "Vlan-interface1" not in modes


def test_comware_route_mode_iface_routed():
    """An interface with no Type letter (route mode) classifies as routed."""
    info = _comware_merge_to_switchport_info("GE1/0/1", {}, {})
    assert info.enabled is False


def test_comware_hybrid_collapses_to_trunk():
    """Hybrid mode is treated as trunk with PVID as native."""
    modes = {"GE1/0/1": {"mode": "hybrid", "pvid": 50}}
    membership = {"GE1/0/1": {"tagged": [100, 200], "untagged": [50]}}
    info = _comware_merge_to_switchport_info("GE1/0/1", modes, membership)
    assert info.admin_mode == "trunk"
    assert info.native_vlan == 50
    assert info.allowed_vlans == [100, 200]


def test_comware_strips_port_status_suffix():
    """Comware members like `GE1/0/1(U)` get the link-state suffix stripped."""
    text = (
        " VLAN ID: 100\n"
        " Tagged Ports:\n"
        "   GE1/0/1(U), GE1/0/2(D)\n"
        " Untagged Ports:\n"
        "   None\n"
    )
    membership = _parse_comware_display_vlan_all(text)
    assert membership == {
        "GigabitEthernet1/0/1": {"tagged": [100], "untagged": []},
        "GigabitEthernet1/0/2": {"tagged": [100], "untagged": []},
    }


def test_comware_invert_vlan_all():
    """Inverter builds per-port membership from per-VLAN sections; expands abbrevs."""
    text = (
        " VLAN ID: 10\n"
        " Tagged Ports:\n"
        "   None\n"
        " Untagged Ports:\n"
        "   GE1/0/1\n"
        "\n"
        " VLAN ID: 100\n"
        " Tagged Ports:\n"
        "   GE1/0/2\n"
        " Untagged Ports:\n"
        "   None\n"
        "\n"
        " VLAN ID: 200\n"
        " Tagged Ports:\n"
        "   GE1/0/2\n"
        " Untagged Ports:\n"
        "   None\n"
    )
    membership = _parse_comware_display_vlan_all(text)
    assert membership == {
        "GigabitEthernet1/0/1": {"tagged": [], "untagged": [10]},
        "GigabitEthernet1/0/2": {"tagged": [100, 200], "untagged": []},
    }


# ----- Extreme EXOS ---------------------------------------------------------


def test_exos_parse_show_ports_membership():
    """`Internal Tag` and `802.1Q Tag` lines per port populate untagged/tagged."""
    text = (
        "Port:\t1\n"
        "\tVLAN cfg:\n"
        "\t\t Name: native, Internal Tag = 99, MAC-limit = No-limit\n"
        "\t\t Name: vlan100, 802.1Q Tag = 100, MAC-limit = No-limit\n"
        "\t\t Name: vlan200, 802.1Q Tag = 200, MAC-limit = No-limit\n"
    )
    membership = _parse_exos_show_ports_membership(text)
    assert membership == {"1": {"tagged": [100, 200], "untagged": [99]}}


def test_exos_parse_show_ports_handles_stacked_port_ids():
    """Stacked port notation `1:1` is preserved as-is."""
    text = (
        "Port:\t1:1\n"
        "\tVLAN cfg:\n"
        "\t\t Name: vlan10, Internal Tag = 10, MAC-limit = No-limit\n"
    )
    membership = _parse_exos_show_ports_membership(text)
    assert membership == {"1:1": {"tagged": [], "untagged": [10]}}


def test_exos_merge_no_untagged_yields_trunk_no_native():
    """Tagged-only port maps to trunk with no native."""
    info = _exos_merge_to_switchport_info({"tagged": [100, 200], "untagged": []})
    assert info.admin_mode == "trunk"
    assert info.native_vlan is None
    assert info.allowed_vlans == [100, 200]


def test_exos_merge_empty_membership_yields_routed():
    """A port with no membership classifies as routed."""
    info = _exos_merge_to_switchport_info({"tagged": [], "untagged": []})
    assert info.enabled is False
