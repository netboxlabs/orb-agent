"""Unit tests for batch-4 field mappers (vendor row → SwitchportInfo)."""

from custom_napalm.alcatel_aos import (
    _alcatel_aos_aggregate_vlan_port,
    _alcatel_aos_port_to_switchport_info,
)
from custom_napalm.brocade_fastiron import (
    _expand_fastiron_ports,
    _fastiron_aggregate_to_switchport,
)
from custom_napalm.dell_powerconnect import (
    _parse_pc_show_interfaces_switchport,
    _pc_row_to_switchport_info,
)
from custom_napalm.extreme_vsp import (
    _parse_vsp_port_vlans,
    _vsp_row_to_switchport_info,
)
from custom_napalm.hp_procurve import (
    _parse_procurve_vlan_detail,
    _procurve_aggregate_to_switchport,
)

# ----- Alcatel-Lucent AOS ---------------------------------------------------


def test_alcatel_aos_access_single_untagged():
    """Single untagged VLAN with no tagged → access on that VLAN."""
    info = _alcatel_aos_port_to_switchport_info({"untagged": [100], "tagged": []})
    assert info.admin_mode == "access"
    assert info.access_vlan == 100
    assert info.allowed_vlans is None


def test_alcatel_aos_trunk_with_native():
    """Untagged + qtagged rows merge into trunk with native + tagged list."""
    info = _alcatel_aos_port_to_switchport_info({"untagged": [10], "tagged": [20, 30]})
    assert info.admin_mode == "trunk"
    assert info.native_vlan == 10
    assert info.allowed_vlans == [20, 30]


def test_alcatel_aos_trunk_no_native():
    """qtagged-only port → trunk with no native VLAN."""
    info = _alcatel_aos_port_to_switchport_info({"untagged": [], "tagged": [100, 200]})
    assert info.admin_mode == "trunk"
    assert info.native_vlan is None
    assert info.allowed_vlans == [100, 200]


def test_alcatel_aos_aggregator_skips_forbidden_status():
    """STATUS=forbidden rows are excluded from the aggregated membership."""
    rows = [
        {"vlan_id": "10", "port": "1/1/1", "type": "untagged", "status": "forward"},
        {"vlan_id": "999", "port": "1/1/1", "type": "qtagged", "status": "forbidden"},
    ]
    aggregated = _alcatel_aos_aggregate_vlan_port(rows)
    assert aggregated == {"1/1/1": {"untagged": [10], "tagged": []}}


# ----- Brocade FastIron -----------------------------------------------------


def test_fastiron_expand_port_range():
    """`ethe 1/1/1 to 1/1/4` expands to four bare port IDs."""
    assert _expand_fastiron_ports("ethe 1/1/1 to 1/1/4") == [
        "1/1/1",
        "1/1/2",
        "1/1/3",
        "1/1/4",
    ]


def test_fastiron_expand_single_component_range():
    """
    Bare-digit ranges (CES/CER format) expand without a leading slash.

    Older FastIron CES/CER hardware uses single-component port IDs in
    ``show running-config vlan`` (e.g. ``ethe 1 to 4``). The expansion
    used to emit ``["/1", "/2", ...]`` because the prefix-builder
    unconditionally appended a slash; the fix preserves bare digits.
    """
    assert _expand_fastiron_ports("ethe 1 to 4") == ["1", "2", "3", "4"]
    assert _expand_fastiron_ports("ethe 2 ethe 11") == ["2", "11"]


def test_fastiron_expand_mixed_lag_and_ethe():
    """Mixed `ethe` + `lag` tokens are normalised; `lag N` becomes `lagN`."""
    assert _expand_fastiron_ports("ethe 1/1/1 lag 5 ethe 1/2/4:1") == [
        "1/1/1",
        "lag5",
        "1/2/4:1",
    ]


def test_fastiron_aggregate_dual_mode_is_trunk_with_native():
    """Untagged in one VLAN + tagged in others → trunk with the untagged as native."""
    info = _fastiron_aggregate_to_switchport({"untagged": 10, "tagged": [20, 30]})
    assert info.admin_mode == "trunk"
    assert info.native_vlan == 10
    assert info.allowed_vlans == [20, 30]


def test_fastiron_aggregate_tagged_only_no_native():
    """Tagged-only port maps to trunk with native=None."""
    info = _fastiron_aggregate_to_switchport({"untagged": None, "tagged": [100, 200]})
    assert info.admin_mode == "trunk"
    assert info.native_vlan is None
    assert info.allowed_vlans == [100, 200]


def test_fastiron_aggregate_empty_membership_yields_routed():
    """Port with no membership at all classifies as routed."""
    info = _fastiron_aggregate_to_switchport({"untagged": None, "tagged": []})
    assert info.enabled is False


# ----- HP ProCurve ----------------------------------------------------------


def test_procurve_aggregate_access_one_untagged():
    """One Untagged VID + no Tagged → access mode on that VID."""
    info = _procurve_aggregate_to_switchport({"untagged": 100, "tagged": []})
    assert info.enabled is True
    assert info.admin_mode == "access"
    assert info.access_vlan == 100
    assert info.allowed_vlans is None


def test_procurve_aggregate_trunk_with_native():
    """Untagged + Tagged → trunk with the untagged VID as native."""
    info = _procurve_aggregate_to_switchport({"untagged": 10, "tagged": [20, 30]})
    assert info.admin_mode == "trunk"
    assert info.native_vlan == 10
    assert info.allowed_vlans == [20, 30]


def test_procurve_aggregate_trunk_no_native_and_routed():
    """Tagged-only → trunk no native; empty membership → routed/disabled."""
    info = _procurve_aggregate_to_switchport({"untagged": None, "tagged": [100, 200]})
    assert info.admin_mode == "trunk"
    assert info.native_vlan is None
    assert info.allowed_vlans == [100, 200]

    info = _procurve_aggregate_to_switchport({"untagged": None, "tagged": []})
    assert info.enabled is False
    assert info.admin_mode is None


def test_procurve_parse_vlan_detail_skips_gvrp_and_forbid():
    """Only Tagged/Untagged rows are returned; GVRP/Forbid are dropped."""
    text = (
        " Status and Counters - VLAN Information - VLAN 10\n"
        "  Port Information  Mode      Unknown VLAN  Status\n"
        "  ----------------- --------- ------------- ----------\n"
        "  1                 Tagged    Learn         Up\n"
        "  2                 Untagged  Learn         Up\n"
        "  Trk1              GVRP      Learn         Down\n"
        "  3                 Forbid    Learn         Down\n"
    )
    assert _parse_procurve_vlan_detail(text) == [("1", "Tagged"), ("2", "Untagged")]


# ----- Dell PowerConnect ----------------------------------------------------


def test_pc_access_mode_yields_access_on_untagged_vid():
    """Access mode with one Untagged VID classifies as access."""
    info = _pc_row_to_switchport_info({
        "interface": "gi1/0/1",
        "port_mode": "Access",
        "default_vlan": "enabled",
        "untagged": [100],
        "tagged": [],
    })
    assert info.admin_mode == "access"
    assert info.access_vlan == 100


def test_pc_trunk_default_vlan_disabled_drops_native():
    """Trunk with `Default VLAN: disabled` strips the native VLAN."""
    info = _pc_row_to_switchport_info({
        "interface": "gi1/0/4",
        "port_mode": "Trunk",
        "default_vlan": "disabled",
        "untagged": [],
        "tagged": [100, 200],
    })
    assert info.admin_mode == "trunk"
    assert info.native_vlan is None
    assert info.allowed_vlans == [100, 200]


def test_pc_general_mode_collapses_to_trunk():
    """General mode collapses to trunk with native = Untagged VID."""
    info = _pc_row_to_switchport_info({
        "interface": "gi1/0/3",
        "port_mode": "General",
        "untagged": [10],
        "tagged": [20, 30],
    })
    assert info.admin_mode == "trunk"
    assert info.native_vlan == 10
    assert info.allowed_vlans == [20, 30]


def test_pc_unknown_mode_yields_routed():
    """Modes other than Access/Trunk/General classify as routed."""
    info = _pc_row_to_switchport_info({
        "interface": "gi1/0/9",
        "port_mode": "Layer3",
        "untagged": [],
        "tagged": [],
    })
    assert info.enabled is False


def test_pc_access_without_untagged_falls_back_to_routed():
    """Access mode + missing Untagged row → routed (avoid clobbering NetBox)."""
    info = _pc_row_to_switchport_info({
        "interface": "gi1/0/1",
        "port_mode": "Access",
        "default_vlan": "enabled",
        "untagged": [],
        "tagged": [],
    })
    assert info.enabled is False
    assert info.admin_mode is None


def test_pc_access_with_multiple_untagged_falls_back_to_routed():
    """Access mode + >1 Untagged row → routed (ambiguous; don't guess)."""
    info = _pc_row_to_switchport_info({
        "interface": "gi1/0/1",
        "port_mode": "Access",
        "default_vlan": "enabled",
        "untagged": [10, 20],
        "tagged": [],
    })
    assert info.enabled is False
    assert info.admin_mode is None


def test_pc_access_with_tagged_falls_back_to_routed():
    """Access mode + unexpected Tagged rows → routed (membership shape mismatch)."""
    info = _pc_row_to_switchport_info({
        "interface": "gi1/0/1",
        "port_mode": "Access",
        "default_vlan": "enabled",
        "untagged": [10],
        "tagged": [20],
    })
    assert info.enabled is False
    assert info.admin_mode is None


def test_pc_membership_ref_line_does_not_pollute_row():
    """
    Membership reference line must not become a generic Field key.

    For port names without slashes (Te1, Po10, etc.) the generic
    ``Field: Value`` regex used to match this line and add a spurious
    ``port_te1_is_member_in`` key to the row dict.
    """
    text = (
        "Port  : Te1\n"
        "Port Mode: Access\n"
        "Default VLAN: enabled\n"
        "\n"
        "Port Te1 is member in:\n"
        "Vlan       Name             Egress rule    Type\n"
        "----     -------------    -----------    ----\n"
        "100      USERS            Untagged       Static\n"
    )
    rows = _parse_pc_show_interfaces_switchport(text)
    assert rows[0]["interface"] == "Te1"
    assert rows[0]["untagged"] == [100]
    # The membership reference line must not have produced a stray key.
    assert "port_te1_is_member_in" not in rows[0]


def test_pc_unnamed_vlan_row_is_captured():
    """Membership rows with a blank Name column still produce a VID."""
    text = (
        "Port  : gi1/0/1\n"
        "Port Mode: Access\n"
        "Default VLAN: enabled\n"
        "\n"
        "Port gi1/0/1 is member in:\n"
        "Vlan       Name             Egress rule    Type\n"
        "----     -------------    -----------    ----\n"
        "99                          Untagged       Static\n"
    )
    rows = _parse_pc_show_interfaces_switchport(text)
    assert rows[0]["interface"] == "gi1/0/1"
    assert rows[0]["untagged"] == [99]
    assert rows[0]["tagged"] == []


def test_fastiron_lag_membership_is_captured():
    """`tagged lag <N>` lines must be picked up by the regex parser."""
    from pathlib import Path

    from custom_napalm.brocade_fastiron import FastIronDriver
    from tests.custom_drivers.mock_device import FakeCLIDevice

    mock_dir = (
        Path(__file__).parent
        / "brocade_fastiron"
        / "mock_data"
        / "test_get_interfaces_vlans"
        / "lag_membership"
    )
    driver = object.__new__(FastIronDriver)
    driver.hostname = driver.username = driver.password = "test"
    driver.timeout = 60
    driver.device = FakeCLIDevice(mock_dir)
    result = driver.get_interfaces_vlans()
    # LAG members produced by the driver's regex parser (the ntc-template
    # path emitted in batch-4 v1 dropped these silently).
    assert "lag1" in result
    assert result["lag1"]["tagged"] == [100, 200]
    assert "lag5" in result
    assert result["lag5"]["mode"] == "access"
    assert result["lag5"]["untagged"] == 300


def test_pc_section_parser_handles_multiple_ports():
    """Section parser separates ports correctly on `Port  :` header lines."""
    text = (
        "Port  : gi1/0/1\n"
        "Port Mode: Access\n"
        "Default VLAN: enabled\n"
        "\n"
        "Port gi1/0/1 is member in:\n"
        "Vlan       Name             Egress rule    Type\n"
        "----     -------------    -----------    ----\n"
        "10       USERS            Untagged       Static\n"
        "\n"
        "Port  : gi1/0/2\n"
        "Port Mode: Trunk\n"
        "Default VLAN: enabled\n"
        "\n"
        "Port gi1/0/2 is member in:\n"
        "Vlan       Name             Egress rule    Type\n"
        "----     -------------    -----------    ----\n"
        "1        default          Untagged       Default\n"
        "100      DATA             Tagged         Static\n"
    )
    rows = _parse_pc_show_interfaces_switchport(text)
    assert [r["interface"] for r in rows] == ["gi1/0/1", "gi1/0/2"]
    # `Port gi1/0/1 is member in:` reference lines must NOT spawn new sections.
    assert rows[0]["port_mode"] == "Access"
    assert rows[0]["untagged"] == [10]
    assert rows[1]["port_mode"] == "Trunk"
    assert rows[1]["untagged"] == [1]
    assert rows[1]["tagged"] == [100]


# ----- Extreme VSP / VOSS ---------------------------------------------------


def test_vsp_single_vlan_matching_untagged_yields_access():
    """One VLAN listed and UNTAGGED_VID matches → access on that VID."""
    info = _vsp_row_to_switchport_info({
        "port": "1/1",
        "vlan_ids": [100],
        "untagged_vid": 100,
    })
    assert info.admin_mode == "access"
    assert info.access_vlan == 100
    assert info.allowed_vlans is None


def test_vsp_multiple_vlans_with_untagged_yields_trunk_native():
    """Multiple VLANs listed with non-zero UNTAGGED_VID → trunk + native."""
    info = _vsp_row_to_switchport_info({
        "port": "1/2",
        "vlan_ids": [10, 20, 30],
        "untagged_vid": 10,
    })
    assert info.admin_mode == "trunk"
    assert info.native_vlan == 10
    assert info.allowed_vlans == [10, 20, 30]


def test_vsp_untagged_zero_yields_trunk_no_native():
    """UNTAGGED_VID = 0 means all-tagged trunk with no native."""
    info = _vsp_row_to_switchport_info({
        "port": "1/3",
        "vlan_ids": [100, 200],
        "untagged_vid": 0,
    })
    assert info.admin_mode == "trunk"
    assert info.native_vlan is None
    assert info.allowed_vlans == [100, 200]


def test_vsp_empty_vlan_list_yields_routed():
    """A port with no VLAN membership classifies as routed."""
    info = _vsp_row_to_switchport_info({
        "port": "1/4",
        "vlan_ids": [],
        "untagged_vid": 0,
    })
    assert info.enabled is False


def test_vsp_full_range_yields_trunk_all():
    """A 1-4094 VLAN range collapses to trunk-all via the wildcard signal."""
    info = _vsp_row_to_switchport_info({
        "port": "1/7",
        "vlan_ids": "all",
        "untagged_vid": 10,
    })
    assert info.admin_mode == "trunk"
    assert info.allowed_vlans == "all"
    assert info.native_vlan == 10


def test_vsp_parser_promotes_full_range_to_wildcard():
    """`1-4094` in the VLAN_IDS column becomes `vlan_ids='all'` after parsing."""
    text = (
        "PORT     VLAN_IDS                              UNTAGGED_VID\n"
        "--------------------------------------------------------------------------------\n"
        "1/7      1-4094                                10\n"
    )
    rows = _parse_vsp_port_vlans(text)
    assert rows == [{"port": "1/7", "vlan_ids": "all", "untagged_vid": 10}]


def test_vsp_parser_skips_header_and_separator_rows():
    """Header and dash separator lines must not produce bogus port entries."""
    text = (
        "================================================================================\n"
        "                                  Port Vlans\n"
        "================================================================================\n"
        "PORT     VLAN_IDS                              UNTAGGED_VID\n"
        "--------------------------------------------------------------------------------\n"
        "1/1      100                                   100\n"
        "1/5      100-105,200                           100\n"
    )
    rows = _parse_vsp_port_vlans(text)
    assert [r["port"] for r in rows] == ["1/1", "1/5"]
    assert rows[1]["vlan_ids"] == [100, 101, 102, 103, 104, 105, 200]
    assert rows[1]["untagged_vid"] == 100
