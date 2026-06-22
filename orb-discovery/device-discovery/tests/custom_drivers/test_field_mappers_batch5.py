"""Unit tests for batch-5 field mappers (vendor row → SwitchportInfo)."""

from custom_napalm.avaya_ers import (
    _ers_aggregate_to_switchport,
    _expand_ers_port_list,
    _parse_ers_show_vlan_interface_info,
)
from custom_napalm.brocade_netiron import (
    _invert_netiron_vlan_config,
    _netiron_aggregate_to_switchport,
    _netiron_split_port_list,
)
from custom_napalm.extreme_slx import (
    _parse_slx_vlan_brief,
    _slx_aggregate_to_switchport,
    _slx_invert_vlan_brief,
)
from custom_napalm.ubiquiti_edgeswitch import (
    _edgesw_row_to_switchport_info,
    _parse_edgesw_port_membership,
    _parse_edgesw_switchport_summary,
)
from custom_napalm.ubiquiti_unifiswitch import (
    _parse_unifi_vlan_detail,
    _parse_unifi_vlan_list,
    _unifi_aggregate_to_switchport,
)

# ----- Brocade/Extreme NetIron ----------------------------------------------


def test_netiron_split_port_list_short_e_token():
    """NetIron short ``e`` token is recognised alongside ``ethe``."""
    assert _netiron_split_port_list("e 1/1 e 1/3") == ["1/1", "1/3"]
    assert _netiron_split_port_list("ethe 1/1 to 1/4") == ["1/1", "1/2", "1/3", "1/4"]


def test_netiron_split_port_list_bare_digit_range_no_leading_slash():
    """Bare-digit ranges (CES form) expand without a leading slash."""
    assert _netiron_split_port_list("ethe 1 to 4") == ["1", "2", "3", "4"]
    assert _netiron_split_port_list("e 2 e 11") == ["2", "11"]


def test_netiron_aggregate_dual_mode_is_trunk_with_native():
    """Untagged in one VLAN + tagged in others → trunk with the untagged as native."""
    info = _netiron_aggregate_to_switchport({"untagged": 10, "tagged": [20, 30]})
    assert info.admin_mode == "trunk"
    assert info.native_vlan == 10
    assert info.allowed_vlans == [20, 30]


def test_netiron_aggregate_tagged_only_no_native():
    """Tagged-only port maps to trunk with native=None."""
    info = _netiron_aggregate_to_switchport({"untagged": None, "tagged": [100, 200]})
    assert info.admin_mode == "trunk"
    assert info.native_vlan is None
    assert info.allowed_vlans == [100, 200]


def test_netiron_invert_lag_membership():
    """``tagged lag <N>`` and ``untagged lag <N>`` lines are captured as ``lagN``."""
    raw = (
        "vlan 100 name DATA\n"
        " tagged lag 1 ethe 1/2\n"
        " untagged ethe 1/3\n"
        "!\n"
        "vlan 300 name NATIVE-LAG\n"
        " untagged lag 5\n"
        "!\n"
    )
    per_port = _invert_netiron_vlan_config(raw)
    assert per_port["lag1"] == {"untagged": [], "tagged": [100]}
    assert per_port["lag5"] == {"untagged": [300], "tagged": []}
    assert per_port["1/2"] == {"untagged": [], "tagged": [100]}
    assert per_port["1/3"] == {"untagged": [100], "tagged": []}


def test_netiron_canonical_map_handles_digit_leading_prefix_and_named_types():
    """
    Canonical map handles digit-leading Ethernet prefixes and Ve/Lag/Loopback.

    Pins both Codex P1 fixes from PR #391 review:
    - ``10GigabitEthernet3/4`` and ``40GigabitEthernet5/1`` must enter the
      map (the original ``[A-Za-z]+`` prefix regex rejected leading digits).
    - ``Ve2``, ``Lag5``, ``Loopback1`` map back to lowercase keys
      (``ve2``, ``lag5``, ``loopback1``) so VLAN entries for VE/LAG/Loopback
      survive ``apply_interface_vlans()`` exact-match.
    """
    from custom_napalm.brocade_netiron import NetIronDriver

    fake = type(
        "F",
        (),
        {
            "send_command": lambda self, cmd: (
                "GigabitEthernet1/1 is up, line protocol is up\n"
                "  Hardware is GigabitEthernet, address is 0024.38a5.1c00 (bia 0024.38a5.1c00)\n"
                "10GigabitEthernet3/4 is up, line protocol is up\n"
                "  Hardware is 10GigabitEthernet, address is 0024.38a5.1c01 (bia 0024.38a5.1c01)\n"
                "40GigabitEthernet5/1 is up, line protocol is up\n"
                "  Hardware is 40GigabitEthernet, address is 0024.38a5.1c02 (bia 0024.38a5.1c02)\n"
                "Ve2 is up, line protocol is up\n"
                "  Hardware is Virtual, address is 0024.38a5.1c03 (bia 0024.38a5.1c03)\n"
                "Lag5 is up, line protocol is up\n"
                "  Hardware is Lag, address is 0024.38a5.1c04 (bia 0024.38a5.1c04)\n"
                "Loopback1 is up, line protocol is up\n"
                "  Hardware is Loopback\n"
            ),
        },
    )()
    driver = object.__new__(NetIronDriver)
    driver.device = fake
    cmap = driver._netiron_canonical_name_map()
    assert cmap.get("1/1") == "GigabitEthernet1/1"
    assert cmap.get("3/4") == "10GigabitEthernet3/4"
    assert cmap.get("5/1") == "40GigabitEthernet5/1"
    assert cmap.get("ve2") == "Ve2"
    assert cmap.get("lag5") == "Lag5"
    assert cmap.get("loopback1") == "Loopback1"


def test_netiron_canonical_map_handles_bare_digit_ces_form():
    r"""
    Bare-digit Ethernet IDs (CES form) enter the canonical map.

    Pins the Codex P1 fix from PR #391 round-10 review: CES platforms
    emit canonical names with no slot/port slash (e.g.
    ``GigabitEthernet1`` for unit 1 port 1). The previous regex
    required ``\d+/\d+`` and rejected bare-numeric suffixes,
    leaving those ports in the bare-key fallback path and dropping
    VLAN updates via apply_interface_vlans().
    """
    from custom_napalm.brocade_netiron import NetIronDriver

    fake = type(
        "F",
        (),
        {
            "send_command": lambda self, cmd: (
                "GigabitEthernet1 is up, line protocol is up\n"
                "  Hardware is GigabitEthernet, address is 0024.38a5.1c00 (bia 0024.38a5.1c00)\n"
                "GigabitEthernet11 is up, line protocol is up\n"
                "  Hardware is GigabitEthernet, address is 0024.38a5.1c01 (bia 0024.38a5.1c01)\n"
                "10GigabitEthernet3 is up, line protocol is up\n"
                "  Hardware is 10GigabitEthernet, address is 0024.38a5.1c02 (bia 0024.38a5.1c02)\n"
            ),
        },
    )()
    driver = object.__new__(NetIronDriver)
    driver.device = fake
    cmap = driver._netiron_canonical_name_map()
    # CES bare-digit suffixes match the ethernet branch (not the named branch).
    assert cmap.get("1") == "GigabitEthernet1"
    assert cmap.get("11") == "GigabitEthernet11"
    assert cmap.get("3") == "10GigabitEthernet3"


def test_netiron_aggregate_multiple_untagged_yields_routed():
    """Multi-untagged (anomalous; 802.1Q forbids) → routed, not access-on-last."""
    info = _netiron_aggregate_to_switchport({"untagged": [10, 20], "tagged": []})
    assert info.enabled is False
    assert info.admin_mode is None


# ----- Avaya/Extreme ERS ----------------------------------------------------


def test_ers_untag_all_yields_access_on_pvid():
    """``UntagAll`` → access mode on the PVID; membership list is ignored."""
    info = _ers_aggregate_to_switchport(
        {"pvid": 10, "tagging": "UntagAll"}, [10, 99]
    )
    assert info.admin_mode == "access"
    assert info.access_vlan == 10
    assert info.native_vlan is None
    assert info.allowed_vlans is None


def test_ers_untag_pvid_only_yields_trunk_with_native():
    """``UntagPvidOnly`` → trunk with native=PVID; tagged=members minus PVID."""
    info = _ers_aggregate_to_switchport(
        {"pvid": 10, "tagging": "UntagPvidOnly"}, [10, 20, 30]
    )
    assert info.admin_mode == "trunk"
    assert info.native_vlan == 10
    assert info.allowed_vlans == [20, 30]


def test_ers_tag_all_yields_trunk_no_native_with_pvid_tagged():
    """``TagAll`` → trunk, no native; PVID stays in tagged list when a member."""
    info = _ers_aggregate_to_switchport(
        {"pvid": 1, "tagging": "TagAll"}, [1, 100, 200]
    )
    assert info.admin_mode == "trunk"
    assert info.native_vlan is None
    assert info.allowed_vlans == [1, 100, 200]


def test_ers_disable_yields_routed():
    """``Disable`` (or any unknown tagging mode) → routed/disabled."""
    info = _ers_aggregate_to_switchport(
        {"pvid": 1, "tagging": "Disable"}, []
    )
    assert info.enabled is False
    assert info.admin_mode is None


def test_ers_hybrid_yields_trunk_with_native():
    """
    ERS ``Hybrid`` tagging mode → trunk with native=PVID + tagged=members-PVID.

    Pins the Codex P1 fix from PR #391 round-5 review: ``Hybrid`` is the
    same NetBox-aligned semantics as ``UntagPvidOnly`` (PVID untagged
    native, others tagged) but the previous mapper fell through to
    routed for any non-{UntagAll,UntagPvidOnly,TagAll} value, dropping
    valid switchport ports as routed.
    """
    info = _ers_aggregate_to_switchport(
        {"pvid": 10, "tagging": "Hybrid"}, [10, 20, 30]
    )
    assert info.admin_mode == "trunk"
    assert info.native_vlan == 10
    assert info.allowed_vlans == [20, 30]


def test_ers_row_port_tokens_ignores_protocol_id():
    """
    ``vlan_pid`` is a Protocol-ID hex string, not a port token.

    Pins the Copilot fix from PR #391 round-10 review: the ntc-template's
    ``vlan_pid`` field captures the ``PID`` column from ``show vlan``
    (a value like ``0x0000``), not a port identifier. The previous
    parser appended it to the port-token list, polluting the per-port
    aggregate. Only ``vlan_port_members`` should be returned.
    """
    from custom_napalm.avaya_ers import _ers_row_port_tokens

    row = {
        "vlan_id": "10",
        "vlan_pid": "0x0000",                # NOT a port — Protocol ID
        "vlan_port_members": ["1/1", "1/2"],  # actual ports
    }
    assert _ers_row_port_tokens(row) == ["1/1", "1/2"]


def test_ers_expand_port_list_wildcards():
    """
    ``ALL`` / ``<unit>/ALL`` expand against the known-ports catalog.

    Pins the Codex P1 fix from PR #391 round-7 review: the previous
    expander treated ``1/ALL`` as a literal port name, so VLANs whose
    membership is reported via the unit-wide wildcard never got
    associated with the actual ports in that unit, and those ports
    fell back to routed in the trunk-mode aggregator.
    """
    known = {"1/1", "1/2", "1/24", "2/1", "2/2"}

    # No catalog → wildcards return empty (back-compat for direct callers).
    assert _expand_ers_port_list("ALL") == []
    assert _expand_ers_port_list("1/ALL") == []

    # With catalog → chassis-wide ALL expands to every known port.
    assert _expand_ers_port_list("ALL", known) == sorted(known)

    # With catalog → unit-wide <unit>/ALL expands to known ports in that unit.
    assert _expand_ers_port_list("1/ALL", known) == ["1/1", "1/2", "1/24"]
    assert _expand_ers_port_list("2/ALL", known) == ["2/1", "2/2"]
    # Unit not in catalog → empty.
    assert _expand_ers_port_list("9/ALL", known) == []


def test_ers_tag_pvid_only_yields_trunk_no_native():
    """
    ERS ``TagPvidOnly`` → trunk, no native, all members tagged (same as TagAll).

    Pins the Codex P1 fix from PR #391 round-6 review: ``TagPvidOnly``
    was recognised by the regex but never handled by the mapper, so
    valid switchports fell through to routed and were silently dropped.
    """
    info = _ers_aggregate_to_switchport(
        {"pvid": 10, "tagging": "TagPvidOnly"}, [10, 100, 200]
    )
    assert info.admin_mode == "trunk"
    assert info.native_vlan is None
    assert info.allowed_vlans == [10, 100, 200]


def test_ers_intf_info_parser_handles_no_stg_layout():
    """
    Parser handles ``Port FilterUF FilterUR PVID PRI Tagging Name`` layout.

    Pins the Codex P1 fix from PR #391 round-5 review: ERS firmware
    variants emit the columns in different orders. Anchoring on the
    Tagging keyword (rather than counting fixed columns) makes the
    parser robust across both v1 (STG before PVID) and v2 (no STG; PRI
    after PVID) layouts.
    """
    # v1 layout: Port FilterUF FilterUR STG PVID Tagging Name Pri
    v1 = (
        "Filter Filter\n"
        "       Untagged   Unregistered                                       PVID\n"
        "Port   Frames     Frames     STG  PVID  Tagging       Name           Pri\n"
        "----   ----       ----       ---  ----  -------       ----           ---\n"
        "1/1    No         Yes        1    10    UntagAll      USER-1         0\n"
    )
    out = _parse_ers_show_vlan_interface_info(v1)
    assert out["1/1"]["pvid"] == 10
    assert out["1/1"]["tagging"].lower() == "untagall"

    # v2 layout: no STG column; PRI follows PVID.
    # Row: 13 No Yes 1011 4 Hybrid (PVID=1011, PRI=4, Tagging=Hybrid)
    v2 = (
        "Filter Filter\n"
        "       Untagged   Unregistered                  PVID\n"
        "Port   Frames     Frames     PVID  PRI  Tagging        Name\n"
        "----   ----       ----       ----  ---  -------        ----\n"
        "13     No         Yes        1011  4    Hybrid         UPLINK-13\n"
    )
    out = _parse_ers_show_vlan_interface_info(v2)
    assert out["13"]["pvid"] == 1011
    assert out["13"]["tagging"].lower() == "hybrid"


def test_ers_untag_all_with_invalid_pvid_yields_routed():
    """
    ``UntagAll`` with missing/out-of-range PVID → routed (defensive).

    Pins the Copilot P1 fix from PR #391 round-11 review: emitting
    ``access_vlan=None`` would clobber the existing NetBox untagged_vlan
    via PATCH. ``coerce_vid`` returns None for non-numeric values (e.g.
    parse errors), missing values, and out-of-range VIDs (≤0 or >4094) —
    all of which now route instead of producing a no-VID access entry.
    """
    info = _ers_aggregate_to_switchport(
        {"pvid": None, "tagging": "UntagAll"}, []
    )
    assert info.enabled is False
    assert info.admin_mode is None

    # Out-of-range PVID also routes.
    info = _ers_aggregate_to_switchport(
        {"pvid": 5000, "tagging": "UntagAll"}, []
    )
    assert info.enabled is False


def test_ers_trunk_modes_with_no_membership_yield_routed():
    """UntagPvidOnly / TagAll trunks need membership data; empty → routed."""
    for mode in ("UntagPvidOnly", "TagAll"):
        info = _ers_aggregate_to_switchport(
            {"pvid": 10, "tagging": mode}, []
        )
        assert info.enabled is False, f"{mode} with empty members should be routed"
        assert info.admin_mode is None


# ----- Extreme SLX-OS -------------------------------------------------------


def test_slx_aggregate_access_one_untagged():
    """One untagged VID + no tagged → access mode on that VID."""
    info = _slx_aggregate_to_switchport({"untagged": 100, "tagged": []})
    assert info.enabled is True
    assert info.admin_mode == "access"
    assert info.access_vlan == 100
    assert info.allowed_vlans is None


def test_slx_aggregate_trunk_with_native_and_tagged_only():
    """Untagged + tagged → trunk with native; tagged-only → trunk no native."""
    info = _slx_aggregate_to_switchport({"untagged": 10, "tagged": [20, 30]})
    assert info.admin_mode == "trunk"
    assert info.native_vlan == 10
    assert info.allowed_vlans == [20, 30]

    info = _slx_aggregate_to_switchport({"untagged": None, "tagged": [100, 200]})
    assert info.admin_mode == "trunk"
    assert info.native_vlan is None
    assert info.allowed_vlans == [100, 200]


def test_slx_invert_canonicalises_eth_and_po_tokens():
    """Inverter expands ``Eth 0/1`` → ``Ethernet 0/1`` and ``Po 1`` → ``Port-channel 1``."""
    text = (
        "VLAN  Name   Type    State    Ports\n"
        "====  ====   ====    ====     ====\n"
        "10    USERS  STATIC  ACTIVE   Eth 0/1(u) Po 1(t)\n"
        "20    DATA   STATIC  ACTIVE   Eth 0/1(t) Po 1(u)\n"
    )
    rows = _parse_slx_vlan_brief(text)
    per_port = _slx_invert_vlan_brief(rows)
    assert per_port["Ethernet 0/1"] == {"untagged": [10], "tagged": [20]}
    assert per_port["Port-channel 1"] == {"untagged": [20], "tagged": [10]}


def test_slx_aggregate_multiple_untagged_yields_routed():
    """SLX: multi-untagged → routed (anomalous; 802.1Q forbids)."""
    info = _slx_aggregate_to_switchport({"untagged": [10, 20], "tagged": []})
    assert info.enabled is False
    assert info.admin_mode is None


def test_slx_invert_drops_out_of_range_vid():
    """VIDs outside 1..4094 are silently dropped during inversion."""
    rows = [
        {"vlan_id": 99999, "ports": [("Ethernet 0/1", "u")]},
        {"vlan_id": 0, "ports": [("Ethernet 0/2", "t")]},
        {"vlan_id": 100, "ports": [("Ethernet 0/3", "u")]},
    ]
    per_port = _slx_invert_vlan_brief(rows)
    assert "Ethernet 0/1" not in per_port
    assert "Ethernet 0/2" not in per_port
    assert per_port["Ethernet 0/3"] == {"untagged": [100], "tagged": []}


# ----- Ubiquiti EdgeSwitch --------------------------------------------------


def test_edgesw_access_single_untagged_yields_access():
    """Access mode with one untagged participation → access on that VID."""
    summary = {"mode": "access", "pvid": 100}
    membership = {"participation": [100], "tagging": [], "pvid": 100}
    info = _edgesw_row_to_switchport_info("0/1", summary, membership)
    assert info.admin_mode == "access"
    assert info.access_vlan == 100
    assert info.allowed_vlans is None


def test_edgesw_trunk_with_native_collects_tagging_list():
    """Trunk with VLAN 1 untagged + tagging list → trunk + native + tagged."""
    summary = {"mode": "trunk", "pvid": 1}
    membership = {"participation": [1, 10, 20], "tagging": [10, 20], "pvid": None}
    info = _edgesw_row_to_switchport_info("0/2", summary, membership)
    assert info.admin_mode == "trunk"
    assert info.native_vlan == 1
    assert info.allowed_vlans == [10, 20]


def test_edgesw_trunk_no_untagged_member_drops_native():
    """Trunk where every participation VID is tagged → trunk no native."""
    summary = {"mode": "trunk", "pvid": 1}
    membership = {"participation": [10, 20], "tagging": [10, 20], "pvid": None}
    info = _edgesw_row_to_switchport_info("0/4", summary, membership)
    assert info.admin_mode == "trunk"
    assert info.native_vlan is None
    assert info.allowed_vlans == [10, 20]


def test_edgesw_general_mode_collapses_to_trunk():
    """General mode collapses to trunk; native = sole untagged member."""
    summary = {"mode": "general", "pvid": 100}
    membership = {"participation": [100, 200], "tagging": [200], "pvid": 100}
    info = _edgesw_row_to_switchport_info("0/3", summary, membership)
    assert info.admin_mode == "trunk"
    assert info.native_vlan == 100
    assert info.allowed_vlans == [200]


def test_edgesw_membership_parser_captures_lag_blocks():
    r"""
    `interface lag <N>` blocks must be parsed from running-config.

    Pins the Codex P1 fix from PR #391 review: the original block regex
    ``\S+(?:/\S+)?`` only matched single tokens, dropping LAG sections
    (which use the multi-token ``interface lag 1`` form on EdgeSwitch CLI).
    Without this, LAG VLAN mappings were silently classified as routed.
    """
    config = (
        "interface 0/1\n"
        " vlan pvid 100\n"
        " vlan participation include 1,100\n"
        "!\n"
        "interface lag 1\n"
        " vlan pvid 1\n"
        " vlan participation include 1,10,20\n"
        " vlan tagging 10,20\n"
        "!\n"
        "interface vlan 1\n"
        " name DEFAULT_VLAN\n"
        "!\n"
    )
    out = _parse_edgesw_port_membership(config)
    assert "0/1" in out
    # ``interface lag 1`` (split-token) reduces to the same key as ``lag1``.
    assert "lag1" in out
    assert sorted(out["lag1"]["participation"]) == [1, 10, 20]
    assert sorted(out["lag1"]["tagging"]) == [10, 20]
    # SVI must NOT have been captured.
    assert "vlan1" not in out


def test_edgesw_membership_parser_handles_cisco_style_access():
    """
    ``switchport access vlan X`` is captured as participation + PVID.

    Pins the Codex P1 fix from PR #391 round-3 review: EdgeSwitch accepts
    both the native ``vlan ...`` syntax and the Cisco-flavoured
    ``switchport ...`` syntax. The previous parser only handled the
    native form, so Cisco-style configs produced empty membership →
    every interface classified as routed.
    """
    config = (
        "interface 0/5\n"
        " switchport mode access\n"
        " switchport access vlan 100\n"
        "!\n"
    )
    out = _parse_edgesw_port_membership(config)
    assert out["0/5"]["participation"] == [100]
    assert out["0/5"]["tagging"] == []
    assert out["0/5"]["pvid"] == 100


def test_edgesw_membership_parser_handles_cisco_style_trunk():
    """``switchport trunk native vlan X`` + ``switchport trunk allowed vlan ...``."""
    config = (
        "interface 0/6\n"
        " switchport mode trunk\n"
        " switchport trunk native vlan 1\n"
        " switchport trunk allowed vlan 10,20,30\n"
        "!\n"
    )
    out = _parse_edgesw_port_membership(config)
    assert out["0/6"]["pvid"] == 1
    assert sorted(out["0/6"]["participation"]) == [1, 10, 20, 30]
    assert sorted(out["0/6"]["tagging"]) == [10, 20, 30]


def test_edgesw_cisco_trunk_allowed_vlan_all_yields_tagged_all():
    """``switchport trunk allowed vlan all`` promotes to mode=tagged-all."""
    config = (
        "interface 0/7\n"
        " switchport mode trunk\n"
        " switchport trunk native vlan 1\n"
        " switchport trunk allowed vlan all\n"
        "!\n"
    )
    membership = _parse_edgesw_port_membership(config)["0/7"]
    assert membership["allowed_all"] is True
    info = _edgesw_row_to_switchport_info(
        "0/7", {"mode": "trunk", "pvid": 1}, membership,
    )
    assert info.admin_mode == "trunk"
    assert info.allowed_vlans == "all"
    assert info.native_vlan == 1


def test_edgesw_normalise_dedupes_repeated_vids():
    """
    Duplicate VIDs in participation/tagging are removed before classification.

    Pins the Copilot P1 fix from PR #391 round-8 review: when an interface
    block mixes native-syntax and Cisco-style directives (or repeats a
    VID across multiple include lines), duplicates leak into the
    derived ``untagged_members`` and the access-path check
    ``len(untagged_members) != 1`` would incorrectly flip a valid
    access-on-100 port to routed.
    """
    from custom_napalm.ubiquiti_edgeswitch import _normalise_edgesw_membership

    membership = {
        "participation": [100, 100, 100],  # repeated
        "tagging": [],
        "pvid": 100,
    }
    participation, tagging, untagged_members = _normalise_edgesw_membership(membership)
    assert participation == [100]
    assert tagging == []
    assert untagged_members == [100]

    # Mixed native + Cisco directives both adding VLAN 100 to participation
    # plus repeated tagging entries — must dedupe both sides.
    membership = {
        "participation": [1, 10, 1, 20, 10],
        "tagging": [10, 20, 10],
        "pvid": 1,
    }
    participation, tagging, untagged_members = _normalise_edgesw_membership(membership)
    assert participation == [1, 10, 20]
    assert tagging == [10, 20]  # PVID 1 stripped + dedupe
    assert untagged_members == [1]


def test_edgesw_native_vlan_participation_exclude_drops_vid():
    """
    ``vlan participation exclude <vlist>`` removes VIDs from membership.

    Pins the Copilot P1 fix from PR #391 round-9 review: native-syntax
    EdgeSwitch configs use ``vlan participation exclude`` to remove a
    VLAN that was implicitly or explicitly included earlier in the same
    block. Without this directive being parsed, an access port with
    ``include 100`` + ``exclude 1`` (where 1 was somehow added) would
    retain VLAN 1 in participation and flip to routed via the
    ``len(untagged_members) != 1`` access guard.
    """
    config = (
        "interface 0/11\n"
        " vlan participation include 1,100\n"
        " vlan participation exclude 1\n"
        " vlan tagging 100\n"
        " vlan pvid 100\n"
        "!\n"
    )
    out = _parse_edgesw_port_membership(config)
    # VLAN 1 must be removed from participation (and from tagging if
    # present, though this fixture only adds it to participation).
    assert out["0/11"]["participation"] == [100]
    assert out["0/11"]["tagging"] == [100]


def test_edgesw_trunk_allowed_remove_purges_duplicates():
    """
    ``switchport trunk allowed vlan remove X`` purges every occurrence of X.

    Pins the Codex P2 fix from PR #391 round-9 review: the previous
    `list.remove(vid)` call only removed the first occurrence, so
    duplicate entries (which can appear when native + Cisco-style
    directives both reference the same VID) survived and falsely
    kept the VLAN present after an explicit `remove`.
    """
    from custom_napalm.ubiquiti_edgeswitch import _trunk_allowed_remove

    entry = {
        "participation": [1, 10, 20, 10],  # duplicate 10
        "tagging": [10, 20, 10],
        "pvid": 1,
        "allowed_all": False,
        "allowed_except": False,
    }
    _trunk_allowed_remove(entry, "10")
    assert 10 not in entry["participation"]
    assert 10 not in entry["tagging"]
    assert entry["participation"] == [1, 20]
    assert entry["tagging"] == [20]


def test_edgesw_cisco_trunk_native_vlan_excluded_from_tagged():
    """
    Native VLAN listed in ``switchport trunk allowed vlan`` stays untagged.

    Pins the Codex P1 fix from PR #391 round-7 review: a common Cisco-style
    config sets ``switchport trunk native vlan 1`` AND lists VLAN 1 inside
    ``switchport trunk allowed vlan 1,10,20``. The previous mapper added
    VLAN 1 to ``tagging`` (matching the allowed list), then derived
    ``untagged_members = participation - tagging`` and got ``[]``,
    misclassifying as trunk-no-native. The fix strips PVID from tagging
    before that derivation so the native VLAN ends up in the right bucket.
    """
    config = (
        "interface 0/10\n"
        " switchport mode trunk\n"
        " switchport trunk native vlan 1\n"
        " switchport trunk allowed vlan 1,10,20\n"
        "!\n"
    )
    membership = _parse_edgesw_port_membership(config)["0/10"]
    info = _edgesw_row_to_switchport_info(
        "0/10", {"mode": "trunk", "pvid": 1}, membership,
    )
    assert info.admin_mode == "trunk"
    assert info.native_vlan == 1
    assert info.allowed_vlans == [10, 20]


def test_edgesw_allowed_all_then_remove_falls_back_to_routed():
    """
    ``allowed vlan all`` followed by ``allowed vlan remove`` → routed.

    Pins the Copilot fix from PR #391 round-10 review: the operator's
    intent is "all VLANs except <vlist>" — unrepresentable in NetBox's
    allowed_vlans list without enumerating the chassis, so the row
    mapper falls back to routed (matches the explicit ``except``
    keyword path) rather than silently emitting tagged-all and
    clobbering NetBox via PATCH.
    """
    config = (
        "interface 0/12\n"
        " switchport mode trunk\n"
        " switchport trunk allowed vlan all\n"
        " switchport trunk allowed vlan remove 10\n"
        "!\n"
    )
    membership = _parse_edgesw_port_membership(config)["0/12"]
    assert membership["allowed_all"] is False
    assert membership["allowed_except"] is True
    info = _edgesw_row_to_switchport_info(
        "0/12", {"mode": "trunk", "pvid": 1}, membership,
    )
    assert info.enabled is False
    assert info.admin_mode is None


def test_edgesw_allowed_all_then_add_falls_back_to_routed():
    """``allowed vlan all`` + add → routed (same all-±-some logic)."""
    config = (
        "interface 0/13\n"
        " switchport mode trunk\n"
        " switchport trunk allowed vlan all\n"
        " switchport trunk allowed vlan add 50\n"
        "!\n"
    )
    membership = _parse_edgesw_port_membership(config)["0/13"]
    assert membership["allowed_except"] is True


def test_edgesw_cisco_trunk_allowed_remove_drops_vids():
    """
    ``switchport trunk allowed vlan remove X`` removes X from membership.

    Pins the Codex P1 fix from PR #391 round-4 review: the previous regex
    captured but discarded the operation token, so ``remove`` and
    ``except`` were silently treated as additive — the inverse of the
    intended semantics.
    """
    config = (
        "interface 0/8\n"
        " switchport mode trunk\n"
        " switchport trunk native vlan 1\n"
        " switchport trunk allowed vlan add 10,20,30\n"
        " switchport trunk allowed vlan remove 20\n"
        "!\n"
    )
    out = _parse_edgesw_port_membership(config)
    assert sorted(out["0/8"]["participation"]) == [1, 10, 30]
    assert sorted(out["0/8"]["tagging"]) == [10, 30]


def test_edgesw_cisco_trunk_allowed_except_yields_routed():
    """
    ``switchport trunk allowed vlan except X`` → routed (defensive).

    NetBox's allowed_vlans list cannot faithfully represent "all except
    these" without enumerating the chassis; falling back to routed
    avoids silently emitting wrong tagged_vlans via PATCH.
    """
    config = (
        "interface 0/9\n"
        " switchport mode trunk\n"
        " switchport trunk allowed vlan except 100\n"
        "!\n"
    )
    membership = _parse_edgesw_port_membership(config)["0/9"]
    assert membership["allowed_except"] is True
    info = _edgesw_row_to_switchport_info(
        "0/9", {"mode": "trunk", "pvid": 1}, membership,
    )
    assert info.enabled is False
    assert info.admin_mode is None


def test_edgesw_membership_parser_normalises_single_token_lag():
    """``interface lag1`` (single token) yields the same key as ``interface lag 1``."""
    config = (
        "interface lag1\n"
        " vlan pvid 100\n"
        " vlan participation include 100\n"
        "!\n"
    )
    out = _parse_edgesw_port_membership(config)
    assert "lag1" in out
    assert out["lag1"]["participation"] == [100]


def test_edgesw_access_no_membership_trusts_summary_pvid():
    """
    Access mode with no membership block → emit access on summary PVID.

    EdgeSwitch's ``show running-config`` omits default-config interfaces,
    so the summary's PVID is the only signal we have for those ports.
    Trust it for Access mode (Codex P2 #391 round-11) — the summary is
    authoritative for mode + PVID. This restores the round-1-removed
    fallback only on the path where membership is unambiguously absent.
    """
    summary = {"mode": "access", "pvid": 100}
    info = _edgesw_row_to_switchport_info("0/9", summary, None)
    assert info.admin_mode == "access"
    assert info.access_vlan == 100


def test_edgesw_access_no_membership_no_pvid_yields_routed():
    """Access mode with neither membership nor a valid summary PVID → routed."""
    info = _edgesw_row_to_switchport_info(
        "0/9", {"mode": "access", "pvid": None}, None,
    )
    assert info.enabled is False
    assert info.admin_mode is None


def test_edgesw_trunk_multi_untagged_yields_routed():
    """
    Trunk with >1 untagged member → routed (anomalous; 802.1Q forbids).

    Pins the Copilot P1 fix from PR #391 round-11 review: trunk previously
    silently picked ``untagged_members[0]`` and dropped the rest, which
    can produce a wrong native VID and clobber NetBox via PATCH. Mirrors
    the multi-untagged routing in netiron / slx / unifiswitch /
    dell_powerconnect.
    """
    summary = {"mode": "trunk", "pvid": 1}
    membership = {
        "participation": [10, 20, 30],
        "tagging": [],  # nothing tagged → both 10 and 20 are untagged
        "pvid": None,
    }
    info = _edgesw_row_to_switchport_info("0/15", summary, membership)
    assert info.enabled is False
    assert info.admin_mode is None


def test_edgesw_trunk_no_membership_yields_routed():
    """Trunk mode with no participation/tagging → routed (no PVID-only trunk)."""
    summary = {"mode": "trunk", "pvid": 1}
    info = _edgesw_row_to_switchport_info("0/8", summary, None)
    assert info.enabled is False
    assert info.admin_mode is None


def test_edgesw_routed_mode_yields_routed():
    """``Routed`` Mode column → routed regardless of membership."""
    summary = {"mode": "routed", "pvid": 1}
    info = _edgesw_row_to_switchport_info("0/5", summary, None)
    assert info.enabled is False
    assert info.admin_mode is None


def test_edgesw_access_mismatched_membership_falls_back_to_routed():
    """Access mode + tagged rows → routed (don't clobber NetBox via PATCH)."""
    summary = {"mode": "access", "pvid": 100}
    membership = {"participation": [100, 200], "tagging": [200], "pvid": 100}
    info = _edgesw_row_to_switchport_info("0/1", summary, membership)
    assert info.enabled is False
    assert info.admin_mode is None


def test_edgesw_summary_parser_skips_header_and_dashes():
    """Header row, dashes separator, and blank lines must not produce ports."""
    text = (
        "                                  Acceptable Ingress     Default\n"
        "Interface     Mode         PVID     Frame Types Filtering  Priority\n"
        "------------- ------------ -------- ----------- ---------- ----------\n"
        "0/1           Access       100      Admit All   Disabled   0\n"
        "0/2           Trunk        1        VLAN Only   Enabled    0\n"
    )
    out = _parse_edgesw_switchport_summary(text)
    assert out == {
        "0/1": {"mode": "access", "pvid": 100},
        "0/2": {"mode": "trunk", "pvid": 1},
    }


def test_edgesw_membership_parser_ignores_svi_blocks():
    """``interface vlan N`` SVI blocks must not appear as switchports."""
    cfg = (
        "hostname x\n"
        "!\n"
        "interface vlan 1\n"
        " ip address 192.168.1.1 255.255.255.0\n"
        "!\n"
        "interface 0/1\n"
        " vlan pvid 100\n"
        " vlan participation include 100\n"
        "!\n"
    )
    out = _parse_edgesw_port_membership(cfg)
    assert "vlan" not in out
    assert "0/1" in out
    assert out["0/1"]["participation"] == [100]
    assert out["0/1"]["pvid"] == 100


# ----- Ubiquiti UniFiSwitch -------------------------------------------------


def test_unifi_aggregate_access_one_untagged():
    """One Untagged VID + no Tagged → access mode on that VID."""
    info = _unifi_aggregate_to_switchport({"untagged": 100, "tagged": []})
    assert info.enabled is True
    assert info.admin_mode == "access"
    assert info.access_vlan == 100
    assert info.allowed_vlans is None


def test_unifi_aggregate_trunk_with_native_and_tagged_only():
    """Untagged + Tagged → trunk + native; Tagged-only → trunk no native."""
    info = _unifi_aggregate_to_switchport({"untagged": 1, "tagged": [10, 20]})
    assert info.admin_mode == "trunk"
    assert info.native_vlan == 1
    assert info.allowed_vlans == [10, 20]

    info = _unifi_aggregate_to_switchport({"untagged": None, "tagged": [100, 200]})
    assert info.admin_mode == "trunk"
    assert info.native_vlan is None
    assert info.allowed_vlans == [100, 200]


def test_unifi_aggregate_multiple_untagged_yields_routed():
    """UnifiSwitch: multi-untagged → routed (anomalous; 802.1Q forbids)."""
    info = _unifi_aggregate_to_switchport({"untagged": [10, 20], "tagged": []})
    assert info.enabled is False
    assert info.admin_mode is None


def test_unifi_aggregate_empty_membership_yields_routed():
    """Port with no membership at all classifies as routed/disabled."""
    info = _unifi_aggregate_to_switchport({"untagged": None, "tagged": []})
    assert info.enabled is False
    assert info.admin_mode is None


def test_unifi_parse_vlan_detail_skips_exclude_and_header():
    """Only `Include` rows survive; Exclude/headers/dashes drop out."""
    text = (
        "VLAN ID........................... 100\n"
        "VLAN Name......................... USERS\n"
        "VLAN Type......................... Static\n"
        "\n"
        "   Interface  Current   Configured  Tagging\n"
        "   ---------  --------  ----------  --------\n"
        "   0/1        Include   Autodetect  Untagged\n"
        "   0/2        Include   Autodetect  Tagged\n"
        "   0/3        Exclude   Autodetect  Tagged\n"
    )
    assert _parse_unifi_vlan_detail(text) == [("0/1", "Untagged"), ("0/2", "Tagged")]


def test_unifi_parse_vlan_list_extracts_vids():
    """`show vlan` table yields a deduplicated, ordered VID list."""
    text = (
        "VLAN ID  VLAN Name                    VLAN Type\n"
        "-------  ---------------------------  --------\n"
        "1        Default                      Default\n"
        "10       USERS                        Static\n"
        "100      DATA                         Static\n"
    )
    assert _parse_unifi_vlan_list(text) == [1, 10, 100]
