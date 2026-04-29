"""Unit tests for custom_napalm._vlan generic classifier."""

from custom_napalm._vlan import (
    SwitchportInfo,
    classify_switchport,
    coerce_vid,
    parse_vlan_range_string,
)

# ----- coerce_vid -------------------------------------------------------


def test_coerce_vid_int_passthrough():
    """Plain int in range is returned unchanged."""
    assert coerce_vid(100) == 100


def test_coerce_vid_string_int():
    """Numeric string is coerced to int."""
    assert coerce_vid("100") == 100


def test_coerce_vid_rejects_bool_true():
    """Bool is subclass of int — must be rejected explicitly."""
    assert coerce_vid(True) is None


def test_coerce_vid_rejects_bool_false():
    """False must be rejected even though int(False) == 0."""
    assert coerce_vid(False) is None


def test_coerce_vid_clamps_below():
    """VID 0 is out of range."""
    assert coerce_vid(0) is None


def test_coerce_vid_clamps_above():
    """VID 4095 is out of range."""
    assert coerce_vid(4095) is None


def test_coerce_vid_accepts_min():
    """VID 1 is the minimum valid value."""
    assert coerce_vid(1) == 1


def test_coerce_vid_accepts_max():
    """VID 4094 is the maximum valid value."""
    assert coerce_vid(4094) == 4094


def test_coerce_vid_none():
    """None input returns None."""
    assert coerce_vid(None) is None


def test_coerce_vid_garbage():
    """Non-numeric garbage returns None."""
    assert coerce_vid("foo") is None
    assert coerce_vid([]) is None
    assert coerce_vid({}) is None


# ----- parse_vlan_range_string -----------------------------------------


def test_parse_range_empty():
    """Empty string returns empty list, no wildcard."""
    assert parse_vlan_range_string("") == ([], False)


def test_parse_range_none_token():
    """'none' / 'NONE' is a valid empty signal, NOT a wildcard."""
    assert parse_vlan_range_string("none") == ([], False)
    assert parse_vlan_range_string("NONE") == ([], False)


def test_parse_range_literal_all():
    """'all' / 'ALL' is the wildcard token."""
    assert parse_vlan_range_string("all") == ([], True)
    assert parse_vlan_range_string("ALL") == ([], True)


def test_parse_range_single_vid():
    """Single VID returns a one-element list."""
    assert parse_vlan_range_string("100") == ([100], False)


def test_parse_range_simple_range():
    """Simple hyphen-delimited range is expanded."""
    assert parse_vlan_range_string("10-12") == ([10, 11, 12], False)


def test_parse_range_comma_list():
    """Comma-separated list is returned in order."""
    assert parse_vlan_range_string("1,10,20") == ([1, 10, 20], False)


def test_parse_range_mixed():
    """Mixed comma list and ranges are combined correctly."""
    assert parse_vlan_range_string("1,10-12,20") == ([1, 10, 11, 12, 20], False)


def test_parse_range_full_range_is_wildcard():
    """1-4094 covers the whole VID space and is promoted to wildcard."""
    vids, is_wildcard = parse_vlan_range_string("1-4094")
    assert vids == []
    assert is_wildcard is True


def test_parse_range_clamps_above():
    """Tokens above 4094 are clamped out and must NOT widen to wildcard."""
    # Tokens above 4094 are clamped out, never returned, AND must NOT widen to wildcard
    vids, is_wildcard = parse_vlan_range_string("5000-9000")
    assert vids == []
    assert is_wildcard is False


def test_parse_range_clamps_partial():
    """Range that starts in-band and ends out-of-band is clamped."""
    vids, is_wildcard = parse_vlan_range_string("4090-9000")
    assert vids == [4090, 4091, 4092, 4093, 4094]
    assert is_wildcard is False  # only because it doesn't start at 1


def test_parse_range_inverted_range_dropped():
    """Inverted range (hi < lo) is silently dropped."""
    assert parse_vlan_range_string("100-50") == ([], False)


def test_parse_range_junk_dropped():
    """Junk tokens are dropped; valid adjacent tokens are kept."""
    assert parse_vlan_range_string("junk,10,bad-bad") == ([10], False)


def test_parse_range_all_junk_not_wildcard():
    """All-junk input returns ([], False) — NOT a wildcard."""
    assert parse_vlan_range_string("junk,nonsense") == ([], False)


# ----- classify_switchport ---------------------------------------------


def _info(**kwargs) -> SwitchportInfo:
    """Build a SwitchportInfo with sensible defaults for tests."""
    return SwitchportInfo(
        enabled=kwargs.pop("enabled", True),
        admin_mode=kwargs.pop("admin_mode", None),
        oper_mode=kwargs.pop("oper_mode", None),
        access_vlan=kwargs.pop("access_vlan", None),
        native_vlan=kwargs.pop("native_vlan", None),
        allowed_vlans=kwargs.pop("allowed_vlans", None),
        voice_vlan=kwargs.pop("voice_vlan", None),
    )


def test_classify_routed_when_disabled():
    """Disabled interface always resolves to routed."""
    out = classify_switchport(_info(enabled=False))
    assert out == {"mode": "routed", "tagged": [], "untagged": None}


def test_classify_routed_when_no_mode():
    """No admin or oper mode resolves to routed."""
    out = classify_switchport(_info(admin_mode=None, oper_mode=None))
    assert out == {"mode": "routed", "tagged": [], "untagged": None}


def test_classify_routed_when_oper_routed():
    """DTP dynamic port with oper_mode=routed resolves to routed."""
    out = classify_switchport(_info(admin_mode="dynamic", oper_mode="routed"))
    assert out == {"mode": "routed", "tagged": [], "untagged": None}


def test_classify_access():
    """Basic access port returns access mode with correct untagged VID."""
    out = classify_switchport(_info(admin_mode="access", access_vlan=100))
    assert out == {"mode": "access", "tagged": [], "untagged": 100}


def test_classify_access_with_voice_promoted_to_trunk():
    """Voice VLAN on an access port is promoted to trunk."""
    out = classify_switchport(_info(admin_mode="access", access_vlan=100, voice_vlan=200))
    # NetBox 'access' mode disallows tagged VLANs, so we promote
    assert out == {"mode": "trunk", "tagged": [200], "untagged": 100}


def test_classify_access_voice_equal_to_access_no_promotion():
    """Voice VLAN equal to access VLAN does not trigger promotion."""
    out = classify_switchport(
        _info(admin_mode="access", access_vlan=100, voice_vlan=100)
    )
    # Voice == access (operator misconfig). Promoting would put voice in
    # `tagged` and access in `untagged`, but they're the same VID — that
    # produces a degenerate trunk. Keep plain access instead.
    assert out == {"mode": "access", "tagged": [], "untagged": 100}


def test_classify_trunk_explicit_list():
    """Trunk with explicit allowed list returns all VIDs as tagged."""
    out = classify_switchport(_info(admin_mode="trunk", native_vlan=1, allowed_vlans=[10, 20, 30]))
    assert out == {"mode": "trunk", "tagged": [10, 20, 30], "untagged": 1}


def test_classify_trunk_strips_native_from_tagged():
    """Native VLAN is excluded from the tagged list."""
    out = classify_switchport(_info(admin_mode="trunk", native_vlan=10, allowed_vlans=[10, 20]))
    assert out == {"mode": "trunk", "tagged": [20], "untagged": 10}


def test_classify_trunk_all_via_wildcard():
    """String 'all' for allowed_vlans produces trunk-all mode."""
    out = classify_switchport(_info(admin_mode="trunk", native_vlan=1, allowed_vlans="all"))
    assert out == {"mode": "trunk-all", "tagged": [], "untagged": 1}


def test_classify_dtp_fallback_to_oper_trunk():
    """DTP dynamic port with oper_mode=trunk is treated as trunk."""
    out = classify_switchport(
        _info(admin_mode="dynamic", oper_mode="trunk", native_vlan=1, allowed_vlans=[10])
    )
    assert out == {"mode": "trunk", "tagged": [10], "untagged": 1}


def test_classify_dtp_fallback_to_oper_access():
    """DTP dynamic port with oper_mode=access is treated as access."""
    out = classify_switchport(_info(admin_mode="dynamic", oper_mode="access", access_vlan=100))
    assert out == {"mode": "access", "tagged": [], "untagged": 100}


def test_classify_rejects_bool_vlan_inputs():
    """Bool values passed as VIDs are rejected by coerce_vid."""
    out = classify_switchport(
        _info(
            admin_mode="trunk",
            native_vlan=True,  # bool — should drop
            allowed_vlans=[10, False, 20],  # bool in list — should drop
        )
    )
    # native_vlan rejected → None; tagged keeps only valid ints
    assert out == {"mode": "trunk", "tagged": [10, 20], "untagged": None}


def test_classify_clamps_oob_vids_in_tagged():
    """Out-of-band VIDs in the allowed list are clamped out."""
    out = classify_switchport(_info(admin_mode="trunk", native_vlan=1, allowed_vlans=[0, 10, 4095, 20]))
    assert out == {"mode": "trunk", "tagged": [10, 20], "untagged": 1}


# ----- additional classifier edge cases -----


def test_classify_trunk_all_via_full_range_list():
    """List form covering 1..4094 must promote to trunk-all, not stay as a list."""
    full_range = list(range(1, 4095))
    out = classify_switchport(_info(admin_mode="trunk", native_vlan=1, allowed_vlans=full_range))
    assert out == {"mode": "trunk-all", "tagged": [], "untagged": 1}


def test_classify_trunk_junk_string_falls_back_to_plain_trunk():
    """All-junk string for allowed_vlans must NOT widen to trunk-all."""
    out = classify_switchport(_info(admin_mode="trunk", native_vlan=1, allowed_vlans="junk,nonsense"))
    assert out == {"mode": "trunk", "tagged": [], "untagged": 1}


def test_classify_trunk_with_no_allowed_vlans():
    """admin_mode=trunk with allowed_vlans=None → plain trunk, empty tagged."""
    out = classify_switchport(_info(admin_mode="trunk", native_vlan=99, allowed_vlans=None))
    assert out == {"mode": "trunk", "tagged": [], "untagged": 99}


def test_classify_dtp_with_no_oper_signal_is_routed():
    """admin=dynamic with oper=None resolves to routed (no useful info)."""
    out = classify_switchport(_info(admin_mode="dynamic", oper_mode=None))
    assert out == {"mode": "routed", "tagged": [], "untagged": None}


def test_classify_unknown_admin_mode_with_no_oper_routed():
    """Unrecognized admin_mode string + no oper_mode → routed."""
    out = classify_switchport(_info(admin_mode=None, oper_mode=None, access_vlan=100))
    assert out == {"mode": "routed", "tagged": [], "untagged": None}


def test_classify_access_with_oob_access_vlan_drops_untagged():
    """Out-of-range access_vlan coerces to None, leaving untagged=None."""
    out = classify_switchport(_info(admin_mode="access", access_vlan=4095))
    assert out == {"mode": "access", "tagged": [], "untagged": None}


def test_classify_access_with_zero_access_vlan_drops_untagged():
    """VID 0 is out of range and produces untagged=None."""
    out = classify_switchport(_info(admin_mode="access", access_vlan=0))
    assert out == {"mode": "access", "tagged": [], "untagged": None}


def test_classify_trunk_native_oob_drops_native():
    """Out-of-range native_vlan coerces to None."""
    out = classify_switchport(_info(admin_mode="trunk", native_vlan=9999, allowed_vlans=[10, 20]))
    assert out == {"mode": "trunk", "tagged": [10, 20], "untagged": None}
