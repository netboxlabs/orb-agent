"""Unit tests for custom_napalm.nxos.nxos_row_to_switchport_info (inlined from former _nxos_common)."""

from custom_napalm.nxos import _maybe_int, nxos_row_to_switchport_info


def test_maybe_int_rejects_bool_true():
    """Reject ``bool`` (int subclass) so it does not coerce to VID 1."""
    assert _maybe_int(True) is None


def test_maybe_int_rejects_bool_false():
    """Mirrors True case: False must not coerce to VID 0."""
    assert _maybe_int(False) is None


def test_maybe_int_passes_through_string_int():
    """Plain string-int still coerces normally."""
    assert _maybe_int("42") == 42


def test_maybe_int_treats_none_sentinel_as_none():
    """NX-OS emits 'none' for absent voice VLAN; mapper returns None."""
    assert _maybe_int("none") is None


def test_nxos_disabled_switchport_is_routed():
    """Switchport 'Disabled' means the port is in routed (L3) mode."""
    info = nxos_row_to_switchport_info({"switchport": "Disabled"})
    assert info.enabled is False


def test_nxos_access_basic():
    """NX-API access row produces correct access_vlan and voice_vlan=None for 'none'."""
    info = nxos_row_to_switchport_info({
        "switchport": "Enabled",
        "admin_mode": "access",
        "oper_mode": "access",
        "access_vlan": "100",
        "native_vlan": "1",
        "voice_vlan": "none",
        "trunk_vlans": "1-4094",
    })
    assert info.enabled is True
    assert info.admin_mode == "access"
    assert info.access_vlan == 100
    assert info.voice_vlan is None  # "none" string → None


def test_nxos_voice_vlan_extracted():
    """Numeric voice_vlan string is coerced to int."""
    info = nxos_row_to_switchport_info({
        "switchport": "Enabled",
        "admin_mode": "access",
        "access_vlan": "100",
        "voice_vlan": "200",
    })
    assert info.voice_vlan == 200


def test_nxos_trunk_with_explicit_list():
    """Trunk row with comma-separated VIDs produces an explicit allowed_vlans list."""
    info = nxos_row_to_switchport_info({
        "switchport": "Enabled",
        "admin_mode": "trunk",
        "oper_mode": "trunk",
        "native_vlan": "1",
        "trunk_vlans": "10,20,30",
    })
    assert info.admin_mode == "trunk"
    assert info.allowed_vlans == [10, 20, 30]


def test_nxos_trunk_full_range_is_wildcard():
    """'1-4094' trunk_vlans collapses to the 'all' wildcard sentinel."""
    info = nxos_row_to_switchport_info({
        "switchport": "Enabled",
        "admin_mode": "trunk",
        "native_vlan": "1",
        "trunk_vlans": "1-4094",
    })
    assert info.allowed_vlans == "all"


def test_nxos_dynamic_admin_falls_through_to_oper():
    """'dynamic auto' admin_mode normalizes to 'dynamic'; oper_mode is preserved."""
    info = nxos_row_to_switchport_info({
        "switchport": "Enabled",
        "admin_mode": "dynamic auto",
        "oper_mode": "trunk",
        "native_vlan": "1",
        "trunk_vlans": "10",
    })
    assert info.admin_mode == "dynamic"
    assert info.oper_mode == "trunk"


def test_nxos_missing_keys_safe_defaults_to_access():
    """Row with only 'switchport: Enabled' resolves to access via the SSH oper-down heuristic."""
    info = nxos_row_to_switchport_info({"switchport": "Enabled"})
    assert info.enabled is True
    assert info.admin_mode == "access"
    assert info.access_vlan is None


def test_nxos_oper_down_defaults_to_access_to_preserve_vlan_data():
    """Down switchport on the SSH path defaults to access so access_vlan still drives classification."""
    info = nxos_row_to_switchport_info({
        "switchport": "Enabled",
        "mode": "down",
        "access_vlan": "100",
        "native_vlan": "1",
        "voice_vlan": "none",
        "trunking_vlans": "1-4094",
    })
    assert info.enabled is True
    assert info.admin_mode == "access"
    assert info.access_vlan == 100


def test_nxos_oper_down_inference_does_not_override_explicit_admin():
    """Heuristic must NOT fire when admin_mode is explicitly set (NX-API path)."""
    info = nxos_row_to_switchport_info({
        "switchport": "Enabled",
        "admin_mode": "trunk",
        "oper_mode": "down",
        "native_vlan": "99",
        "trunk_vlans": "10,20",
    })
    assert info.admin_mode == "trunk"
    assert info.oper_mode is None  # "down" is not a recognized oper-mode value


# ----- ntc-templates alias paths (cisco_nxos template emits 'mode' / 'trunking_vlans') -----

def test_nxos_ntc_template_mode_alias_access():
    """ntc-templates row uses 'mode' (operational), no admin_mode key."""
    info = nxos_row_to_switchport_info({
        "switchport": "Enabled",
        "mode": "access",  # alias for both admin_mode AND oper_mode
        "access_vlan": "100",
        "native_vlan": "1",
        "voice_vlan": "none",
        "trunking_vlans": "1-4094",  # alias for trunk_vlans
    })
    assert info.enabled is True
    assert info.admin_mode == "access"
    assert info.oper_mode == "access"
    assert info.access_vlan == 100


def test_nxos_ntc_template_mode_alias_trunk():
    """ntc-templates trunk row via 'mode' alias with 'trunking_vlans' list."""
    info = nxos_row_to_switchport_info({
        "switchport": "Enabled",
        "mode": "trunk",
        "access_vlan": "1",
        "native_vlan": "99",
        "voice_vlan": "none",
        "trunking_vlans": "10,20,30",
    })
    assert info.admin_mode == "trunk"
    assert info.oper_mode == "trunk"
    assert info.allowed_vlans == [10, 20, 30]
    assert info.native_vlan == 99


def test_nxos_ntc_template_trunking_vlans_full_range_wildcard():
    """ntc-templates 'trunking_vlans: 1-4094' collapses to the 'all' wildcard."""
    info = nxos_row_to_switchport_info({
        "switchport": "Enabled",
        "mode": "trunk",
        "trunking_vlans": "1-4094",
        "native_vlan": "1",
    })
    assert info.allowed_vlans == "all"


def test_nxos_nxapi_keys_take_priority_over_aliases():
    """When both 'admin_mode' (NX-API) and 'mode' (ntc) are present, prefer NX-API."""
    info = nxos_row_to_switchport_info({
        "switchport": "Enabled",
        "admin_mode": "trunk",
        "mode": "access",  # ntc alias — must NOT override admin_mode
        "trunk_vlans": "10",
        "trunking_vlans": "999",  # alias — must be ignored
        "native_vlan": "1",
    })
    assert info.admin_mode == "trunk"
    assert info.allowed_vlans == [10]
