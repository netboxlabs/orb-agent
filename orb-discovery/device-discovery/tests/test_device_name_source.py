#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Tests for the device_name_source option (hostname vs fqdn Device.name)."""

import pytest

from device_discovery.device_name import apply_device_name_emission
from device_discovery.policy.models import Defaults, Options
from device_discovery.translate import (
    _resolve_device_name,
    translate_data,
    translate_device,
)

DEVICE_INFO = {
    "hostname": "core-rtr-01",
    "fqdn": "core-rtr-01.dc1.example.net",
    "vendor": "Juniper",
    "model": "MX240",
    "serial_number": "JN123456",
    "os_version": "23.4R2.13",
    "interface_list": ["xe-0/0/0"],
}

FQDN_OPTIONS = Options(device_name_source="fqdn")


@pytest.fixture
def defaults():
    """Minimal policy defaults."""
    return Defaults(site="Site A")


# ---------------------------------------------------------------------------
# Basic selection
# ---------------------------------------------------------------------------


def test_default_option_keeps_hostname(defaults):
    """Without the option, Device.name is the hostname fact (old behavior)."""
    device = translate_device(dict(DEVICE_INFO), defaults, options=Options())
    assert device.name == "core-rtr-01"


def test_no_options_keeps_hostname(defaults):
    """options=None keeps the hostname fact."""
    device = translate_device(dict(DEVICE_INFO), defaults)
    assert device.name == "core-rtr-01"


def test_fqdn_source_uses_fqdn_fact(defaults):
    """device_name_source: fqdn names the device by the fqdn fact."""
    device = translate_device(dict(DEVICE_INFO), defaults, options=FQDN_OPTIONS)
    assert device.name == "core-rtr-01.dc1.example.net"


def test_fqdn_comparison_is_case_insensitive():
    """Hostname/fqdn case differences must not reject a real FQDN."""
    info = dict(DEVICE_INFO, hostname="CORE-RTR-01")
    assert (
        _resolve_device_name(info, FQDN_OPTIONS) == "core-rtr-01.dc1.example.net"
    )


# ---------------------------------------------------------------------------
# Positive validation: everything not clearly hostname + "." + more falls back
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_fqdn",
    [
        None,  # fact missing entirely
        "",  # empty
        "None",  # junos stringifies an undetermined fqdn fact
        "Unknown",  # ios-family placeholder default
        "N/A",  # paloalto placeholder
        "core-rtr-01.not set",  # ios keeps the text after "Default domain is"
        "core-rtr-01",  # no domain configured -> fqdn == hostname
        "CORE-RTR-01",  # same, case-insensitively
        "core-rtr-01.",  # trailing dot only, no label after the hostname
        "other-host.dc1.example.net",  # not derived from this hostname
    ],
)
def test_fqdn_source_falls_back_to_hostname(defaults, bad_fqdn):
    """Values failing the positive check fall back to the hostname fact."""
    info = dict(DEVICE_INFO, fqdn=bad_fqdn)
    device = translate_device(info, defaults, options=FQDN_OPTIONS)
    assert device.name == "core-rtr-01"


def test_dotted_hostname_is_kept_to_avoid_double_domain():
    """ios/junos build hostname+'.'+domain blindly; guard the doubled form."""
    info = dict(
        DEVICE_INFO,
        hostname="rtr1.dc1.example.net",
        fqdn="rtr1.dc1.example.net.dc1.example.net",
    )
    assert _resolve_device_name(info, FQDN_OPTIONS) == "rtr1.dc1.example.net"


def test_blank_hostname_omits_name():
    """No usable hostname means no name, even if an fqdn fact is present."""
    info = dict(DEVICE_INFO, hostname="")
    assert _resolve_device_name(info, FQDN_OPTIONS) is None


# ---------------------------------------------------------------------------
# Option value normalization (mirrors emit_prefix_vlan)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("FQDN", "fqdn"), ("  fqdn  ", "fqdn"), ("Hostname", "hostname"), (None, "hostname")],
)
def test_option_value_is_normalized(raw, expected):
    """Trim + lowercase; None resolves to the default."""
    assert Options(device_name_source=raw).device_name_source == expected


def test_unrecognized_option_value_warns_and_defaults(caplog):
    """A typo keeps today's naming instead of failing the whole policy."""
    with caplog.at_level("WARNING"):
        opts = Options(device_name_source="dns")
    assert opts.device_name_source == "hostname"
    assert any("device_name_source" in r.getMessage() for r in caplog.records)


def test_boolean_option_value_warns_and_defaults(caplog):
    """A bare YAML on/off arrives as a boolean and names no source."""
    with caplog.at_level("WARNING"):
        opts = Options(device_name_source=True)
    assert opts.device_name_source == "hostname"


def test_sequence_option_value_is_rejected():
    """yaml.v3 rejects a sequence into the Go twin's string field; match it."""
    with pytest.raises(ValueError):
        Options(device_name_source=["fqdn"])


# ---------------------------------------------------------------------------
# Nested stubs and emit_device_name interplay
# ---------------------------------------------------------------------------


def test_nested_stubs_on_interfaces_and_ips_carry_the_fqdn(defaults):
    """Interface and IPAddress device stubs inherit the resolved name."""
    data = {
        "driver": "junos",
        "device": dict(DEVICE_INFO),
        "interface": {
            "xe-0/0/0": {
                "is_enabled": True,
                "is_up": True,
                "speed": 10000,
                "mtu": 1500,
                "mac_address": "aa:bb:cc:dd:ee:ff",
                "description": "",
                "last_flapped": -1.0,
            }
        },
        "interface_ip": {"xe-0/0/0": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}},
        "defaults": defaults,
        "options": FQDN_OPTIONS,
    }
    entities = list(translate_data(data))
    fqdn = "core-rtr-01.dc1.example.net"

    devices = [e.device for e in entities if e.HasField("device")]
    assert devices and all(d.name == fqdn for d in devices)

    ifaces = [e.interface for e in entities if e.HasField("interface")]
    assert ifaces and all(i.device.name == fqdn for i in ifaces)

    ips = [e.ip_address for e in entities if e.HasField("ip_address")]
    assert ips and all(
        ip.assigned_object_interface.device.name == fqdn for ip in ips
    )


def test_emit_device_name_false_still_suppresses_the_fqdn(defaults):
    """emit_device_name: false is orthogonal and wins over the fqdn name."""
    device = translate_device(
        dict(DEVICE_INFO), defaults, options=FQDN_OPTIONS, netbox_id=42
    )
    assert device.name == "core-rtr-01.dc1.example.net"
    assert apply_device_name_emission(device, False, "10.0.0.5") is True
    assert device.HasField("name") is False


# ---------------------------------------------------------------------------
# Virtual chassis: FQDN naming does not apply to stacks
# ---------------------------------------------------------------------------


def _stack_data():
    return {
        "driver": "ios",
        "device": {
            "hostname": "core-sw",
            "vendor": "Cisco",
            "model": "WS-C3850-12XS",
            "os_version": "17.6.4",
            "serial_number": "FOC2401L0AB",
            "uptime": 12345.0,
            "fqdn": "core-sw.dc1.example.net",
            "interface_list": [],
        },
        "interface": {},
        "interface_ip": {},
        "chassis_members": {
            "members": [
                {"id": 1, "serial": "FOC2401L0AB", "model": "WS-C3850-12XS",
                 "role": "active", "priority": 15, "mac": "aabb.cc00.0001",
                 "state": "ready"},
                {"id": 2, "serial": "FOC2401L0CD", "model": "WS-C3850-12XS",
                 "role": "standby", "priority": 14, "mac": "aabb.cc00.0002",
                 "state": "ready"},
            ],
            "domain": None,
        },
        "target_hostname": "core-sw",
        "options": FQDN_OPTIONS,
    }


def test_stack_members_keep_template_names_including_master():
    """Every stack member — the master included — is template-named."""
    entities = list(translate_data(_stack_data()))
    names = {e.device.name for e in entities if e.HasField("device")}
    assert names == {"core-sw-1", "core-sw-2"}

    vcs = [e.virtual_chassis for e in entities if e.HasField("virtual_chassis")]
    assert len(vcs) == 1
    assert vcs[0].master.name == "core-sw-1"


# ---------------------------------------------------------------------------
# Real driver outputs: no driver may yield a bad name
# ---------------------------------------------------------------------------

# (driver, hostname, fqdn) triples harvested from the NAPALM test suite's
# test_get_facts expected results (napalm/test/<driver>/mocked_data/...),
# covering every core driver that reports both facts.
NAPALM_FACT_PAIRS = [
    ("eos", "localhost", "localhost"),  # normal
    ("ios", "NS2903-ASW-01", "NS2903-ASW-01.int.ogenstad.com"),  # normal
    ("ios", "NS2903-ASW-01", "Unknown"),  # empty_show_hosts
    ("ios", "c2950", "c2950.example.com"),  # old-2950
    ("iosxr", "edge01.tab01", "edge01.tab01"),  # normal
    ("iosxr", "iosxr3", "iosxr3"),  # normal_alt_form
    ("iosxr_netconf", "NCS540-27", "NCS540-27"),  # ncs540
    ("iosxr_netconf", "NCS540DE-39", "NCS540DE-39"),  # ncs540l
    ("iosxr_netconf", "NCS5516-632", "NCS5516-632"),  # ncs5500
    ("iosxr_netconf", "hope", "hope"),  # 8000
    ("iosxr_netconf", "pavarotti", "pavarotti"),  # xrv9k
    ("iosxr_netconf", "santiago-temp", "santiago-temp"),  # asr9k-x64
    ("junos", "vsrx", "vsrx"),  # normal
    ("nxos", "nxos-spine1", "nxos-spine1.domain.com"),  # normal
    ("nxos_ssh", "EGGS-SW01", "EGGS-SW01.spam.com"),  # 7009_6_2_14
    ("nxos_ssh", "SWITCHNAME", "SWITCHNAME.dcn.fr.tld.com"),  # N93180
    ("nxos_ssh", "SWITCH_NXOSv", "SWITCH_NXOSv.y.z.a.com"),  # newer_version
    ("nxos_ssh", "nxos1", ""),  # missing_domain
    ("nxos_ssh", "nxos1", "nxos1.twb-tech.com"),  # normal
    # Not in the NAPALM tree but reported in review:
    ("panos", "fw1", "N/A"),
    ("ios", "rtr1", "rtr1.not set"),  # "Default domain is not set"
]


@pytest.mark.parametrize(("driver", "hostname", "fqdn"), NAPALM_FACT_PAIRS)
def test_real_driver_facts_never_yield_a_bad_name(driver, hostname, fqdn):
    """Over real get_facts outputs the result is the hostname or a real FQDN."""
    name = _resolve_device_name(
        {"hostname": hostname, "fqdn": fqdn}, FQDN_OPTIONS
    )
    assert name == hostname or (
        name == fqdn
        and not any(ch.isspace() for ch in name)
        and name.lower().startswith(hostname.lower() + ".")
    )
