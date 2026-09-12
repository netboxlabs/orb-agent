#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Tests for the device_name_source option (hostname vs fqdn Device.name)."""

import pytest

from device_discovery.policy.models import Defaults, Options
from device_discovery.translate import _resolve_device_name, translate_device

DEVICE_INFO = {
    "hostname": "core-rtr-01",
    "fqdn": "core-rtr-01.dc1.example.net",
    "vendor": "Juniper",
    "model": "MX240",
    "serial_number": "JN123456",
    "os_version": "23.4R2.13",
    "interface_list": ["xe-0/0/0"],
}


@pytest.fixture
def defaults():
    """Minimal policy defaults."""
    return Defaults(site="Site A")


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
    options = Options(device_name_source="fqdn")
    device = translate_device(dict(DEVICE_INFO), defaults, options=options)
    assert device.name == "core-rtr-01.dc1.example.net"


@pytest.mark.parametrize(
    "bad_fqdn",
    [
        None,  # fact missing entirely
        "",  # empty
        "None",  # junos stringifies an undetermined fqdn fact
        "Unknown",  # ios-family placeholder default
        "core-rtr-01",  # no domain configured -> fqdn == hostname
    ],
)
def test_fqdn_source_falls_back_to_hostname(defaults, bad_fqdn):
    """Unusable fqdn values fall back to the hostname fact."""
    info = dict(DEVICE_INFO, fqdn=bad_fqdn)
    options = Options(device_name_source="fqdn")
    device = translate_device(info, defaults, options=options)
    assert device.name == "core-rtr-01"


def test_fqdn_source_with_blank_hostname_and_fqdn_omits_name():
    """No usable hostname AND no usable fqdn must OMIT Device.name."""
    info = dict(DEVICE_INFO, hostname="", fqdn="Unknown")
    assert _resolve_device_name(info, Options(device_name_source="fqdn")) is None


def test_fqdn_source_with_blank_hostname_still_uses_fqdn():
    """A usable fqdn names the device even when the hostname fact is blank."""
    info = dict(DEVICE_INFO, hostname="")
    name = _resolve_device_name(info, Options(device_name_source="fqdn"))
    assert name == "core-rtr-01.dc1.example.net"


def test_invalid_source_value_rejected():
    """Unknown device_name_source values fail policy validation."""
    with pytest.raises(ValueError):
        Options(device_name_source="dns")
