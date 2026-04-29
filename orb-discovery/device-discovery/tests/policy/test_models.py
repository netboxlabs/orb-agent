#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""NetBox Labs - Policy Models Unit Tests."""

from device_discovery.policy.models import Options


def test_options_create_unknown_vlans_default_true():
    """Options.create_unknown_vlans defaults to True."""
    opts = Options()
    assert opts.create_unknown_vlans is True


def test_options_create_unknown_vlans_overridable():
    """Options.create_unknown_vlans accepts an explicit False override."""
    opts = Options(create_unknown_vlans=False)
    assert opts.create_unknown_vlans is False
