#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""NetBox Labs - Policy Models Unit Tests."""

import pytest
from pydantic import ValidationError

from device_discovery.policy.models import Options


def test_options_create_unknown_vlans_default_true():
    """Options.create_unknown_vlans defaults to True."""
    opts = Options()
    assert opts.create_unknown_vlans is True


def test_options_create_unknown_vlans_overridable():
    """Options.create_unknown_vlans accepts an explicit False override."""
    opts = Options(create_unknown_vlans=False)
    assert opts.create_unknown_vlans is False


def test_options_discover_modules_default_off():
    """Options.discover_modules defaults to 'off' (backwards compatibility)."""
    opts = Options()
    assert opts.discover_modules == "off"


@pytest.mark.parametrize("value", ["off", "linecards", "full"])
def test_options_discover_modules_accepts_enum_values(value):
    """Options.discover_modules accepts each documented enum value."""
    opts = Options(discover_modules=value)
    assert opts.discover_modules == value


def test_options_discover_modules_rejects_unknown_value():
    """Options.discover_modules rejects values outside the enum."""
    with pytest.raises(ValidationError):
        Options(discover_modules="bogus")
