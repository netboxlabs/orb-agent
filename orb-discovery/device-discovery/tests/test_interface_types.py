#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Tests for the vendored NetBox interface-type value set."""

from device_discovery.interface_types import VALID_INTERFACE_TYPES


def test_valid_interface_types_has_structural_and_physical():
    """Structural + physical NetBox types are present; device-native ones are not."""
    for t in ("lag", "virtual", "bridge", "other", "1000base-t", "10gbase-x-sfpp"):
        assert t in VALID_INTERFACE_TYPES
    # device-native / bogus values must NOT be considered valid NetBox types
    for bogus in ("ether", "bond", "G/10Gig", "not-a-type"):
        assert bogus not in VALID_INTERFACE_TYPES
    assert len(VALID_INTERFACE_TYPES) > 150
