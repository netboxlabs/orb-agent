#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Tests for Defaults.stack_member_name_template validation/normalization."""

import logging

from device_discovery.policy.models import Defaults
from device_discovery.stack_naming import DEFAULT_STACK_MEMBER_TEMPLATE


def test_default_when_unset():
    """An unset template defaults to the legacy format."""
    assert Defaults().stack_member_name_template == DEFAULT_STACK_MEMBER_TEMPLATE


def test_valid_custom_template_is_kept():
    """A well-formed custom template is preserved verbatim."""
    d = Defaults(stack_member_name_template="{name}-css{id}")
    assert d.stack_member_name_template == "{name}-css{id}"


def test_invalid_template_falls_back_with_warning(caplog):
    """An unusable template is replaced by the default and logs a WARN (never raises)."""
    with caplog.at_level(logging.WARNING):
        d = Defaults(stack_member_name_template="{name}-{id:09d}")
    assert d.stack_member_name_template == DEFAULT_STACK_MEMBER_TEMPLATE
    assert any("stack_member_name_template" in r.message for r in caplog.records)


def test_missing_name_placeholder_falls_back():
    """A template without {name} collides across stacks, so it falls back."""
    d = Defaults(stack_member_name_template="member-{id}")
    assert d.stack_member_name_template == DEFAULT_STACK_MEMBER_TEMPLATE


def test_non_string_falls_back():
    """A non-string template falls back rather than raising a ValidationError."""
    d = Defaults(stack_member_name_template=123)
    assert d.stack_member_name_template == DEFAULT_STACK_MEMBER_TEMPLATE
