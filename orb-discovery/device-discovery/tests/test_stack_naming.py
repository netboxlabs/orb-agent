#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Tests for stack member name templating helpers."""

import pytest

from device_discovery.stack_naming import (
    DEFAULT_STACK_MEMBER_TEMPLATE,
    render_stack_member_name,
    stack_template_problem,
)


def test_default_template_reproduces_legacy_name():
    """The default template renders the historical <name>-<id> form."""
    assert DEFAULT_STACK_MEMBER_TEMPLATE == "{name}-{id}"
    assert render_stack_member_name(DEFAULT_STACK_MEMBER_TEMPLATE, "sw-stack", 1) == "sw-stack-1"


def test_custom_template_renders():
    """A custom template substitutes both placeholders."""
    assert render_stack_member_name("{name}-css{id}", "sw-stack", 2) == "sw-stack-css2"


@pytest.mark.parametrize("tmpl", ["{name}-{id}", "{name}-css{id}", "{name}_{id}_unit"])
def test_valid_templates_have_no_problem(tmpl):
    """Well-formed templates report no problem."""
    assert stack_template_problem(tmpl) is None


@pytest.mark.parametrize(
    "tmpl,needle",
    [
        ("", "empty"),
        ("   ", "empty"),
        ("{id}", "name"),  # missing {name} -> cross-stack collision
        ("{name}", "vary"),  # no id -> not distinct per member
        ("{name}-{foo}", "unknown"),  # unknown placeholder
        ("{name}-{id:09d}", "disallow"),  # ':' format spec
        ("{name}-{id.real}", "disallow"),  # '.' attribute access
    ],
)
def test_invalid_templates_report_a_problem(tmpl, needle):
    """Unusable templates report a reason containing the expected keyword."""
    problem = stack_template_problem(tmpl)
    assert problem is not None and needle in problem.lower()
