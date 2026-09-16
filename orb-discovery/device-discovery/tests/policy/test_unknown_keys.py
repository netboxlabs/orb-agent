#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""NetBox Labs - Unrecognized Policy Key Warning Unit Tests."""

import logging

import yaml

from device_discovery.policy.models import Config, Options, PolicyRequest

MISPLACED_OPTION = """
policies:
  my-policy:
    config:
      discover_modules: full
      defaults:
        site: test-site
    scope:
      - hostname: 10.0.0.1
        username: u
        password: p
        driver: ios
"""


def test_misplaced_option_is_reported_with_the_nesting_it_belongs_under(caplog):
    """
    An option written at config level names the path it should have used.

    This is the exact shape that made a real report unreproducible: the key
    is silently dropped, module discovery stays off, and the entity count is
    identical with and without it.
    """
    with caplog.at_level(logging.WARNING):
        PolicyRequest(policies=yaml.safe_load(MISPLACED_OPTION)["policies"])
    messages = [r.getMessage() for r in caplog.records]
    assert any("discover_modules" in m for m in messages), messages
    assert any("options.discover_modules" in m for m in messages), f"expected the correct path in the warning, got {messages}"


def test_unknown_key_is_reported_even_with_no_suggestion(caplog):
    """A key that matches nothing anywhere is still reported rather than dropped."""
    with caplog.at_level(logging.WARNING):
        Config(**{"totally_made_up_key": 42})
    messages = [r.getMessage() for r in caplog.records]
    assert any("totally_made_up_key" in m for m in messages), messages


def test_recognized_keys_are_silent(caplog):
    """A correct policy logs nothing, so the warning stays meaningful."""
    good = """
    policies:
      my-policy:
        config:
          options:
            discover_modules: full
          defaults:
            site: test-site
        scope:
          - hostname: 10.0.0.1
            username: u
            password: p
            driver: ios
    """
    with caplog.at_level(logging.WARNING):
        req = PolicyRequest(policies=yaml.safe_load(good)["policies"])
    assert req.policies["my-policy"].config.options.discover_modules == "full"
    assert [r.getMessage() for r in caplog.records] == []


def test_unknown_keys_do_not_change_parsed_values(caplog):
    """The key is still ignored: warning only, no behaviour change."""
    with caplog.at_level(logging.WARNING):
        opts = Options(discover_modules="full", bogus="x")
    assert opts.discover_modules == "full"
    assert not hasattr(opts, "bogus")


def test_options_block_reports_its_own_unknown_keys(caplog):
    """The options block is checked too, not just the config block above it."""
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        Options(nope_option=1)
    joined = " ".join(r.getMessage() for r in caplog.records)
    assert "nope_option" in joined, joined
    assert "options" in joined, joined


def test_blocks_with_operator_chosen_keys_stay_silent(caplog):
    """
    Only config and options are checked, by design.

    The policy map is keyed by names an operator picks, scope entries vary by
    driver, and the surrounding YAML may carry anchors. Warning on those would
    fire on correct files, which would train operators to ignore the warning.
    """
    from device_discovery.policy.models import Defaults, Napalm, Policy

    with caplog.at_level(logging.WARNING):
        Defaults(site="s", anchor_leftover=1)
        Napalm(hostname="h", username="u", password="p", extra_scope_key=1)
        Policy(scope=[{"hostname": "h", "username": "u", "password": "p"}], stray=1)
    assert [r.getMessage() for r in caplog.records] == []
