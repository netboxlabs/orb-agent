"""
Unit tests for custom_napalm.cisco_asa_ssh._parse_output_resilient.

These tests replace the real ``ntc_templates.parse.parse_output`` call with a
controllable fake so the bounded strip-and-retry behaviour can be verified in
isolation from the actual cisco_asa TextFSM templates (which are exercised
end-to-end by the ``redundant_member`` / ``firepower_block`` driver
scenarios in ``test_driver.py``).
"""

import logging

import pytest
from textfsm.parser import TextFSMError

from custom_napalm import cisco_asa_ssh


@pytest.fixture
def logger():
    """A real (but isolated) logger so `.warning` calls don't error."""
    return logging.getLogger("test.cisco_asa_ssh.parse_resilient")


def test_strips_offending_line_once_and_succeeds(monkeypatch, logger):
    """One retriable TextFSMError is stripped and the second attempt succeeds."""
    calls = []

    def fake_parse_output(platform, command, data):
        calls.append(data)
        if len(calls) == 1:
            raise TextFSMError(
                "State Error raised. Rule Line: 94. Input Line:                               Driver version        : 4.12.0"
            )
        return [{"ok": True}]

    monkeypatch.setattr(cisco_asa_ssh, "parse_output", fake_parse_output)

    data = "line one\n                              Driver version        : 4.12.0\nline three"
    result = cisco_asa_ssh._parse_output_resilient("show version", data, logger)

    assert result == [{"ok": True}]
    assert len(calls) == 2
    # The offending line must be gone from the retried data.
    assert "Driver version" not in calls[1]
    assert "line one" in calls[1]
    assert "line three" in calls[1]


def test_reraises_when_message_has_no_input_line(monkeypatch, logger):
    """A TextFSMError without an 'Input Line:' marker is not retriable — re-raise as-is."""
    calls = []

    def fake_parse_output(platform, command, data):
        calls.append(data)
        raise TextFSMError("Some unrelated template compilation failure")

    monkeypatch.setattr(cisco_asa_ssh, "parse_output", fake_parse_output)

    with pytest.raises(TextFSMError, match="Some unrelated template compilation failure"):
        cisco_asa_ssh._parse_output_resilient("show version", "irrelevant data", logger)

    assert len(calls) == 1


def test_bounded_by_max_stripped_lines(monkeypatch, logger):
    """An endless stream of distinct offending lines is bounded, not retried forever."""
    calls = []

    def fake_parse_output(platform, command, data):
        calls.append(data)
        first_line = data.splitlines()[0]
        raise TextFSMError(f"State Error raised. Rule Line: 94. Input Line: {first_line}")

    monkeypatch.setattr(cisco_asa_ssh, "parse_output", fake_parse_output)

    # More unique lines than _MAX_STRIPPED_LINES so every retry finds something new to strip.
    data = "\n".join(f"unique line {i}" for i in range(cisco_asa_ssh._MAX_STRIPPED_LINES + 10))

    with pytest.raises(TextFSMError, match=r"more than \d+ lines"):
        cisco_asa_ssh._parse_output_resilient("show version", data, logger)

    assert len(calls) == cisco_asa_ssh._MAX_STRIPPED_LINES
