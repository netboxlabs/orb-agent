"""Unit tests for custom_napalm._textfsm.parse_output_lenient."""

import logging

import pytest
from ntc_templates.parse import ParsingException, parse_output
from textfsm.parser import TextFSMError

from custom_napalm import _textfsm
from custom_napalm._textfsm import parse_output_lenient

_LOGGER = "test.custom_napalm.textfsm"
_HOST = "192.0.2.10"


@pytest.fixture(autouse=True)
def _fresh_warning_state(monkeypatch):
    """Each test starts with no host/command already warned about."""
    monkeypatch.setattr(_textfsm, "_warned", set())


def _parse(platform, command, data, host=_HOST):
    return parse_output_lenient(platform, command, data, host=host, logger=logging.getLogger(_LOGGER))

_BRIEF_KNOWN = """\
PHY: Physical
*down: administratively down
InUti/OutUti: input utility/output utility
Interface                   PHY   Protocol  InUti OutUti   inErrors  outErrors
GigabitEthernet0/0/1        up    up        0.01%  0.01%          0          0
GigabitEthernet0/0/2        down  down         0%     0%          0          0
"""

_BRIEF_UNKNOWN_LEGEND = """\
PHY: Physical
*down: administratively down
-down: link flap down
InUti/OutUti: input utility/output utility
Interface                   PHY   Protocol  InUti OutUti   inErrors  outErrors
GigabitEthernet0/0/1        up    up        0.01%  0.01%          0          0
GigabitEthernet0/0/2        down  down         0%     0%          0          0
"""


def _template_dir(tmp_path, templates: dict[str, str], command_rows: list[str]):
    """Write an ntc-templates style index plus templates and return the directory."""
    index = "Template, Hostname, Platform, Command\n\n" + "\n".join(command_rows) + "\n"
    (tmp_path / "index").write_text(index, encoding="utf-8")
    for name, body in templates.items():
        (tmp_path / name).write_text(body, encoding="utf-8")
    return tmp_path


_TWO_STATE_TEMPLATE = """\
Value NAME (\\S+)

Start
  ^name\\s+${NAME} -> Record
  ^begin -> Block
  ^forbidden -> Error
  ^. -> Error

Block
  ^end -> Start
  ^. -> Error
"""

# Catch-all spellings other ntc-templates use, including one carrying a message.
_SPELLINGS_TEMPLATE = """\
Value NAME (\\S+)

Start
  ^name\\s+${NAME} -> Record
  ^a -> A
  ^.* -> Error

A
  ^b -> B
  ^.+ -> Error

B
  ^c -> C
  ^.*$$ -> Error

C
  ^d -> D
  ^.  -> Error

D
  ^e -> Start
  ^. -> Error "unexpected line"
"""


def _use_templates(tmp_path, monkeypatch, templates: dict[str, str], command_rows: list[str]):
    monkeypatch.setenv("NTC_TEMPLATES_DIR", str(_template_dir(tmp_path, templates, command_rows)))


def test_known_output_parses_strictly_without_warning(caplog):
    """Output the template accepts comes back exactly as parse_output returns it, with no warning."""
    with caplog.at_level(logging.DEBUG, logger=_LOGGER):
        rows = _parse("huawei_vrp", "display interface brief", _BRIEF_KNOWN)

    assert rows == parse_output(platform="huawei_vrp", command="display interface brief", data=_BRIEF_KNOWN)
    assert caplog.records == []


def test_unknown_line_is_skipped_with_a_warning(caplog):
    """A line the template rejects is skipped; the rows around it still parse and the warning names host and line."""
    with pytest.raises(TextFSMError):
        parse_output(platform="huawei_vrp", command="display interface brief", data=_BRIEF_UNKNOWN_LEGEND)

    with caplog.at_level(logging.DEBUG, logger=_LOGGER):
        rows = _parse("huawei_vrp", "display interface brief", _BRIEF_UNKNOWN_LEGEND)

    assert rows == parse_output(platform="huawei_vrp", command="display interface brief", data=_BRIEF_KNOWN)
    assert [r.levelno for r in caplog.records] == [logging.WARNING]
    message = caplog.records[0].getMessage()
    assert _HOST in message
    assert "skipped 1 line" in message
    assert "-down: link flap down" in message


def test_warning_counts_every_skipped_line_and_samples_distinct_ones(tmp_path, monkeypatch, caplog):
    """The warning counts all skipped lines, including repeats, and quotes the first three distinct ones."""
    _use_templates(tmp_path, monkeypatch, {"t.textfsm": _TWO_STATE_TEMPLATE}, ["t.textfsm, .*, test_os, show thing"])
    data = "x1\nname a\nx1\nx2\nx3\nx4\n"

    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        _parse("test_os", "show thing", data)

    message = caplog.records[0].getMessage()
    assert "skipped 5 lines" in message
    assert "['x1', 'x2', 'x3']" in message
    assert "x4" not in message


def test_blank_lines_a_catch_all_consumes_are_not_counted(tmp_path, monkeypatch, caplog):
    """``^.*`` also matches empty lines; those are not unknown content, so they are neither counted nor sampled."""
    _use_templates(tmp_path, monkeypatch, {"t.textfsm": _SPELLINGS_TEMPLATE}, ["t.textfsm, .*, test_os, show thing"])

    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        _parse("test_os", "show thing", "name a\n\n   \nstray\n")

    message = caplog.records[0].getMessage()
    assert "skipped 1 line" in message
    assert "['stray']" in message


def test_repeat_warnings_for_a_host_and_command_drop_to_debug(caplog):
    """The same host and command warn once; repeats log at DEBUG, and another host still warns."""
    with caplog.at_level(logging.DEBUG, logger=_LOGGER):
        _parse("huawei_vrp", "display interface brief", _BRIEF_UNKNOWN_LEGEND)
        _parse("huawei_vrp", "display interface brief", _BRIEF_UNKNOWN_LEGEND)
        _parse("huawei_vrp", "display interface brief", _BRIEF_UNKNOWN_LEGEND, host="192.0.2.11")

    assert [r.levelno for r in caplog.records] == [logging.WARNING, logging.DEBUG, logging.WARNING]


def test_unknown_lines_are_skipped_in_every_state(tmp_path, monkeypatch):
    """The catch-all error rule is neutralised in every state, not only Start."""
    _use_templates(tmp_path, monkeypatch, {"t.textfsm": _TWO_STATE_TEMPLATE}, ["t.textfsm, .*, test_os, show thing"])
    data = "name a\nstray in start\nbegin\nstray in block\nend\nname b\n"

    assert _parse("test_os", "show thing", data) == [{"name": "a"}, {"name": "b"}]


def test_other_catch_all_spellings_are_skipped(tmp_path, monkeypatch):
    """``^.*``, ``^.+``, ``^.*$$``, extra spacing and a catch-all with a message all skip instead of raising."""
    _use_templates(tmp_path, monkeypatch, {"t.textfsm": _SPELLINGS_TEMPLATE}, ["t.textfsm, .*, test_os, show thing"])
    # TextFSM keeps the trailing space of ``^.  -> Error``, so only a line with a space after its first character hits it.
    data = "name a\n?\na\n?\nb\n?\nc\n? x\nd\n?\ne\nname b\n"

    assert _parse("test_os", "show thing", data) == [{"name": "a"}, {"name": "b"}]


def test_specific_error_rules_still_raise_without_a_warning(tmp_path, monkeypatch, caplog):
    """A template's own targeted Error rule still fails the parse, and nothing claims lines were skipped."""
    _use_templates(tmp_path, monkeypatch, {"t.textfsm": _TWO_STATE_TEMPLATE}, ["t.textfsm, .*, test_os, show thing"])

    with caplog.at_level(logging.DEBUG, logger=_LOGGER), pytest.raises(TextFSMError, match="forbidden"):
        _parse("test_os", "show thing", "name a\nstray\nforbidden\n")

    assert caplog.records == []


def test_multi_template_command_reraises_the_strict_error(tmp_path, monkeypatch):
    """Commands parsed by several merged templates are not retried; the strict error propagates."""
    _use_templates(
        tmp_path,
        monkeypatch,
        {"a.textfsm": _TWO_STATE_TEMPLATE, "b.textfsm": _TWO_STATE_TEMPLATE},
        ["a.textfsm:b.textfsm, .*, test_os, show thing"],
    )

    with pytest.raises(TextFSMError, match="stray"):
        _parse("test_os", "show thing", "name a\nstray\n")


def test_command_without_a_template_still_raises_parsing_exception():
    """A command the index has no template for is not a TextFSM rejection; ntc-templates' own error propagates."""
    with pytest.raises(ParsingException):
        _parse("no_such_platform", "show thing", "irrelevant\n")
