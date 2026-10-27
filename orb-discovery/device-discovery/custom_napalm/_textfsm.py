# Copyright 2026 NetBox Labs Inc
"""
ntc-templates parsing that skips lines a template does not know.

Most ntc-templates end each state with a catch-all ``^. -> Error`` rule, so a
single line added by newer firmware aborts the whole parse and fails the getter.
``parse_output_lenient`` parses strictly first. Only when that raises does it
parse again with the catch-all rules turned into skips, so unknown lines are
counted and logged instead.
"""

import logging
import os

import ntc_templates.parse
from ntc_templates.parse import parse_output
from textfsm import TextFSM, clitable
from textfsm.parser import TextFSMError

# Catch-all spellings used across ntc-templates, compared after stripping.
_CATCH_ALL_MATCHES = frozenset({"^.", "^.*", "^.+", "^.*$$"})
_SAMPLE_LINES = 3

# (host, platform, command) already warned about; repeats log at DEBUG.
_warned: set[tuple[str, str, str]] = set()


class _SkippingFSM(TextFSM):
    """TextFSM whose catch-all ``Error`` rules skip the line and record it instead of raising."""

    def __init__(self, template):
        """Build the FSM, then turn every catch-all ``Error`` rule into a plain skip."""
        super().__init__(template)
        self.skipped: list[str] = []
        self._skip_rules = set()
        for rules in self.states.values():
            for rule in rules:
                if rule.line_op == "Error" and rule.match.strip() in _CATCH_ALL_MATCHES:
                    rule.line_op = ""
                    rule.new_state = ""
                    self._skip_rules.add(rule)

    def _CheckRule(self, rule, line):
        matched = super()._CheckRule(rule, line)
        # ``^.*`` catch-alls also consume blank lines, which are not unknown content.
        if matched and rule in self._skip_rules and line.strip():
            self.skipped.append(line)
        return matched


def _template_dir() -> str:
    """Return the template directory ``parse_output`` reads, honouring ``NTC_TEMPLATES_DIR``."""
    template_dir = os.environ.get("NTC_TEMPLATES_DIR")
    if template_dir is None:
        template_dir = os.path.join(os.path.dirname(ntc_templates.parse.__file__), "templates")
    return template_dir


def _skipping_fsm(platform: str, command: str) -> _SkippingFSM | None:
    """Build the command's template with skipping catch-alls; None when the index merges several templates."""
    template_dir = _template_dir()
    index = clitable.CliTable("index", template_dir).index
    row = index.GetRowMatch({"Platform": platform, "Command": command})
    names = index.index[row]["Template"].split(":")
    if len(names) != 1:
        return None
    with open(os.path.join(template_dir, names[0]), encoding="utf-8") as template:
        return _SkippingFSM(template)


def parse_output_lenient(
    platform: str, command: str, data: str, *, host: str, logger: logging.Logger
) -> list[dict]:
    """
    Parse like ``parse_output``, skipping lines the template's catch-all rules reject.

    Logs how many lines were skipped and the first few distinct ones, at WARNING
    the first time for a host and command and at DEBUG after that. A template's
    targeted ``Error`` rules still raise.
    """
    try:
        return parse_output(platform=platform, command=command, data=data)
    except TextFSMError:
        fsm = _skipping_fsm(platform, command)
        if fsm is None:
            raise
    records = fsm.ParseText(data)

    key = (host, platform, command)
    level = logging.DEBUG if key in _warned else logging.WARNING
    _warned.add(key)
    sample = list(dict.fromkeys(line.strip() for line in fsm.skipped))[:_SAMPLE_LINES]
    count = len(fsm.skipped)
    logger.log(
        level,
        "%s: %s template for %r skipped %d %s it does not know, e.g. %s",
        host, platform, command, count, "line" if count == 1 else "lines", sample,
    )

    header = [name.lower() for name in fsm.header]
    return [dict(zip(header, record)) for record in records]
