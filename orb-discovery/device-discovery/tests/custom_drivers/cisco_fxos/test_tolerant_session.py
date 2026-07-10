"""
Unit tests for custom_napalm.cisco_fxos._TolerantNxosSSH.session_preparation.

FXOS (and similar NX-OS-lookalike shells) authenticate fine but never echo
"terminal width 511" or the paging-disable command, so the stock
CiscoNxosSSH.session_preparation raises ReadTimeout before any getter can
run. These tests exercise session_preparation directly on an instance built
via __new__ (bypassing the real Netmiko connect/login flow) with the prep
steps mocked, to verify the tolerant subclass survives a non-echoing shell
and behaves identically to the stock behaviour on one that does echo.
"""

from unittest.mock import MagicMock

from netmiko.exceptions import ReadTimeout

from custom_napalm.cisco_fxos import _TolerantNxosSSH


def _make_instance() -> _TolerantNxosSSH:
    """Build a _TolerantNxosSSH instance without running Netmiko's real __init__/connect."""
    return object.__new__(_TolerantNxosSSH)


def test_session_preparation_tolerates_read_timeout_on_both_steps():
    """Both terminal-width and paging prep timing out must not abort session_preparation."""
    conn = _make_instance()
    conn._test_channel_read = MagicMock(return_value="")
    conn.set_terminal_width = MagicMock(side_effect=ReadTimeout("no echo"))
    conn.disable_paging = MagicMock(side_effect=ReadTimeout("no echo"))
    conn.set_base_prompt = MagicMock(return_value="")

    conn.session_preparation()

    conn._test_channel_read.assert_called_once()
    conn.set_terminal_width.assert_called_once()
    conn.disable_paging.assert_called_once()
    conn.set_base_prompt.assert_called_once()
    assert conn.ansi_escape_codes is True


def test_session_preparation_normal_path_applies_both_steps():
    """When the shell echoes normally, both prep steps run with no exception swallowed."""
    conn = _make_instance()
    conn._test_channel_read = MagicMock(return_value="")
    conn.set_terminal_width = MagicMock(return_value="terminal width 511")
    conn.disable_paging = MagicMock(return_value="")
    conn.set_base_prompt = MagicMock(return_value="")

    conn.session_preparation()

    conn._test_channel_read.assert_called_once()
    conn.set_terminal_width.assert_called_once()
    conn.disable_paging.assert_called_once()
    conn.set_base_prompt.assert_called_once()
    assert conn.ansi_escape_codes is True
