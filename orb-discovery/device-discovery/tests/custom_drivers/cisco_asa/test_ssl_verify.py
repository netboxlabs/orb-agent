"""Tests for the ssl_verify optional_arg of custom_napalm.cisco_asa.ASADriver."""

import ssl
from unittest.mock import Mock

from custom_napalm.cisco_asa import _OP_LEGACY_SERVER_CONNECT, ASADriver, _ASARest


def _https_ssl_context(rest: _ASARest) -> ssl.SSLContext:
    adapter = rest.session.get_adapter("https://example.invalid")
    return adapter.poolmanager.connection_pool_kw["ssl_context"]


def test_ssl_verify_defaults_to_false():
    """ssl_verify defaults to False, preserving pre-existing behaviour."""
    driver = ASADriver("device.example.invalid", "user", "pass")
    assert driver.device.ssl_verify is False


def test_ssl_verify_opt_in_via_optional_args():
    """optional_args ssl_verify=True is threaded into the HTTP helper."""
    driver = ASADriver("device.example.invalid", "user", "pass", optional_args={"ssl_verify": True})
    assert driver.device.ssl_verify is True


def test_auth_token_request_honours_ssl_verify():
    """The token request passes the configured verify flag to requests."""
    rest = _ASARest("user", "pass", "https://device.example.invalid/api", timeout=5, ssl_verify=True)
    response = Mock(status_code=204, headers={"X-Auth-Token": "tok"})
    rest.session.post = Mock(return_value=response)

    ok, code = rest.get_auth_token()

    assert ok is True
    assert rest.session.post.call_args.kwargs["verify"] is True


def test_get_resp_honours_ssl_verify():
    """API requests pass the configured verify flag to requests."""
    rest = _ASARest("user", "pass", "https://device.example.invalid/api", timeout=5, ssl_verify=True)
    response = Mock(status_code=200)
    response.json.return_value = {"kind": "object#QuerySerialNumber"}
    rest.session.get = Mock(return_value=response)

    rest.get_resp("/monitoring/serialnumber")

    assert rest.session.get.call_args.kwargs["verify"] is True


def test_tls_context_verifies_certificates_when_enabled():
    """verify=True yields a validating TLS context that keeps legacy renegotiation."""
    ctx = _https_ssl_context(_ASARest("user", "pass", "https://device.example.invalid/api", timeout=5, ssl_verify=True))
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.options & _OP_LEGACY_SERVER_CONNECT == _OP_LEGACY_SERVER_CONNECT


def test_tls_context_skips_verification_by_default():
    """A driver without ssl_verify still gets the non-validating legacy TLS context."""
    ctx = _https_ssl_context(ASADriver("device.example.invalid", "user", "pass").device)
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_NONE
