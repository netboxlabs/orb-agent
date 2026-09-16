# Vendored FortiOS captures

Source: https://github.com/networktocode/ntc-templates `tests/fortinet/` (Apache-2.0).
`flat_*` are `get system interface`, `phys_*` are `get system interface physical`.

Routable addresses were replaced with the RFC 5737 documentation range 203.0.113.0/24,
preserving the four-octet shape. Nothing else was altered: indentation, field order and
line endings are as upstream, including the CRLF line endings of the 7.0 flat capture and
the `== [ VPN-TUN ]` / `name: VPN-LAB` mismatch in the 6.0 flat capture. Verified by diffing
against fresh upstream copies: identical line counts, and every differing line differs only
in an address token.

These are the no-regression baseline for the local parsers in
`custom_napalm/fortinet_fortios_ssh.py`. See `baseline.json` and `../test_corpus_parity.py`.
