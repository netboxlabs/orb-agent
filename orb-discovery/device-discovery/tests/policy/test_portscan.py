#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""NetBox Labs - Port scanning helpers tests."""

from unittest.mock import MagicMock

import device_discovery.policy.portscan as portscan


def test_expand_hostnames_range_sorted():
    """Ensure IP range expansion returns sorted, inclusive hosts."""
    hosts, parsed_as_range = portscan.expand_hostnames("10.0.0.3-10.0.0.1")

    assert parsed_as_range is True
    assert hosts == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_expand_hostnames_cidr_and_single_host():
    """Ensure CIDR ranges and /32 addresses are expanded correctly."""
    hosts, parsed_as_range = portscan.expand_hostnames("192.0.2.0/30")
    assert parsed_as_range is True
    assert hosts == ["192.0.2.1", "192.0.2.2"]

    hosts, parsed_as_range = portscan.expand_hostnames("192.0.2.10/32")
    assert parsed_as_range is True
    assert hosts == ["192.0.2.10"]


def test_expand_hostnames_invalid_range_returns_original():
    """Invalid ranges fall back to the original hostname."""
    hosts, parsed_as_range = portscan.expand_hostnames("router-alpha-beta")

    assert parsed_as_range is False
    assert hosts == ["router-alpha-beta"]


def test_expand_hostnames_partial_ipv4_range_last_octet():
    """Support shorthand last-octet ranges like 192.168.1.10-20."""
    hosts, parsed = portscan.expand_hostnames("192.168.1.10-20")

    assert parsed is True
    assert hosts == [
        "192.168.1.10",
        "192.168.1.11",
        "192.168.1.12",
        "192.168.1.13",
        "192.168.1.14",
        "192.168.1.15",
        "192.168.1.16",
        "192.168.1.17",
        "192.168.1.18",
        "192.168.1.19",
        "192.168.1.20",
    ]


def test_expand_hostnames_masked_range_uses_ip_portion():
    """Range endpoints can include masks; the IP portion defines bounds."""
    hosts, parsed = portscan.expand_hostnames("192.168.3.22/28-192.168.4.22/28")

    assert parsed is True
    assert hosts[0] == "192.168.3.22"
    assert hosts[-1] == "192.168.4.22"
    # Inclusive count between the two addresses
    assert len(hosts) == 257


def test_has_reachable_port_returns_true_for_any_reachable(monkeypatch):
    """Should return True when any probed port is reachable."""
    calls: list[tuple[str, int, float]] = []

    def fake_probe(hostname, port, timeout):
        calls.append((hostname, port, timeout))
        return port == 443

    monkeypatch.setattr(portscan, "_probe_port", fake_probe)

    reachable = portscan.has_reachable_port("example.com", [22, 443, 443], 1.0)

    assert reachable is True
    probed_ports = {port for _, port, _ in calls}
    assert probed_ports == {22, 443}


def test_has_reachable_port_handles_exceptions(monkeypatch):
    """Exceptions during probing are ignored and treated as unreachable."""

    def flaky_probe(hostname, port, timeout):
        if port == 22:
            raise OSError("connection refused")
        return False

    monkeypatch.setattr(portscan, "_probe_port", flaky_probe)

    reachable = portscan.has_reachable_port("example.com", [22, 80], 0.1)

    assert reachable is False


def test_has_reachable_port_with_no_ports(monkeypatch):
    """No ports configured should skip probing and return False."""
    mock_probe = MagicMock()
    monkeypatch.setattr(portscan, "_probe_port", mock_probe)

    reachable = portscan.has_reachable_port("example.com", [], 1.0)

    assert reachable is False
    mock_probe.assert_not_called()


def test_find_reachable_hosts_returns_mapping(monkeypatch):
    """Reachability results are returned per-host with shared port list."""
    calls: list[tuple[str, tuple[int, ...], float]] = []

    def fake_reachable(hostname, ports, timeout):
        calls.append((hostname, tuple(ports), timeout))
        return hostname == "host-a"

    monkeypatch.setattr(portscan, "has_reachable_port", fake_reachable)

    result = portscan.find_reachable_hosts(
        ["host-a", "host-b"], ports=[22, 80], timeout=0.25
    )

    assert result == {"host-a": True, "host-b": False}
    assert ("host-a", (22, 80), 0.25) in calls
    assert ("host-b", (22, 80), 0.25) in calls


def test_find_reachable_hosts_logs_exceptions(monkeypatch):
    """Host errors are logged and treated as unreachable."""

    def flaky_reachable(hostname, ports, timeout):
        if hostname == "bad-host":
            raise RuntimeError("boom")
        return True

    mock_logger = MagicMock()
    monkeypatch.setattr(portscan, "has_reachable_port", flaky_reachable)
    monkeypatch.setattr(portscan, "logger", mock_logger)

    result = portscan.find_reachable_hosts(
        ["bad-host", "good-host"], ports=[22], timeout=0.1
    )

    assert result["bad-host"] is False
    assert result["good-host"] is True
    mock_logger.warning.assert_called_once()


def test_expand_hostnames_rejects_cidr_over_the_cap(monkeypatch):
    """A prefix wider than the cap expands to nothing instead of allocating it."""
    mock_logger = MagicMock()
    monkeypatch.setattr(portscan, "logger", mock_logger)

    # /15 is 131072 addresses, twice the cap. Deliberately small enough that
    # the unguarded version fails fast rather than hanging the suite.
    hosts, parsed = portscan.expand_hostnames("10.0.0.0/15")

    assert hosts == []
    assert parsed is True
    mock_logger.error.assert_called_once()
    message = mock_logger.error.call_args[0][0] % mock_logger.error.call_args[0][1:]
    assert "10.0.0.0/15" in message
    assert str(portscan.MAX_EXPANDED_HOSTS) in message


def test_expand_hostnames_rejects_range_over_the_cap(monkeypatch):
    """The range branch is bounded too, not just the CIDR branch."""
    mock_logger = MagicMock()
    monkeypatch.setattr(portscan, "logger", mock_logger)

    hosts, parsed = portscan.expand_hostnames("10.0.0.0-10.2.0.0")

    assert hosts == []
    assert parsed is True
    mock_logger.error.assert_called_once()


def test_expand_hostnames_allows_a_cidr_exactly_at_the_cap():
    """The cap is inclusive, so the largest allowed prefix still expands."""
    hosts, parsed = portscan.expand_hostnames("10.0.0.0/16")

    assert parsed is True
    assert len(hosts) == portscan.MAX_EXPANDED_HOSTS - 2  # network + broadcast


def test_expand_hostnames_rejects_a_standard_ipv6_subnet(monkeypatch):
    """
    The reported case: a /64 returns at once instead of allocating 2**64 strings.

    Before the cap this call never returned. It is the first thing an operator
    would type, since /64 is the standard IPv6 subnet size, and it took the
    whole process down rather than failing the one scope.
    """
    mock_logger = MagicMock()
    monkeypatch.setattr(portscan, "logger", mock_logger)

    hosts, parsed = portscan.expand_hostnames("2001:db8::/64")

    assert hosts == []
    assert parsed is True
    mock_logger.error.assert_called_once()


def test_expand_hostnames_keeps_small_ipv6_prefixes():
    """Bounded IPv6 prefixes are still legitimate targets and must survive."""
    hosts, parsed = portscan.expand_hostnames("2001:db8::/120")

    assert parsed is True
    assert len(hosts) == 255
    assert hosts[0] == "2001:db8::1"


def test_count_hostnames_agrees_with_expand_for_every_shape():
    """
    Counting and expanding must never disagree about what a target means.

    The policy budget is charged from count_hostnames against notation the
    expander has not run yet, so a shape the two read differently would let a
    policy pay one price and allocate another. Cross-checked here rather than
    asserted per-shape, so a new branch in one has to be added to the other.
    """
    shapes = [
        "10.0.0.0/24",
        "10.0.0.0/22",
        "10.0.0.4/31",
        "10.0.0.5/32",
        "fd00::/126",
        "2001:db8::/120",
        "10.0.0.0-255",
        "192.168.1.10-20",
        "10.0.0.3-10.0.0.1",
        "192.168.3.22/28-192.168.4.22/28",
        "router-alpha-beta",
        "plain-hostname.example.com",
        "10.0.0.1",
    ]

    for shape in shapes:
        expanded, _ = portscan.expand_hostnames(shape)
        assert portscan.count_hostnames(shape) == len(expanded), (
            f"{shape}: count and expand disagree"
        )


def test_count_hostnames_does_not_materialize_an_oversized_target():
    """
    A target the expander refuses is still counted, and counted cheaply.

    The whole point of counting is to price a policy before paying for it, so
    the count has to be available for exactly the targets expansion would
    decline. A /64 has 2**64 addresses and must come back as that number
    rather than as the empty list the expander returns.
    """
    # Host counts, matching what expansion would have returned: IPv6 drops the
    # network address, IPv4 drops network and broadcast.
    assert portscan.count_hostnames("2001:db8::/64") == 2**64 - 1
    assert portscan.count_hostnames("0.0.0.0/0") == 2**32 - 2
