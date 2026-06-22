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
