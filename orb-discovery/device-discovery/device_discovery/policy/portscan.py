#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""Async TCP port scanning helpers and hostname expansion."""

import ipaddress
import logging
import socket
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# Upper bound on how many addresses one scope entry may expand to.
#
# Every expanded address is materialized as a string and becomes its own
# discovery job, so the cost lands on both memory and connection attempts.
# ``ipaddress.ip_network`` is version-agnostic, so an IPv6 prefix parses just as
# cleanly as an IPv4 one, and a /64 -- the standard IPv6 subnet size, so the
# first thing an operator would try -- yields 2**64 addresses. Unbounded, the
# expansion allocates until the process dies, which takes every other policy
# down with it rather than failing the one scope. The bound is checked from the
# address count BEFORE anything is enumerated.
#
# 65536 is a /16 in IPv4 and a /112 in IPv6: wider than any plausible discovery
# scope, narrow enough that a mistyped prefix fails immediately.
MAX_EXPANDED_HOSTS = 65536


def _exceeds_expansion_cap(target: str, count: int) -> bool:
    """Return True (and say so) when ``target`` would expand past the cap."""
    if count <= MAX_EXPANDED_HOSTS:
        return False
    logger.error(
        "Target %s expands to %d addresses, above the limit of %d; skipping it. "
        "Narrow the prefix or range.",
        target, count, MAX_EXPANDED_HOSTS,
    )
    return True


def _parse_range_endpoint(token: str, base: ipaddress._BaseAddress | None = None):
    """Parse an IP/range endpoint, allowing partial IPv4 octet when base is given."""
    token = token.strip()
    try:
        return ipaddress.ip_address(token)
    except ValueError:
        pass

    try:
        return ipaddress.ip_interface(token).ip
    except ValueError:
        pass

    if base and isinstance(base, ipaddress.IPv4Address) and token.isdigit():
        last_octet = int(token)
        if 0 <= last_octet <= 255:
            octets = str(base).split(".")
            octets[-1] = str(last_octet)
            try:
                return ipaddress.ip_address(".".join(octets))
            except ValueError:
                return None
    return None


def expand_hostnames(hostname: str) -> tuple[list[str], bool]:
    """
    Expand a hostname into a list of addresses; return a parsed_as_range flag.

    Three forms are recognized, and the two expanding ones do NOT agree on
    count, which is deliberate but easy to trip over:

    - A range (``10.0.0.0-255``) is an operator enumerating addresses, so both
      endpoints are included: 256 hosts.
    - A CIDR (``10.0.0.0/24``) is a network, so the addresses that are
      structurally not hosts are excluded: 254, dropping the network and
      broadcast addresses. IPv6 has no broadcast, so only the network address
      goes: ``fd00::/126`` yields 3, not 2.
    - Anything else is returned unchanged with the flag False, including a
      CIDR or range that failed to parse.

    An expansion wider than ``MAX_EXPANDED_HOSTS`` yields an empty list with the
    flag True: the scope is skipped and named in an error, rather than allocating
    it. See that constant for why the bound is not optional.
    """
    sanitized_hostname = hostname.strip()

    if "-" in sanitized_hostname:
        start_part, end_part = sanitized_hostname.split("-", 1)
        start_ip = _parse_range_endpoint(start_part)
        end_ip = _parse_range_endpoint(end_part, base=start_ip)
        if not start_ip or not end_ip or start_ip.version != end_ip.version:
            return [sanitized_hostname], False

        start_int, end_int = sorted((int(start_ip), int(end_ip)))
        if _exceeds_expansion_cap(sanitized_hostname, end_int - start_int + 1):
            return [], True
        hosts = [
            str(ipaddress.ip_address(ip_int)) for ip_int in range(start_int, end_int + 1)
        ]
        return hosts, True

    if "/" in sanitized_hostname:
        try:
            network = ipaddress.ip_network(sanitized_hostname, strict=False)
        except ValueError:
            return [sanitized_hostname], False

        if _exceeds_expansion_cap(sanitized_hostname, network.num_addresses):
            return [], True
        return [str(ip) for ip in network.hosts()], True

    return [sanitized_hostname], False


def _network_host_count(network) -> int:
    """
    Host count for a network, without materializing anything.

    Mirrors what ``network.hosts()`` yields. A /31 and a /32 have no network and
    broadcast pair to exclude and stay 2 and 1, and the same holds for /127 and
    /128. IPv6 has no broadcast, so only the network address is excluded.
    """
    if network.prefixlen >= network.max_prefixlen - 1:
        return network.num_addresses
    return network.num_addresses - (2 if network.version == 4 else 1)


def count_hostnames(hostname: str) -> int:
    """
    Report how many addresses ``expand_hostnames`` would return, without expanding.

    A policy is charged against this before any target is expanded, so the two
    must never disagree about what a target means: this follows the same
    dispatch, calls the same endpoint parser, and treats anything unparseable as
    the single hostname the expander falls back to.

    The count is reported for targets the expander refuses as well. A refused
    target still has a size, and the size is exactly what the budget needs in
    order to refuse it before anything is allocated.
    """
    sanitized_hostname = hostname.strip()

    if "-" in sanitized_hostname:
        start_part, end_part = sanitized_hostname.split("-", 1)
        start_ip = _parse_range_endpoint(start_part)
        end_ip = _parse_range_endpoint(end_part, base=start_ip)
        if not start_ip or not end_ip or start_ip.version != end_ip.version:
            return 1
        start_int, end_int = sorted((int(start_ip), int(end_ip)))
        return end_int - start_int + 1

    if "/" in sanitized_hostname:
        try:
            network = ipaddress.ip_network(sanitized_hostname, strict=False)
        except ValueError:
            return 1
        return _network_host_count(network)

    return 1


def _probe_port(hostname: str, port: int, timeout: float) -> bool:
    """Return True if the TCP port is reachable using sockets."""
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return True
    except OSError:
        return False


def has_reachable_port(hostname: str, ports: Iterable[int], timeout: float) -> bool:
    """
    Check if any of the given TCP ports are reachable.

    Runs socket connects in a thread pool so it works even when an asyncio loop
    is already running.
    """
    port_list = list(dict.fromkeys(ports))
    if not port_list:
        return False

    worker_count = min(len(port_list), 64)
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [
            executor.submit(_probe_port, hostname, port, timeout)
            for port in port_list
        ]
        for future in as_completed(futures):
            try:
                if future.result():
                    return True
            except Exception:
                continue
    return False


def find_reachable_hosts(
    hostnames: Iterable[str], ports: Iterable[int], timeout: float
) -> dict[str, bool]:
    """
    Return a mapping of hostname -> reachability using threaded port probes.

    Each hostname is probed concurrently by calling has_reachable_port, which
    itself uses a thread pool for per-host port probing.
    """
    host_list = list(hostnames)
    port_list = list(ports or [])
    if not host_list or not port_list:
        return dict.fromkeys(host_list, False)

    worker_count = min(len(host_list), 64)
    results: dict[str, bool] = {}

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_host = {
            executor.submit(has_reachable_port, hostname, port_list, timeout): hostname
            for hostname in host_list
        }
        for future in as_completed(future_to_host):
            hostname = future_to_host[future]
            try:
                results[hostname] = future.result()
            except Exception as exc:
                logger.warning(
                    "Port scan failed for host %s with error: %s", hostname, exc
                )
                results[hostname] = False

    return results
