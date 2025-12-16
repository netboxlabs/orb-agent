#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""Async TCP port scanning helpers and hostname expansion."""

import ipaddress
import logging
import socket
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


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
    """Expand hostname into a list of addresses; return parsed_as_range flag."""
    sanitized_hostname = hostname.strip()

    if "-" in sanitized_hostname:
        start_part, end_part = sanitized_hostname.split("-", 1)
        start_ip = _parse_range_endpoint(start_part)
        end_ip = _parse_range_endpoint(end_part, base=start_ip)
        if not start_ip or not end_ip or start_ip.version != end_ip.version:
            return [sanitized_hostname], False

        start_int, end_int = sorted((int(start_ip), int(end_ip)))
        hosts = [
            str(ipaddress.ip_address(ip_int)) for ip_int in range(start_int, end_int + 1)
        ]
        return hosts, True

    if "/" in sanitized_hostname:
        try:
            network = ipaddress.ip_network(sanitized_hostname, strict=False)
        except ValueError:
            return [sanitized_hostname], False

        hosts = [str(ip) for ip in network.hosts()]
        if not hosts:
            hosts = [str(network.network_address)]
        return hosts, True

    return [sanitized_hostname], False


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
