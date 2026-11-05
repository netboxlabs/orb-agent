#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""Discover the correct NAPALM Driver."""

import copy
import inspect
import logging
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from importlib import import_module
from importlib.metadata import packages_distributions
from pkgutil import walk_packages
from typing import Any

from jnpr.junos.exception import ConnectAuthError as JunosConnectAuthError
from napalm import get_network_driver
from napalm.base.base import NetworkDriver
from napalm.nxapi_plumbing.errors import NXAPIAuthError
from ncclient.transport.errors import AuthenticationError as NetconfAuthenticationError
from paramiko.ssh_exception import AuthenticationException

from device_discovery.log_config import configure_default_logging, failure_text

_DRIVER_MISMATCH_MARKERS = ["%", "Invalid input", "^"]

# Set up logging
configure_default_logging()
logger = logging.getLogger(__name__)


def walk_napalm_packages(module: Any, prefix: str, packages: list[str]) -> list[str]:
    """
    Walks a directory tree looking for napalm network driver classes.

    This function walks the directory tree rooted at the given module's path,
    looking for submodules that contain napalm network driver classes.

    Args:
    ----
        module (Any): The module to start walking from.
        prefix (str): The prefix to prepend to package names.
        packages (list[str]): A list to store the found package names.

    Returns:
    -------
        list[str]: A list of package names that contain napalm network driver classes.

    """
    for package in walk_packages(module.__path__, module.__name__ + "."):
        try:
            submodule = import_module(package.name)
            for _, obj in inspect.getmembers(submodule):
                if (
                    inspect.isclass(obj)
                    and issubclass(obj, NetworkDriver)
                    and obj is not NetworkDriver
                ):
                    packages.append(package.name[len(prefix) :])
                    break
        except Exception as e:
            logger.error(f"Error importing module {package.name}: {str(e)}")
    return packages


def napalm_driver_list() -> list[str]:
    """
    List the available NAPALM drivers.

    This function scans the installed Python modules to identify NAPALM drivers,
    appending their names (with the 'napalm_' prefix removed) to a list of known drivers.

    Returns
    -------
        List[str]: A list of strings representing the names of available NAPALM drivers.
                   The list includes some predefined driver names and dynamically
                   discovered driver names from the installed packages.

    """
    napalm_packages = ["eos", "ios", "iosxr", "iosxr_netconf", "junos", "nxos", "nxos_ssh"]
    prefix = "napalm_"
    for dist in packages_distributions():
        if dist.startswith(prefix):
            package_found = False
            try:
                module = import_module(dist)
                for _, obj in inspect.getmembers(module):
                    if inspect.isclass(obj) and issubclass(obj, NetworkDriver):
                        napalm_packages.append(dist[len(prefix) :])
                        package_found = True
                        break
                if package_found:
                    continue
                napalm_packages = walk_napalm_packages(module, prefix, napalm_packages)
            except Exception as e:
                logger.error(f"Error importing module {dist}: {str(e)}")
    return napalm_packages


def custom_napalm_driver_list() -> list[str]:
    """
    List the available custom NAPALM drivers from the custom_napalm package.

    Returns
    -------
        List[str]: Driver short-names (e.g. 'panos', 'huawei_vrp') found in custom_napalm.

    """
    try:
        module = import_module("custom_napalm")
        return walk_napalm_packages(module, "custom_napalm.", [])
    except Exception as e:
        logger.error(f"Error loading custom_napalm drivers: {str(e)}")
        return []


_default_discovery_drivers = napalm_driver_list()
# Dedup the union so native names that also have a custom_napalm override
# (e.g. eos, ios, nxos) appear once. NAPALM's get_network_driver() looks
# up custom_napalm.<name> before napalm.<name>, so the custom override is
# always selected at runtime regardless of this list's order — the dedup
# is cosmetic but keeps the /api/v1/drivers payload clean.
supported_drivers = list(
    dict.fromkeys(_default_discovery_drivers + custom_napalm_driver_list()),
)


def set_napalm_logs_level(level: int):
    """
    Set the logging level for NAPALM and related libraries.

    Args:
    ----
        level (int): The logging level to set. Typically, this can be one of the
                     standard logging levels (e.g., logging.DEBUG, logging.INFO,
                     logging.WARNING, logging.ERROR, logging.CRITICAL).

    This function adjusts the logging levels for the "napalm", "ncclient","paramiko"
    and "pyeapi" loggers to the specified level, which is useful for controlling the
    verbosity of log output from these libraries.

    """
    logging.getLogger("napalm").setLevel(level)
    logging.getLogger("ncclient").setLevel(level)
    logging.getLogger("paramiko").setLevel(level)
    logging.getLogger("pyeapi").setLevel(level)


def discover_device_driver(
    info: dict, drivers: list[str] | None = None, policy: str | None = None
) -> str | None:
    """
    Discover the correct NAPALM driver for the given device information.

    Args:
    ----
        info (dict): A dictionary containing device connection information.
            Expected keys are 'hostname', 'username', 'password', 'timeout',
            and 'optional_args'.
        drivers (list[str] | None): An optional list of driver names to try.
            When provided, only those drivers are attempted. When None,
            only standard NAPALM drivers are tried (custom_napalm drivers
            are excluded from auto-discovery unless explicitly specified).
        policy (str | None): The policy the device belongs to, named in every log line.

    Returns:
    -------
        str: The name of the driver that successfully connects and identifies
             the device. Returns an empty string if no suitable driver is found.

    """
    host = str(info.hostname).replace("\r\n", "").replace("\n", "")
    prefix = f"Policy {policy}, Hostname {host}" if policy else f"Hostname {host}"
    set_napalm_logs_level(logging.CRITICAL)
    try:
        driver_list = drivers if drivers is not None else _default_discovery_drivers
        refused = []
        credentials_work = False
        for driver in driver_list:
            outcome = _try_driver(info, driver, prefix)
            if outcome == _MATCH:
                return driver
            if outcome == _REFUSED:
                refused.append(driver)
            elif outcome == _READ_FACTS:
                credentials_work = True
        # Facts read with the same credentials show a refusal was transient,
        # so each refused driver gets one more try. Only facts count: some
        # drivers open a session without logging in.
        if credentials_work:
            for driver in refused:
                logger.info(
                    "%s: retrying '%s' driver, its login was refused but another "
                    "driver read the device with the same credentials",
                    prefix,
                    driver,
                )
                if _try_driver(info, driver, prefix) == _MATCH:
                    return driver
        return None
    finally:
        set_napalm_logs_level(logging.getLogger().getEffectiveLevel())


_MATCH = "match"
_READ_FACTS = "read facts"
_REFUSED = "refused"
_FAILED = "failed"

# What a refused login raises: netmiko's exception subclasses paramiko's, and
# PyEZ (junos), ncclient (NETCONF drivers) and NX-API raise their own. Drivers
# that wrap one, as iosxr and iosxr_netconf do, keep it as the cause. eos over
# eAPI reports a refusal as a plain connection error and is not told apart.
_LOGIN_REFUSED = (
    AuthenticationException,
    JunosConnectAuthError,
    NetconfAuthenticationError,
    NXAPIAuthError,
)


def _refused(error: BaseException | None) -> bool:
    """Whether a driver failed on a refused login, also when it wrapped the refusal in another error."""
    seen = set()
    while error is not None and id(error) not in seen:
        if isinstance(error, _LOGIN_REFUSED):
            return True
        seen.add(id(error))
        if error.__cause__ is not None:
            error = error.__cause__
        else:
            error = None if error.__suppress_context__ else error.__context__
    return False


@contextmanager
def driver_session(device: Any, prefix: str) -> Iterator[Any]:
    """
    Open a driver session and always close it.

    NAPALM's own context manager prints a bug-report request to stdout for any
    exception it does not define, and a close that fails there turns a
    session that read everything into a failure. Here a failed close is one
    WARNING line.
    """
    try:
        device.open()
    except Exception:
        with suppress(Exception):
            device.close()
        raise
    try:
        yield device
    finally:
        try:
            device.close()
        except Exception as e:
            logger.warning(f"{prefix}: Error closing the session: {failure_text(e)}")


class DriverMismatchError(Exception):
    """A driver's facts show it does not fit the device it logged in to."""


def _cli_error_in(facts: dict, *fields: str) -> bool:
    """Whether any of these facts holds CLI error output instead of a name."""
    return any(
        marker in str(facts.get(field) or "")
        for marker in _DRIVER_MISMATCH_MARKERS
        for field in fields
    )


def _unknown(value: object) -> bool:
    # junos reports facts it could not read as the text "None".
    return not value or str(value).strip().lower() in ("unknown", "none")


def facts_mismatch(facts: dict) -> str | None:
    """
    Why a driver's facts cannot be a real device, or None when they can.

    A missing serial number alone is accepted: virtual devices often have none,
    and a driver set on the scope entry has always ingested them. The FQDN is
    not checked: it is never sent as the name while it holds error text.
    """
    if _cli_error_in(facts, "hostname"):
        return "its hostname holds CLI error output"
    if _unknown(facts.get("hostname")) and _unknown(facts.get("serial_number")):
        return "it reported no hostname and no serial number"
    return None


def _try_driver(info: Any, driver: str, prefix: str) -> str:
    """Try one driver: a match, facts from another platform, a refused login, or another failure."""
    try:
        logger.info("%s: Trying '%s' driver", prefix, driver)
        np_driver = get_network_driver(driver)
        # Drivers pop and rename keys in optional_args (iosxr_netconf
        # takes port and ssh_config_file), so each one gets its own copy.
        with driver_session(
            np_driver(
                info.hostname,
                info.username,
                info.password,
                info.timeout,
                copy.deepcopy(info.optional_args),
            ),
            f"{prefix}: '{driver}' driver",
        ) as device:
            device_info = device.get_facts()
            serial = device_info.get("serial_number", "Unknown")
            # Collection refuses what facts_mismatch names, so discovery must not pick it.
            if (
                str("Unknown" if serial is None else serial).lower() == "unknown"
                or _cli_error_in(device_info, "hostname", "fqdn")
                or facts_mismatch(device_info)
            ):
                logger.info("%s: '%s' driver did not work", prefix, driver)
                return _READ_FACTS
            return _MATCH
    except Exception as e:
        # One line: netmiko's messages span ten, and the agent splits stderr per line.
        logger.info(
            "%s: '%s' driver did not work. Exception: %s", prefix, driver, failure_text(e)
        )
        return _REFUSED if _refused(e) else _FAILED
