#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""Discover the correct NAPALM Driver."""

import inspect
import logging
from importlib import import_module
from importlib.metadata import packages_distributions
from pkgutil import walk_packages
from typing import Any

from napalm import get_network_driver
from napalm.base.base import NetworkDriver

# Set up logging
logging.basicConfig(level=logging.INFO)
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
    napalm_packages = ["eos", "ios", "iosxr_netconf", "junos", "nxos", "nxos_ssh"]
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


supported_drivers = napalm_driver_list()


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


def discover_device_driver(info: dict) -> str | None:
    """
    Discover the correct NAPALM driver for the given device information.

    Args:
    ----
        info (dict): A dictionary containing device connection information.
            Expected keys are 'hostname', 'username', 'password', 'timeout',
            and 'optional_args'.

    Returns:
    -------
        str: The name of the driver that successfully connects and identifies
             the device. Returns an empty string if no suitable driver is found.

    """
    set_napalm_logs_level(logging.CRITICAL)
    for driver in supported_drivers:
        try:
            logger.info(f"Hostname {info.hostname}: Trying '{driver}' driver")
            np_driver = get_network_driver(driver)
            with np_driver(
                info.hostname,
                info.username,
                info.password,
                info.timeout,
                info.optional_args,
            ) as device:
                device_info = device.get_facts()
                if device_info.get("serial_number", "Unknown").lower() == "unknown":
                    logger.info(
                        f"Hostname {info.hostname}: '{driver}' driver did not work"
                    )
                    continue
                set_napalm_logs_level(logging.INFO)
                return driver
        except Exception as e:
            logger.info(
                f"Hostname {info.hostname}: '{driver}' driver did not work. Exception: {str(e)}"
            )
    set_napalm_logs_level(logging.INFO)
    return None
