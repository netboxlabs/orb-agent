#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""Orb Discovery entry point."""

import argparse
import sys
from importlib.metadata import version

import netboxlabs.diode.sdk.version as SdkVersion
import uvicorn

from device_discovery.client import Client
from device_discovery.parser import parse_config_file
from device_discovery.server import app
from device_discovery.version import version_semver


def main():
    """
    Main entry point for the Agent CLI.

    Parses command-line arguments and starts the backend.
    """
    parser = argparse.ArgumentParser(description="Orb Discovery Backend")
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"Discovery version: {version_semver()}, NAPALM version: {version('napalm')}, "
        f"Diode SDK version: {SdkVersion.version_semver()}",
        help="Display Discovery, NAPALM and Diode SDK versions",
    )
    parser.add_argument(
        "-c",
        "--config",
        metavar="config.yaml",
        help="Yaml configuration file",
        type=str,
        required=True,
    )
    args = parser.parse_args()

    try:
        cfg = parse_config_file(args.config)
        client = Client()
        client.init_client(target=cfg.config.target, api_key=cfg.config.api_key)
        uvicorn.run(
            app,
            host=cfg.config.host,
            port=cfg.config.port,
        )
    except (KeyboardInterrupt, RuntimeError):
        pass
    except Exception as e:
        sys.exit(f"ERROR: Unable to start discovery backend: {e}")


if __name__ == "__main__":
    main()
