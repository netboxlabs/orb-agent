#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""Orb Worker entry point."""

import argparse
import os
import sys

import netboxlabs.diode.sdk.version as SdkVersion
import uvicorn

from worker.models import DiodeConfig
from worker.server import app, manager
from worker.version import version_semver


def main():
    """
    Main entry point for the Agent CLI.

    Parses command-line arguments and starts the backend.
    """
    parser = argparse.ArgumentParser(description="Orb Worker Backend")
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"Worker version: {version_semver()},  "
        f"Diode SDK version: {SdkVersion.version_semver()}",
        help="Display Version",
    )
    parser.add_argument(
        "-s",
        "--host",
        default="0.0.0.0",
        help="Server host",
        type=str,
        required=False,
    )
    parser.add_argument(
        "-p",
        "--port",
        default=8071,
        help="Server port",
        type=int,
        required=False,
    )
    parser.add_argument(
        "-t",
        "--diode-target",
        help="Diode target",
        type=str,
        required=True,
    )

    parser.add_argument(
        "-k",
        "--diode-api-key",
        help="Diode API key. Environment variables can be used by wrapping them in ${} (e.g. ${MY_API_KEY})",
        type=str,
        required=True,
    )

    parser.add_argument(
        "-a",
        "--diode-app-name-prefix",
        help="Diode producer_app_name prefix",
        type=str,
        required=False,
    )

    try:
        args = parser.parse_args()
        api_key = args.diode_api_key
        if api_key.startswith("${") and api_key.endswith("}"):
            env_var = api_key[2:-1]
            api_key = os.getenv(env_var, api_key)

        config = DiodeConfig(
            target=args.diode_target, prefix=args.diode_app_name_prefix, api_key=api_key
        )
        manager.setup(config)
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
        )
    except (KeyboardInterrupt, RuntimeError):
        pass
    except Exception as e:
        sys.exit(f"ERROR: Unable to start worker backend: {e}")


if __name__ == "__main__":
    main()
