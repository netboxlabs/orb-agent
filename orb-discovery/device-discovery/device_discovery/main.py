#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""Device Discovery entry point."""

import argparse
import os
import sys
from importlib.metadata import version

import netboxlabs.diode.sdk.version as SdkVersion
import uvicorn

from device_discovery.client import Client
from device_discovery.metrics import setup_metrics_export
from device_discovery.server import app
from device_discovery.version import version_semver


def main():
    """
    Main entry point for the Agent CLI.

    Parses command-line arguments and starts the backend.
    """
    parser = argparse.ArgumentParser(description="Orb Device Discovery Backend")
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"Device Discovery version: {version_semver()}, NAPALM version: {version('napalm')}, "
        f"Diode SDK version: {SdkVersion.version_semver()}",
        help="Display Device Discovery, NAPALM and Diode SDK versions",
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
        default=8072,
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
        "-c",
        "--diode-client-id",
        help="Diode Client ID. Environment variables can be used by wrapping them in ${} (e.g. ${MY_CLIENT_ID})",
        type=str,
        required=True,
    )

    parser.add_argument(
        "-k",
        "--diode-client-secret",
        help="Diode Client Secret. Environment variables can be used by wrapping them in ${} (e.g. ${MY_CLIENT_SECRET})",
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

    parser.add_argument(
        "--otel-endpoint",
        help="OpenTelemetry exporter endpoint",
        type=str,
        required=False,
    )

    parser.add_argument(
        "--otel-export-period",
        help="Period in seconds between OpenTelemetry exports (default: 60)",
        type=int,
        default=60,
        required=False,
    )

    try:
        args = parser.parse_args()
        target = args.diode_target
        if target.startswith("${") and target.endswith("}"):
            env_var = target[2:-1]
            target = os.getenv(env_var, target)
        client_id = args.diode_client_id
        if client_id.startswith("${") and client_id.endswith("}"):
            env_var = client_id[2:-1]
            client_id = os.getenv(env_var, client_id)
        client_secret = args.diode_client_secret
        if client_secret.startswith("${") and client_secret.endswith("}"):
            env_var = client_secret[2:-1]
            client_secret = os.getenv(env_var, client_secret)

        if args.otel_endpoint:
            setup_metrics_export(args.otel_endpoint, args.otel_export_period)

        client = Client()
        client.init_client(
            prefix=args.diode_app_name_prefix,
            target=target,
            client_id=client_id,
            client_secret=client_secret,
        )

        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
        )
    except (KeyboardInterrupt, RuntimeError):
        pass
    except Exception as e:
        sys.exit(f"ERROR: Unable to start discovery backend: {e}")


if __name__ == "__main__":
    main()
