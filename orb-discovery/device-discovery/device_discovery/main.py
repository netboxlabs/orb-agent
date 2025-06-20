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


def resolve_env_var(value: str) -> str:
    """
    Resolve environment variable if value is in ${VAR_NAME} format.

    Args:
    ----
        value (str): The value to resolve, may contain ${ENV_VAR} pattern

    Returns:
    -------
        str: The resolved value from environment variable, or original value if not a variable reference

    """
    if value.startswith("${") and value.endswith("}"):
        env_var = value[2:-1]
        return os.getenv(env_var, value)
    return value


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
        help="Diode target. Environment variable can be used by wrapping it in ${} (e.g. ${TARGET})",
        type=str,
        required=False,
    )

    parser.add_argument(
        "-c",
        "--diode-client-id",
        help="Diode Client ID. Environment variable can be used by wrapping it in ${} (e.g. ${MY_CLIENT_ID})",
        type=str,
        required=False,
    )

    parser.add_argument(
        "-k",
        "--diode-client-secret",
        help="Diode Client Secret. Environment variable can be used by wrapping it in ${} (e.g. ${MY_CLIENT_SECRET})",
        type=str,
        required=False,
    )

    parser.add_argument(
        "-a",
        "--diode-app-name-prefix",
        help="Diode producer_app_name prefix",
        type=str,
        required=False,
    )

    parser.add_argument(
        "-d",
        "--dry-run",
        help="Run in dry-run mode, do not ingest data",
        action="store_true",
        required=False,
    )

    parser.add_argument(
        "-o",
        "--dry-run-output-dir",
        help="Output dir for dry-run mode. Environment variable can be used by wrapping it in ${} (e.g. ${OUTPUT_DIR})",
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
        if not args.dry_run:
            missing = [
                name
                for name, val in [
                    ("--diode-target", args.diode_target),
                    ("--diode-client-id", args.diode_client_id),
                    ("--diode-client-secret", args.diode_client_secret),
                ]
                if not val
            ]
            if missing:
                parser.error(
                    f"{', '.join(missing)} required when not running with --dry-run"
                )

        target = resolve_env_var(args.diode_target) if args.diode_target else None
        client_id = (
            resolve_env_var(args.diode_client_id) if args.diode_client_id else None
        )
        client_secret = (
            resolve_env_var(args.diode_client_secret)
            if args.diode_client_secret
            else None
        )
        output_dir = (
            resolve_env_var(args.dry_run_output_dir)
            if args.dry_run_output_dir
            else None
        )

        if args.otel_endpoint:
            setup_metrics_export(args.otel_endpoint, args.otel_export_period)

        client = Client()
        client.init_client(
            prefix=args.diode_app_name_prefix,
            target=target,
            client_id=client_id,
            client_secret=client_secret,
            dry_run=args.dry_run,
            dry_run_output_dir=output_dir,
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
