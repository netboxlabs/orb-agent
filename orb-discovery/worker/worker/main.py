#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""Orb Worker entry point."""

import argparse
import os
import sys

import netboxlabs.diode.sdk.version as SdkVersion
import uvicorn
from netboxlabs.diode.sdk import DiodeClient

from worker.metrics import setup_metrics_export
from worker.models import DiodeConfig
from worker.server import app, manager
from worker.version import version_semver


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
    parser = argparse.ArgumentParser(description="Orb Worker Backend")
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"Orb Worker version: {version_semver()},  "
        f"Diode SDK version: {SdkVersion.version_semver()}",
        help="Display Orb Worker and Diode SDK versions",
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

        config = DiodeConfig(
            target=target,
            prefix=args.diode_app_name_prefix,
            client_id=client_id,
            client_secret=client_secret,
            dry_run=args.dry_run,
            dry_run_output_dir=output_dir,
        )

        try:
            if not config.dry_run and client_id is not None and client_secret is not None:
                DiodeClient(
                    target=config.target,
                    app_name="validate",
                    app_version="0.0.0",
                    client_id=client_id,
                    client_secret=client_secret,
                )
        except Exception as e:
            sys.exit(f"ERROR: Unable to connect to Diode Server: {e}")

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
