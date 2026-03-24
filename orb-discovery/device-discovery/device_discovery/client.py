#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""Diode SDK Client for Orb Discovery."""

import logging
import threading
from typing import Any

from netboxlabs.diode.sdk import (
    DiodeClient,
    DiodeDryRunClient,
    DiodeOTLPClient,
    create_message_chunks,
    estimate_message_size,
)

from device_discovery.entity_metadata import apply_run_id_to_entities
from device_discovery.translate import translate_data
from device_discovery.version import version_semver

APP_NAME = "device-discovery"
APP_VERSION = version_semver()
MAX_MESSAGE_SIZE_BYTES = 3 * 1024 * 1024  # 3MB threshold for chunking

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Client:
    """
    Singleton class for managing the Diode client for device-discovery.

    This class ensures only one instance of the Diode client is created and provides methods
    to initialize the client and ingest data.

    Attributes
    ----------
        diode_client (DiodeClient): Instance of the DiodeClient.

    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        """
        Create a new instance of the Client if one does not already exist.

        Returns
        -------
            Client: The singleton instance of the Client.

        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize the Client instance with no Diode client."""
        if not hasattr(self, "diode_client"):  # Prevent reinitialization
            self.diode_client = None

    def init_client(
        self,
        prefix: str,
        target: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        dry_run: bool = False,
        dry_run_output_dir: str | None = None,
    ):
        """
        Initialize the Diode client with the specified target, client credentials, and TLS verification.

        Args:
        ----
            prefix (str): The prefix for the producer app name.
            target (str | None): The target endpoint for the Diode client.
            client_id (str | None): The client ID for authentication.
            client_secret (str | None): The client secret for authentication.
            dry_run (bool): If True, the client will not perform actual ingestion.
            dry_run_output_dir (str | None): Directory for dry-run output, if applicable.

        """
        with self._lock:
            if dry_run:
                self.diode_client = DiodeDryRunClient(
                    app_name=f"{prefix}/{APP_NAME}" if prefix else APP_NAME,
                    output_dir=dry_run_output_dir,
                )
            elif client_id is not None and client_secret is not None:
                self.diode_client = DiodeClient(
                    target=target,
                    app_name=f"{prefix}/{APP_NAME}" if prefix else APP_NAME,
                    app_version=APP_VERSION,
                    client_id=client_id,
                    client_secret=client_secret,
                )
            else:
                logger.debug("Initializing Diode OTLP client")
                self.diode_client = DiodeOTLPClient(
                    target=target,
                    app_name=f"{prefix}/{APP_NAME}" if prefix else APP_NAME,
                    app_version=APP_VERSION,
                )

    def ingest(
        self,
        metadata: dict[str, Any] | None,
        data: dict,
        run_id: str | None = None,
    ):
        """
        Ingest data using the Diode client after translating it.

        Args:
        ----
            metadata (dict[str, Any] | None): Metadata to attach to the ingestion request.
            data (dict): The data to be ingested.
            run_id (str | None): Discovery run ID for ingest and per-entity metadata.

        Raises:
        ------
            ValueError: If the Diode client is not initialized.

        """
        if self.diode_client is None:
            raise ValueError("Diode client not initialized")

        with self._lock:
            translated_entities = translate_data(data)
            entities_list = (
                translated_entities
                if isinstance(translated_entities, list)
                else list(translated_entities)
            )
            if run_id is not None:
                apply_run_id_to_entities(entities_list, run_id)

            request_metadata = dict(metadata or {})
            if run_id is not None:
                request_metadata["run_id"] = str(run_id)

            entity_count = len(entities_list)

            hostname = request_metadata.get("hostname") or "unknown-host"

            # Check message size and chunk if needed
            size_bytes = estimate_message_size(entities_list)

            if size_bytes > MAX_MESSAGE_SIZE_BYTES:
                chunks = create_message_chunks(entities_list)
                chunk_num = len(chunks)
                logger.info(
                    f"Hostname {hostname}: Message size {size_bytes} bytes exceeds 3MB, "
                    f"splitting into {chunk_num} chunks"
                )

                for i, chunk in enumerate(chunks, 1):
                    response = self.diode_client.ingest(
                        entities=chunk, metadata=request_metadata
                    )
                    if response.errors:
                        error_msg = (
                            f"Ingestion failed for {hostname} chunk {i}/{chunk_num}: "
                            f"{response.errors}"
                        )
                        logger.error(f"ERROR {error_msg}")
                        raise RuntimeError(error_msg)

                logger.info(
                    f"Hostname {hostname}: Successfully ingested {entity_count} entities "
                    f"in {chunk_num} chunks"
                )
            else:
                response = self.diode_client.ingest(
                    entities=entities_list, metadata=request_metadata
                )

                if response.errors:
                    error_msg = f"Ingestion failed for {hostname}: {response.errors}"
                    logger.error(f"ERROR {error_msg}")
                    raise RuntimeError(error_msg)

                logger.info(
                    f"Hostname {hostname}: Successfully ingested {entity_count} entities"
                )
