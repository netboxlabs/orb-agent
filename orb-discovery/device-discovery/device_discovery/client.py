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
from device_discovery.log_config import configure_default_logging
from device_discovery.stubs import prune_nested_refs
from device_discovery.translate import translate_data
from device_discovery.version import version_semver
from device_discovery.vlan_scope import (
    UNSCOPED_VLAN_WARNING,
    count_unscoped_vlans,
)

APP_NAME = "device-discovery"
APP_VERSION = version_semver()
MAX_MESSAGE_SIZE_BYTES = 3 * 1024 * 1024  # 3MB threshold for chunking

# Set up logging
configure_default_logging()
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
            # Assigned before diode_client, which is the re-init guard: a second
            # thread that passes the guard must never reach ingest before this
            # exists.
            # An unscoped VLAN is a config mistake, not an event: a policy
            # either sets a group or it does not. Warn once per policy rather
            # than once per device per cycle, which on a large estate would be
            # thousands of identical lines an operator learns to filter out.
            # Keyed per policy RUNNER, not a single flag and not per policy
            # name: this Client is a process-wide singleton shared by every
            # policy, so one flag would report whichever policy ingested first
            # and silence the rest. The key is the runner rather than the name
            # so a policy that is deleted and recreated warns again, and so a
            # job still in flight from the deleted runner cannot write a key
            # its replacement reads. One short string per policy start.
            self.warned_unscoped_vlan_runs: set[str] = set()
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
    ) -> int:
        """
        Ingest data using the Diode client after translating it.

        Args:
        ----
            metadata (dict[str, Any] | None): Metadata to attach to the ingestion request.
            data (dict): The data to be ingested.
            run_id (str | None): Discovery run ID for ingest and per-entity metadata.

        Returns:
        -------
            int: Number of entities ingested.

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
            # Membership is tested before counting: once a policy has been
            # warned the count would be discarded, and this runs for every
            # device on every cycle for the life of the process.
            policy_name = str((metadata or {}).get("policy_name", "<unnamed>"))
            run_key = str((metadata or {}).get("policy_instance", policy_name))
            if run_key not in self.warned_unscoped_vlan_runs:
                unscoped_vlans = count_unscoped_vlans(entities_list)
                if unscoped_vlans:
                    self.warned_unscoped_vlan_runs.add(run_key)
                    logger.warning(
                        UNSCOPED_VLAN_WARNING,
                        unscoped_vlans,
                        str((metadata or {}).get("hostname", "unknown-host")),
                        policy_name,
                    )

            if run_id is not None:
                apply_run_id_to_entities(entities_list, run_id)

            # Trim nested Device/Interface refs to matcher-only stubs to
            # shrink the wire payload. Runs after run_id annotation so
            # the annotation (which only writes to top-level entities)
            # has already finished — stubs cherry-pick source_match and
            # are otherwise free of copied annotation. Runs before
            # estimate_message_size so chunking decisions see the
            # trimmed payload size.
            prune_nested_refs(entities_list)

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

            return entity_count
