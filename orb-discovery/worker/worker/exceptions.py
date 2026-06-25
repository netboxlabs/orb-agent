#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
Exception hierarchy raised by worker ingestion.

Covers both the scheduled run() path (via PolicyRunner._send_entities)
and the ingest callback.
"""


class IngestError(Exception):
    """
    Base for pipeline-side ingestion failures.

    Integrations should catch this when they want uniform handling. New
    subclasses are added under this base in future minor releases.
    """


class IngestUnavailable(IngestError):
    """
    Transient pipeline failure — Diode unreachable, queue full, rate-limited.

    Retry-friendly. The integration MAY retry with backoff.
    """


class IngestRejected(IngestError):
    """
    Permanent pipeline rejection for this call.

    Reasons include bad payload, instance retired, or policy removed.
    The integration should NOT retry; the call will fail again.
    """
