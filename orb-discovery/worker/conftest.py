"""Test configuration — set required environment variables before any imports."""
import os
import tempfile

os.environ.setdefault(
    "BUNDLES_ROOT_PATH",
    tempfile.mkdtemp(prefix="orb-test-bundles-"),
)
