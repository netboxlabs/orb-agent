#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""NetBox Labs - Client Unit Tests."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from device_discovery.client import Client
from device_discovery.translate import translate_data


@pytest.fixture
def sample_data():
    """Sample data for testing ingestion."""
    return {
        "device": {
            "hostname": "router1",
            "model": "ISR4451",
            "vendor": "Cisco",
            "serial_number": "123456789",
            "site": "New York",
            "driver": "ios",
        },
        "interface": {
            "GigabitEthernet0/0": {
                "is_enabled": True,
                "mtu": 1500,
                "mac_address": "00:1C:58:29:4A:71",
                "speed": 1000,
                "description": "Uplink Interface",
            }
        },
        "interface_ip": {
            "GigabitEthernet0/0": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}
        },
        "vlan": {
            1: {
                "name": "default",
                "interfaces": ["GigabitEthernet0/0/1", "GigabitEthernet0/0/2"],
            },
            2: {"name": "vlan2", "interfaces": []},
        },
        "driver": "ios",
        "defaults": SimpleNamespace(
            site="New York",
            role=None,
            tags=None,
            if_type="other",
            location="local",
            tenant="test",
            device=None,
            interface=None,
            ipaddress=None,
            prefix=None,
            vlan=None,
        ),
    }


@pytest.fixture
def mock_version_semver():
    """Mock the version_semver function."""
    with patch("device_discovery.client.version_semver", return_value="0.0.0") as mock:
        yield mock


@pytest.fixture
def mock_diode_client_class():
    """Mock the DiodeClient class."""
    with patch("device_discovery.client.DiodeClient") as mock:
        yield mock


def test_init_client(mock_diode_client_class, mock_version_semver):
    """Test the initialization of the Diode client."""
    client = Client()
    client.init_client(
        prefix="prefix",
        target="https://example.com",
        client_id="abc",
        client_secret="def",
    )

    mock_diode_client_class.assert_called_once_with(
        target="https://example.com",
        app_name="prefix/device-discovery",
        app_version=mock_version_semver(),
        client_id="abc",
        client_secret="def",
    )


def test_ingest_success(mock_diode_client_class, sample_data):
    """Test successful data ingestion."""
    client = Client()
    client.init_client(
        prefix="", target="https://example.com", client_id="abc", client_secret="def"
    )

    mock_diode_instance = mock_diode_client_class.return_value
    mock_diode_instance.ingest.return_value.errors = []
    hostname = sample_data["device"]["hostname"]

    with patch(
        "device_discovery.client.translate_data",
        return_value=translate_data(sample_data),
    ) as mock_translate_data:
        client.ingest(hostname, sample_data)
        mock_translate_data.assert_called_once_with(sample_data)
        mock_diode_instance.ingest.assert_called_once()


def test_ingest_failure(mock_diode_client_class, sample_data):
    """Test data ingestion with errors."""
    client = Client()
    client.init_client(
        prefix="prefix",
        target="https://example.com",
        client_id="abc",
        client_secret="def",
    )

    mock_diode_instance = mock_diode_client_class.return_value
    mock_diode_instance.ingest.return_value.errors = ["Error1", "Error2"]
    hostname = sample_data["device"]["hostname"]

    with patch(
        "device_discovery.client.translate_data",
        return_value=translate_data(sample_data),
    ) as mock_translate_data:
        client.ingest(hostname, sample_data)
        mock_translate_data.assert_called_once_with(sample_data)
        mock_diode_instance.ingest.assert_called_once()

    assert len(mock_diode_instance.ingest.return_value.errors) > 0


def test_ingest_without_initialization():
    """Test ingestion without client initialization raises ValueError."""
    Client._instance = None  # Reset the Client singleton instance
    client = Client()
    with pytest.raises(ValueError, match="Diode client not initialized"):
        client.ingest("", {})


def test_client_dry_run(tmp_path, sample_data):
    """Ensure dry-run initializes DiodeDryRunClient."""
    client = Client()
    client.init_client(
        prefix="prefix",
        dry_run=True,
        dry_run_output_dir=tmp_path,
    )
    hostname = sample_data["device"]["hostname"]
    client.ingest(hostname, sample_data)
    files = list(tmp_path.glob("prefix_device-discovery*.json"))

    assert len(files) == 1
    for file in files:
        with open(file) as f:
            data = f.read()
            assert sample_data["device"]["hostname"] in data
            assert sample_data["interface"]["GigabitEthernet0/0"]["mac_address"] in data


def test_client_dry_run_stdout(capsys, sample_data):
    """Ensure dry-run initializes with None output dir when not provided."""
    client = Client()
    client.init_client(
        prefix="prefix",
        dry_run=True,
    )

    hostname = sample_data["device"]["hostname"]
    client.ingest(hostname, sample_data)

    captured = capsys.readouterr()
    assert sample_data["device"]["hostname"] in captured.out
    assert sample_data["interface"]["GigabitEthernet0/0"]["mac_address"] in captured.out
