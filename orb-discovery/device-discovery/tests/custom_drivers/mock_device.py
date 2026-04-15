"""
Fake device objects for custom NAPALM driver unit tests.

Flavours:
  FakeCLIDevice      -- intercepts send_command() for Netmiko-based drivers.
  FakeXmlDevice      -- intercepts op() / show() / xml_root() for pan.xapi-based drivers.
  FakeHTTPSession    -- intercepts get() / post() / cli() for REST API drivers
                        (ArubaOS-Switch and similar).
  FakePyaoscxSession -- intercepts request() for pyaoscx-based AOS-CX drivers.
  FakeNetconfConn    -- intercepts get() / get_config() for NETCONF drivers.
  FakeRestDevice     -- intercepts get_resp() for Cisco ASA REST drivers.

File-name mapping
-----------------
CLI:  "display version"  →  <mock_dir>/display_version.txt
      "display current-configuration | inc sysname"  →  display_current-configuration___inc_sysname.txt
      Rule: replace every run of non-word chars (except '-') with a single '_', strip leading/trailing '_'.

XML:  op(cmd="<show><system><info></info></system></show>")
      →  Each '<' and '>' becomes '_', '/' becomes '_', spaces removed.
      →  _show__system__info___info___system___show_.xml
      (Same convention as napalm-panos community driver.)
      show() → running_config.xml

HTTP (REST): get("system/status")            → system_status.json
             get("port-statistics")          → port-statistics.json
             get("system/status/switch")     → system_status_switch.json
             cli("show running-config")      → cli_show_running-config.json
             Rule for GET: replace '/' with '_'.
             Rule for CLI: same as CLI above, prefixed with 'cli_'.
             Missing files return an empty dict with status 404 (ok=False).
"""

import json
import re
from pathlib import Path


def _cli_filename(command: str) -> str:
    """Map a CLI command string to a .txt filename."""
    name = re.sub(r"[^\w\-]", "_", command)
    name = re.sub(r"_+", "_", name).strip("_")
    return name + ".txt"


def _xml_filename(cmd: str) -> str:
    """Map a pan.xapi op() command string to a .xml filename."""
    name = cmd.replace("<", "_").replace(">", "_").replace("/", "_").replace(" ", "")
    return name + ".xml"


class FakeCLIDevice:
    """
    Drop-in replacement for a Netmiko device connection.

    Reads responses from ``<mock_dir>/<filename>.txt``.
    Returns an empty string for any command whose file is missing,
    so tests don't blow up on optional commands.
    """

    def __init__(self, mock_dir: Path) -> None:
        """Store the directory containing mock response files."""
        self._mock_dir = mock_dir

    def send_command(self, command: str, **kwargs) -> str:
        """Return the contents of the mock file for *command*, or empty string if missing."""
        filename = _cli_filename(command)
        path = self._mock_dir / filename
        if not path.exists():
            return ""
        return path.read_text(encoding="utf-8")

    # --- Netmiko channel stubs (needed by is_alive checks) ---
    def write_channel(self, data: str) -> None:
        """No-op stub for Netmiko's write_channel."""

    class remote_conn:
        """Stub for Netmiko's remote_conn attribute."""

        class transport:
            """Stub for Netmiko's transport attribute."""

            @staticmethod
            def is_active() -> bool:
                """Always return True — the fake connection is always alive."""
                return True


class FakeXmlDevice:
    """
    Drop-in replacement for pan.xapi.PanXapi.

    Reads XML responses from ``<mock_dir>/<filename>.xml``.
    """

    def __init__(self, mock_dir: Path) -> None:
        """Store the directory containing mock XML response files."""
        self._mock_dir = mock_dir
        self._current_file: Path | None = None

    def op(self, cmd: str = "") -> None:
        """Resolve and store the XML mock file path for the given XML command string."""
        self._current_file = self._mock_dir / _xml_filename(cmd)

    def show(self) -> None:
        """Point to the running_config.xml mock file."""
        self._current_file = self._mock_dir / "running_config.xml"

    def xml_root(self) -> str:
        """Return the content of the last recorded mock file, or an empty success response."""
        if self._current_file and self._current_file.exists():
            return self._current_file.read_text(encoding="utf-8")
        return "<response status='success'><result/></response>"


class FakeHTTPSession:
    """
    Drop-in replacement for ``_ArubaOSSDevice`` in ArubaOS-Switch REST driver tests.

    Intercepts ``get(endpoint)``, ``post(endpoint, payload=...)``, and ``cli(cmd)``
    calls and serves responses from JSON files in the mock directory.

    File naming:
        get("system/status")            → system_status.json
        get("port-statistics")          → port-statistics.json
        get("system/status/switch")     → system_status_switch.json
        cli("show running-config")      → cli_show_running-config.json
        cli("show config")              → cli_show_config.json

    Missing files for GET/POST: returns a ``_MockResponse`` with ``status_code=404``
    and ``ok=False``; ``json()`` returns an empty dict ``{}``.

    Missing files for CLI: returns ``""`` (empty string). ``cli()`` uses
    ``missing_status=200`` so the response is still ``ok=True``; the base64 field
    will be absent and the method returns ``""`` gracefully without error.
    """

    class _MockResponse:
        """Minimal requests.Response look-alike."""

        def __init__(self, data: dict, status_code: int = 200) -> None:
            self._data = data
            self.status_code = status_code
            self.ok = status_code < 400

        def json(self) -> dict:
            """Return the parsed JSON payload."""
            return self._data

    def __init__(self, mock_dir: Path) -> None:
        """Store the directory containing mock JSON response files."""
        self._mock_dir = mock_dir

    def _load(self, filename: str, *, missing_status: int = 404) -> "_MockResponse":
        path = self._mock_dir / filename
        if path.exists():
            return self._MockResponse(json.loads(path.read_text(encoding="utf-8")), 200)
        return self._MockResponse({}, missing_status)

    def get(self, endpoint: str, **kwargs) -> "_MockResponse":
        """Return mock response for a GET request to the given endpoint path."""
        filename = endpoint.replace("/", "_").strip("_") + ".json"
        return self._load(filename)

    def post(self, endpoint: str, payload: dict | None = None, **kwargs) -> "_MockResponse":
        """Return mock response for a POST request (non-CLI calls only)."""
        filename = endpoint.replace("/", "_").strip("_") + ".json"
        return self._load(filename)

    def delete(self, endpoint: str, **kwargs) -> "_MockResponse":
        """Stub DELETE — always succeeds (used for logout)."""
        return self._MockResponse({}, 204)

    def close(self) -> None:
        """No-op stub — no real session to close."""

    def cli(self, cmd: str) -> str:
        """Run a mock CLI command and return decoded text output."""
        import base64

        safe = re.sub(r"[^\w\-]", "_", cmd)
        safe = re.sub(r"_+", "_", safe).strip("_")
        filename = f"cli_{safe}.json"
        resp = self._load(filename, missing_status=200)
        encoded = resp.json().get("result_base64_encoded", "")
        if not encoded:
            return ""
        try:
            return base64.b64decode(encoded).decode("utf-8")
        except Exception:
            return ""


class FakePyaoscxSession:
    """
    Drop-in replacement for a pyaoscx v2 Session object.

    Maps session.request(operation, path, ...) to <mock_dir>/<filename>.json
    where the filename is derived from the path by:
      1. Strip the query string (everything from '?' onward).
      2. Replace '/' with '_'.
      3. Strip leading/trailing '_'.
      4. Append '.json'.

    Examples:
        "system?attributes=hostname,software_info,boot_time"  → system.json
        "system/subsystems?attributes=product_info&depth=2"   → system_subsystems.json
        "system/interfaces?depth=2"                           → system_interfaces.json
        "system/vlans?depth=2"                                → system_vlans.json
        "fullconfigs/running-config"                          → fullconfigs_running-config.json

    Returns a mock response with ``.text`` (JSON string) and ``.status_code`` (200).
    If the file is missing, returns an empty JSON object ``{}`` with status 200.

    """

    class _MockResponse:
        """Minimal requests.Response look-alike."""

        def __init__(self, text: str, status_code: int = 200) -> None:
            self.text = text
            self.status_code = status_code

    def __init__(self, mock_dir: Path) -> None:
        """Store the directory containing mock JSON response files."""
        self._mock_dir = mock_dir

    def request(
        self,
        operation: str,
        path: str,
        params: dict | None = None,
        data: dict | None = None,
        verify: bool = False,
    ) -> "_MockResponse":
        """Return a mock response for the given REST path."""
        # Drop query string
        base_path = path.split("?")[0]
        # Build filename: replace / with _, strip edges
        name = base_path.replace("/", "_").strip("_") + ".json"
        file_path = self._mock_dir / name
        if file_path.exists():
            text = file_path.read_text(encoding="utf-8")
        else:
            text = "{}"
        return self._MockResponse(text)


class FakeNetconfConn:
    """
    Mock ncclient manager for NETCONF-based driver unit tests.

    Each test method has its own mock_dir. ``get()`` reads ``response.xml`` from
    that directory; ``get_config(source)`` reads ``{source}_config.xml``
    (e.g. ``running_config.xml``, ``candidate_config.xml``).

    Examples:
        test_get_facts/normal/response.xml
        test_get_interfaces/normal/response.xml
        test_get_interfaces_ip/normal/response.xml
        test_get_config/normal/running_config.xml
        test_get_config_sanitized/normal/running_config.xml

    """

    class _Response:
        """Minimal ncclient reply look-alike (exposes .data_xml as a string)."""

        def __init__(self, xml: str) -> None:
            self.data_xml = xml

    def __init__(self, mock_dir: Path) -> None:
        """Store the directory containing mock XML response files."""
        self._mock_dir = mock_dir

    @property
    def server_capabilities(self) -> list[str]:
        """Return empty capabilities — driver treats this as a modern (non-R19) device."""
        return []

    def get(self, filter=None, with_defaults=None, **kwargs) -> "_Response":
        """Return ``response.xml`` from the mock directory."""
        path = self._mock_dir / "response.xml"
        xml = path.read_text(encoding="utf-8") if path.exists() else "<data/>"
        return self._Response(xml)

    def get_config(self, source: str = "running", **kwargs) -> "_Response":
        """Return ``{source}_config.xml`` from the mock directory."""
        path = self._mock_dir / f"{source}_config.xml"
        xml = path.read_text(encoding="utf-8") if path.exists() else "<data/>"
        return self._Response(xml)

    def close_session(self) -> None:
        """No-op stub."""


class FakeRestDevice:
    """
    Drop-in replacement for _ASARest in Cisco ASA driver unit tests.

    Maps get_resp(endpoint) to <mock_dir>/<path>.json where path is the
    endpoint with the leading '/' stripped and remaining '/' replaced with '_'.

    Returns {} for missing files (silent). has_active_token() always returns True.

    Examples:
        /monitoring/serialnumber   -> monitoring_serialnumber.json
        /interfaces/physical       -> interfaces_physical.json
        /cli                       -> cli.json

    """

    def __init__(self, mock_dir: Path) -> None:
        """Store the directory containing mock JSON response files."""
        self._mock_dir = mock_dir

    def get_resp(
        self,
        endpoint: str = "",
        data: str | None = None,
        params: dict | None = None,
        throw: bool = True,
    ) -> dict:
        """Return the contents of the mock JSON file for *endpoint*, or {} if missing."""
        name = endpoint.lstrip("/").replace("/", "_") + ".json"
        path = self._mock_dir / name
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))

    def has_active_token(self) -> bool:
        """Always True — the fake connection is always alive."""
        return True

    def get_auth_token(self) -> tuple[bool, None]:
        """Stub — not called by tests (open() is bypassed)."""
        return (True, None)

    def delete_token(self) -> tuple[bool, None]:
        """Stub — not called by tests (close() is bypassed)."""
        return (True, None)

    def close_session(self) -> None:
        """No-op stub — no real session to close."""
