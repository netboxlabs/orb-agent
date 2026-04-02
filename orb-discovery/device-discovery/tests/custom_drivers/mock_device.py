"""
Fake device objects for custom NAPALM driver unit tests.

Two flavours:
  FakeCLIDevice   -- intercepts send_command() for Netmiko-based drivers.
  FakeXmlDevice   -- intercepts op() / show() / xml_root() for pan.xapi-based drivers.

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
"""

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
