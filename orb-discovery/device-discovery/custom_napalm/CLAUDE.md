# Custom NAPALM Drivers — Developer Guide

This directory contains custom NAPALM drivers shipped directly with `device-discovery`. Each driver
is a flat Python file (`<driver_name>.py`) that exposes a `NetworkDriver` subclass. NAPALM's built-in
`get_network_driver()` checks `custom_napalm.<name>` before `napalm.<name>`, so no PyPI publishing is
needed and the driver is available immediately once the package is installed.

---

## How driver lookup works

`napalm.get_network_driver("my_driver")` tries, in order:

1. `custom_napalm.my_driver` — **this directory**
2. `napalm.my_driver`
3. `napalm_my_driver` (community package)

`device_discovery/discovery.py` scans `custom_napalm` at startup and adds discovered drivers to
`supported_drivers`, so they can be referenced in policy YAML by name.

---

## Critical import rule — never skip this

**Wrong** (causes NAPALM to return the base class instead of your driver):
```python
from napalm.base import NetworkDriver   # puts NetworkDriver in module namespace
class MyDriver(NetworkDriver): ...      # NAPALM's inspect scan finds NetworkDriver first (alphabetical)
```

**Correct**:
```python
import napalm.base as _napalm_base      # private alias — never in module namespace
class MyDriver(_napalm_base.NetworkDriver): ...
```

NAPALM uses `inspect.getmembers(module)` in alphabetical order and returns the first
`NetworkDriver` subclass it finds. If `NetworkDriver` itself is imported into the module
namespace, `N` sorts before your class name and the base class (whose `__init__` raises
`NotImplementedError`) is returned instead of your driver.

---

## Required methods

`device-discovery` calls exactly five NAPALM getters. Implement all five; unimplemented ones
must return the correct empty type so the rest of the pipeline doesn't break.

| Method | Return type | Empty return |
|--------|-------------|--------------|
| `get_facts()` | `dict` | `{}` |
| `get_interfaces()` | `dict[str, dict]` | `{}` |
| `get_interfaces_ip()` | `dict[str, dict]` | `{}` |
| `get_config(retrieve, full, sanitized, format)` | `models.ConfigDict` | `{"running":"","candidate":"","startup":""}` |
| `get_vlans()` | `dict` | `{}` |

`get_facts` **must** return a dict with these keys (any extra keys are fine):
```
hostname, vendor, model, os_version, serial_number, uptime (float, seconds), fqdn, interface_list (list[str])
```

---

## File structure

```
device-discovery/
├── custom_napalm/
│   ├── __init__.py          # re-export convenience only, not required by NAPALM
│   ├── CLAUDE.md            # this file
│   ├── huawei_vrp.py        # Netmiko + ntc-templates example
│   ├── panos.py             # XML API (pan-python) example
│   └── panos_ssh.py         # Netmiko + ntc-templates example
└── tests/
    └── custom_drivers/
        ├── base_test.py           # BaseDriverTest + parametrize_scenarios
        ├── mock_device.py         # FakeCLIDevice, FakeXmlDevice
        └── <driver_name>/
            ├── __init__.py
            ├── conftest.py
            ├── test_driver.py
            └── mock_data/
                ├── test_get_facts/normal/
                ├── test_get_interfaces/normal/
                ├── test_get_interfaces_ip/normal/
                ├── test_get_config/normal/
                └── test_get_vlans/normal/
```

After adding a new file, register it in `custom_napalm/__init__.py`:
```python
from custom_napalm.my_driver import MyDriver
__all__ = [..., "MyDriver"]
```

`pyproject.toml` already uses `find` with `include = ["device_discovery*", "custom_napalm*"]`,
so no `pyproject.toml` changes are needed.

After changes, re-install so the package index is updated:
```bash
pip install -e .           # from device-discovery/
```

---

## Approach A — Netmiko + ntc-templates (SSH CLI)

Use this when the device has an SSH CLI and ntc-templates has templates for the needed commands.
`panos_ssh.py` and `huawei_vrp.py` follow this pattern.

### Check available ntc-templates

```bash
ls .venv/lib/python*/site-packages/ntc_templates/templates/<platform>_*.textfsm
# e.g. paloalto_panos_show_system_info.textfsm
```

Verify a template parses your expected output before writing the driver:
```python
from ntc_templates.parse import parse_output
result = parse_output(platform="paloalto_panos", command="show system info", data=raw_cli_output)
print(result)  # list of dicts
```

### Driver skeleton

```python
import re
import socket
import napalm.base as _napalm_base
from napalm.base import models
from napalm.base.helpers import mac as normalize_mac
from napalm.base.netmiko_helpers import netmiko_args
from ntc_templates.parse import parse_output
import logging

logger = logging.getLogger(__name__)


class MyDriver(_napalm_base.NetworkDriver):

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.device = None
        if optional_args is None:
            optional_args = {}
        self.netmiko_optional_args = netmiko_args(optional_args)
        self.netmiko_optional_args.setdefault("port", 22)

    def open(self):
        # Use the Netmiko device_type string (e.g. "paloalto_panos", "huawei_vrp")
        self.device = self._netmiko_open(
            "netmiko_device_type_string", netmiko_optional_args=self.netmiko_optional_args
        )

    def close(self):
        self._netmiko_close()

    def is_alive(self):
        if self.device is None:
            return {"is_alive": False}
        try:
            self.device.write_channel(chr(0))
            return {"is_alive": self.device.remote_conn.transport.is_active()}
        except (socket.error, EOFError, OSError, AttributeError):
            return {"is_alive": False}

    def get_facts(self) -> dict:
        raw = self.device.send_command("show version")        # adjust command
        parsed = parse_output(platform="vendor_platform", command="show version", data=raw)
        if not parsed:
            return {}
        row = parsed[0]
        return {
            "hostname": row.get("hostname", "Unknown"),
            "vendor": "Vendor Name",
            "model": row.get("model", "Unknown"),
            "os_version": row.get("version", "Unknown"),
            "serial_number": row.get("serial", "Unknown"),
            "uptime": float(_parse_uptime(row.get("uptime", ""))),
            "fqdn": "Unknown",
            "interface_list": [],
        }

    def get_interfaces(self) -> dict:
        return {}

    def get_interfaces_ip(self) -> dict:
        return {}

    def get_config(self, retrieve="all", full=False, sanitized=False, format="text") -> models.ConfigDict:
        config: models.ConfigDict = {"running": "", "candidate": "", "startup": ""}
        if retrieve in ("all", "running"):
            config["running"] = self.device.send_command("show running-config")
        return config

    def get_vlans(self) -> dict:
        return {}
```

### Netmiko device_type strings for common vendors

| Vendor / OS | Netmiko string |
|-------------|----------------|
| Palo Alto PAN-OS | `paloalto_panos` |
| Huawei VRP | `huawei_vrp` |
| Cisco IOS | `cisco_ios` |
| Cisco NX-OS | `cisco_nxos` |
| Arista EOS | `arista_eos` |
| Juniper Junos | `juniper_junos` |
| HP/H3C Comware | `hp_comware` |
| Fortinet | `fortinet` |

Full list: `python -c "from netmiko import CLASS_MAPPER; print(list(CLASS_MAPPER.keys()))"`

### ntc-templates platform strings

The platform string for `parse_output()` is the Netmiko device type with `_` separators:
`paloalto_panos`, `huawei_vrp`, `cisco_ios`, etc.

**Watch out for the `^. -> Error` catch-all.** Some templates raise `TextFSMError` for any
unrecognised line (e.g. `paloalto_panos_show_interface_management.textfsm`). Only include lines
that match a template rule in the corresponding mock file. Always test parsing with real or
carefully crafted sample output before writing mock data.

---

## Approach B — Protocol client (XML API, RESTCONF, NETCONF, …)

Use this when the device exposes a structured API rather than (or in addition to) SSH CLI.
`panos.py` uses `pan.xapi.PanXapi` (PAN-OS XML API) as an example.

The same import rule and method contract apply. The `open()` method instantiates the protocol
client and stores it in `self.device`. The fake device for tests (`FakeXmlDevice`) intercepts
`op()`, `show()`, and `xml_root()` calls.

---

## Writing unit tests

Unit tests live in `tests/custom_drivers/<driver_name>/` and use a file-system-based mock: you
place static response files in subdirectories, one per scenario, and `BaseDriverTest` compares
the driver's output against `expected_result.json`.

### 1. Create the test module

**`tests/custom_drivers/<driver_name>/__init__.py`** — empty file.

**`tests/custom_drivers/<driver_name>/conftest.py`**:
```python
from pathlib import Path
from tests.custom_drivers.base_test import parametrize_scenarios

MOCK_DATA_ROOT = Path(__file__).parent / "mock_data"

def pytest_generate_tests(metafunc):
    parametrize_scenarios(metafunc, MOCK_DATA_ROOT)
```

**`tests/custom_drivers/<driver_name>/test_driver.py`**:
```python
from pathlib import Path
from custom_napalm.my_driver import MyDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice  # or FakeXmlDevice

class TestMyDriver(BaseDriverTest):
    driver_cls = MyDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"
```

Use `FakeCLIDevice` for Netmiko-based drivers and `FakeXmlDevice` for XML API drivers.

### 2. Create mock data

Create one directory per test method × scenario:

```
mock_data/
├── test_get_facts/
│   └── normal/
│       ├── <command_file_1>        # CLI: .txt  |  XML: .xml
│       ├── <command_file_2>
│       └── expected_result.json
├── test_get_interfaces/normal/
├── test_get_interfaces_ip/normal/
├── test_get_config/normal/
└── test_get_vlans/normal/
```

Adding a new scenario is as simple as adding a new subdirectory (e.g. `test_get_facts/no_serial/`).
No Python changes needed.

### FakeCLIDevice — filename mapping

`send_command(cmd)` reads `<mock_dir>/<filename>.txt` where:
- Every run of characters that are neither word characters (`\w`) nor hyphens (`-`) is replaced by a single `_`.
- Leading and trailing `_` are stripped.

Examples:
```
"show system info"                              → show_system_info.txt
"show interface hardware"                       → show_interface_hardware.txt
"show interface management"                     → show_interface_management.txt
"show config running"                           → show_config_running.txt
"display version"                               → display_version.txt
"display current-configuration | inc sysname"   → display_current-configuration_inc_sysname.txt
```

If a file is missing, `FakeCLIDevice` returns `""` (silent — no error). Use this for optional
commands the driver calls only when the previous command returned data.

### FakeXmlDevice — filename mapping

`op(cmd="<show><system><info></info></system></show>")` → file resolved by:
- Replace `<` → `_`, `>` → `_`, `/` → `_`, remove spaces.
- Append `.xml`.

Examples:
```
"<show><system><info></info></system></show>"  → _show__system__info___info___system___show_.xml
"<show><interface><hardware/></interface></show>" → _show__interface__hardware___interface___show_.xml
```

`show()` always reads `running_config.xml`.

`xml_root()` returns the file content as a string, or a minimal success response if the file
is missing.

### Writing expected_result.json

The easiest approach is to run the driver against the mock data once and capture the output:

```python
# One-off script — run from device-discovery/
from pathlib import Path
import json
from custom_napalm.my_driver import MyDriver
from tests.custom_drivers.mock_device import FakeCLIDevice

mock_dir = Path("tests/custom_drivers/my_driver/mock_data/test_get_facts/normal")
driver = object.__new__(MyDriver)
driver.hostname = driver.username = driver.password = "test"
driver.timeout = 60
driver.device = FakeCLIDevice(mock_dir)
result = driver.get_facts()
print(json.dumps(result, indent=2))
```

Paste the output into `expected_result.json`. After the driver is stable, this file becomes the
regression fixture — future changes that alter the output will cause tests to fail.

### Running tests

```bash
# From device-discovery/
.venv/bin/pytest tests/custom_drivers/ -v
```

All existing drivers run in the same invocation. A new driver's tests are auto-discovered.

---

## End-to-end validation with mockit

[mockit](https://registry.gitlab.com/slurpit.io/mockit) is an SSH mock server that replays
pre-recorded CLI output for a given `DEVICE_TYPE`. It supports the same Netmiko device-type
strings.

### 1. Start a mockit container locally

No external test lab needed. Run mockit as a standalone container, mapping its SSH port to any
free port on your machine:

```bash
docker run -d --rm \
  --name my-device \
  -e DEVICE_TYPE=netmiko_device_type_string \
  -e SSH_USERNAME=admin \
  -e SSH_PASSWORD=admin \
  -p 10048:22 \
  registry.gitlab.com/slurpit.io/mockit:latest
```

Replace `netmiko_device_type_string` with the appropriate string for your vendor (e.g.
`paloalto_panos`, `huawei_vrp`, `cisco_ios`). Pick any free host port for the `-p` mapping;
`10048` is just an example.

> **Important**: `huawei_vrpv8` has empty templates in mockit — use `huawei_vrp` instead.
> Always verify that the `DEVICE_TYPE` returns non-empty responses for the commands your driver
> uses before writing the driver (SSH in and try the commands manually, see below).

Verify SSH access and test your commands interactively:
```bash
ssh -p 10048 -o StrictHostKeyChecking=no admin@localhost   # password: admin
# once in: try your driver's commands
# show system info
# show interface hardware
# etc.
```

Stop the container when done (the `--rm` flag removes it automatically):
```bash
docker stop my-device
```

### 2. Start device-discovery in dry-run mode

```bash
cd device-discovery
pip install -e .    # ensure custom_napalm is registered in the egg-info
mkdir -p /tmp/dryrun
.venv/bin/device-discovery -d -o /tmp/dryrun &
```

### 3. Submit a policy

```bash
curl -X POST http://localhost:8072/api/v1/policies \
  -H 'Content-Type: application/x-yaml' \
  --data-binary 'policies:
  my-driver-test:
    scope:
      - driver: my_driver       # the flat-file name without .py
        hostname: localhost
        username: admin
        password: admin
        timeout: 30
        optional_args:
          port: 10048
    schedule:
      type: interval
      hours: 1'
```

> Use `hostname: localhost` + `optional_args.port: <host_port>` — the Docker network IP
> (172.28.x.x) is not reachable from the host.

### 4. Inspect the output

```bash
ls /tmp/dryrun/
# device-discovery_<timestamp>.json

python3 -c "
import json
data = json.load(open('/tmp/dryrun/<file>.json'))
entities = data['entities']
print(f'Total entities: {len(entities)}')
for e in entities[:3]:
    print(json.dumps(e, indent=2)[:400])
"
```

A successful run produces a device entity + interface entities. Verify:
- `device.name` matches the hostname returned by the device.
- `device.device_type.manufacturer.name` and `model` match `get_facts()`.
- Interface entities are present and have correct names.

### 5. Troubleshoot

Check server logs:
```bash
.venv/bin/device-discovery -d -o /tmp/dryrun > /tmp/dd.log 2>&1 &
tail -f /tmp/dd.log
```

Common errors:

| Error | Cause | Fix |
|-------|-------|-----|
| `specified driver 'x' was not found` | `custom_napalm` not in egg-info | Run `pip install -e .` |
| `NetmikoTimeoutException` | Wrong IP / not using mapped host port | Use `localhost` + `optional_args.port` |
| `NotImplementedError` in napalm's `__init__` | Wrong import pattern | Use `import napalm.base as _napalm_base` |
| ntc-templates `TextFSMError` | Mock file has unrecognised lines | Check template for `^. -> Error`; only include valid lines |
| Empty `supported_drivers` for custom drivers | `ImportError` silently swallowed | Run `python -c "import custom_napalm"` to debug |

---

## Validation checklist

Before opening a PR with a new driver, confirm all of the following:

- [ ] Driver file is `custom_napalm/<driver_name>.py` (flat file, not a package).
- [ ] Class inherits from `_napalm_base.NetworkDriver` (uses `import napalm.base as _napalm_base`).
- [ ] All five getters are implemented: `get_facts`, `get_interfaces`, `get_interfaces_ip`, `get_config`, `get_vlans`.
- [ ] `get_facts` returns all required keys including a float `uptime`.
- [ ] Driver is re-exported in `custom_napalm/__init__.py`.
- [ ] `pip install -e .` shows `custom_napalm` in `netboxlabs_device_discovery.egg-info/top_level.txt`.
- [ ] `python -c "from device_discovery.discovery import supported_drivers; print(supported_drivers)"` includes the new driver.
- [ ] Unit test module created under `tests/custom_drivers/<driver_name>/`.
- [ ] Mock data files exist for all five test methods with an `expected_result.json` for each.
- [ ] `ruff check .` from `device-discovery/` reports no errors.
- [ ] `pytest tests/custom_drivers/ -v` — all tests pass (existing + new).
- [ ] `docker run` mockit container starts and SSH access works (`ssh -p <port> admin@localhost`).
- [ ] `device-discovery` dry-run produces a device entity + interface entities with correct fields.
