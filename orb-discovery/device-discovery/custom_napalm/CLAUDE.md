# Custom NAPALM Drivers — Developer Guide

This directory contains custom NAPALM drivers shipped directly with `device-discovery`. Each driver
is a flat Python file (`<driver_name>.py`) that exposes a `NetworkDriver` subclass. NAPALM's built-in
`get_network_driver()` checks `custom_napalm.<name>` before `napalm.<name>`, so no PyPI publishing is
needed and the driver is available immediately once the package is installed.

Driver files **must** follow the `<vendor>_<os>[_ssh].py` naming convention, matching the
[netmiko platform string](https://ktbyers.github.io/netmiko/PLATFORMS.html) wherever one exists
(e.g. `paloalto_panos.py`, `huawei_vrp.py`, `aruba_aoscx_ssh.py`). The only exception is
`alcatel_aos.py` which predates this convention but already matches the netmiko name.

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

Beyond the required five, drivers should also implement the optional getters where the
platform supports the concept — see [`get_interfaces_vlans`](#optional-method-get_interfaces_vlans)
(switchport/VLAN associations) and [`get_network_instances`](#optional-method-get_network_instances)
(VRF discovery; implement on every platform with an L3 VRF concept).

| Method | Return type | Empty return |
|--------|-------------|--------------|
| `get_facts()` | `dict` | `{}` |
| `get_interfaces()` | `dict[str, dict]` | `{}` |
| `get_interfaces_ip()` | `dict[str, dict]` | `{}` |
| `get_config(retrieve, full, sanitized, format)` | `models.ConfigDict` | `{"running":"","candidate":"","startup":""}` — **must honour `sanitized=True`** |
| `get_vlans()` | `dict` | `{}` |

`get_facts` **must** return a dict with these keys (any extra keys are fine):
```
hostname, vendor, model, os_version, serial_number, uptime (float, seconds), fqdn, interface_list (list[str])
```

### `get_interfaces()` — `mac_address` field

Each per-interface dict carries a `mac_address` string. The translator
emits it as `Interface.primary_mac_address` and NetBox matches the
interface via its `unique_primary_mac_address` matcher, so populating
it is highly valuable to operators.

**Populate it whenever the platform exposes a per-port MAC.** Acceptable
sources:
- SSH CLI: a `show interfaces`-style command that prints a per-port MAC
  (Cisco-family `Hardware ... address`, Dell `Burned MAC`, Mellanox
  `HW address`, etc.).
- Structured API: a field in the same payload the driver already
  pulls (AOS-CX `hw_intf_info.mac_addr`, PAN-OS `mac`, etc.).
- gNMI / NETCONF state tree: e.g. SR Linux's
  `interface[name=*]/ethernet/hw-mac-address`, SR OS NETCONF's
  `state_ns:hardware-mac-address`.

**Normalise through `napalm.base.helpers.mac`** before returning:

```python
from napalm.base.helpers import mac as normalize_mac

try:
    mac_address = normalize_mac(mac_raw) if mac_raw else ""
except Exception:
    # napalm.mac() rejected the value — log at WARNING and emit an
    # empty MAC. Keeping the malformed raw string would lead NetBox's
    # unique_primary_mac_address matcher to treat it as a distinct
    # interface, which is worse than the missing-MAC behaviour callers
    # already handle gracefully.
    logger.warning(
        "%s: normalize_mac rejected %r for interface %s — emitting empty MAC",
        DRIVER_NAME, mac_raw, name,
    )
    mac_address = ""
```

**Set `mac_address = ""` only when the platform genuinely doesn't
expose per-port MAC.** Real cases:
- Cisco Small Business SG300 / SG350 / SG550 — one chassis MAC across
  all ports; no per-port concept.
- Cisco AireOS WLC — most "interfaces" are virtual (mgmt / dynamic
  VLANs / AP-manager) with no L2 MAC.
- Extreme EXOS — all ports share the system MAC by design; no
  per-port MAC field in any standard ``show ports*`` command.

For every other driver, an unsupported (`""`) MAC field is a feature
gap, not the intended steady state — track in the supported-platforms
table and follow up with a driver-specific fix.

### `get_interfaces()` — sub-interfaces

When the underlying platform supports L3 sub-interfaces (VLAN-tagged
routed interfaces named `<parent>.<vlanid>` — Cisco IOS / ASA / FTD,
Juniper, Huawei VRP, Cumulus / Linux, Palo Alto PAN-OS, Nokia SR Linux,
etc.), the driver MUST emit one dict entry per sub-interface alongside
its physical parent:

```python
{
  "GigabitEthernet0/1":     {...},  # parent, physical
  "GigabitEthernet0/1.100": {...},  # sub on VLAN 100
  "GigabitEthernet0/1.200": {...},  # sub on VLAN 200
}
```

The Diode translator's `extract_parent_interface_name()` recognises the
`.` and `:` separator conventions and automatically links each sub to
its parent as a NetBox `virtual` interface — drivers do NOT need to
emit any extra parent reference, just the correctly-named entries.

`get_interfaces_ip()` MUST key IPs by the same sub-interface name (not
collapse onto the parent). The translator pairs IP entries with
interface entries by exact key match.

Common pitfalls:
- The CLI command for physical interfaces (`show interface hardware`,
  `get system interface physical`, etc.) often does NOT list
  sub-interfaces. A separate command (`show interface logical`,
  `get system interface`, ...) usually does. The driver must merge
  both.
- ntc-templates with strict `^. -> Error` rules can crash on
  sub-interface-only lines (e.g. ASA's `Encapsulation: 802.1Q VLAN`,
  VRP's `PVID:`). Pre-filter unrecognised lines via a driver-local
  regex before calling `parse_output()`.
- Linux `ip link show` decorates sub-interface names with the parent
  suffix `@<parent>` (e.g. `swp1.100@swp1`). Strip the suffix so the
  name in NetBox is the canonical `swp1.100`.
- FortiGate VLAN sub-interfaces use **arbitrary operator-chosen names**
  (e.g. `dmz`, `voice`) with `set vlanid` + `set interface "port1"`.
  These can't be auto-linked through naming alone; either emit them
  as standalone interfaces (losing parent linkage) or synthesise
  `parent.vlanid` names via driver-local parsing of the
  `interface:` / `vlanid:` fields.

**Platforms that DON'T expose L3 sub-interfaces** (legitimate
`mac_address=""`-style cases — emit only physical entries):
- Pure L2 switches (Cisco SG300, AireOS WLC, ProCurve, AOS-Switch,
  EXOS, EdgeSwitch / UniFi Switch, Mellanox MLNX-OS / Onyx, etc.)
- Platforms that route via VLAN-interfaces only (Avaya ERS, Brocade
  FastIron / NetIron `ve N`, OmniSwitch, ArubaOS controllers — the
  `aruba_os` driver covers ArubaOS MM/MC where the L3 model is
  `vlan N` + `loopback`, never `port.N`).
- Ciena SAOS (port IDs are bare numbers / LAG names; traffic is
  handled via VLAN-based services, not `parent.sub` naming).
- Cisco FXOS (the Firepower chassis-management layer — L3
  sub-interfaces live in the FTD / ASA running on top, not in FXOS
  itself).
- Cisco ACI APIC (port profiles + encap VLANs, not `.N` naming).

**Platforms with operator-chosen sub-interface names** (don't fit
the `parent.X` convention; would need driver-local synthesis of
`parent.vlanid` from configured fields):
- FortiOS (VLAN sub-interfaces are named `dmz`, `voice`, etc. with
  `set vlanid` + `set interface "port1"`).
- MikroTik RouterOS (VLAN sub-interfaces in `interface print
  detail` carry `vlan-id=` + `interface=` properties but operator
  picks the name, e.g. `ether1-vlan100`).
- Nokia SR OS (L3 interfaces have operator-chosen names like
  `to-peer-1`; SAPs use `:` separator e.g. `1/1/1:100`. The
  translator already handles the `:` form, but emitting SAPs at
  all is a feature addition for the SR OS driver).
- Ericsson SmartEdge / IPOS (sub-interfaces under `circuit` profiles
  with operator-chosen names).

### `get_interfaces()` — driver-provided `type`

A driver MAY include a per-interface `type` key in the dict it returns from
`get_interfaces()`. This is a device-discovery extension (standard NAPALM
`get_interfaces()` has no type field): use it when the platform tells you the
interface's kind from device state and name/speed inference would be
unreliable — LAG / aggregation, virtual / logical, bridge, tunnels, etc.

Rules:
- The value **must be a valid NetBox interface type** (a member of
  `device_discovery.interface_types.VALID_INTERFACE_TYPES` — the NetBox
  `dcim` `InterfaceTypeChoices` values, e.g. `lag`, `virtual`, `bridge`,
  `1000base-t`). Map the device-native value to a NetBox type in the driver;
  do not emit the raw device string. An invalid value is ignored (with a
  warning) and the pipeline falls back to its heuristics — it is never
  emitted.
- Precedence: the driver `type` is honored **below** a user
  `interface_patterns` match (operators keep an explicit override) and
  **above** the built-in patterns, speed-based detection, and `if_type`.
- Omit the key (or set it empty) when you cannot classify reliably; leave
  physical ports to speed-based detection, which is accurate when the driver
  reports `speed`.

Only classify what the device tells you authoritatively. Reference
implementations: `ciena_saos` (`port show` TYPE column → `lag`) and
`mikrotik_routeros` (RouterOS `type` → `lag`/`virtual`/`bridge`).

---

## Optional method: `get_interfaces_vlans`

A driver MAY implement `get_interfaces_vlans()` to populate NetBox
`Interface.mode` / `untagged_vlan` / `tagged_vlans`. The runner calls it via
`getattr(...)` so drivers without it are silently skipped.

**Output shape** (per interface):

```python
{
    "mode":     "access" | "trunk" | "trunk-all" | "routed",
    "tagged":   list[int],          # VIDs in 1..4094, never the untagged VID
    "untagged": int | None,         # VID in 1..4094, None for routed
}
```

`device_discovery.translate.apply_interface_vlans()` maps these to NetBox:
`access` → `access`, `trunk` → `tagged`, `trunk-all` → `tagged-all`,
`routed` → no change (Diode PATCH semantics — see translate.py docstring).

**Use the generic classifier — do NOT reimplement.** `custom_napalm/_vlan.py`
exposes `SwitchportInfo` (vendor-neutral intermediate) and
`classify_switchport()` (the pure-function classifier that handles voice-VLAN
promotion, DTP fallback, wildcard signaling, VID clamping, and bool-rejection).

**The driver only does field extraction:**

```python
from custom_napalm._vlan import SwitchportInfo, classify_switchport, parse_vlan_range_string

def get_interfaces_vlans(self) -> dict[str, dict]:
    raw = self.device.send_command("show interfaces switchport")  # or RPC, or eAPI
    rows = parse_output(...)  # or vendor JSON / XML
    result: dict[str, dict] = {}
    for row in rows:
        info = SwitchportInfo(
            enabled=...,
            admin_mode=...,    # "access" | "trunk" | "dynamic" | None
            oper_mode=...,     # for DTP fallback; None if not applicable
            access_vlan=...,
            native_vlan=...,
            allowed_vlans=...,  # list[int] | "all" | None
            voice_vlan=...,
        )
        result[ifname] = classify_switchport(info)
    return result
```

## Optional method: `get_network_instances`

A driver SHOULD implement the standard NAPALM `get_network_instances()`
when the platform has an L3 VRF concept (VRF / VPN-instance / VPRN /
network-instance / routing-instance). The runner calls it behind the
`discover_vrfs` policy option; the translator emits one NetBox `VRF`
entity per instance and attaches it to the IP addresses / prefixes of
the instance's member interfaces. L2-only platforms (access switches,
WLCs, OLTs) skip it — the NAPALM base-class stub raises
`NotImplementedError`, which the runner logs and tolerates.

**Output shape** — the NAPALM OpenConfig dict, keyed by instance name:

```python
{
    "MGMT": {
        "name": "MGMT",
        "type": "L3VRF",          # or DEFAULT_INSTANCE / L2VSI / raw vendor type
        "state": {"route_distinguisher": "65000:1"},   # "" when unconfigured
        "interfaces": {"interface": {"Management1": {}}},
    },
    "default": { ... "type": "DEFAULT_INSTANCE" ... },
}
```

**Conventions every implementation follows** (established in the
iosxr / nokia / huawei / comware / cumulus / sonic batches):

- **Seed a `DEFAULT_INSTANCE`** for the global routing table with
  **empty** interface membership — the discovery pipeline only consumes
  VRF memberships; every interface not claimed by a VRF is in the
  default table by definition. Use the platform's own name for it
  (`default`, `Base`, …).
- **Guard the seed**: skip any parsed row whose name collides with the
  seeded default-instance key, so device data can never re-type the
  global table as an L3VRF.
- **RD only when real**: emit `""` (never sentinels) when the device
  reports no RD — normalize forms like `not set` / `<not set>`. The
  translator keeps `rd` off the wire when empty so the VRF matches
  NetBox records with a NULL rd.
- **Member names must match `get_interfaces()` / `get_interfaces_ip()`
  naming exactly** — the VRF→IP attachment joins on interface name
  (e.g. SR OS VPRN members are keyed `<service>/<interface>` because
  that's how the driver names them for IP discovery; Linux kernel
  `@parent` decorations are stripped).
- **Honor the `name` filter on every return path** (including degraded
  ones): `{name: instance}` for a known name, `{}` for unknown.
- **Parse defensively**: prefer ntc-templates only after verifying they
  survive real-device output — several (cisco_xr `show vrf all detail`,
  comware `display ip vpn-instance instance-name`, huawei summary)
  error-exit or mis-attribute on routine lines, and those drivers parse
  driver-locally instead. Guard against CLI error banners on platforms
  that return them as non-empty output (SONiC).

**Tests**: add `mock_data/test_get_network_instances/<scenario>/`
fixtures — `BaseDriverTest.test_get_network_instances` auto-discovers
them and validates the OC shape (it skips drivers without fixtures or
without an implementation). Cover at minimum a `normal` scenario and an
empty/no-VRFs scenario; pin any output variant your parser specifically
handles. Also add the driver to the ownership pin matrix in
`tests/test_runner_vrf_dispatch.py`.

## Optional method: `get_modules`

A driver MAY implement `get_modules()` to populate NetBox `Module` /
`ModuleBay` entities, gated behind the `discover_modules` policy option
(`off` / `linecards` / `full`). The runner calls it via `getattr(...)` so
drivers without it are silently skipped. See
`docs/backends/device_discovery/README.md#modules--modulebays` for the
emission contract, the three modes, and the canonical envelope shape.

**Optics without a parent module.** Do not require a parent slot / linecard / FRU
bay in order to emit a transceiver. Fixed-port platforms report optics with nothing
above them, and optics in the fixed ports of a partly-modular chassis have no parent
either. Collect optics independently of the bay walk, attach the ones whose parent
resolves, and promote the rest with `orphan_optic_bay(ifname, optic)` (imported
directly from `custom_napalm._modules`). Gate on "no bays AND no optics", never on
"no bays" alone.

**Promote only a row that is already a transceiver with BOTH a model and a serial.**
This precondition is what keeps promotion safe, and it is not optional. It means the
change is either a correct fix or a no-op on hardware you cannot sample — never a
source of invented data. Do not promote a row carrying only a serial (a DOM / cage
reading with no PID, for instance): `_modules._validate_bay` requires only a serial,
so such a row would survive validation and land in NetBox as
`ModuleType(model="Unknown")`, collapsing every unidentified optic across every
device into one bogus module type. A row the device serialised but did not identify
should be skipped with a warning naming the interface, not guessed at.

## Mock fakes for structured-API drivers

For drivers that use a non-CLI transport, use these test fakes:

| Transport | Fake | File convention |
|---|---|---|
| Netmiko (SSH CLI) | `FakeCLIDevice` | `<sanitized-cmd>.txt` |
| pyeapi (Arista eAPI) / NX-API JSON | `FakeJsonRpcDevice` | `<sanitized-cmd>.json` |
| PyEZ (Juniper NETCONF) | `FakePyEZDevice` | `<rpc-name>.xml` (kebab-case) |
| Pure NETCONF (ncclient) | `FakeNetconfConn` | `response.xml`, `<source>_config.xml` |
| pan.xapi (PAN-OS XML API) | `FakeXmlDevice` | `<sanitized-xml>.xml` |
| ArubaOS-Switch REST | `FakeHTTPSession` | `<endpoint>.json` |
| pyaoscx | `FakePyaoscxSession` | `<path>.json` |
| Cisco ASA REST | `FakeRestDevice` | `<path>.json` |

---

## Config sanitization

`runner.py` calls `get_config(sanitized=True)` by default (operators can set `sanitize_config: false`
in the policy options to opt out). Every driver **must** honour the flag.

Sanitization logic lives inline in the driver — define module-level compiled regexes and a private
`_sanitize_config(text: str) -> str` function just above the class:

```python
import re

_SET_FIELDS_RE = re.compile(
    r"(set\s+(?:password|passwd|psk|psksecret|secret|auth-password))\s+.*",
    re.IGNORECASE,
)
_ENC_RE = re.compile(r"(\bENC\b)\s+\S+")


def _sanitize_config(text: str) -> str:
    text = _SET_FIELDS_RE.sub(r"\1 <redacted>", text)
    text = _ENC_RE.sub(r"\1 <redacted>", text)
    return text
```

Then call it inside `get_config()` after fetching, before returning:

```python
def get_config(self, retrieve="all", full=False, sanitized=False, format="text"):
    config = {"running": "", "candidate": "", "startup": ""}
    if retrieve in ("all", "running"):
        config["running"] = self.device.send_command("show full-configuration")
    if sanitized:
        for key in ("running", "candidate", "startup"):
            if config[key]:
                config[key] = _sanitize_config(config[key])
    return config
```

### Patterns to redact per vendor

| Vendor | Fields |
|--------|--------|
| FortiOS | `set password/passwd/psk/psksecret/secret/auth-password <v>`, standalone `ENC <v>` |
| PAN-OS | XML tags: `<phash>`, `<password>`, `<psk>`, `<secret>`, `<hash>`, `<bind-password>`, `<api-key>` |
| Huawei VRP | `cipher <v>`, `secret [N] <v>`, `community [read\|write] <v>` |

Redacted value is always the literal string `<redacted>`.

### Testing sanitization

Each driver needs a `test_get_config_sanitized/normal/` scenario (alongside `test_get_config/normal/`).
The mock config file should contain intentional sensitive fields; `expected_result.json` has them
replaced with `<redacted>`. Generate it with:

```bash
python3 -c "
from pathlib import Path; import json
from custom_napalm.my_driver import MyDriver
from tests.custom_drivers.mock_device import FakeCLIDevice

mock_dir = Path('tests/custom_drivers/my_driver/mock_data/test_get_config_sanitized/normal')
driver = object.__new__(MyDriver)
driver.hostname = driver.username = driver.password = 'test'
driver.timeout = 60
driver.device = FakeCLIDevice(mock_dir)
print(json.dumps(driver.get_config(sanitized=True), indent=2))
" > tests/custom_drivers/my_driver/mock_data/test_get_config_sanitized/normal/expected_result.json
```

Verify no raw secrets made it through:
```bash
grep -c "<redacted>" tests/custom_drivers/my_driver/mock_data/test_get_config_sanitized/normal/expected_result.json
grep -c "MyRawSecret" tests/custom_drivers/my_driver/mock_data/test_get_config_sanitized/normal/expected_result.json
# Expected: 0
```

---

## File structure

```
device-discovery/
├── custom_napalm/
│   ├── __init__.py              # re-export convenience only, not required by NAPALM
│   ├── CLAUDE.md                # this file
│   ├── huawei_vrp.py            # Netmiko + ntc-templates example
│   ├── paloalto_panos.py        # XML API (pan-python) example
│   └── paloalto_panos_ssh.py    # Netmiko + ntc-templates example
└── tests/
    └── custom_drivers/
        ├── base_test.py           # BaseDriverTest + parametrize_scenarios
        ├── mock_device.py         # FakeCLIDevice, FakeXmlDevice
        └── <vendor_os>/           # matches driver filename, e.g. paloalto_panos/
            ├── __init__.py
            ├── conftest.py
            ├── test_driver.py
            └── mock_data/
                ├── test_get_facts/normal/
                ├── test_get_interfaces/normal/
                ├── test_get_interfaces_ip/normal/
                ├── test_get_config/normal/
                ├── test_get_config_sanitized/normal/
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
`panos_ssh.py` and `vrp.py` follow this pattern.

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

# --- config sanitization (adjust patterns for this vendor) ---
_SENSITIVE_RE = re.compile(r"(set\s+(?:password|secret))\s+.*", re.IGNORECASE)


def _sanitize_config(text: str) -> str:
    return _SENSITIVE_RE.sub(r"\1 <redacted>", text)


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
        if sanitized:
            for key in ("running", "candidate", "startup"):
                if config[key]:
                    config[key] = _sanitize_config(config[key])
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

### Supported ssh DEVICE_TYPE
a10
accedian
adtran_os
alcatel_aos
alcatel_sros
allied_telesis_awplus
apresia_aeos
arista_eos
aruba_aoscx
aruba_os
aruba_osswitch
aruba_procurve
audiocode_66
audiocode_72
avaya_ers
avaya_vsp
broadcom_icos
brocade_fastiron
brocade_fos
brocade_netiron
brocade_nos
brocade_vdx
brocade_vyos
calix_b6
cdot_cros
centec_os
checkpoint_gaia
ciena_saos
cisco_asa
cisco_ftd
cisco_ios
cisco_nxos
cisco_s300
cisco_viptela
cisco_wlc
cisco_xe
cisco_xr
cloudgenix_ion
coriant
dell_dnos9
dell_force10
dell_isilon
dell_os10
dell_os6
dell_os9
dell_powerconnect
dell_sonic
dlink_ds
eltex
eltex_esr
endace
enterasys
ericsson_ipos
extreme
extreme_ers
extreme_exos
extreme_netiron
extreme_nos
extreme_slx
extreme_tierra
extreme_vdx
extreme_vsp
extreme_wing
f5_linux
f5_ltm
f5_tmsh
flexvnf
fortinet
generic
generic_termserver
hp_comware
hp_procurve
huawei
huawei_olt
huawei_smartax
huawei_vrpv8
ipinfusion_ocnos
juniper_junos
juniper_screenos
keymile
keymile_nos
linux
mellanox
mellanox_mlnxos
mikrotik_routeros/v6
mikrotik_routeros/v7
mikrotik_switchos
mrv_lx
mrv_optiswitch
netapp_cdot
netgear_prosafe
netscaler
nokia_srl
nokia_sros
oneaccess_oneos
ovs_linux
paloalto_panos
pluribus
quanta_mesh
rad_etx
raisecom_roap
ruckus_fastiron
ruijie_os
sixwind_os
sophos_sfos
supermicro_smis
tplink_jetstream
ubiquiti_edgerouter
ubiquiti_edgeswitch
ubiquiti_unifiswitch
vyatta_vyos
vyos
watchguard_fireware
yamaha
zte_zxros
zyxel_os


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

Pick up the latest output file and print a grouped summary:

```bash
FILE=$(ls -t /tmp/dryrun/*.json | head -1)

python3 - "$FILE" <<'EOF'
import json, sys
data  = json.load(open(sys.argv[1]))
ents  = data["entities"]
print(f"Total entities: {len(ents)}\n")

dev   = next((e["device"]      for e in ents if "device"    in e), None)
intfs = [e["interface"]        for e in ents if "interface" in e]
ips   = [e["ip_address"]       for e in ents if "ip_address" in e]
prefs = [e["prefix"]["prefix"] for e in ents if "prefix"    in e]
cfgs  = [e for e in ents if "config" in e]

if dev:
    print("DEVICE")
    print(f"  name:     {dev['name']}")
    print(f"  vendor:   {dev['device_type']['manufacturer']['name']}")
    print(f"  model:    {dev['device_type']['model']}")
    print(f"  serial:   {dev.get('serial', 'n/a')}")
    print(f"  platform: {dev['platform']['name']}")

print(f"\nINTERFACES ({len(intfs)})")
for i in sorted(intfs, key=lambda x: x["name"]):
    speed = f"  speed={i['speed']}" if "speed" in i else ""
    print(f"  {i['name']:20s}  enabled={i.get('enabled','?')}{speed}")

print(f"\nIP ADDRESSES ({len(ips)})")
for ip in ips:
    intf = ip.get("assigned_object_interface", {}).get("name", "?")
    print(f"  {ip['address']:20s}  interface: {intf}")

print(f"\nPREFIXES ({len(prefs)})")
for p in prefs:
    print(f"  {p}")

if cfgs:
    cfg = cfgs[0]["config"]
    print("\nCONFIG")
    print(f"  running:   {len(cfg.get('running',''))} chars")
    print(f"  candidate: {len(cfg.get('candidate',''))} chars")
    print(f"  startup:   {len(cfg.get('startup',''))} chars")
EOF
```

A successful run produces a device entity + interface entities. Verify:
- `device.name` matches the hostname returned by the device.
- `device.device_type.manufacturer.name` and `model` match `get_facts()`.
- Interface entities are present with correct `name`, `type`, and `enabled` fields.
- Interfaces with IPs appear in both `ip_address` and `prefix` entities.
- If config capture is enabled: `CONFIG` block shows non-zero char counts and no raw secrets.

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

- [ ] Driver file is `custom_napalm/<vendor>_<os>[_ssh].py` (flat file, not a package; matches the netmiko platform string where one exists).
- [ ] Class inherits from `_napalm_base.NetworkDriver` (uses `import napalm.base as _napalm_base`).
- [ ] All five getters are implemented: `get_facts`, `get_interfaces`, `get_interfaces_ip`, `get_config`, `get_vlans`.
- [ ] `get_network_instances` is implemented when the platform has an L3 VRF concept (see [Optional method: `get_network_instances`](#optional-method-get_network_instances)), with `test_get_network_instances/` fixtures and a row in the `tests/test_runner_vrf_dispatch.py` ownership matrix.
- [ ] `get_facts` returns all required keys including a float `uptime`.
- [ ] Driver is re-exported in `custom_napalm/__init__.py`.
- [ ] `pip install -e .` shows `custom_napalm` in `netboxlabs_device_discovery.egg-info/top_level.txt`.
- [ ] `python -c "from device_discovery.discovery import supported_drivers; print(supported_drivers)"` includes the new driver.
- [ ] Unit test module created under `tests/custom_drivers/<driver_name>/`.
- [ ] Mock data files exist for all five test methods with an `expected_result.json` for each.
- [ ] `test_get_config_sanitized/normal/` mock data exists with sensitive fields + redacted expected output.
- [ ] `ruff check .` from `device-discovery/` reports no errors.
- [ ] `pytest tests/custom_drivers/ -v` — all tests pass (existing + new).
- [ ] `docker run` mockit container starts and SSH access works (`ssh -p <port> admin@localhost`).
- [ ] `device-discovery` dry-run produces a device entity + interface entities with correct fields.
