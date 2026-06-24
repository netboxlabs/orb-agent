# gnmi-discovery

Orb gNMI discovery backend — an event-driven network discovery service that maintains long-lived gNMI subscriptions and ingests device, interface, and hardware-inventory changes into NetBox via Diode within seconds of them occurring.

Unlike SNMP/NAPALM-based polling, `gnmi-discovery` reacts to ON_CHANGE notifications from the device itself (with SAMPLE and GET fallback for devices that don't support streaming), so NetBox stays up to date continuously rather than on a polling interval.

## How it works

1. For each target in a policy, `gnmi-discovery` opens a gNMI session and negotiates the best delivery mode (auto ladder: ON_CHANGE → SAMPLE → GET).
2. Inbound notifications are reconciled into a per-target in-memory model of device, interfaces, and hardware components.
3. After a configurable debounce window, the snapshot is translated to Diode entities (Device, Interface, Module/ModuleBay) and ingested.
4. The model is pruned each cycle so departed interfaces stop being ingested — removals are counted but not propagated as NetBox deletes (Diode delete unavailable).

### Device enrichment

- **Serial**: the device's own serial is taken from the `CHASSIS` component (`/components/component` with `state/type == CHASSIS`); its `state/serial-no` becomes `Device.Serial`. The chassis is not surfaced as a module — non-chassis inventory components become Modules instead.
- **Manufacturer**: discovered, not just defaulted. NetBox requires a manufacturer on `DeviceType`, `Platform`, and `ModuleType`, so a `DeviceType` (with manufacturer and model) is always emitted. The device manufacturer is resolved as the first non-empty of: the operator's `manufacturer` default, the `CHASSIS` component's `state/mfg-name`, the gNMI Capabilities vendor, then `Unknown`. The same resolved manufacturer is attached to the `Platform`.
- **Device model** (`DeviceType.Model`): first non-empty of the operator's `model` default, the `CHASSIS` component's `state/part-no`, then `Unknown`.
- **Module manufacturer** (`ModuleType.Manufacturer`): each module/transceiver may be a different vendor than the chassis, so it is the first non-empty of that component's own `state/mfg-name`, the resolved device manufacturer, then `Unknown`. The module model stays its `state/part-no` (else `Unknown`).
- **Platform / software version**: the discovered software version (`/system/state/software-version`) is appended to the operator's `platform` default, which acts as the NOS-name prefix (e.g. platform `Arista EOS` + version `4.30.1F` → platform `Arista EOS 4.30.1F`). If only one is present, that value alone is used; if neither is present, no platform is set.

## Requirements

A running [NetBox Diode](https://github.com/netboxlabs/diode) endpoint, or use `--dry-run` for local testing.

## Usage

```sh
Usage of gnmi-discovery:
  -diode-app-name-prefix string
        diode producer_app_name prefix
  -diode-client-id string
        diode client ID. Environment variable can be used by wrapping it in ${} (e.g. ${DIODE_CLIENT_ID})
  -diode-client-secret string
        diode client secret. Environment variable can be used by wrapping it in ${} (e.g. ${DIODE_CLIENT_SECRET})
  -diode-target string
        diode target. Environment variable can be used by wrapping it in ${} (e.g. ${DIODE_TARGET})
  -dry-run
        run in dry-run mode, do not ingest data
  -dry-run-output-dir string
        output dir for dry-run mode. Environment variable can be used by wrapping it in ${} (e.g. ${DRY_RUN_OUTPUT_DIR})
  -help
        show this help
  -host string
        server host (default "0.0.0.0")
  -log-format string
        log format (default "TEXT")
  -log-level string
        log level (default "INFO")
  -otel-endpoint string
        OpenTelemetry exporter endpoint (e.g. localhost:4317). Environment variable can be used by wrapping it in ${} (e.g. ${OTEL_ENDPOINT})
  -otel-export-period int
        Period in seconds between OpenTelemetry exports (default 10)
  -port int
        server port (default 8075)
  -profiles-dir string
        directory of gNMI profile overrides (empty = embedded profiles only)
```

## Policy RFC

```yaml
policies:
  gnmi_fabric:
    config:
      mode: auto           # auto (default) | on_change | sample | get
      debounce_ms: 2000    # flush delay after last notification (default 2000)
      sample_interval_ms: 300000   # SAMPLE subscription interval (default 300000 = 5m)
      get_interval_ms: 900000      # GET poll interval (default 900000 = 15m)
      options:                     # per-policy behavior toggles (peer to defaults)
        capture_config: false      # capture the CONFIG datastore into Device.config.running (default off)
      defaults:
        site: New York NY          # NetBox site (default "undefined")
        role: Router               # NetBox device role (default "undefined")
        location: ""               # NetBox location (optional)
        tags: []                   # NetBox tags applied to all entities
        asset_tag: ""              # literal, or a "/"-prefixed gNMI path reference (see below)
        device:
          manufacturer: ""         # override manufacturer (optional)
          model: ""                # override model (optional)
          platform: ""             # override platform (optional)
          comments: ""
          tags: []
        interface:
          if_type: other           # fallback interface type (default "other")
          description: ""
          tags: []
        ip_address:                # NetBox defaults applied to discovered IP addresses
          role: ""
          tenant: ""
          description: ""
          comments: ""
          tags: []
        vrf:                       # NetBox defaults applied to discovered VRFs (name/RD come from discovery)
          tenant: ""
          description: ""
          comments: ""
          tags: []
        # Name-regex -> NetBox type, highest precedence (first match wins):
        interface_patterns:
          - match: "^Ethernet"
            type: 10gbase-x-sfpp
        # Name-regex; matching interfaces are skipped entirely:
        interface_exclude_patterns:
          - "^Management"
    scope:
      targets:
        - host: 10.0.0.11:6030       # Arista EOS default gNMI port
          username: ${GNMI_USER}     # ${ENV_VAR} syntax supported
          password: ${GNMI_PASS}
          tls:                       # TLS is the default (system root CAs)
            skip_verify: true        # keep TLS but don't verify the target cert
            insecure: false          # opt-in PLAINTEXT (no TLS) — off by default
            ca: /run/secrets/ca.pem  # optional mTLS
            cert: /run/secrets/cert.pem
            key: /run/secrets/key.pem
          profile: arista_eos        # pin a profile (auto-detect if omitted)
          mode: on_change            # per-target mode override
          origin: openconfig         # gNMI path origin (default); set "" for origin-less
          netbox_id: 42              # pin to an existing NetBox device ID
          override_defaults:         # per-target defaults override
            site: Chicago IL

        - host: 10.0.0.21:57400     # Nokia SR-OS default gNMI port
          username: admin
          password: pw
```

### Interface type discovery

Each interface's NetBox type is resolved per-interface by this precedence:

1. `interface_exclude_patterns` — if the interface name matches any regex, the
   interface is skipped entirely (no NetBox interface is emitted for it).
2. `interface_patterns` — the first pattern whose regex matches the interface
   name assigns its `type`. This wins over everything below.
3. OpenConfig `state/type` — the discovered `iana-if-type`/`openconfig-if-types`
   identityref is mapped to a NetBox type for the structural families: LAG
   (`ieee8023adLag`, `ifAggregate`) → `lag`; loopback / VLAN / tunnel /
   prop-virtual → `virtual`.
4. Built-in name patterns — a bundled cross-vendor name→type table
   (`defaultInterfacePatterns`) covers ethernet *media* and aggregates the OC
   type can't convey: Cisco `Gi/Te/HundredGig…`, Juniper `xe-/ge-`, Huawei
   `10GE/25GE/40GE/100GE` + `Eth-Trunk`/`Vlanif`, and
   `Port-channel`/`PortChannel`/`ae`/`Bundle-Ether` → `lag`.
5. Speed-based media — the `ethernet/state/port-speed` identityref
   (`SPEED_10GB` → `10gbase-x-sfpp`, etc.).
6. `interface.if_type` — the policy default.
7. `"other"` — last resort when no default is set.

Both pattern lists may also appear under a target's `override_defaults` and are
validated (regex-compiled) at `POST /policies`, so a bad regex returns 400.

The built-in name patterns and speed-based inference (steps 4–5) already type
common vendor interfaces with no policy configuration. `interface_patterns` is
for overriding those built-ins or typing names they don't cover — it takes
precedence over both.

### Asset tag

OpenConfig defines no standard asset-tag leaf (unlike SNMP's ENTITY-MIB
`entPhysicalAssetID`), so there is no zero-config auto-discovery. `defaults.asset_tag`
accepts either:

- a **literal** string (e.g. `asset_tag: DC1-RACK7`), or
- a **gNMI path reference** — any value beginning with `/` (e.g.
  `asset_tag: /components/component[name=Chassis]/state/id`). The leaf is read
  from the discovered snapshot when it is one of the subscribed paths, otherwise
  via a targeted Get, so you can point at whatever leaf your platform carries the
  tag in.

Either form is vetted before it becomes `Device.asset_tag`: well-known
placeholders (`unknown`, `n/a`, `no asset tag`, …) are rejected, the value must
be printable UTF-8, and it must fit NetBox's 50-character column. A value that
fails vetting (or a path that does not resolve) leaves the asset tag unset.
Mirrors snmp-discovery's "OID reference or literal" mechanism.

### Config capture

With `options.capture_config: true`, each discovery cycle fetches the target's
**CONFIG datastore** once (a single gNMI `Get` of type `CONFIG` over `/`,
JSON_IETF) and stores it as `Device.config.running`. gNMI has no `startup` or
`candidate` datastore, so only `running` is populated, and the artifact is the
serialized OpenConfig CONFIG tree (JSON), not a CLI config. Secrets are redacted
best-effort: values under auth-oriented leaf names (`password`, `secret`,
`private-key`, `pre-shared-key`, `auth-password`, …) are replaced with `***`
(most devices already return hashed values). A capture failure logs a warning and
the inventory flush proceeds without config.

### Delivery modes

| Mode | Behaviour |
|------|-----------|
| `auto` | Try ON_CHANGE first; fall back to SAMPLE, then GET on rejection |
| `on_change` | Subscribe STREAM ON_CHANGE; reconnect with debounce |
| `sample` | Subscribe STREAM SAMPLE at `sample_interval_ms` |
| `get` | Poll via gNMI Get every `get_interval_ms` |

### Bundled profiles

Profiles live in `mapping/gnmi-profiles/` and are compiled into the binary. Bundled profiles:

| Profile | Match |
|---------|-------|
| `_base` | fallback for any vendor |
| `arista_eos` | vendor = `Arista` |
| `nokia_sros` | vendor = `Nokia` |
| `nvidia_cumulus` | vendor = `nvidia`, `cumulus`, or `mellanox` (alias-matched) |

`match.vendor` accepts a comma-separated alias list (matched any-of, most-specific alias wins); `nvidia_cumulus` uses this to cover the differing Organization strings NVIDIA Cumulus reports across releases. The `arista_eos`, `nokia_sros`, and `nvidia_cumulus` overlays are placeholders inheriting `_base` paths, pending real-device validation.

To add vendor-specific overrides without rebuilding, mount a directory and pass `-profiles-dir`:

```sh
gnmi-discovery -profiles-dir /etc/gnmi-profiles ...
```

A profile override file uses `extends: _base` to inherit bundled paths and override only the differences.

## Run gnmi-discovery

```sh
git clone https://github.com/netboxlabs/orb-agent.git
cd orb-discovery/gnmi-discovery/
make build
build/gnmi-discovery \
  --diode-target grpc://192.168.31.114:8080/diode \
  --diode-client-id '${DIODE_CLIENT_ID}' \
  --diode-client-secret '${DIODE_CLIENT_SECRET}'
```

Dry-run (no Diode required):

```sh
build/gnmi-discovery --dry-run --dry-run-output-dir /tmp/gnmi-dry --port 8075
```

## Docker Image

`gnmi-discovery` is built from source into the `netboxlabs/orb-agent` image (from
`orb-discovery/gnmi-discovery` in this repo); there is no standalone
`gnmi-discovery` image. Run it via the agent image, which launches the backend on
demand, or use orb-test-lab for local testing.

Profile overrides work the same way under the agent image — point the backend at a
profiles directory with `--profiles-dir`:

```sh
gnmi-discovery \
  --diode-target grpc://... \
  --profiles-dir /etc/gnmi-profiles \
  ...
```

## Routes (v1)

### Get runtime and capabilities information

<details>
 <summary><code>GET</code> <code><b>/api/v1/status</b></code> <code>(gets gnmi-discovery runtime data)</code></summary>

##### Parameters

> None

##### Responses

> | http code | content-type | response |
> |-----------|--------------|----------|
> | `200` | `application/json; charset=utf-8` | `{"start_time":"...","up_time_seconds":3,"version":"0.0.0","policies":[{"name":"demo","status":"running","targets":[...],"runs":[...]}]}` |

##### Example cURL

> ```sh
>  curl -X GET -H "Content-Type: application/json" http://localhost:8075/api/v1/status
> ```

</details>

<details>
 <summary><code>GET</code> <code><b>/api/v1/capabilities</b></code> <code>(gets gnmi-discovery capabilities)</code></summary>

##### Parameters

> None

##### Responses

> | http code | content-type | response |
> |-----------|--------------|----------|
> | `200` | `application/json; charset=utf-8` | `{"capabilities":["targets","on_change","sample","get"]}` |

##### Example cURL

> ```sh
>  curl -X GET -H "Content-Type: application/json" http://localhost:8075/api/v1/capabilities
> ```

</details>

### Policies Management

<details>
 <summary><code>POST</code> <code><b>/api/v1/policies</b></code> <code>(Creates a new policy)</code></summary>

##### Parameters

> | name | type | data type | description |
> |------|------|-----------|-------------|
> | None | required | YAML object | yaml format specified in [Policy RFC](#policy-rfc) |

##### Responses

> | http code | content-type | response |
> |-----------|--------------|----------|
> | `201` | `application/json; charset=UTF-8` | `{"detail":"policies [policy_name] were started"}` |
> | `400` | `application/json; charset=UTF-8` | `{"detail":"invalid Content-Type. Only 'application/x-yaml' is supported"}` |
> | `400` | `application/json; charset=UTF-8` | Any other policy error |
> | `409` | `application/json; charset=UTF-8` | `{"detail":"policy 'policy_name' already exists"}` |

##### Example cURL

> ```sh
>  curl -X POST -H "Content-Type: application/x-yaml" --data-binary @policy.yaml http://localhost:8075/api/v1/policies
> ```

</details>

<details>
 <summary><code>DELETE</code> <code><b>/api/v1/policies/{policy_name}</b></code> <code>(delete an existing policy)</code></summary>

##### Parameters

> | name | type | data type | description |
> |------|------|-----------|-------------|
> | `policy_name` | required | string | The unique policy name |

##### Responses

> | http code | content-type | response |
> |-----------|--------------|----------|
> | `200` | `application/json; charset=UTF-8` | `{"detail":"policy 'policy_name' was deleted"}` |
> | `404` | `application/json; charset=UTF-8` | `{"detail":"policy not found"}` |
> | `500` | `application/json; charset=UTF-8` | `{"detail":"<error>"}` (policy stop failure) |

##### Example cURL

> ```sh
>  curl -X DELETE http://localhost:8075/api/v1/policies/policy_name
> ```

</details>
