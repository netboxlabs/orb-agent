# gNMI Discovery
The gNMI discovery backend is an event-driven network discovery service that maintains long-lived [gNMI](https://github.com/openconfig/gnmi) subscriptions and ingests device, interface, and hardware-inventory changes into NetBox via Diode within seconds of them occurring.

Unlike SNMP/NAPALM-based polling, `gnmi_discovery` reacts to `ON_CHANGE` notifications from the device itself (with `SAMPLE` and `GET` fallback for devices that don't support streaming), so NetBox stays up to date continuously rather than on a polling interval.

## Diode Entities
The gNMI discovery backend uses the [Diode Go SDK](https://github.com/netboxlabs/diode-sdk-go) to ingest the following entities:

* Device (with `DeviceType`, `Platform`, and serial/manufacturer enrichment)
* Interface
* Module / ModuleBay (hardware inventory)
* IP Address
* VRF

## Configuration
The `gnmi_discovery` backend requires no special configuration; `host` and `port` may be overridden. It uses the `diode` settings from the `common` subsection to forward discovery results.

```yaml
orb:
  backends:
    common:
      diode:
        target: grpc://192.168.0.100:8080/diode
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
        agent_name: agent01
    gnmi_discovery:
      host: 192.168.5.11 # default localhost
      port: 8076 # default 8075
      log_level: ERROR # default INFO
      log_format: JSON # default TEXT
      profiles_dir: /opt/orb/gnmi-profiles # optional: directory of gNMI profile overrides
      otel_export_period: 30 # optional: seconds between OpenTelemetry metric exports (default 10)
```

| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| host | str | no | REST API host (default `localhost`) |
| port | int | no | REST API port (default `8075`) |
| log_level | str | no | Log level: `DEBUG`/`INFO`/`WARN`/`ERROR` (default `INFO`) |
| log_format | str | no | Log format: `TEXT` or `JSON` (default `TEXT`) |
| profiles_dir | str | no | Directory of gNMI profile overrides (empty = embedded profiles only) |
| otel_export_period | int | no | Seconds between OpenTelemetry metric exports (default `10`) |

## Policy
gNMI discovery policies are broken into two subsections: `config` and `scope`.

### Config
`config` defines behavior for the whole policy and is optional overall.

| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| mode | str | no | Delivery mode: `auto` (default), `on_change`, `sample`, or `get`. `auto` negotiates the best mode per target (`ON_CHANGE → SAMPLE → GET`). |
| debounce_ms | int | no | Flush delay in ms after the last notification before a snapshot is ingested (default `2000`). |
| sample_interval_ms | int | no | `SAMPLE` subscription interval in ms (default `300000` = 5m). |
| get_interval_ms | int | no | `GET` poll interval in ms (default `900000` = 15m). |
| probe_timeout_ms | int | no | How long a sweep waits for one address to answer (default `3000`). Too low and a whole subnet reports as absent with no failure signal. |
| rescan_interval_ms | int | no | Re-probe addresses this policy is not subscribed to, picking up devices that were down when the policy was applied. Unset or `0` disables it; a non-zero value below `60000` is rejected. |
| options | map | no | Per-policy toggles. `capture_config` (bool) captures the CONFIG datastore into `Device.config.running` (default off). |
| defaults | map | no | NetBox defaults applied to discovered entities (see below). |

#### Defaults
| Key | Type | Description |
|:---:|:----:|:-----------:|
| site | str | NetBox site (default `undefined`) |
| role | str | NetBox device role (default `undefined`) |
| location | str | NetBox location (optional) |
| tags | list | NetBox tags applied to all entities |
| device | map | Device overrides: `manufacturer`, `model`, `platform`, `comments`, `tags` |
| interface | map | Interface defaults: `if_type` (fallback type, default `other`), `description`, `tags` |
| ip_address | map | IP address defaults: `role`, `tenant`, `description`, `comments`, `tags` |
| vrf | map | VRF defaults: `tenant`, `description`, `comments`, `tags` (name/RD come from discovery) |
| interface_patterns | list | Name-regex → NetBox type, highest precedence (first match wins). |
| interface_exclude_patterns | list | Name-regex; matching interfaces are skipped entirely. |

### Scope
`scope` defines the list of gNMI targets to discover.

| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| targets | list | yes | The gNMI endpoints to discover (see target fields below). |
| username | str | no | Default gNMI username for every target that does not set its own. `${ENV_VAR}` syntax is supported. |
| password | str | no | Default gNMI password for every target that does not set its own. `${ENV_VAR}` syntax is supported. |
| port | int | no | Default port for every target whose `host` carries no port and that sets no `port` of its own (default `9339`). |
| origin | str | no | Default gNMI path origin. A target that sets `origin: ""` keeps origin-less paths rather than inheriting. |
| tls | map | no | Default TLS settings. A target's own `tls` block **replaces** this one entirely rather than merging field by field, because a bool cannot distinguish "unset" from "false". |

Scope-level settings are defaults, not overrides: a target that sets a field keeps
its own value. What counts is that the field is *present*, not that it is
non-empty, so a target inside a credentialed scope can connect anonymously by
writing `username: ""` and `password: ""`. `mode`, `profile` and `override_defaults` are deliberately not
scope fields — `mode` and `override_defaults` duplicate the policy-level `config`
knobs, and a scope-level `profile` would pin one vendor profile onto every device
in a range whose contents are by definition unknown.

#### Target
| Key | Type | Required | Description |
|:---:|:----:|:--------:|:-----------:|
| host | str | yes | A single endpoint (`10.0.0.11`, `10.0.0.11:6030`, `switch-a.example.com`), a CIDR (`10.0.0.0/24`), or a range (`10.1.0.0-50`, `10.2.0.0-10.2.0.9`). A CIDR or range cannot carry an inline `:port` — use the `port` field. |
| port | int | no | Port for this target, used when `host` carries no inline port (default `9339`). An inline `host:port` wins over this field, which wins over the scope's. |
| username | str | no | gNMI username. `${ENV_VAR}` syntax is supported. Set it to `""` to connect anonymously from inside a scope that sets one — an omitted field inherits, an explicitly empty one does not. |
| password | str | no | gNMI password. `${ENV_VAR}` syntax is supported. Set it to `""` to block the scope's, as with `username`. |
| tls | map | no | TLS settings: `skip_verify` (keep TLS, don't verify the cert), `insecure` (opt-in PLAINTEXT, off by default), `ca`/`cert`/`key` (optional mTLS). TLS with system root CAs is the default. |
| mode | str | no | Per-target delivery mode override (`auto`/`on_change`/`sample`/`get`). |
| profile | str | no | Pin a gNMI profile (auto-detected when omitted). |
| origin | str | no | gNMI path origin (default `openconfig`); set `""` for origin-less paths. |
| netbox_id | int | no | Pin discovery to an existing NetBox device ID. Silently ignored when `host` is a CIDR or range: one NetBox device ID cannot describe a range. |
| override_defaults | map | no | Per-target overrides of the policy `defaults`. |

#### Ranges and subnets
A `host` that names more than one address is expanded and each address is probed
once before anything is subscribed to; only the addresses that answer get a
subscription. This matters because a gNMI subscription is a persistent stream
rather than a poll — without the probe, a `/24` would leave ~250 goroutines
redialling empty addresses for the life of the policy.

A CIDR excludes its network and broadcast addresses, so `10.0.0.0/24` is 254 and
`10.0.0.0/22` is 1022. A `/31` and a `/32` have no such pair to exclude and stay
2 and 1. A range excludes nothing, because the operator enumerated it explicitly:
`10.0.0.0-255` is 256, not 254. A policy may expand to at most 1024 addresses in
total, counted across all its targets and checked before any expansion happens.

A probe answers the question "is anything listening on the gNMI port", and
nothing more. Any response admits the address, including a rejected RPC or a
failed TLS handshake — an mTLS device probed without a client cert, or a campus
of self-signed certificates, is present, not absent. Only silence means absence.
Probes carry no credentials, so a sweep never sprays the scope password across a
range.

A single named host is never probed: naming it is the operator asserting it
exists, and a device that happens to be rebooting should not be dropped for the
life of the policy.

The sweep reports itself as a run on `/status`, named after the host strings you
wrote, with the number of addresses that answered and the reason the rest did
not. A range where nothing answered is reported as a failed run.

#### Interface type discovery
Each interface's NetBox type is resolved per interface, in precedence order:
1. `interface_exclude_patterns` — a name matching any regex is skipped (no interface emitted).
2. `interface_patterns` — the first matching regex assigns its `type` (wins over the rest).
3. OpenConfig `state/type` — the discovered identityref maps to a NetBox type for structural families (LAG → `lag`; loopback/VLAN/tunnel/prop-virtual → `virtual`).

### Sample
A sample policy exercising the common gNMI discovery parameters.
```yaml
orb:
  ...
  policies:
    gnmi_discovery:
      gnmi_fabric:
        config:
          mode: auto
          debounce_ms: 2000
          defaults:
            site: New York NY
            role: Router
            tags: [gnmi-discovery, orb-agent]
            interface_patterns:
              - match: "^Ethernet"
                type: 10gbase-x-sfpp
            interface_exclude_patterns:
              - "^Management"
          rescan_interval_ms: 3600000    # re-probe hourly for devices that were down
        scope:
          username: ${GNMI_USER}         # inherited by every target below
          password: ${GNMI_PASS}
          port: 6030                     # Arista EOS default gNMI port
          tls:
            ca: /run/secrets/ca.pem      # prefer a CA over skip_verify
          targets:
            - host: 10.0.0.0/24          # swept: only addresses that answer subscribe
            - host: 10.1.0.0-50
            - host: 10.0.0.11            # a named host is subscribed without probing
              profile: arista_eos
            - host: 10.0.0.21            # Nokia SR-OS
              port: 57400
              username: admin
              netbox_id: 42              # honoured: a bare address, not a range
```
