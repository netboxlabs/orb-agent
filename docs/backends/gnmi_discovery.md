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
      host: 192.168.5.11 # default 0.0.0.0
      port: 8076 # default 8075
      log_level: ERROR # default INFO
      log_format: JSON # default TEXT
      profiles_dir: /opt/orb/gnmi-profiles # optional: directory of gNMI profile overrides
      otel_export_period: 30 # optional: seconds between OpenTelemetry metric exports (default 10)
```

| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| host | str | no | REST API host (default `0.0.0.0`) |
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
| targets | list | yes | The gNMI endpoints to subscribe to (see target fields below). |

#### Target
| Key | Type | Required | Description |
|:---:|:----:|:--------:|:-----------:|
| host | str | yes | `host:port` of the gNMI endpoint (e.g. `10.0.0.11:6030`). When the port is omitted, the IANA gNMI port `9339` is used. |
| username | str | no | gNMI username. `${ENV_VAR}` syntax is supported. |
| password | str | no | gNMI password. `${ENV_VAR}` syntax is supported. |
| tls | map | no | TLS settings: `skip_verify` (keep TLS, don't verify the cert), `insecure` (opt-in PLAINTEXT, off by default), `ca`/`cert`/`key` (optional mTLS). TLS with system root CAs is the default. |
| mode | str | no | Per-target delivery mode override (`auto`/`on_change`/`sample`/`get`). |
| profile | str | no | Pin a gNMI profile (auto-detected when omitted). |
| origin | str | no | gNMI path origin (default `openconfig`); set `""` for origin-less paths. |
| netbox_id | int | no | Pin discovery to an existing NetBox device ID. |
| override_defaults | map | no | Per-target overrides of the policy `defaults`. |

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
        scope:
          targets:
            - host: 10.0.0.11:6030       # Arista EOS default gNMI port
              username: ${GNMI_USER}
              password: ${GNMI_PASS}
              tls:
                skip_verify: true
              profile: arista_eos
            - host: 10.0.0.21:57400      # Nokia SR-OS default gNMI port
              username: admin
              password: ${GNMI_PASS}
```
