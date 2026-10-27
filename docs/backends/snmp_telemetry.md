# SNMP Telemetry
The SNMP telemetry backend polls SNMP devices under policies and exports the collected metrics over OTLP through the agent's `common.otlp` settings. A policy may also receive SNMP traps and informs from the devices it names and count them. It ingests nothing into Diode.

The backend's own [README](../../orb-telemetry/snmp-telemetry/README.md) is the reference for the metric model, the bundled SNMP profiles, the security posture and trap reception. This page covers how to reach the backend through the agent.

## Configuration
`common.otlp.grpc` is required: every metric the backend produces leaves over OTLP. With `snmp_telemetry` enabled and no endpoint, the agent reports the missing setting and refuses to start, the way it does for any backend that fails to configure. Every other key is optional.

```yaml
orb:
  backends:
    common:
      otlp:
        grpc: "grpc://otel-collector:4317"
    snmp_telemetry:
      start_mode: on_demand              # the image declares this backend on demand; see the README's Backends section
      host: 127.0.0.1                    # default localhost
      port: 8078                         # default: a free port on a loopback host, 8078 otherwise
      log_level: INFO                    # default INFO (DEBUG, INFO, WARN, ERROR)
      log_format: TEXT                   # default TEXT (TEXT, JSON)
      otel_export_period: 10             # seconds between checks for newly polled values, default 10
      policy_env_vars: [SNMP_COMMUNITY]  # unset by default: every ${NAME} reference in a policy is refused
      # Both directories must exist; the image creates neither, so they are shown commented out.
      # snmp_profiles_root: /opt/orb/profiles   # unset by default: every per-policy profiles_dir is refused
      # snmp_profiles_dir: /opt/orb/overrides   # unset by default: only the bundled profiles are used
```

| Parameter | Type | Default | Description |
|:---------:|:----:|:-------:|:------------|
| host | str | `localhost` | Address the backend's API binds. The agent reaches it on loopback; the API has no authentication, so widen it only behind your own access control. |
| port | int | free port | Port of the backend's API, 1 to 65535. Unset, a loopback `host` gets a port free at each start and any other `host` gets 8078; see [Backend keys](../configs/agent_yaml.md#backend-keys). |
| log_level | str | `INFO` | `DEBUG`, `INFO`, `WARN` or `ERROR`; any other value is refused. The agent passes `DEBUG` when the backend has `debug: true` or the agent runs with its debug flag. |
| log_format | str | `TEXT` | `TEXT` or `JSON`; any other value is refused. |
| otel_export_period | int | 10 | Seconds between checks for newly polled values to export, 1 to 31536000: the longest a poll's values wait before they are sent. Each check exports a device's latest poll once, so keep it at or below the shortest `metrics_interval` of any policy; see [When metrics are exported](#when-metrics-are-exported). |
| policy_env_vars | str or list | unset | Environment variable names a policy may read through `${NAME}` in `community`, `username`, `auth_passphrase` or `priv_passphrase`. A comma-separated string or a list of names, never `${...}` references. Unset refuses every reference. |
| snmp_profiles_root | str | unset | Directory a policy's own `profiles_dir` must resolve inside. Unset refuses every per-policy `profiles_dir`. |
| snmp_profiles_dir | str | unset | Directory of profile YAML files overlaid on the bundled profiles. |

The environment variables `policy_env_vars` names must be present in the agent's environment; the backend inherits it.

## Policy
A policy names the targets to poll and the SNMP credentials to use. `metrics_interval` is the number of seconds between collection runs for every target in the policy.

```yaml
orb:
  policies:
    snmp_telemetry:
      core_metrics:
        config:
          metrics_interval: 60
        scope:
          targets:
            - host: "192.168.1.1"
            - host: "192.168.1.2"
          authentication:
            protocol_version: "v2c"
            community: "public"
```

A policy receives traps by declaring the address they arrive on:

```yaml
orb:
  policies:
    snmp_telemetry:
      core_traps:
        scope:
          authentication:
            protocol_version: "v3"
            security_level: "authPriv"
            username: "netbox-poller"
            auth_protocol: "SHA"
            auth_passphrase: "authpass123"
            priv_protocol: "AES"
            priv_passphrase: "privpass123"
          targets:
            - host: "10.0.0.0/24"
          traps:
            listen: "0.0.0.0:162"
```

A credential may be read from the agent's environment as `${NAME}` only when `policy_env_vars` in the backend configuration names it; otherwise the policy is refused.

Three rules matter when writing agent config:

- Policies naming the same `listen` string share one socket, opened when the first of them starts and closed when the last stops.
- The string is the identity. `0.0.0.0:162` and `:162` are two bind attempts at one port, and the second policy fails to apply with the bind error, which the agent logs. Spell `listen` identically across policies.
- A policy may omit `metrics_interval` to receive traps only, as `core_traps` above does. Its targets are still expanded: they are the addresses the socket accepts traps from.

The full parameter tables are in the backend README under [Policy Configuration](../../orb-telemetry/snmp-telemetry/README.md#policy-configuration) and [Receiving traps](../../orb-telemetry/snmp-telemetry/README.md#receiving-traps).

## Metrics
Every series of a policy is exported under an instrumentation scope carrying `policy_name`, one scope per policy; datapoints carry the device attributes (`device_ip`, `device_port`, `netbox_id`, `snmp_context`) and the profile's tags. Poll metrics are described in the backend README. Trap reception adds three:

- `snmp.traps_received{device_ip, trap_name, version}` counts traps and informs attributed to a policy, under that policy's scope.
- `snmp.traps_dropped{reason}` counts datagrams that produced no trap.
- `snmp.traps_datagrams` counts every datagram read from any trap socket.

The `trap_name` set and the drop reasons are listed under [Receiving traps](../../orb-telemetry/snmp-telemetry/README.md#receiving-traps).

Tag values read from an OCTET STRING are rendered as valid UTF-8 before export, since one value that is not would drop the whole export of every policy:

- UTF-8 text is kept, and a value of only NUL bytes, an unset string, is empty.
- Anything else, such as a MAC read without a `hwaddr` conversion or text that is not UTF-8, reads as the colon-separated hex of its bytes: `00:1b:21:bb:e6:f0`, the same value `hwaddr` gives for a MAC.

`snmp.invalid_utf8_repaired{attribute}` counts any string the exporter still had to repair, which should stay at zero. The rules are in the backend README under [SNMP Profiles](../../orb-telemetry/snmp-telemetry/README.md#snmp-profiles).

## When metrics are exported
Each poll's values are exported once, by the first export after the poll. `otel_export_period` is how often the backend checks for newly polled values, so it is the longest a poll's values wait before they leave, not how often they are sent. At `metrics_interval: 60` a device is exported once a minute and the backend downstream stores one sample per series per poll; policies on different intervals in one backend each export once per poll.

- A check exports a device's latest poll, so a policy whose `metrics_interval` is shorter than `otel_export_period` has only its latest poll before each check exported; the polls in between are not. Starting such a policy logs a warning naming both periods. Keep `otel_export_period` at or below the shortest `metrics_interval` of any policy.
- A declaration throttled by `poll_time_sec` leaves with every poll, from the reading it kept, so every series of a device has one sample per poll.
- A run that fails or is cut short exports nothing: the device's earlier values are not sent again as if they were current.
- An export that would carry no policy's values, only the backend's own counters (`snmp.traps_datagrams`, `snmp.traps_dropped`, `snmp.invalid_utf8_repaired`), is sent at most once a minute. The counters are cumulative, so the next export carries their totals, and the export made at shutdown is sent whatever it carries, so they leave with their final totals.
- Trap counts are not polled: `snmp.traps_received` is exported at every check while a policy holds it, as before.
- A poll whose export still fails after the OTLP exporter's own retries is not sent again.
- With a `metrics_interval` of five minutes or more, samples are as far apart as Prometheus' default five-minute lookback, so a panel showing the latest value can show gaps between polls. Query such a policy's series with a range at least one interval wide, such as `last_over_time(metric[6m])` at `metrics_interval: 300`.

Why this way. The backend used to export every `otel_export_period` whatever the interval, re-sending each stored value, and every export stamps a value with the time it is collected, so each poll was stored `metrics_interval / otel_export_period` times, six at the defaults: six times the broker traffic, the platform's processing and the samples stored downstream. Of the ways to send a poll once:

- An export period tied to `metrics_interval` cannot serve two policies on different intervals in one backend, and a poll that drifts against the export tick is still sent twice or not at all.
- An export right after each poll sends one export per device per poll, since each target is polled as its own job: a policy over a /24 would send about 254 exports a minute instead of 6.
- Delta temporality changes how counters and histograms report, not gauges, and every polled value is a gauge whose callback reads the stored value again at every export, so the repeats would stay.

So the backend keeps one periodic export and hands each poll's values to it once.

## When a policy starts or changes
Every target polls as soon as its policy starts, then every `metrics_interval`. A policy starts when it is applied, when it is edited, and when the agent or the backend restarts, so its first values are exported within one `otel_export_period` (10 seconds by default) plus the time the poll takes, rather than one interval later. In a large policy the last target's first values follow up to 10 seconds after that.

- A large policy spreads its first polls about 10 milliseconds apart, counted from when it starts, closer when needed to fit a policy of more than 1,000 targets into 10 seconds and every policy into one interval. Each target keeps its offset afterwards, so the policy's polls do not all run in the same instant.
- An edit, even to one device, reaches the backend as a removal followed by an apply. The devices the edit keeps poll again as it applies, so their series miss no sample: the next one comes early, or at most 10 seconds late. Added devices poll at once, and removed devices stop.
- Removing or editing a policy cancels any poll still in flight at once, so it does not wait out `snmp_timeout` on a device that does not answer.

## Traps and the container
The trap socket is the one listener in the backend that must be reachable from the device network. With `--net=host` the port a policy's `listen` names is already exposed. In bridge mode publish it, `-p 162:162/udp` for a policy listening on 162. The container runs as root by default, the image sets no other user, so binding a port below 1024 inside it needs no capability.

What a policy body can do through `listen`, and why the listen address is not access control, is described under [Binding and access control](../../orb-telemetry/snmp-telemetry/README.md#binding-and-access-control) and [Receiving traps](../../orb-telemetry/snmp-telemetry/README.md#receiving-traps).
