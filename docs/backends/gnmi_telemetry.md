# gNMI Telemetry
The gNMI telemetry backend subscribes to gNMI streaming telemetry from network devices under policies and exports what arrives as metrics over OTLP through the agent's `common.otlp` settings. It ingests nothing into Diode.

The backend's own [README](../../orb-telemetry/gnmi-telemetry/README.md) is the reference for the subscription model, the bundled metric profiles, the security posture and the delivery-mode ladder. This page covers how to reach the backend through the agent.

## Configuration
`common.otlp.grpc` is required: every metric the backend produces leaves over OTLP. With `gnmi_telemetry` enabled and no endpoint, the agent reports the missing setting and refuses to start, the way it does for any backend that fails to configure. Every other key is optional.

```yaml
orb:
  backends:
    common:
      otlp:
        grpc: "grpc://otel-collector:4317"
    gnmi_telemetry:
      start_mode: on_demand              # the image declares this backend on demand; see the README's Backends section
      host: 127.0.0.1                    # default localhost
      port: 8079                         # default: a free port on a loopback host, 8079 otherwise
      log_level: INFO                    # default INFO (DEBUG, INFO, WARN, ERROR)
      log_format: TEXT                   # default TEXT (TEXT, JSON)
      otel_export_period: 10             # seconds between checks for new values, default 10
      policy_env_vars: [GNMI_PASSWORD]   # unset by default: every ${NAME} reference in a policy is refused
      # Both directories must exist; the image creates neither, so they are shown commented out.
      # profiles_root: /opt/orb/profiles   # unset by default: every per-policy profiles_dir is refused
      # profiles_dir: /opt/orb/overrides   # unset by default: only the bundled profiles are used
```

| Parameter | Type | Default | Description |
|:---------:|:----:|:-------:|:------------|
| host | str | `localhost` | Address the backend's API binds. The agent reaches it on loopback; the API has no authentication, so widen it only behind your own access control. |
| port | int | free port | Port of the backend's API, 1 to 65535. Unset, a loopback `host` gets a port free at each start and any other `host` gets 8079; see [Backend keys](../configs/agent_yaml.md#backend-keys). |
| log_level | str | `INFO` | `DEBUG`, `INFO`, `WARN` or `ERROR`; any other value is refused. The agent passes `DEBUG` when the backend has `debug: true` or the agent runs with its debug flag. |
| log_format | str | `TEXT` | `TEXT` or `JSON`; any other value is refused. |
| otel_export_period | int | 10 | Seconds between checks for new values to export, 1 to 31536000: the longest an update waits before it is sent. Each check exports a series' latest value once, so keep it at or below the shortest `metrics_interval` of any policy; see [When metrics are exported](#when-metrics-are-exported). |
| policy_env_vars | str or list | unset | Environment variable names a policy may read through `${NAME}` in `username`, `password` or a `tls` file path. A comma-separated string or a list of names, never `${...}` references. Unset refuses every reference. |
| profiles_root | str | unset | Directory a policy's own `profiles_dir` must resolve inside. Unset refuses every per-policy `profiles_dir`. |
| profiles_dir | str | unset | Directory of metric profile YAML files overlaid on the bundled profiles; a file replaces the bundled profile of the same name. |

The environment variables `policy_env_vars` names must be present in the agent's environment; the backend inherits it.

## Policy
A policy names the targets to subscribe to and the credentials to reach them with. `metrics_interval` is the SAMPLE cadence asked of the device in seconds, the Get polling interval when a device falls to polling, and the basis of the staleness window. Everything under `scope` is inherited by every target, and a target may override a field with its own value.

```yaml
orb:
  policies:
    gnmi_telemetry:
      core_metrics:
        config:
          metrics_interval: 30
        scope:
          username: "admin"
          password: "${GNMI_PASSWORD}"     # allowed only when policy_env_vars names it
          port: 57400                      # the binary dials 9339 unless told otherwise
          tls:
            ca: /opt/orb/ca.pem            # verify the devices against this bundle
          targets:
            - host: "192.168.1.1"
            - host: "192.168.1.2"
              id: "42"                     # exported as netbox_id
            - host: "192.168.2.0/24"       # a CIDR prefix: every address that answers is subscribed
            - host: "192.168.3.10-20"      # a range over the last octet
```

A target's `host` is one address or hostname, a CIDR prefix, or a range over the last octet; a prefix or range is swept, and each address that answers Capabilities gets a subscription of its own, while the ones that do not are probed again only when `config.rescan_interval_ms` is set. A credential or a TLS file path may be read from the agent's environment as `${NAME}` only when `policy_env_vars` in the backend configuration names it; otherwise the policy is refused. A CIDR or range target may carry a credential only when TLS verifies the server, as `tls.ca` does above, or when the policy sets `send_credentials_to_unverified_targets: true`.

### Delivery modes
For each target the backend selects a metric profile from the vendor and network OS the device reports, and asks for the profile's paths in the mode the profile names: counters at the `metrics_interval` SAMPLE cadence, states ON_CHANGE. A device that refuses that request is asked for SAMPLE on every path, and one that refuses that too is polled with Get at the same interval. `config.mode` narrows the ladder: `on_change` keeps the profile's own modes and skips the all-SAMPLE rung, `sample` asks for SAMPLE on every path from the start; both still fall to Get. A target may set its own `mode`, and `profile` pins a metric profile instead of matching it from the device's Capabilities.

The full parameter tables are in the backend README under [Policy Configuration](../../orb-telemetry/gnmi-telemetry/README.md#policy-configuration).

## Metrics
Every metric name comes from the profile: a profile metric named `if_in_octets` is exported as `gnmi.if_in_octets`, so the names a policy produces are known before it runs. Every series is exported under an instrumentation scope carrying `policy_name`, one scope per policy, and carries `device_ip`, plus `netbox_id` when the target sets `id`, and whatever path keys the profile promotes, such as `interface_name`. A profile metric of type `counter` is exported as a cumulative total and one of type `gauge` as a gauge; an enumerated or boolean leaf is mapped to the integer the profile names.

A SAMPLE or Get series that receives no update for three `metrics_interval`s is withheld and dropped until the device sends the leaf again; an ON_CHANGE series keeps its last value until the device deletes the element, the stream's next initial dump omits it, or the policy stops.

Eight metrics describe the backend itself, among them `gnmi.target_up{device_ip, mode}`, `gnmi.updates_dropped_total{reason}`, `gnmi.mode_fallback_total` and `gnmi.exports_failed_total`; they are listed under [Metrics](../../orb-telemetry/gnmi-telemetry/README.md#metrics), and the profile format under [Metric Profiles](../../orb-telemetry/gnmi-telemetry/README.md#metric-profiles).

## When metrics are exported
Each update is exported once, by the first export after it arrives. `otel_export_period` is how often the backend checks for new values, so it is the longest an update waits before it leaves, not how often a value is sent. A SAMPLE subscription or Get poll at `metrics_interval: 30` is exported every 30 seconds, one sample per series per update; policies on different intervals in one backend each export once per update.

- A check exports a series' latest value. A leaf that changed several times between two checks reports the last of them, as the gauge it is always has, and a policy whose `metrics_interval` is shorter than `otel_export_period` has only its latest sample before each check exported; the samples in between are not. Starting such a policy logs a warning naming both periods. Keep `otel_export_period` at or below the shortest `metrics_interval` of any policy.
- A leaf the device streams on change is sent when it changes and, while its value holds, again once per `metrics_interval`: the device sends nothing until it changes, and the series would otherwise go quiet downstream. `gnmi.target_up` is sent the same way.
- An export that would carry no policy's values, only the backend's own counters (`gnmi.updates_dropped_total`, `gnmi.mode_fallback_total` and the rest), is sent at most once a minute. The counters are cumulative, so the next export carries their totals, and the export made at shutdown is sent whatever it carries, so they leave with their final totals.
- An update whose export still fails after the OTLP exporter's own retries is not sent again. `gnmi.exports_failed_total` counts such exports, and leaves with the next export that gets through. When the agent's OTLP bridge has no room for an export, it asks the exporter to send it again after 5 seconds, which the exporter does once within its 10 second export timeout.
- With a `metrics_interval` of five minutes or more, samples are as far apart as Prometheus' default five-minute lookback, so a panel showing the latest value can show gaps between updates. Query such a policy's series with a range at least one interval wide, such as `last_over_time(metric[6m])` at `metrics_interval: 300`.

Why this way. The backend used to export every `otel_export_period` whatever the cadence, re-sending the last value of each series, and every export stamps a value with the time it is collected, so a 30 second sample was stored three times at the defaults, and a 60 second one six: that many times the broker traffic, the platform's processing and the samples stored downstream. Of the ways to send an update once:

- An export period tied to `metrics_interval` cannot serve two policies on different intervals in one backend, and an update that drifts against the export tick is still sent twice or not at all.
- An export right after each update would send one export per notification, and a device streams its subscriptions as many notifications.
- Delta temporality changes how counters report, not gauges, and the gauges' callbacks read the stored value again at every export, so the repeats would stay.

So the backend keeps one periodic export and hands each update to it once.

