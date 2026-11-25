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

### Attributes
A policy can put attributes of its own on every series of its targets, exported as OTLP datapoint attributes. `scope.attributes` applies to every target, and `attributes` on a target applies to that target, a key it sets taking the target's value over the scope's:

```yaml
orb:
  policies:
    gnmi_telemetry:
      edge_metrics:
        config:
          metrics_interval: 30
        scope:
          username: "admin"
          password: "${GNMI_PASSWORD}"
          attributes:
            netbox.site.name: "dc-west"
            netbox.tenant.name: "tenant-a"
          targets:
            - host: "192.168.1.1"
            - host: "192.168.1.2"
              attributes:
                netbox.site.name: "dc-east"
                rack_units: 2
```

- Keys start with an ASCII letter, are valid UTF-8 and are case-sensitive; no other convention is enforced. OTel-style names keep them clear of the names the profiles promote: a `netbox.` namespace with the property named, such as `netbox.site.name`, which Prometheus shows as `netbox_site_name`. A string, `true` or `false`, an integer within 64 bits or a float is exported as a string, a boolean, a 64-bit integer or a double.
- The merge is key by key: a target's block overrides the keys it names and keeps the rest of the scope's, so a target cannot remove a scope key.
- A target's attributes are bounded in number, in the length of each key and string value, and in their size together, since every series and every export repeats them; the limits are under [`attributes`](../../orb-telemetry/gnmi-telemetry/README.md#attributes).
- The policy is refused, with an error naming the policy, the target and the key, for a null, map, list, empty string or unquoted date, an integer past 64 bits, an empty key, a key the collector sets itself (`device_ip`, `netbox_id`, the `mode` of `gnmi.target_up`, and `policy_name`, the policy scope key of earlier releases), a key in the `orb` namespace (`orb.`, `orb_` and the like), which the Orb platform strips, or a key a profile of the policy's profile set promotes, such as `interface_name` or `component_name` in the bundled set.
- Keys are also compared as Prometheus writes them, every character outside `[A-Za-z0-9_]` turned into an underscore: `netbox.id` is refused because it becomes `netbox_id`, `netbox.site.name` beside `netbox_site_name` because the two become one label, and `job`, `instance` or a key starting with `otel_scope_` because Prometheus sets or reserves those labels itself, the `otel_scope_` ones from the instrumentation scope every policy's series carry. A key must start with a letter because Prometheus prefixes any other: `2 cents` would become `key_2_cents`.
- Two ranges sharing an address with different attributes are refused when the policy is applied; give them the same attributes, or split the ranges so they share no address. A target naming a single address inside a range keeps its own attributes, as it keeps its own port and credentials, but does not clear a conflict between two ranges.
- `gnmi.target_up` carries the target's attributes too.
- A change takes effect when the policy is applied again: an edit reaches the backend as a removal followed by an apply.
- The agent re-encodes a policy before posting it, so some numbers change type on the way: a float with no fractional part below 1,000,000 in magnitude, such as `3.0`, arrives as the integer `3`; and an integer of 2^64 or more, or below -2^63, arrives as a float. This holds whether Fleet delivers the policy as YAML or as a JSON object. Quote a number to keep its exact text.

`attributes` needs orb-agent 2.18.0 (gnmi-telemetry 1.2.0). With an older agent, the backend logs `ignoring unrecognized policy key` with `key=attributes` and runs the policy without them. The full rules are under [`attributes`](../../orb-telemetry/gnmi-telemetry/README.md#attributes) in the backend README.

### Delivery modes
For each target the backend selects a metric profile from the vendor and network OS the device reports, and asks for the profile's paths in the mode the profile names: counters at the `metrics_interval` SAMPLE cadence, states ON_CHANGE. A device that refuses that request is asked for SAMPLE on every path, and one that refuses that too is polled with Get at the same interval. `config.mode` narrows the ladder: `on_change` keeps the profile's own modes and skips the all-SAMPLE rung, `sample` asks for SAMPLE on every path from the start; both still fall to Get. A target may set its own `mode`, and `profile` pins a metric profile instead of matching it from the device's Capabilities.

The full parameter tables are in the backend README under [Policy Configuration](../../orb-telemetry/gnmi-telemetry/README.md#policy-configuration).

## Metrics
Every metric name comes from the profile: a profile metric named `if_in_octets` is exported as `gnmi.if_in_octets`, so the names a policy produces are known before it runs. Every series is exported under an instrumentation scope carrying `orb.policy.name`, one scope per policy, and carries `device_ip`, plus `netbox_id` when the target sets `id`, whatever path keys the profile promotes, such as `interface_name`, and the policy's own `attributes` for the target. A profile metric of type `counter` is exported as a cumulative total and one of type `gauge` as a gauge; an enumerated or boolean leaf is mapped to the integer the profile names.

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

## A policy's errors in the heartbeat
Every 10 seconds the agent reads the backend's status (`GET /api/v1/status`), which lists each policy it runs with `running`, or `running_with_errors` and the policy's `last_error`: the most recent error of its targets, or of the sweep that found them. A policy running with errors stays `running` in the heartbeat, its `error` set to that `last_error`, and the next read that finds it `running` sends an empty `error` again. The error is masked as a run's reason is, so a value of one of the policy's secret references that it quotes is sent as `********`, and it is kept to 1 KB, ending `... (truncated)` past that, since the heartbeat goes out every few seconds. The collection errors of all the agent's policies are kept to 8 KB together in each heartbeat, so that it stays small however many policies fail: when they add up to more, each gets an equal share, an error shorter than its share is sent whole, and the others are cut to theirs, ending `... (truncated)`. An error the backend recorded (its `last_error_at`) before the policy now under that name began to run is not sent: it is the error of a policy removed from under the name, and one without that time is masked with that policy's values too, while the agent keeps them. A policy that failed to apply keeps sending why, not its collection error. The per-target status the backend also reports is not sent.
