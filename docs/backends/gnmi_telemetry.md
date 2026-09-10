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
      host: 127.0.0.1                    # default localhost
      port: 8079                         # default 8079
      log_level: INFO                    # default INFO (DEBUG, INFO, WARN, ERROR)
      log_format: TEXT                   # default TEXT (TEXT, JSON)
      otel_export_period: 10             # seconds between exports, default 10
      policy_env_vars: [GNMI_PASSWORD]   # unset by default: every ${NAME} reference in a policy is refused
      # Both directories must exist; the image creates neither, so they are shown commented out.
      # profiles_root: /opt/orb/profiles   # unset by default: every per-policy profiles_dir is refused
      # profiles_dir: /opt/orb/overrides   # unset by default: only the bundled profiles are used
```

| Parameter | Type | Default | Description |
|:---------:|:----:|:-------:|:------------|
| host | str | `localhost` | Address the backend's API binds. The agent reaches it on loopback; the API has no authentication, so widen it only behind your own access control. |
| port | int | 8079 | Port of the backend's API, 1 to 65535. |
| log_level | str | `INFO` | `DEBUG`, `INFO`, `WARN` or `ERROR`; any other value is refused. The agent passes `DEBUG` when the backend has `debug: true` or the agent runs with its debug flag. |
| log_format | str | `TEXT` | `TEXT` or `JSON`; any other value is refused. |
| otel_export_period | int | 10 | Seconds between OTLP exports, 1 to 31536000. |
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
```

A credential or a TLS file path may be read from the agent's environment as `${NAME}` only when `policy_env_vars` in the backend configuration names it; otherwise the policy is refused. A CIDR or range target may carry a credential only when TLS verifies the server, or when the policy sets `send_credentials_to_unverified_targets: true`.

### Delivery modes
For each target the backend selects a metric profile from the vendor and network OS the device reports, and asks for the profile's paths in the mode the profile names: counters at the `metrics_interval` SAMPLE cadence, states ON_CHANGE. A device that refuses that request is asked for SAMPLE on every path, and one that refuses that too is polled with Get at the same interval. `config.mode` narrows the ladder: `on_change` keeps the profile's own modes and skips the all-SAMPLE rung, `sample` asks for SAMPLE on every path from the start; both still fall to Get. A target may set its own `mode`, and `profile` pins a metric profile instead of matching it from the device's Capabilities.

The full parameter tables are in the backend README under [Policy Configuration](../../orb-telemetry/gnmi-telemetry/README.md#policy-configuration).

## Metrics
Every metric name comes from the profile: a profile metric named `if_in_octets` is exported as `gnmi.if_in_octets`, so the names a policy produces are known before it runs. Every series carries `device_ip` and `policy`, plus `netbox_id` when the target sets `id`, and whatever path keys the profile promotes, such as `interface_name`. A profile metric of type `counter` is exported as a cumulative total and one of type `gauge` as a gauge; an enumerated or boolean leaf is mapped to the integer the profile names.

Export runs on `otel_export_period`, independently of the sample cadence, and carries the last value of each series. A SAMPLE or Get series that receives no update for three `metrics_interval`s is withheld and dropped until the device sends the leaf again; an ON_CHANGE series keeps its last value until the device deletes the element, the stream's next initial dump omits it, or the policy stops.

Seven metrics describe the backend itself, among them `gnmi.target_up{device_ip, policy, mode}`, `gnmi.updates_dropped_total{reason}` and `gnmi.mode_fallback_total`; they are listed under [Metrics](../../orb-telemetry/gnmi-telemetry/README.md#metrics), and the profile format under [Metric Profiles](../../orb-telemetry/gnmi-telemetry/README.md#metric-profiles).
