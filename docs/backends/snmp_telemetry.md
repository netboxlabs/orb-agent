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
      host: 127.0.0.1                    # default localhost
      port: 8078                         # default 8078
      log_level: INFO                    # default INFO (DEBUG, INFO, WARN, ERROR)
      log_format: TEXT                   # default TEXT (TEXT, JSON)
      otel_export_period: 10             # seconds between exports, default 10
      policy_env_vars: [SNMP_COMMUNITY]  # unset by default: every ${NAME} reference in a policy is refused
      # Both directories must exist; the image creates neither, so they are shown commented out.
      # snmp_profiles_root: /opt/orb/profiles   # unset by default: every per-policy profiles_dir is refused
      # snmp_profiles_dir: /opt/orb/overrides   # unset by default: only the bundled profiles are used
```

| Parameter | Type | Default | Description |
|:---------:|:----:|:-------:|:------------|
| host | str | `localhost` | Address the backend's API binds. The agent reaches it on loopback; the API has no authentication, so widen it only behind your own access control. |
| port | int | 8078 | Port of the backend's API, 1 to 65535. |
| log_level | str | `INFO` | `DEBUG`, `INFO`, `WARN` or `ERROR`; any other value is refused. The agent passes `DEBUG` when the backend has `debug: true` or the agent runs with its debug flag. |
| log_format | str | `TEXT` | `TEXT` or `JSON`; any other value is refused. |
| otel_export_period | int | 10 | Seconds between OTLP exports, 1 to 31536000. |
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
Poll metrics are described in the backend README. Trap reception adds three:

- `snmp.traps_received{device_ip, policy, trap_name, version}` counts traps and informs attributed to a policy.
- `snmp.traps_dropped{reason}` counts datagrams that produced no trap.
- `snmp.traps_datagrams` counts every datagram read from any trap socket.

The `trap_name` set and the drop reasons are listed under [Receiving traps](../../orb-telemetry/snmp-telemetry/README.md#receiving-traps).

## Traps and the container
The trap socket is the one listener in the backend that must be reachable from the device network. With `--net=host` the port a policy's `listen` names is already exposed. In bridge mode publish it, `-p 162:162/udp` for a policy listening on 162. The container runs as root by default, the image sets no other user, so binding a port below 1024 inside it needs no capability.

What a policy body can do through `listen`, and why the listen address is not access control, is described under [Binding and access control](../../orb-telemetry/snmp-telemetry/README.md#binding-and-access-control) and [Receiving traps](../../orb-telemetry/snmp-telemetry/README.md#receiving-traps).
