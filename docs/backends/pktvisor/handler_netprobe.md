# Netprobe handler (netprobe)

- [Example of policy](#example-of-policy-with-input-netprobe-and-handler-netprobe)
- [Metrics Group](#metrics-group)
- [Filters](#filters)
- [Configurations](#configurations)

## Example of policy with input netprobe and handler NETPROBE

```yaml
handlers:
  modules:
    default_netprobe:
      type: netprobe
      metric_groups:
        enable:
          - counters
          - quantiles
          - histograms
input:
  input_type: netprobe
  tap: default_netprobe
  config:
    targets:
      primary_site:
        target: www.example.com
      secondary_site:
        target: www.example.net
kind: collection
```

**Handler Type**: "netprobe"

## Metrics Group

- [Check the netprobe metrics belonging to each group](metrics.md#netprobe-metrics)

| Metric Group | Default  |
|:------------:|:--------:|
| `quantiles`  | disabled |
|  `counters`  | enabled  |
| `histograms` | enabled  |
| `http_response_phases` | disabled |

## Filters

- No filters available.

## Configurations

- [Abstract configurations](handlers.md#abstract-configurations).

The netprobe handler accepts `recorded_stream`, `xact_ttl_secs` and
`xact_ttl_ms`. `recorded_stream` is presence-based, so setting it to `false`
still enables it; omit the key to disable.

What is probed, including the required `targets` map, is configured on the
netprobe input instead. See [Netprobe input](input_netprobe.md) for the test
types, their settings and the HTTP response checks.

Netprobe settings describe the probe rather than the host the agent runs on, so
they are often worth setting on the policy's `input` rather than on the tap. A
policy input may override any of the tap's netprobe settings; see
[Input in a policy](inputs.md#input-in-a-policy).

```yaml
handlers:
  modules:
    default_netprobe:
      type: netprobe
      metric_groups:
        enable:
          - counters
          - quantiles
          - histograms
input:
  input_type: netprobe
  tap: default_netprobe
  config:
    targets:
      primary_site:
        target: www.example.com
      secondary_site:
        target: www.example.net
    test_type: ping
    interval_msec: 2500
    timeout_msec: 2000
    packets_per_test: 5
    packets_interval_msec: 20
    packet_payload_size: 56
kind: collection
```
