# Netprobe

Handler type: `netprobe`

- [Example of policy](#example-of-policy-with-input-netprobe-and-handler-netprobe)
- [Metrics Group](#metrics-group)
- [Filters](#filters)
- [Configurations](#configurations)
- [Target attributes](#target-attributes)

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


## Metrics Group

- [Check the netprobe metrics belonging to each group](../metrics.md#netprobe-metrics)

| Metric Group | Default  |
|:------------:|:--------:|
| `quantiles`  | disabled |
|  `counters`  | enabled  |
| `histograms` | enabled  |
| `http_response_phases` | disabled |

## Filters

- No filters available.

## Configurations

- [Abstract configurations](README.md#abstract-configurations).

The netprobe handler accepts `recorded_stream`, `xact_ttl_secs` and
`xact_ttl_ms`. `recorded_stream` is presence-based, so setting it to `false`
still enables it; omit the key to disable.

What is probed, including the required `targets` map, is configured on the
netprobe input instead. See [Netprobe input](../inputs/netprobe.md) for the test
types, their settings and the HTTP response checks.

Netprobe settings describe the probe rather than the host the agent runs on, so
they are often worth setting on the policy's `input` rather than on the tap. A
policy input may override any of the tap's netprobe settings; see
[Input in a policy](../inputs/README.md#input-in-a-policy).

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

## Target attributes

Besides the policy's own [`attributes`](../README.md#policy-attributes), each target can set
`attributes` under `input.config.targets.<name>.attributes`. Needs orb-agent 2.18.0.

```yaml
kind: collection
attributes:
  netbox.site.name: dc-west
  netbox.tenant.name: acme
input:
  input_type: netprobe
  config:
    test_type: ping
    targets:
      gw1:
        target: 192.0.2.1
        attributes:
          netbox.site.name: dc-east
          netbox_id: netbox-device-42
          device_ip: 192.0.2.1
handlers:
  modules:
    probe_metrics:
      type: netprobe
```

- The target's attributes are laid over the policy's, key by key, and the target's value wins.
  Here the series of `gw1` carry `netbox.site.name: dc-east`, `netbox.tenant.name: acme`,
  `netbox_id`, `device_ip` and `target`.
- The same rules apply as for the policy's attributes: values are exported as text, so quote a
  number whose exact text matters, and the agent refuses the policy for the reasons listed under
  [Checks before the policy is applied](../README.md#checks-before-the-policy-is-applied). The
  limits apply to the merged set of each target. A target key whose Prometheus name matches a
  different policy key is a clash; the same key written the same way is an override.
- A key may not be `target`, `status_code` or `rcode`, the labels the handler sets itself. The
  agent refuses `target` (and `policy`, `handler`, `tap`, `device`, `le` and `quantile`) before it
  sends anything, so an edit that uses one leaves the running version running. For `status_code`
  and `rcode` only `pktvisord` refuses the policy, when it loads it. An edit it refuses has
  already removed the running version, so the policy runs nothing until the body is fixed; see
  [Edits](../README.md#edits).
- Target attributes are not part of the input's config: policies that differ only in them share
  one input. pktvisor's own netprobe documentation has the same section.
