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
      config:
        targets:
          primary_site:
            target: www.example.com
          secondary_site:
            target: www.example.net
input:
  input_type: netprobe
  tap: default_netprobe
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

## Filters

- No filters available.

## Configurations

- [Abstract configurations](handlers.md#abstract-configurations).

|                          Config                          | Type |          Required           | Default |
|:--------------------------------------------------------:|:----:|:---------------------------:|:-------:|
|               [targets](#targets)               | map  |              ✅              |    -    |

### targets

Type: : *map*

Here, the targets against which the probe will run are defined.
For each target is required to specify the target name and the address to be tested.

```yaml
targets: map
```
Example:
```yaml
targets:
  target_name:
    target: ipv4 address to test
```
Generic Example:
```yaml
targets:
  primary_site:
    target: www.example.com
```

- In netprobe policies it makes a lot of sense to use the settings from the input directly in the policy, since the settings are more related to the probe than the device the orb agent is running on. Therefore, it is worth reinforcing here the ability to override all tap settings in the policy. See here the available configurations for netprobe.

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
          config:
            targets:
              primary_site:
                target: www.example.com
              secondary_site:
                target: www.example.net
    input:
      input_type: netprobe
      tap: default_netprobe
      config:
        test_type: ping
        interval_msec: 2500
        timeout_msec: 2000
        packets_per_test: 5
        packets_interval_msec: 20
        packet_payload_size: 56
    kind: collection
```
