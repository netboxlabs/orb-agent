# BGP

Handler type: `bgp`

- [Example of policy](#example-of-policy-with-input-pcap-and-handler-bgp)
- [Metrics Group](#metrics-group)
- [Filters](#filters)
- [Configurations](#configurations)

## Example of policy with input pcap and handler BGP

```yaml
handlers:
  window_config:
    deep_sample_rate: 100
    num_periods: 8
  modules:
    default_bgp:
      type: bgp
      config:
        topn_count: 25
input:
  input_type: pcap
  tap_selector:
    all:
      - key1: value1
      - key2: value
  filter:
    bpf: net 192.168.1.0/24
  config:
    iface: wlo1
    host_spec: 192.168.1.0/24
    pcap_source: libpcap
    debug: true
config:
  merge_like_handlers: true
kind: collection
```


## Metrics Group

- [Check BGP metrics](../metrics.md#bgp-metrics)

- No metrics group available

## Filters

- No filters available.

## Configurations

- [Abstract configurations](README.md#abstract-configurations).
- `recorded_stream`. Marks the stream as a recording rather than live traffic. Presence-based: setting it to `false` still enables it, so omit the key to disable.
