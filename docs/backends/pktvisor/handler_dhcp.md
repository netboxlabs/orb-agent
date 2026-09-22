# DHCP handler (dhcp)

- [Example of policy](#example-of-policy-with-input-pcap-and-handler-dhcp)
- [Metrics Group](#metrics-group)
- [Filters](#filters)
- [Configurations](#configurations)

## Example of policy with input pcap and handler DHCP

```yaml
handlers:
  window_config:
    deep_sample_rate: 100
    num_periods: 8
  modules:
    default_dhcp:
      type: dhcp
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
kind: collection
```

**Handler Type**: "dhcp"

## Metrics Group

- [Check dhcp metrics](metrics.md#dhcp-metrics)

- No metrics group available

## Filters

- No filters available.

## Configurations

- [Abstract configurations](handlers.md#abstract-configurations).
- `recorded_stream`: *bool*. Marks the stream as a recording rather than live traffic. It also accepts `xact_ttl_secs` and `xact_ttl_ms`.
