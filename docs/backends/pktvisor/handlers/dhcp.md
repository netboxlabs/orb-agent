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

## Monitoring DHCP services

DHCP exchanges run on UDP ports 67 and 68, so a policy that only wants DHCP
narrows the capture with a BPF filter rather than analysing every packet. Pairing
the `dhcp` handler with `net` gives the DHCP counters alongside the general
traffic picture for the same packets.

```yaml
handlers:
  modules:
    dhcp_traffic:
      type: dhcp
    net_traffic:
      type: net
input:
  input_type: pcap
  tap: default_pcap
  filter:
    bpf: "port 67 or port 68"
kind: collection
```

## Metrics Group

- [Check dhcp metrics](../metrics.md#dhcp-metrics)

- No metrics group available

## Filters

- No filters available.

## Configurations

- [Abstract configurations](README.md#abstract-configurations).
- `recorded_stream`. Marks the stream as a recording rather than live traffic. Presence-based: setting it to `false` still enables it, so omit the key to disable.
- `xact_ttl_secs` / `xact_ttl_ms`: *int*. Time to live for transactions, in seconds or milliseconds.
