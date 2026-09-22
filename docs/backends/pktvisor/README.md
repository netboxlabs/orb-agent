# Pktvisor
The `pktvisor` backend embeds the [pktvisord](https://github.com/netboxlabs/pktvisor) process inside Orb Agent to run deep packet analytics, active probes, and streaming aggregations directly at the edge. Pktvisor policies let you decide which network taps to activate, which analyzers to run, and how the resulting metrics are exported to your observability stack.

## Reference

| Page | Contents |
|:--|:--|
| [Inputs](inputs.md) | The data streams a policy can consume: `pcap`, `flow`, `dnstap`, `netprobe`, with their configuration and filters. |
| [Netprobe input](input_netprobe.md) | The active probe input in detail: ICMP, TCP, HTTP and DNS over HTTPS tests, their targets and response checks. |
| [Handlers](handlers.md) | The handler section, the available handler types and versions, metric groups, and the configurations shared by all handlers. |
| [Metrics](metrics.md) | Every metric each handler produces. |

Handler references: [DNS](handler_dns.md), [Network](handler_net.md),
[Flow](handler_flow.md), [DHCP](handler_dhcp.md), [BGP](handler_bgp.md),
[Packet capture](handler_pcap.md), [Netprobe](handler_netprobe.md),
[Input resources](handler_input_resources.md).

## Configuration
Orb writes a temporary pktvisor configuration file on startup based on the `orb.backends.pktvisor` block. Any key that is not handled explicitly is forwarded to `visor.config` in the generated file, so you can pass through native pktvisor options such as logging, crashpad, or custom data paths when needed.

### Backend settings
| Parameter | Type | Required | Default | Description |
|:---------:|:----:|:--------:|:-------:|-------------|
| `host` | string | no | `localhost` | Admin API host. Written to `visor.config.host`, which is the address the `pktvisord` the agent starts binds its admin API to, and the address the agent uses to reach it. Change it only to alter that bind address. |
| `port` | string | no | `10853` | Admin API port. Written to `visor.config.port`, which is the port `pktvisord` binds its admin API to. |
| `taps` | map | no | – | Declarative tap definitions copied into `visor.taps`. Each tap sets the data source (`input_type`, `config`, and optional `tags`). Not validated as required, but an agent with no taps has nothing for a policy to analyse. |
| *other keys* | any | no | – | Added verbatim under `visor.config` (for example `log_level`, crashpad options, or storage paths). |

Pktvisor ships with the Orb agent container image. If you run Orb on a bare host, ensure the `pktvisord` binary is in `$PATH` or adjust your deployment accordingly.

### Taps
A tap names a data source once, on the agent, so that policies can refer to it.
Each tap sets an `input_type`, its `config`, and optional `tags` that a policy can
select on. See [Inputs](inputs.md) for the configuration each input type accepts.

A tap has no `filter` key: filters belong to the policy's `input`, and a `filter`
written on a tap is ignored without an error. For packet capture a BPF expression
can also go in the tap's `config`, since `pcap` accepts `bpf` there.

```yaml
orb:
  backends:
    pktvisor:
      host: 0.0.0.0
      port: "10853"
      taps:
        dns_pcap:
          input_type: pcap
          config:
            iface: eth0
            bpf: "port 53"
        sflow:
          input_type: flow
          config:
            flow_type: sflow
            port: 6343
            bind: 192.168.1.1
          tags:
            virtual: false
            vhost: 2
    common:
      otlp:
        http: "http://otel-collector.monitoring.svc.cluster.local:4318"
```

### Exporting pktvisor metrics
`pktvisord` can stream OpenTelemetry HTTP metrics directly to a collector. Configure the shared `backends.common.otlp` section, as in the example above, to point Orb Agent at your collector endpoint.

## Policy structure
Define pktvisor policies under `orb.policies.pktvisor`. Each entry key becomes the policy name pushed to `pktvisord`, and the agent wraps the body you write in the envelope `pktvisord` expects, so the body is just the four sections below.

```yaml
orb:
  policies:
    pktvisor:
      my_policy:
        input: ...
        handlers: ...
        config: ...
        kind: collection
```

| Section | Required | Description |
|:--|:--|:--|
| [`input`](inputs.md) | yes | The data stream to analyse: a tap name or tag selector, plus the input type and any filters. |
| [`handlers`](handlers.md) | yes | The analyzer modules to run on that input, and their configuration, filters and metric groups. |
| [`config`](handlers.md#config-section) | no | Policy level settings. Currently only `merge_like_handlers`. |
| [`kind`](handlers.md#kind-section) | yes | The only supported value is `collection`. |

A policy name must be unique within the backend. Policy, tap and handler module
names must match `[a-zA-Z_][a-zA-Z0-9_-]*`, so they start with a letter or
underscore and contain only letters, digits, `_` or `-`.

## Example policy
The following policy inspects DNS traffic captured from the `edge_dns` tap and runs both DNS-specific and network-wide analytics. Use this pattern when you want to reuse a tap across multiple handlers.

```yaml
orb:
  policies:
    pktvisor:
      edge_dns_inspection:
        input:
          input_type: pcap
          tap: edge_dns
        config:
          merge_like_handlers: true
        handlers:
          window_config:
            num_periods: 5
            deep_sample_rate: 100
          modules:
            dns_summary:
              type: dns
              require_version: "2.0"
              metric_groups:
                enable:
                  - counters
                  - quantiles
              config:
                public_suffix_list: true
                topn_count: 25
            net_overview:
              type: net
        kind: collection
```

Note the `require_version: "2.0"` on the DNS module. A module that omits `require_version` runs version `1.0` of that handler; see [available handlers](handlers.md#available-handlers).

## Additional resources
- [Pktvisor project home](https://github.com/netboxlabs/pktvisor) — feature overview, module reference, and deployment notes.
