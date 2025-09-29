# Pktvisor
The `pktvisor` backend embeds the [pktvisord](https://github.com/netboxlabs/pktvisor) process inside Orb Agent to run deep packet analytics, active probes, and streaming aggregations directly at the edge. Pktvisor policies let you decide which network taps to activate, which analyzers to run, and how the resulting metrics are exported to your observability stack.

## Configuration
Orb writes a temporary pktvisor configuration file on startup based on the `orb.backends.pktvisor` block. Any key that is not handled explicitly is forwarded to `visor.config` in the generated file, so you can pass through native pktvisor options such as logging, crashpad, or custom data paths when needed.

### Backend settings
| Parameter | Type | Required | Default | Description |
|:---------:|:----:|:--------:|:-------:|-------------|
| `host` | string | no | `localhost` | Admin API host exposed by `pktvisord`. Use this when `pktvisord` runs outside the Orb container. |
| `port` | string | no | `10853` | Admin API port. Must match the listener configured for `--admin-api`. |
| `taps` | map | yes | – | Declarative tap definitions copied into `visor.taps`. Each tap sets the data source (`input_type`, `config`, `filter`, and optional `tags`). |
| *other keys* | any | no | – | Added verbatim under `visor.config` (for example `log_level`, crashpad options, or storage paths). |

Pktvisor ships with the Orb agent container image. If you run Orb on a bare host, ensure the `pktvisord` binary is in `$PATH` or adjust your deployment accordingly.

### Exporting pktvisor metrics
`pktvisord` can stream OpenTelemetry HTTP metrics directly to a collector. Configure the shared backend section to point Orb Agent at your collector endpoint:

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
          filter:
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
...
```

## Policy structure
Define pktvisor policies under `orb.policies.pktvisor`. Each entry key becomes the policy name pushed to `pktvisord`, and the policy body must follow the schema documented in the [Orb Policy Reference](https://orb.community/documentation/advanced_policies/#pktvisor-policy). Orb automatically wraps the policy with the expected version metadata, so you only provide the sections described below.

### `input`
Describes the data stream the policy consumes.
- `input_type` (required): must match the tap type (`pcap`, `flow`, `dnstap`, `netprobe`, ...).
- `tap`: name of a tap defined in `orb.backends.pktvisor.taps`.
- `tap_selector`: alternatively select taps by tags (`any` or `all` matching semantics).
- `filter`: optional packet, flow, or probe filters (for example `bpf` strings or DNS selectors).
- `config`: per-policy overrides of tap behavior (for example netprobe timing, flow sampling, DNS capture depth). Tap-level settings win if both are provided.

### `handlers`
Controls which analyzer modules run on the selected input.
- `config`: global handler knobs such as `deep_sample_rate`, `num_periods`, `topn_count`, or `merge_like_handlers`.
- `modules`: map keyed by module ID. Each module requires a `type` (`dns`, `net`, `netprobe`, …) and can specify `require_version`, module-specific `config`, `filter`, and `metric_groups.enable`/`metric_groups.disable` lists to turn metric families on or off. See the pktvisor repository for module-specific options and supported metric groups.

### `config`
Optional policy-level settings applied before handlers run. Common parameters include `merge_like_handlers`, custom flush intervals, or reporter options. Values are passed straight to `visor.policies.<name>.config` and validated by `pktvisord`.

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
        handlers:
          config:
            merge_like_handlers: true
          modules:
            dns_summary:
              type: dns
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

## Additional resources
- [Pktvisor project home](https://github.com/netboxlabs/pktvisor) — feature overview, module reference, and deployment notes.
- [Orb agent configuration guide](https://orb.community/documentation/orb_agent_configs/#pktvisor-configuration) — tap definitions and available input options.
- [Orb policy reference](https://orb.community/documentation/advanced_policies/) — complete pktvisor policy schema with per-module settings and examples.
