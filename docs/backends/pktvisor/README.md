# Pktvisor
The `pktvisor` backend embeds the [pktvisord](https://github.com/netboxlabs/pktvisor) process inside Orb Agent to run deep packet analytics, active probes, and streaming aggregations directly at the edge. Pktvisor policies let you decide which network taps to activate, which analyzers to run, and how the resulting metrics are exported to your observability stack.

## Reference

The two sections of a policy have a folder each.

| Page | Contents |
|:--|:--|
| [Inputs](inputs/README.md) | The data streams a policy can consume, and how a tap is declared. Covers `pcap`, `flow` and `dnstap` inline, with [`netprobe`](inputs/netprobe.md) on its own page. |
| [Handlers](handlers/README.md) | The handler section, the available handler types and versions, metric groups, and the settings shared by every handler. One page per handler: [DNS](handlers/dns.md), [Network](handlers/net.md), [Flow](handlers/flow.md), [DHCP](handlers/dhcp.md), [BGP](handlers/bgp.md), [Packet capture](handlers/pcap.md), [Netprobe](handlers/netprobe.md), [Input resources](handlers/input_resources.md). |
| [Metrics](metrics.md) | The metrics each handler produces. The `input_resources` metrics are on [its own page](handlers/input_resources.md). |

## Configuration
Orb writes a temporary pktvisor configuration file each time it starts `pktvisord`, based on the `orb.backends.pktvisor` block; a pktvisor declared on demand that never starts writes none. Any key that is not handled explicitly is forwarded to `visor.config` in the generated file, so you can pass through native pktvisor options such as logging, crashpad, or custom data paths when needed.

### Backend settings
| Parameter | Type | Required | Default | Description |
|:---------:|:----:|:--------:|:-------:|-------------|
| `host` | string | no | `localhost` | Admin API host. Written to `visor.config.host`, which is the address the `pktvisord` the agent starts binds its admin API to, and the address the agent uses to reach it. Change it only to alter that bind address. |
| `port` | string | no | free port | Admin API port, written to `visor.config.port` and passed to `pktvisord` with `-p`. Unset, a loopback `host` gets a port free at each start and any other `host` gets `10853`; see [Backend keys](../../configs/agent_yaml.md#backend-keys). |
| `taps` | map | no | – | Declarative tap definitions copied into `visor.taps`. Each tap sets the data source (`input_type`, `config`, and optional `tags`). Not required: `netprobe` and `flow` policies can run on taps the agent manages. Tap names that start with `fleet_` are refused here. |
| *other keys* | any | no | – | Added verbatim under `visor.config` (for example `log_level`, crashpad options, or storage paths). |

Pktvisor ships with the Orb agent container image. If you run Orb on a bare host, ensure the `pktvisord` binary is in `$PATH` or adjust your deployment accordingly.

### Taps
A tap names a data source once, on the agent, so that policies can refer to it.
There are two kinds: local taps, which you declare on the agent, and taps the agent
manages for `netprobe` and `flow` policies.

#### Local taps
Each tap sets an `input_type`, its `config`, and optional `tags` that a policy can
select on. See [Inputs](inputs/README.md) for the configuration each input type accepts.

A tap has no `filter` key: filters belong to the policy's `input`, and a `filter`
written on a tap is ignored without an error. For packet capture a BPF expression
can also go in the tap's `config`, since `pcap` accepts `bpf` there.

```yaml
orb:
  backends:
    pktvisor:
      start_mode: on_demand   # the image declares this backend on demand; see the README's Backends section
      host: 0.0.0.0
      port: "10853"
      taps:
        edge_dns:
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

A `pcap` or `dnstap` policy always needs a local tap, since the interface or socket is a
property of the host. Names starting with `fleet_` are reserved for the taps the agent
manages. A local tap with that prefix is refused when the agent configures the backend,
and the agent does not start.

##### Defining taps with environment variables
In a container, you can define local taps with `ORB_BACKENDS__PKTVISOR__TAPS__<NAME>__...`
variables instead of a config file. Names are lower-cased, so
`ORB_BACKENDS__PKTVISOR__TAPS__EDGE_DNS__INPUT_TYPE` defines the tap `edge_dns`, and a
policy must name it that way.

```bash
ORB_BACKENDS__PKTVISOR__START_MODE=on_demand
ORB_BACKENDS__PKTVISOR__TAPS__EDGE_DNS__INPUT_TYPE=pcap
ORB_BACKENDS__PKTVISOR__TAPS__EDGE_DNS__CONFIG__IFACE=eth0
```

These variables replace the image's whole `pktvisor` entry, including its `start_mode`.
Set `ORB_BACKENDS__PKTVISOR__START_MODE=on_demand` as well, or `pktvisord` starts with
the agent instead of when the first pktvisor policy arrives. Values set this way are
strings. See [Environment variable configuration](../../advanced_config/env_config.md)
for how the overlay works.

Taps are the one backend setting an agent in Fleet mode accepts from its edge. The agent
reports them in `agent_config` from its first connect, and in the backend capabilities
from the next connect after `pktvisord` starts.

#### Taps the agent manages
A policy that names no tap, and has `input_type` `netprobe` or `flow`, runs on a tap the
agent manages. The tap is `fleet_netprobe` or `fleet_flow`. You do not declare it:

- When the agent applies the policy, it creates the tap through the `pktvisord` tap API.
  The tap carries only the `input_type`. Everything else stays in the policy's
  `input.config`.
- The agent sends `pktvisord` a copy of the policy with `input.tap` set to the managed
  tap. Your policy body is not changed.
- When no policy uses the tap any more, the agent deletes it.
- Managed taps are not part of the capabilities the agent sends to Fleet.

A policy names no tap when `input.tap` is absent, null or empty and `input.tap_selector`
is absent or null. Two related cases:

- A policy that names no tap with any other input type, such as `pcap` or `dnstap`, is
  refused: `pktvisor policy with input_type "pcap" must name a tap in input.tap or
  input.tap_selector; the agent creates taps only for netprobe and flow`. For `sflow` the
  message adds `(for sFlow, use input_type flow)`.
- A policy that sets `input.tap` to a name starting with `fleet_` is refused. Leave
  `input.tap` out to use the managed tap.

Policies with an identical input config share one input stream. For `flow`, `pktvisor`
refuses a different config on a UDP port that is already in use.

`pktvisord` puts the tap name in its handler names, so moving a policy between a managed
tap and a local one starts new metric series.

### Exporting pktvisor metrics
`pktvisord` can stream OpenTelemetry HTTP metrics directly to a collector. Configure the shared `backends.common.otlp` section, as in the example above, to point Orb Agent at your collector endpoint.

`pktvisord` summarizes each policy in one-minute windows and pushes each window once, within about 5 seconds of its closing. A policy's first metrics therefore arrive about a minute after it starts, and each later window a minute after the one before; a push carries only the policies with a newly closed window. With [`merge_like_handlers`](handlers/README.md#config-section), a merged window is pushed once every handler in the policy has closed it. A policy whose `window_config` sets `num_periods: 1` never closes a window while it runs, so it pushes its running totals once a minute instead.

When a [`pcap_file`](inputs/README.md#pcap_file) capture ends, its open window counts as closed and is pushed once. A capture shorter than a minute therefore still produces metrics, and one with `num_periods: 1` stops pushing once a minute.

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
| [`input`](inputs/README.md) | yes | The data stream to analyse: a tap name or tag selector, plus the input type and any filters. |
| [`handlers`](handlers/README.md) | yes | The analyzer modules to run on that input, and their configuration, filters and metric groups. |
| [`config`](handlers/README.md#config-section) | no | Policy level settings. Currently only `merge_like_handlers`. |
| [`kind`](handlers/README.md#kind-section) | yes | The only supported value is `collection`. |

A policy name must be unique within the backend. Policy, tap and handler module
names must match `[a-zA-Z_][a-zA-Z0-9_-]*`, so they start with a letter or
underscore and contain only letters, digits, `_` or `-`.

## Policies from Fleet
A policy from Fleet has the same body as an `orb.policies.pktvisor.<name>` entry: `kind`,
`input`, `handlers` and `config`. The agent wraps it in the envelope `pktvisord` expects.
The policy name must match `[a-zA-Z_][a-zA-Z0-9_-]*`. The agent refuses any other name
before it calls `pktvisord`.

This body probes two targets with the managed `fleet_netprobe` tap. It names no tap:

```yaml
kind: collection
input:
  input_type: netprobe
  config:
    test_type: ping
    interval_msec: 5000
    targets:
      gateway:
        target: 192.0.2.1
      resolver:
        target: 192.0.2.53
handlers:
  modules:
    probe_metrics:
      type: netprobe
```

### Flow
The managed tap carries no config, so a `flow` body that does not set
[`pcap_file`](inputs/README.md#pcap_file-flow) sets both `port` and `bind` in
`input.config`. `pktvisord` refuses a flow input without them.

```yaml
kind: collection
input:
  input_type: flow
  config:
    flow_type: sflow
    port: 6343
    bind: 0.0.0.0
handlers:
  modules:
    flow_metrics:
      type: flow
```

Behind a container, use `bind: 0.0.0.0` and publish the UDP port. Use `input_type: flow`,
not the `sflow` alias, because the agent creates managed taps only for `flow` and
`netprobe`. A `pcap_file` is replayed while the policy is applied, so keep it well under
the 10 second apply timeout.

### Edits
An edit is a remove followed by an apply. A flow listener closes briefly when the edited
policy is the last one on its port.

The agent checks the policy name and the tap before an edit removes the running policy.
So when the agent refuses an edit:

- The old version keeps running, and the policy shows `failed_to_apply`.
- After a refused rename, the old version's series lose their policy attribution until
  the edit is fixed or the policy is removed.
- The next `pktvisord` restart drops the old version.

Two failures come after the old version is removed: the agent cannot create the tap, or
`pktvisord` refuses the new version. Then the old version is already gone, and the policy
runs nothing until the edit is fixed.

### Policies that are refused
The agent refuses a policy with a bad name, or one that names no tap and has an input
type other than `netprobe` or `flow`. It still starts `pktvisord` on demand first, as it
already does for a name with a slash.

If `pktvisord` takes longer than the 10 second apply timeout to accept a policy on a
managed tap, the agent keeps that tap until it next starts `pktvisord`, even after the
last policy that used it is removed.

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

Note the `require_version: "2.0"` on the DNS module. A module that omits `require_version` runs version `1.0` of that handler; see [available handlers](handlers/README.md#available-handlers).

## Additional resources
- [Pktvisor project home](https://github.com/netboxlabs/pktvisor) — feature overview, module reference, and deployment notes.
