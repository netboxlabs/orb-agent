# Pktvisor inputs

An input is the data stream a policy analyses. Each input is declared once on the
agent as a *tap*, under `orb.backends.pktvisor.taps`, and a policy then selects a
tap by name or by tag.

| Input type | Purpose |
|:--|:--|
| [`pcap`](#packet-capture-pcap) | Live packet capture from a network interface, or a pcap file. |
| [`flow`](#sflownetflow-flow) | sFlow and Netflow records received on a UDP port. |
| [`dnstap`](#dnstap) | dnstap stream from a DNS server, over a unix socket or TCP. |
| [`netprobe`](input_netprobe.md) | Active probes against a list of targets: ICMP, TCP, HTTP and DNS over HTTPS. |

`sflow` is also accepted as an input type and is handled by the same module as
`flow`. A `mock` input exists for testing and is not documented here.

A tap declares the input type and its configuration; the policy that uses it may
override parts of that configuration. See [Input in a policy](#input-in-a-policy) below and
the [policy structure](README.md#policy-structure) for how the two fit together.

## Input in a policy

A policy's `input` section names the data stream it analyses. It selects a tap,
declares what type that tap is, and may narrow or adjust it.

**Required**

`input_type` - the type of input. It is validated against the type of the tap
selected by `tap` or `tap_selector`; if they disagree, the policy fails.

`tap` - the name of a tap declared under `orb.backends.pktvisor.taps`, or
`tap_selector` - tags to match against the declared taps. Exactly one of the two
must be set. A selector uses either `any` or `all`, not both, and a selector that
matches no tap is an error.

**Optional**

`filter` - what data to include from the input.

`config` - how the input is used. These keys are the same ones the tap accepts,
documented per input type below.

A tap's configuration and the policy input's configuration are merged, with the
policy input's values taking precedence for any key set in both.

### Selecting a tap by name

```yaml
input:
  tap: tap_name
  input_type: type_of_input
  filter:
    bpf: ...
  config:
    ...
```

### Selecting taps by tag

Matching any of the tags:

```yaml
input:
  tap_selector:
    any:
      - key1: value1
      - key2: value2
  input_type: type_of_input
  filter:
    bpf: ...
  config:
    ...
```

Matching all of them:

```yaml
input:
  tap_selector:
    all:
      - key1: value1
      - key2: value2
  input_type: type_of_input
  filter:
    bpf: ...
  config:
    ...
```

A selector that matches more than one tap attaches the policy to each of them,
which generates a separate set of metrics per tap. See
[`merge_like_handlers`](handlers.md#merge_like_handlers) for scraping them together.

## Declaring a tap

A tap abstracts away host level details, such as the ethernet interface or the
dnstap socket location, so that a policy can apply to a broad set of agents
without naming them. Taps are declared under `orb.backends.pktvisor.taps`, and a
single agent can declare as many as it needs.

A tap accepts `input_type`, `config` and `tags` only. It has no `filter` key, and
one written there is ignored without an error: filters belong to the policy's
[`input`](#input-in-a-policy). A `pcap` tap can still carry a `bpf` expression in
its `config`, which is where the example below puts it.

```yaml
orb:
  backends:
    pktvisor:
      taps:
        first_tap_name:
          input_type: type
          config: ...
          tags:
            key1: value1
            key2: value2
        second_tap_name:
          input_type: type
          config: ...
          tags:
            key1: value1
            key3: value3
```

The following inputs are supported: `pcap`, `flow`, `dnstap` and `netprobe`. For each input type, specific configuration, filters and tags can be defined.

## Packet Capture (pcap)

> **Example:** Pktvisor PCAP Tap Configuration
> ```yaml
> orb:
>   backends:
>     pktvisor:
>       taps:
>         my_pcap_tap:
>           input_type: pcap
>           config:
>             pcap_source: "libpcap"
>             debug: true
>             iface: auto
>             host_spec: "192.168.0.1/24"
>             bpf: "port 53"
>           tags:
>             pcap: true
> ```

### pcap configuration

The following configurations are available for pcap inputs.

|                                       Config                                       | Type |
|:----------------------------------------------------------------------------------:|:-----|
|                         [pcap_file](#pcap_file)                         | str  |
|                       [pcap_source](#pcap_source)                       | str  |
|                          [iface](#iface)                          | str  |
|                         [host_spec](#host_spec)                         | str  |
|                             [debug](#debug)                             | bool |
| [tcp_packet_reassembly_cache_limit](#tcp_packet_reassembly_cache_limit) | int  |

### pcap_file

Type: *str*

One option of using pktvisor is for reading existing network data files. In this case, the path to the file must be passed. This variable is dominant, so if a file is passed, pktvisor will do the entire process based on the file.

```yaml
pcap_file: "path/to/file"
```

### pcap_source

Type: *str*

`pcap_source` specifies the type of library to use. Default: `libpcap`. Options are `libpcap`, `af_packet` (Linux) and `mock` (for testing).

```yaml
pcap_source: "af_packet"
```

### iface

Type: *str*

Name of the interface to bind.

```yaml
iface: str
```
Example:
```yaml
iface: eth0
```

> **Tip:**
>
> You can use `auto` as iface. In this way, the network with the highest data flow will be analyzed.
>
> ```yaml
> iface: auto
> ```

### host_spec

Type: *str*

The `host_spec` setting is useful to determine the direction of observed packets, once knowing the host ip, it is possible to determine the data flow direction, ie if they are being sent by the observed host (from host) or received (to host).

```yaml
host_spec: str
```
Example:
```yaml
host_spec: "192.168.0.1/24"
```

### debug

Type: *bool*

When `true` activate debug logs. It applies to live capture only and is ignored when `pcap_file` is set

```yaml
debug: true
```

### tcp_packet_reassembly_cache_limit

Type: *int*

Sets the maximum number of TCP connections tracked for reassembly. The cache is keyed by connection, not by packet. Default value: `300000`.

To remove limit set `tcp_packet_reassembly_cache_limit` to `0`.

```yaml
tcp_packet_reassembly_cache_limit: 300000
```

### pcap filters

|          Filter          | Type |
|:------------------------:|:-----|
| [`bpf`](#bpf) | str  |

### bpf

Type: *str*

`bpf` filter data based on Berkeley Packet Filters (BPF).

```yaml
bpf: str
```
Example:
```yaml
bpf: "port 53"
```

## sFlow/Netflow (flow)

> **Example:** Pktvisor FLOW Tap Configuration
> ```yaml
> orb:
>   backends:
>     pktvisor:
>       taps:
>         my_flow_tap:
>           input_type: flow
>           config:
>             port: 6343
>             bind: 192.168.1.1
>             flow_type: sflow
>           tags:
>             flow: true
> ```

### flow configuration

The following configs are available for flow inputs. A flow input reads either
from a capture file or from a UDP socket: set `pcap_file`, or set both `port` and
`bind`. An input that sets neither fails to start.

|               Config               | Type |
|:----------------------------------:|:-----|
| [pcap_file](#pcap_file-flow) | str  |
|   [port](#port-flow)    | int  |
|   [bind](#port-flow)    | str  |
| [flow_type](#flow_type) | str  |

### pcap_file (flow)

Type: *str*

Reads flow records from a capture file instead of a socket. When set, `port` and
`bind` are not used.

```yaml
pcap_file: /path/to/flows.pcap
```

### port (flow)

Type: *int* and **bind**: *str*

Receives flow records on a UDP socket. Both must be set together; only UDP bind
is supported.

```yaml
port: int
bind: str
```
Example:
```yaml
port: 6343
bind: 192.168.1.1
```

### flow_type

Type: *str*

Default: sflow. Accepted values are `sflow`, `netflow` and `ipfix`.

```yaml
flow_type: str
```
Example:
```yaml
flow_type: netflow
```

### flow filters

There are no specific filters for the FLOW input.

## dnstap

> **Example:** Pktvisor DNSTAP Tap Configuration
> ```yaml
> orb:
>   backends:
>     pktvisor:
>       taps:
>         my_dnstap_tap:
>           input_type: dnstap
>           config:
>             socket: path/to/file.sock
>           tags:
>             dnstap: true
> ```

### dnstap configuration

The 3 existing DNSTAP configurations (`dnstap_file`, `socket` and `tcp`) are mutually exclusive, that is, only one can be used in each input and one of them must exist. They are arranged in order of priority.

|                  Config                  | Type |
|:----------------------------------------:|:-----|
| [dnstap_file](#dnstap_file) | str  |
|      [socket](#socket)      | str  |
|         [tcp](#tcp)         | str  |

### dnstap_file

Type: *str*

One option of using pktvisor is for reading existing network data files. In this case, the path to the file must be passed. This variable is dominant, so if a file is passed, pktvisor will do the entire process based on the file.

```yaml
dnstap_file: path/to/file
```

### socket

Type: *str*

Path to socket file containing port and ip to bind

```yaml
socket: path/to/file.sock
```

### tcp

Type: *str*

The other way to inform the ip and port to be monitored is through the 'tcp' configuration. Usage syntax is a string with ip:port (only ipv4 is supported for now).

```yaml
tcp: ip:port
```
Example:
```yaml
tcp: 192.168.8.2:235
```

### dnstap filters

|                  Filter                  | Type |
|:----------------------------------------:|:-----|
| [`only_hosts`](#only_hosts) | str[] |

### only_hosts

Type: *str[]*

`only_hosts` filters data to the given hosts. It is read as a list, so a bare
string is rejected. Like every filter it is set on the policy's `input.filter`,
not on the tap.

```yaml
input:
  input_type: dnstap
  tap: my_dnstap_tap
  filter:
    only_hosts:
      - 192.0.2.4/32
      - 198.51.100.0/24
```

## Netprobe

The netprobe input actively probes a list of targets rather than observing
traffic, and it has enough settings of its own, differing by test type, to carry
its own page.

> **Example:** Pktvisor Netprobe Tap Configuration
> ```yaml
> orb:
>   backends:
>     pktvisor:
>       taps:
>         default_netprobe:
>           input_type: netprobe
>           config:
>             test_type: ping
>             interval_msec: 2000
>             timeout_msec: 1000
>             packets_per_test: 10
>             packets_interval_msec: 25
>             packet_payload_size: 56
>             targets:
>               primary_site:
>                 target: www.example.com
>               secondary_site:
>                 target: www.example.net
>           tags:
>             netprobe: true
> ```

See [Netprobe input](input_netprobe.md) for the test types (`ping`, `tcp`,
`http`, `doh`), the per-target keys, the timing settings and the HTTP response
checks.
