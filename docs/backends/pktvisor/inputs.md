# Pktvisor inputs

An input is the data stream a policy analyses. Each input is declared once on the
agent as a *tap*, under `orb.backends.pktvisor.taps`, and a policy then selects a
tap by name or by tag.

| Input type | Purpose |
|:--|:--|
| [`pcap`](#packet-capture-pcap) | Live packet capture from a network interface, or a pcap file. |
| [`flow`](#sflow-netflow-flow) | sFlow and Netflow records received on a UDP port. |
| [`dnstap`](#dnstap) | dnstap stream from a DNS server, over a unix socket or TCP. |
| [`netprobe`](#netprobe) | Active probes (ping) against a list of targets. |

`sflow` is also accepted as an input type and is handled by the same module as
`flow`. A `mock` input exists for testing and is not documented here.

A tap declares the input type and its configuration; the policy that uses it may
override parts of that configuration. See [Inputs in a policy](inputs.md) below and
the [policy structure](README.md#policy-structure) for how the two fit together.

For configure pktvisor you could specify `taps`. It's defined under `visor` top level key ([check an example](https://raw.githubusercontent.com/orb-community/orb/develop/cmd/agent/agent.example.yaml)).

The tap section specifies what data the agent should be listening in on and the goal of Taps is to abstract away host level details such as ethernet interface or dnstap socket location so that collection policies can apply to a broad set of pktvisor agents without worrying about these details. See [here](https://github.com/orb-community/pktvisor/blob/develop/RFCs/2021-04-16-75-taps.md) for more information.

Single or multiple taps can be configured in the same agent.

```yaml
visor:
  taps:
    first_tap_name:
      input_type: type
      config: ...
      filter: ...
      tags:
        key1: value1
        key2: value2
    second_tap_name:
      input_type: type
      config: ...
      filter: ...
      tags:
        key1: value1
        key3: value3
```

The following inputs are supported: `pcap`, `flow`, `dnstap` and `netprobe`. For each input type, specific configuration, filters and tags can be defined.

## Packet Capture (pcap)

> **Example:** Example: Pktvisor PCAP Tap Configuration
> ```yaml
> visor:
>   taps:
>     my_pcap_tap:
>       input_type: pcap
>       config:
>         pcap_source: "libpcap"
>         debug: true
>         iface: auto
>         host_spec: "192.168.0.1/24"
>       filter:
>         bpf: "port 53"
>       tags:
>         pcap: true
> ```

### pcap configuration

There are 5 configurations for pcap input: `pcap_file`, `pcap_source`, `iface`, `host_spec` and `debug`.

|                                       Config                                       | Type |
|:----------------------------------------------------------------------------------:|:-----|
|                         [pcap_file](#pcap-file)                         | str  |
|                       [pcap_source](#pcap-source)                       | str  |
|                          [iface](#pcap-source)                          | str  |
|                         [host_spec](#host-spec)                         | str  |
|                             [debug](#debug)                             | bool |
| [tcp_packet_reassembly_cache_limit](#tcp-packet-reassembly-cache-limit) | int  |

### pcap_file

Type: : *str*

One option of using pktvisor is for reading existing network data files. In this case, the path to the file must be passed. This variable is dominant, so if a file is passed, pktvisor will do the entire process based on the file.

```yaml
pcap_file: "path/to/file"
```

### pcap_source

Type: : *str*

`pcap_source` specifies the type of library to use. Default: libpcap. Options: libpcap or af_packet (linux).

```yaml
pcap_source: "af_packet"
```

### iface

Type: : *str*

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

Type: : *str*

The `host_spec` setting is useful to determine the direction of observed packets, once knowing the host ip, it is possible to determine the data flow direction, ie if they are being sent by the observed host (from host) or received (to host).

```yaml
host_spec: str
```
Example:
```yaml
host_spec: "192.168.0.1/24"
```

### debug

Type: : *bool*

When `true` activate debug logs

```yaml
debug: true
```

### tcp_packet_reassembly_cache_limit

Type: : *int*

Sets the limit of cached packets to be reassembled. Default value: `300000`.

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

> **Example:** Example: Pktvisor FLOW Tap Configuration
> ```yaml
> visor:
>   taps:
>     my_flow_tap:
>       input_type: flow
>       config:
>         port: 6343
>         bind: 192.168.1.1
>         flow_type: sflow
>       tags:
>         flow: true
> ```

### flow configuration

There are 3 configs for flow inputs: `port`, `bind` and `flow_type`.

|               Config               | Type |
|:----------------------------------:|:-----|
|   [port](#port-flow)    | int  |
|   [bind](#port-flow)    | str  |
| [flow_type](#flow-type) | str  |

### port (flow)

Type: : *int* and **bind**: *str*

The other option for using flow is specifying a port AND an ip to bind (only udp bind is supported). Note that, in this case, both variables must be set.

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

Type: : *str*

Default: sflow. options: sflow or netflow (ipfix is supported on netflow).

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

> **Example:** Example: Pktvisor DNSTAP Tap Configuration
> ```yaml
> visor:
>   taps:
>     my_dnstap_tap:
>       input_type: dnstap
>       config:
>         socket: path/to/file.sock
>         tcp: 192.168.8.2:235
>       filter:
>         only_hosts: 192.168.1.4/32
>       tags:
>         dnstap: true
> ```

### dnstap configuration

The 3 existing DNSTAP configurations (`dnstap_file`, `socket` and `tcp`) are mutually exclusive, that is, only one can be used in each input and one of them must exist. They are arranged in order of priority.

|                  Config                  | Type |
|:----------------------------------------:|:-----|
| [dnstap_file](#dnstap-file) | str  |
|      [socket](#socket)      | int  |
|         [tcp](#tcp)         | str  |

### dnstap_file

Type: : *str*

One option of using pktvisor is for reading existing network data files. In this case, the path to the file must be passed. This variable is dominant, so if a file is passed, pktvisor will do the entire process based on the file.

```yaml
dnstap_file: path/to/file
```

### socket

Type: : *str*

Path to socket file containing port and ip to bind

```yaml
socket: path/to/file.sock
```

### tcp

Type: : *str*

The other way to inform the ip and port to be monitored is through the 'tcp' configuration. Usage syntax is a string with port:ip (only ipv4 is supported for now).

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
| [`only_hosts`](#only-hosts) | str  |

### only_hosts

Type: : *str*

`only_hosts` filters data from a specific host.

```yaml
only_hosts: str
```
Example:
```yaml
only_hosts: 192.168.1.4/32
```

## Netprobe

> **Example:** Example: Pktvisor Netprobe Tap Configuration
> ```yaml
> visor:
>   taps:
>     default_netprobe:
>       input_type: netprobe
>       config:
>         test_type: ping
>         interval_msec: 2000
>         timeout_msec: 1000
>         packets_per_test: 10
>         packets_interval_msec: 25
>         packet_payload_size: 56
>       tags:
>         netprobe: true
> ```

### netprobe configuration

The following configs are available for netprobe inputs:

|                             Config                             | Type |          Required           | Default |
|:--------------------------------------------------------------:|:----:|:---------------------------:|:-------:|
|             [test_type](#test-type)             | str  |              ✅              |    -    |
|         [interval_msec](#interval-msec)         | int  |              ❌              |  5000   |
|         [timeout_msec](#interval-msec)          | int  |              ❌              |  2000   |
|      [packets_per_test](#packets-per-test)      | int  |              ❌              |    1    |
| [packets_interval_msec](#packets-interval-msec) | int  |              ❌              |   25    |
|   [packet_payload_size](#packet-payload-size)   | int  |              ❌              |   48    |
|                  [port](#port-netprobe)                  | int  | `Required if test_type=tcp` |    -    |

### test_type

Type: : *str*

Defines the type of the test to be performed. Type options are listed below:

- ping: implements a ping prober that can probe multiple targets. The test will run against the targets to verify if the systems are working fine.
- tcp: TCP probe sets up a TCP connection to the configured targets using the defined port.

```yaml
test_type: str
```
Example:
```yaml
test_type: ping
```

### interval_msec

Type: : *int*

How often to run the probe (in milliseconds).

```yaml
interval_msec: int
```
Example:
```yaml
interval_msec: 5000
```

### timeout_msec

Type: : *int*

Probe timeout (in milliseconds).

```yaml
timeout_msec: int
```
Example:
```yaml
timeout_msec: 2000
```

### packets_per_test

Type: : *int*

Number of packets to be sent in each test.

```yaml
packets_per_test: int
```
Example:
```yaml
packets_per_test: 1
```

### packets_interval_msec

Type: : *int*

Time interval between packets per test (in milliseconds).

```yaml
packets_interval_msec: int
```
Example:
```yaml
packets_interval_msec: 25
```

### packet_payload_size

Type: : *int*

Defines the payload of the packets sent in the tests.

```yaml
packet_payload_size: int
```
Example:
```yaml
packet_payload_size: 48
```

### port (netprobe)

Type: : *int*

Specifies the port on which the TCP test will run (It is only used if the test_type is TCP. Otherwise, is ignored if set).

```yaml
port: int
```
Example:
```yaml
port: 80
```

### netprobe filters

There are no specific filters for Netprobe input.
