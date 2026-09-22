# Flow handler (flow)

- [Example of policy](#example-of-policy-with-input-flow-and-handler-flow)
- [Metrics Group](#metrics-group)
- [Filters](#filters)
- [Configurations](#configurations)

## Example of policy with input flow and handler FLOW

```yaml
handlers:
    config:
        deep_sample_rate: 95
        num_periods: 6
        topn_count: 8
    modules:
        my_flow:
            type: flow
            config:
                sample_rate_scaling: false
                deep_sample_rate: 85
                num_periods: 5
                topn_count: 7
                first_filter_if_as_label: true
                enrichment: true
                device_map:
                  192.168.3.32:
                    name: Device1
                    description: This is a device map example
                    interfaces:
                      2:
                        name: Prov1
                        description: This is an interface map example
                summarize_ips_by_asn: true
                exclude_unknown_asns_from_summarization: true
                exclude_asns_from_summarization:
                  - 16509
                exclude_ips_from_summarization_flow:
                  - 192.168.3.32/32
            metric_groups:
                enable:
                    - cardinality
                    - counters
                    - top_geo
                    - by_packets
                    - by_bytes
                    - conversations
                    - top_ports
                    - top_ips
                    - top_interfaces
                    - top_ips_ports
                    - top_tos
            filter:
                only_ports:
                    - 10853
                    - 10860-10890
                only_device_interfaces:
                    - 216.239.38.10:
                        - 2
                only_directions: "in"
                only_ips:
                  - 192.168.2.1/24
                  - 192.158.1.38/32
                geoloc_notfound: true
                asn_notfound: true
input:
  input_type: flow
  tap: default_flow
kind: collection
```

**Handler Type**: "flow"

## Metrics Group

- [Check the flow metrics belonging to each group](metrics.md#flow-metrics)

|   Metric Group   | Default  |
|:----------------:|:--------:|
|  `cardinality`   | enabled  |
|    `counters`    | enabled  |
|   `by_packets`   | enabled  |
|    `by_bytes`    | enabled  |
|    `top_ips`     | enabled  |
|   `top_ports`    | enabled  |
| `top_ips_ports`  | enabled  |
|    `top_geo`     | disabled |
| `conversations`  | disabled |
| `top_interfaces` | disabled |
|    `top_tos`     | disabled |

## Filters

|                       Filter                        |  Type   | Input |
|:---------------------------------------------------:|:-------:|:-----:|
| [`only_device_interfaces`](#only-device-interfaces) | *str[]* | FLOW  |
|        [`only_directions`](#only-directions)        |  *str*  | FLOW  |
|            [`only_ips`](#only-ips)             | *str[]* | FLOW  |
|          [`only_ports`](#only-ports)           | *str[]* | FLOW  |
|     [`geoloc_notfound`](#geoloc-notfound)      | *bool*  | FLOW  |
|        [`asn_notfound`](#asn-notfound)         | *bool*  | FLOW  |

### only_device_interfaces

Type: *str[]*

Input: FLOW

`only_device_interfaces` filters data by only retaining flows coming from the specific devices and interfaces defined in this filter.

The difference between `only_device_interfaces` and `only_ips` is that `only_ips` filters based on the IPs observed *inside* the flows, while `only_device_interfaces` filters based on the device and interface *sending* the flows.

The `only_device_interfaces` filter usage syntax is:

```yaml
only_device_interfaces:
  - device:
    - interface
```
Example:
```yaml
only_device_interfaces:
  - 216.239.38.10:
    - 2 #port can be passed as int
    - 4-10 #port can be passed as range. Ports from 4 to 10: all ports in this interval will be accepted.
    - "1" #port can be passed as str
  - 192.158.1.38: [9, 4-10]
  - 192.168.2.32:
    - "*" #all ports
```

### only_directions

Type: *str[]*

`only_directions` filters data by its direction. Options are: "in" and/or "out".

The `only_directions` filter usage syntax is:

```yaml
only_directions: [str]
```
Example:
```yaml
only_directions:
    - "in"
```

### only_ips

Type: *str[]*

Input: FLOW

To filter data only from certain source OR destination, you can use `only_ips` filter, for which CIDR (Inter-Domain Routing Classes) ranges are supported.

The `only_ips` filter usage syntax is:

```yaml
only_ips:
  - array
```
Example:
```yaml
only_ips:
  - 192.168.1.1/24
  - 192.158.1.38/32
```

### only_ports

Type: *str[]*

Input: FLOW

`only_ports` filter only filters data being sent to or received on one of the selected TCP/UDP ports (or range of ports).

The `only_ports` filter usage syntax is:

```yaml
only_ports:
  - array
```
Example:
```yaml
only_ports:
  - 10853 #port can be passed as int
  - "10854" #port can be passed as str
  - 10860-10890 #range from 10860 to 10890. All ports in this interval will be accepted
```

### geoloc_notfound

Type: *bool*

Input: FLOW

The source and destination IPs are used to determine the geolocation to know where the data is from and where it is going. When the IPs refer to a region found in the standard databases, the city, state and country (approximated) are returned. However, when it is not possible to determine the IP geolocation, a `not found` is returned.

The `geoloc_notfound` filter usage syntax is:

```yaml
geoloc_notfound: true
```

### asn_notfound

Type: *bool*

Input: FLOW

Based on source and destination IP, it is possible to determine the ASN (Autonomous System Number). When the IP of the source or destination belongs to some not known ASN in the standard databases, a `not found` is returned.

The `asn_notfound` filter usage syntax is:

```yaml
asn_notfound: true
```

## Configurations

- [sample_rate_scaling](#sample-rate-scaling): *bool*

- [first_filter_if_as_label](#first-filter-if-as-label): *bool*

- [enrichment](#enrichment): *bool*

- [device_map](#device-map): *map*

- [summarize_ips_by_asn](#summarize-ips-by-asn): *bool*

- [exclude_asns_from_summarization](#exclude-asns-from-summarization): *str[]*

- [exclude_unknown_asns_from_summarization](#exclude-unknown-asns-from-summarization): *bool*

- [subnets_for_summarization](#subnets-for-summarization): *str[]*

- [exclude_ips_from_summarization](#exclude-ips-from-summarization-flow) *str[]*

- [recorded_stream](#recorded-stream): *bool*

- [Abstract configurations](handlers.md#abstract-configurations).

### sample_rate_scaling

By default, flow metrics are generated by an approximation based on sampling the data. 1 packet every N is analyzed and the prediction of the entire population is made from the sample. If you want to see exactly all the exact data, you can disable `sample_rate_scaling`.

The `sample_rate_scaling` filter usage syntax is:

```yaml
sample_rate_scaling: false
```

### first_filter_if_as_label

This configuration requires the `only_interfaces` filter to be active (true). If this setting is `true`, the interfaces will be used as labels for the metrics.

The `first_filter_if_as_label` filter usage syntax is:

```yaml
first_filter_if_as_label: true
```

### enrichment

When true, uses device map settings.

The `enrichment` configuration usage syntax is:

```yaml
enrichment: True
```

### device_map

This configuration allows the user to assign a custom name to devices and interfaces, and the proper functioning of this configuration depends on the [enrichment](#enrichment) being True.

The `device_map` configuration usage syntax is:

```yaml
device_map:
  device_ip:
    name: "str" #name is required
    description: "Optionally set a description"
    interfaces: #Interfaces are optional
        interface:
            name: "str" #required
            description: "Optionally set a description"
```
Example:
```yaml
device_map:
  192.168.2.32:
    name: Cisco
    description: This is a device map example
    interfaces:
      2:
        name: GoogleProv
        description: This is an interface map example
```

Summarization is a useful strategy for visualization, but also for decreasing the cardinality of the data, and two types of summarization are supported: by [asn](#summarize-ips-by-asn) and by [subnets](#subnets-for-summarization), and summarization by ASN is dominant over subnet, i.e. If both configurations are present, only the IPs of an excluded asn or an unknown asn (if [exclude_unknown_asns_from_summarization](#exclude-unknown-asns-from-summarization) is true) will be summarized by subnet.

### summarize_ips_by_asn

When True, it summarizes data by ASN (Autonomous System Number).

The `summarize_ips_by_asn` configuration usage syntax is:

```yaml
summarize_ips_by_asn: true
```

### exclude_asns_from_summarization

This configuration must be used in conjunction with [summarize_ips_by_asn](#summarize-ips-by-asn), in order to exclude ASNs from summarization. In this case, packets transacted by excluded ASNs will be exposed by IPs.

The `exclude_asns_from_summarization` configuration usage syntax is:

```yaml
exclude_asns_from_summarization:
  - 8075
  - 16509
```

### exclude_unknown_asns_from_summarization

This configuration must be used in conjunction with [summarize_ips_by_asn](#summarize-ips-by-asn), in order to expose IPs from packets transacted by unknown ASNs.

The `exclude_unknown_asns_from_summarization` configuration usage syntax is:

```yaml
exclude_unknown_asns_from_summarization: true
```

### subnets_for_summarization

This configuration allows the summarization of flow data by subnets. Attention: This configuration will only work properly if the [summarize_ips_by_asn](#summarize-ips-by-asn) configuration is not set for the IP, since [summarize_ips_by_asn](#summarize-ips-by-asn) is dominant.

The `subnets_for_summarization` configuration usage syntax is:

```yaml
subnets_for_summarization:
  - 192.168.2.1/24
```

> **Tip:**
>
> It is possible to define a summary pattern by defining the CIDR only. In this way, all present IPs will be summarized.
> For this to be done, just pass the default host mask for IPv4 or/and IPv6 and the desired CIDR for grouping.
> This pattern has less priority than the explicitly defined subnets, so only IPs not belonging to any set subnet will be summarized following the general pattern.

```yaml
subnets_for_summarization:
  - 0.0.0.0/16
  - ::/64
```

### exclude_ips_from_summarization_flow

This configuration must be used in conjunction with [summarize_ips_by_asn](#summarize-ips-by-asn) or [subnets_for_summarization](#subnets-for-summarization) and will remove the specified IPs from the summarization.

The `exclude_ips_from_summarization_flow` configuration usage syntax is:

```yaml
exclude_ips_from_summarization_flow:
  - 192.168.2.1/31
```

### recorded_stream

This configuration is useful when a pcap_file is used in taps/input configuration. Set it to True when you want to load an offline traffic (from a pcap_file).

The `recorded_stream` configuration usage syntax is:

```yaml
recorded_stream: true
```
