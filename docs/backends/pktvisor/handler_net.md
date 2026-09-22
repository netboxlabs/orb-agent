# Network handler (net)

- [Example of policy](#example-of-policy-with-input-pcap-and-handler-netv2)
- [Metrics Group](#metrics-group-20)
- [Filters](#filters-20)
- [Configurations](#configurations)

## Example of policy with input pcap and handler NET(v2)

```yaml
handlers:
  window_config:
    deep_sample_rate: 100
    num_periods: 5
  modules:
    default_net:
      type: net
      require_version: "2.0"
      config:
        topn_count: 25
      filter:
        geoloc_notfound: true
        asn_notfound: true
        only_geoloc_prefix:
          - BR
          - US/CA
        only_asn_number:
          - 7326
          - 16136
      metric_groups:
        disable:
          - cardinality
          - counters
          - top_geo
          - top_ips
          - quantiles
input:
  input_type: pcap
  tap_selector:
    any:
      - key1: value1
      - key2: value2
  filter:
    bpf: net 192.168.1.0/24
  config:
    iface: wlo1
    host_spec: 192.168.1.0/24
    pcap_source: libpcap
    debug: true
kind: collection
```

**Handler Type**: "net"

## Metrics Group (2.0)

- [Check the net metrics belonging to each group](metrics.md#network-metrics)

| Metric Group  | Default |
|:-------------:|:-------:|
| `cardinality` | enabled |
|  `counters`   | enabled |
|   `top_geo`   | enabled |
|   `top_ips`   | enabled |
|  `quantiles`  | enabled |

## Filters (2.0)

|                     Filter                     |  Type   |    Input     |
|:----------------------------------------------:|:-------:|:------------:|
|  [`geoloc_notfound`](#geoloc_notfound-v2)  | *bool*  | PCAP, DNSTAP |
|     [`asn_notfound`](#asn_notfound-v2)     | *bool*  | PCAP, DNSTAP |
| [`only_geoloc_prefix`](#only_geoloc_prefix-v2) | *str[]* | PCAP, DNSTAP |
|    [`only_asn_number`](#only_asn_number-v2)    | *str[]* | PCAP, DNSTAP |

### geoloc_notfound (v2)

Type: *bool*

Input: PCAP

The source and destination IPs are used to determine the geolocation to know where the data is from and where it is going. When the IPs refer to a region found in the standard databases, the city, state and country (approximated) are returned. However, when it is not possible to determine the IP geolocation, a `not found` is returned.

The `geoloc_notfound` filter usage syntax is:

```yaml
geoloc_notfound: true
```

### asn_notfound (v2)

Type: *bool*

Input: PCAP

Based on source and destination IP, it is possible to determine the ASN (Autonomous System Number). When the IP of the source or destination belongs to some not known ASN in the standard databases, a `not found` is returned.

The `asn_notfound` filter usage syntax is:

```yaml
asn_notfound: true
```

### only_geoloc_prefix (v2)

Type: *str[]*

Input: PCAP

Source and destination IPs are used to determine the geolocation to know where the data is from and where it is going. In this way it is possible to filter the data considering the geolocation using the filter `only_geoloc_prefix`.

The `only_geoloc_prefix` filter usage syntax is:

```yaml
only_geoloc_prefix:
  - str
  - str
```
Example:
```yaml
only_geoloc_prefix:
  - BR
  - US/CA
```

### only_asn_number (v2)

Type: *str[]*

Input: PCAP

Based on source and destination IP, it is possible to determine the ASN (Autonomous System Number). In this way it is possible to filter the data considering a specific ASN using the filter `only_asn_number`.

The `only_asn_number` filter usage syntax is:

```yaml
only_asn_number:
  - str
  - str
```
Example:
```yaml
only_asn_number:
  - 7326
  - 16136
```

## Example of policy with input pcap and handler NET(v1)

```yaml
handlers:
  window_config:
    deep_sample_rate: 100
    num_periods: 5
  modules:
    default_net:
      type: net
      config:
        topn_count: 25
      filter:
        geoloc_notfound: true
        asn_notfound: true
        only_geoloc_prefix:
          - BR
          - US/CA
        only_asn_number:
          - 7326
          - 16136
      metric_groups:
        disable:
          - cardinality
          - counters
          - top_geo
          - top_ips
input:
  input_type: pcap
  tap_selector:
    any:
      - key1: value1
      - key2: value2
  filter:
    bpf: net 192.168.1.0/24
  config:
    iface: wlo1
    host_spec: 192.168.1.0/24
    pcap_source: libpcap
    debug: true
kind: collection
```

**Handler Type**: "net"

## Metrics Group (1.0)

- [Check the net metrics belonging to each group](metrics.md#network-metrics)

| Metric Group  | Default |
|:-------------:|:-------:|
| `cardinality` | enabled |
|  `counters`   | enabled |
|   `top_geo`   | enabled |
|   `top_ips`   | enabled |

## Filters (1.0)

|                     Filter                     |  Type   |    Input     |
|:----------------------------------------------:|:-------:|:------------:|
|  [`geoloc_notfound`](#geoloc_notfound-v1)  | *bool*  | PCAP, DNSTAP |
|     [`asn_notfound`](#asn_notfound-v1)     | *bool*  | PCAP, DNSTAP |
| [`only_geoloc_prefix`](#only_geoloc_prefix-v1) | *str[]* | PCAP, DNSTAP |
|    [`only_asn_number`](#only_asn_number-v1)    | *str[]* | PCAP, DNSTAP |

### geoloc_notfound (v1)

Type: *bool*

Input: PCAP

The source and destination IPs are used to determine the geolocation to know where the data is from and where it is going. When the IPs refer to a region found in the standard databases, the city, state and country (approximated) are returned. However, when it is not possible to determine the IP geolocation, a `not found` is returned.

The `geoloc_notfound` filter usage syntax is:

```yaml
geoloc_notfound: true
```

### asn_notfound (v1)

Type: *bool*

Input: PCAP

Based on source and destination IP, it is possible to determine the ASN (Autonomous System Number). When the IP of the source or destination belongs to some not known ASN in the standard databases, a `not found` is returned.

The `asn_notfound` filter usage syntax is:

```yaml
asn_notfound: true
```

### only_geoloc_prefix (v1)

Type: *str[]*

Input: PCAP

Source and destination IPs are used to determine the geolocation to know where the data is from and where it is going. In this way it is possible to filter the data using the geolocation using the filter `only_geoloc_prefix`.
.  The filter supports the following strings:

* Continents:  two-character continent code, as follows:
AF - Africa
AN - Antarctica
AS - Asia
EU - Europe
NA - North America
OC - Oceania
SA - South America

* Country: the two-character ISO 3166-1 country code
* Subdivision: the region-portion of the ISO 3166-2 code for the region

The `only_geoloc_prefix` filter usage syntax is:

```yaml
only_geoloc_prefix:
  - str
  - str
```
Example:
```yaml
only_geoloc_prefix:
  - BR
  - US/CA
```

### only_asn_number (v1)

Type: *str[]*

Input: PCAP

Based on source and destination IP, it is possible to determine the ASN (Autonomous System Number). In this way it is possible to filter the data considering a specific ASN using the filter `only_asn_number`.

The `only_asn_number` filter usage syntax is:

```yaml
only_asn_number:
  - str
  - str
```
Example:
```yaml
only_asn_number:
  - 7326
  - 16136
```

## Configurations

- [recorded_stream](#recorded_stream): *bool*.
- [Abstract configurations](handlers.md#abstract-configurations).

### recorded_stream

> The key is presence-based: the handler checks only whether `recorded_stream`
> is set, never its value, so `recorded_stream: false` still enables it. Omit
> the key entirely to disable.

This configuration is useful when a pcap_file is used in taps/input configuration. Set it to True when you want to load an offline traffic (from a pcap_file).

The `recorded_stream` configuration usage syntax is:

```yaml
recorded_stream: true
```
