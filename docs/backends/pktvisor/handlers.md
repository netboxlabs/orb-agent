# Pktvisor handlers

Handlers are the modules that turn an input stream into metrics. A policy names
one or more handler modules, each with its own type, configuration, filters and
metric groups.

## Available handlers

`pktvisord` registers these handler types. `require_version` selects between the
versions of a type; when it is omitted the handler resolves to version `1.0`.

| Type | Versions | Reference |
|:--|:--|:--|
| `dns` | `1.0`, `2.0` | [DNS handler](handler_dns.md) |
| `net` | `1.0`, `2.0` | [Network handler](handler_net.md) |
| `flow` | `1.0` | [Flow handler](handler_flow.md) |
| `dhcp` | `1.0` | [DHCP handler](handler_dhcp.md) |
| `bgp` | `1.0` | [BGP handler](handler_bgp.md) |
| `pcap` | `1.0` | [Packet capture handler](handler_pcap.md) |
| `netprobe` | `1.0` | [Netprobe handler](handler_netprobe.md) |
| `input_resources` | `1.0` | [Input resources handler](handler_input_resources.md) |

Because the default is `1.0`, a module written as `type: dns` with no
`require_version` runs the 1.0 handler. Use `require_version: "2.0"` to select the
2.0 handler, whose metrics and options differ.

A policy that names a type and version which is not registered is rejected.

## Config section

There is the possibility of defining settings on the policy level. Currently, the only configuration available is the `merge_like_handlers`.

| Policy Configuration  |  Type  | Default |
|:---------------------:|:------:|:-------:|
| `merge_like_handlers` | *bool* |  false  |

### merge_like_handlers

When `merge_like_handlers` config is true, metrics from all handlers of the same type are scraped together. This is useful when the [tap_selector](inputs.md) is used, as, by default, metrics are generated separately for each tap in the policy and this can be very expensive, depending on the number of taps.

The `merge_like_handlers` filter usage syntax is:

```yaml
config:
  merge_like_handlers: true
```

## Kind section

What kind of object you want to create
The only option for now is `"collection"`.

## Handlers section (Analysis)

Handlers are the modules responsible for extracting metrics from inputs. For each handler type, specific configuration, filters and group of metrics can be defined, and there are also window settings ([abstract configurations](#abstract-configurations)) that apply to every handler in the policy:

**Default handler structure:**

```yaml
handlers:
  window_config:
    deep_sample_rate: 100
    num_periods: 5
    topn_count: 10
    topn_percentile_threshold: 0
  modules:
    tap_name:
      type: ...
      require_version: ...
      config: ...
      filter: ...
      metric_groups:
        enable:
          - ...
          - ....
        disable:
          - .....
          - ......
```

To enable any metric group use the syntax:

```yaml
metric_groups:
  enable:
    - group_to_enable
```

To enable all available metric groups use the syntax:

```yaml
metric_groups:
  enable:
    - all
```

In order to disable any metric group use the syntax:

```yaml
metric_groups:
  disable:
    - group_to_disable
```

To disable all metric groups use the syntax:

```yaml
metric_groups:
  disable:
    - all
```

* Attention: enable is dominant over disable. So if both are passed, the metrics group will be enabled;

## Abstract Configurations

These four settings size the metric window and apply to every handler in the
policy. They are set under `window_config`, a sibling of `modules`:

```yaml
handlers:
  window_config:
    num_periods: 5
    deep_sample_rate: 100
  modules:
    ...
```

`window_config` is merged over each module's own `config`, so where the same key
appears in both, the `window_config` value wins.

`num_periods` and `deep_sample_rate` always have a value, defaulting to 5 and 100
when `window_config` is omitted, so setting either inside a module's `config` has
no effect. `topn_count` and `topn_percentile_threshold` have no window default, so
a module's `config` value for those is used unless `window_config` also sets it.

|                  Abstract Configuration                   | Type  |     Default      |
|:---------------------------------------------------------:|:-----:|:----------------:|
|          [`deep_sample_rate`](#deep_sample_rate)          | *int* | 100 (per second) |
|               [`num_periods`](#num_periods)               | *int* |        5         |
|                [`topn_count`](#topn_count)                | *int* |        10        |
 | [`topn_percentile_threshold`](#topn_percentile_threshold) | *int* |        0         |

### deep_sample_rate

`deep_sample_rate` determines the number of data packets that will be analyzed deeply per second. Some metrics are operationally expensive to generate, such as metrics that require string parsing (qname2, qtype, etc.). For this reason, a maximum number of packets per second to be analyzed is determined. If in one second fewer packages than the maximum amount are transacted, all packages will compose the deep metrics sample, if there are more packages than the established one, the value of the variable will be used. Allowed values are in the range [1,100]. Default value is 100.

> **Note:**
> If a value less than 1 is passed, the `deep_sample_rate` will be 1. If the value passed is more than 100, `deep_sample_rate` will be 100.

The `deep_sample_rate` usage syntax is:

```yaml
deep_sample_rate: int
```

### num_periods

`num_periods` determines the amount of minutes of data that will be available on the metrics endpoint. Allowed values are in the range [1,10]. Default value is 5.

The `num_periods` usage syntax is:

```yaml
num_periods: int
```

### topn_count

`topn_count` sets the maximum amount of elements displayed in top metrics. If there is less quantity than the configured value, the composite metrics will have the existing value. But if there are more metrics than the configured value, the variable will be actively limiting. Any positive integer is valid and the default value is 10.

The `topn_count` usage syntax is:

```yaml
topn_count: int
```

### topn_percentile_threshold

`topn_percentile_threshold` sets the threshold of data to be considered based on the percentiles, so allowed values are in the range [0,100].
The default value is 0, that is, all data is considered. If, for example, the value 10 is set, scraped topn metrics will only consider data from the 10th percentile, that is, data between the highest 90%.

The `topn_percentile_threshold` usage syntax is:

```yaml
topn_percentile_threshold: int
```
