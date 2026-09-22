# Pktvisor handlers

Handlers are the modules that turn an input stream into metrics. A policy names
one or more handler modules, each with its own type, configuration, filters and
metric groups.

## Available handlers

`pktvisord` registers these handler types. `require_version` selects between the
versions of a type; when it is omitted the handler resolves to version `1.0`.

| Type | Versions | Reference |
|:--|:--|:--|
| `dns` | `1.0`, `2.0` | [DNS handler](dns.md) |
| `net` | `1.0`, `2.0` | [Network handler](net.md) |
| `flow` | `1.0` | [Flow handler](flow.md) |
| `dhcp` | `1.0` | [DHCP handler](dhcp.md) |
| `bgp` | `1.0` | [BGP handler](bgp.md) |
| `pcap` | `1.0` | [Packet capture handler](pcap.md) |
| `netprobe` | `1.0` | [Netprobe handler](netprobe.md) |
| `input_resources` | `1.0` | [Input resources handler](input_resources.md) |

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

When `merge_like_handlers` config is true, metrics from all handlers of the same type are scraped together. This is useful when the [tap_selector](../inputs/README.md) is used, as, by default, metrics are generated separately for each tap in the policy and this can be very expensive, depending on the number of taps.

The `merge_like_handlers` filter usage syntax is:

```yaml
config:
  merge_like_handlers: true
```

## Kind section

`kind` is required, and the only accepted value is `collection`. A policy
without it is rejected.

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
    module_id:
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

`window_config` is merged over each module's own `config`, key by key, and only
for the keys it actually sets. A module's value for a key `window_config` does not
mention survives.

There is one special case. When `handlers.window_config` is absent, or is present
but is not a map, pktvisord substitutes `num_periods: 5` and
`deep_sample_rate: 100` and merges those, so a module-level value for either of
those two keys is discarded. A `window_config` that is not a map is not an error,
so this substitution is silent. Setting them per
module is therefore only meaningful if `window_config` is present and does not
name them.

Those two fallbacks are themselves configurable for the whole process: every key
set on the `pktvisor` backend other than `taps` is passed through to
`visor.config`, where `periods` and `max_deep_sample` change them.

|                  Abstract Configuration                   | Type  |     Default      |
|:---------------------------------------------------------:|:-----:|:----------------:|
|          [`deep_sample_rate`](#deep_sample_rate)          | *int* |       100        |
|               [`num_periods`](#num_periods)               | *int* |        5         |
|                [`topn_count`](#topn_count)                | *int* |        10        |
 | [`topn_percentile_threshold`](#topn_percentile_threshold) | *int* |        0         |

### deep_sample_rate

`deep_sample_rate` is the percentage of events that are inspected deeply. Some
metrics are expensive to generate, such as those that require string parsing
(qname, qtype and so on), so each event is drawn against this percentage and only
the sampled ones feed those metrics. Allowed values are in the range [1,100], and
the default of 100 inspects every event.

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
