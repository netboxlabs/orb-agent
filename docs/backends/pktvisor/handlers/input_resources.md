# Input resources handler (input_resources)

The `input_resources` handler reports what an input stream itself is costing the
agent: CPU, memory, and how much is attached to it.

Unlike every other handler, you do not name it in a policy. `pktvisord` attaches
it to each input stream on its own, in a generated policy named after that stream
with `-resources` appended. The stream name is the tap name plus a hash of its
configuration, so the policy appears as something like
`edge_dns-a1b2c3d4-resources`. Its metrics therefore appear alongside the metrics
of the policies you did define, without any configuration.

If the handler is not available in the running binary, the input stream is
created without it and the rest of the policy is unaffected.

## Metrics

| Metric | Type | Description |
|:--|:--|:--|
| `cpu_usage` | quantile | Quantiles of 5 second averages of percent CPU usage by the input stream. |
| `memory_bytes` | quantile | Quantiles of 5 second averages of memory usage, in bytes, by the input stream. |
| `policy_count` | counter | Total number of policies attached to the input stream. |
| `handler_count` | counter | Total number of handlers attached to the input stream. |

The two quantiles also export a `_sum` and a `_count` series, as every quantile
does. As elsewhere in pktvisor, the `_sum` series carries the maximum observed
value rather than a sum.

These carry the `resources` schema prefix, so they are exported as
`resources_cpu_usage`, `resources_memory_bytes`, `resources_policy_count` and
`resources_handler_count`.

These are useful for sizing: an input with many policies attached shows the cost
of that fan-out directly, which is what [`merge_like_handlers`](README.md#merge_like_handlers)
is meant to reduce when a policy uses a tap selector.

## Configuration

The handler exposes no filters or metric groups, and because it is never named in
a policy there is no place to configure it. It inherits the window settings
(`num_periods`, `deep_sample_rate`) that apply to the input stream.
