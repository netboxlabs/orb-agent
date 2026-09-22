# Input resources handler (input_resources)

The `input_resources` handler reports what an input stream itself is costing the
agent: CPU, memory, and how much is attached to it.

Unlike every other handler, you do not name it in a policy. `pktvisord` attaches
it to each input stream on its own, in a generated policy named
`<input-name>-resources`. Its metrics therefore appear alongside the metrics of
the policies you did define, without any configuration.

If the handler is not available in the running binary, the input stream is
created without it and the rest of the policy is unaffected.

## Metrics

| Metric | Type | Description |
|:--|:--|:--|
| `cpu_usage` | quantile | Quantiles of 5 second averages of percent CPU usage by the input stream. |
| `memory_bytes` | quantile | Quantiles of 5 second averages of memory usage, in bytes, by the input stream. |
| `policy_count` | counter | Total number of policies attached to the input stream. |
| `handler_count` | counter | Total number of handlers attached to the input stream. |

These are useful for sizing: an input with many policies attached shows the cost
of that fan-out directly, which is what [`merge_like_handlers`](handlers.md#merge-like-handlers)
is meant to reduce when a policy uses a tap selector.

## Configuration

The handler takes no configuration, filters or metric groups of its own. It
inherits the window settings (`num_periods`, `deep_sample_rate`) that apply to the
input stream.
