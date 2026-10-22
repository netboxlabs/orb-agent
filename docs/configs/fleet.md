# Fleet configuration manager

With `orb.config_manager.active: fleet` the agent takes its policies from Fleet,
NetBox Labs' cloud control plane, over one MQTT connection to the broker the
agent's token names. The same connection carries the agent's heartbeats, the
policies sent to it, Diode ingest, and the telemetry its backends export.

```yaml
orb:
  config_manager:
    active: fleet
    sources:
      fleet:
        token_url: "https://..."
        client_id: ${FLEET_CLIENT_ID}
        client_secret: ${FLEET_CLIENT_SECRET}
```

## The OTLP bridge

Backends export OTLP to a bridge the agent runs locally, and the bridge publishes
what they send on the agent's MQTT connection: metrics to the telemetry topic,
Diode data to the ingest topic. Both listeners are unauthenticated, so they bind
to the loopback address unless told otherwise. Each accepts requests of up to
64 MiB from whoever can reach it (see [Message size](#message-size)), so expose
them with `otlp_bridge_bind_host` only on a network where every host that can
reach the ports is trusted to send the agent telemetry. The bridge does not limit
how many connections a client opens or how often it sends (the HTTP listener only
times out slow requests), so put a firewall or proxy that limits both in front of
an exposed listener.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `otlp_bridge_grpc_port` | int | `4317` | Port of the OTLP/gRPC listener. |
| `otlp_bridge_http_port` | int | `4318` | Port of the OTLP/HTTP listener (pktvisor's). |
| `otlp_bridge_bind_host` | string | `localhost` | Host both listeners bind to: `localhost`, `127.0.0.1`, `::1`, or `0.0.0.0` / `::` to expose them, unauthenticated, to the network. |
| `otlp_bridge_max_message_bytes` | int | `4194304` (4 MiB) | The largest payload one MQTT message carries, from 65536 to 67108864. See [Message size](#message-size). |
| `otlp_bridge_max_pending_bytes` | int | `67108864` (64 MiB) | The most payload bytes the bridge holds while it waits for the broker, at least one message at the cap. |

### Message size

A backend sends one export per collection, carrying every policy it runs, so an
export grows with the devices and interfaces the agent watches: about 7 to 11 KB
of protobuf per interface for SNMP. The bridge keeps every message it publishes
under `otlp_bridge_max_message_bytes`, or under the broker's own maximum packet
size when the broker announces a smaller one when the agent connects.

- **A metrics export over the cap is split** into several messages, by resource,
  then scope, then data point. Every message keeps the resource and the scope,
  with its `policy_name`, of each point it carries, so the platform attributes
  the pieces as it would the whole.
- **A single data point too large for a message on its own is dropped**, logged
  and counted; the rest of its export is published.
- **A logs or traces export over the cap is dropped**, logged and counted, and
  the backend is told with a status it does not retry (gRPC `InvalidArgument`,
  HTTP 400).
- **A message is never sent past the broker's maximum packet size.** An MQTT 5
  broker answers an oversized packet by closing the connection, which would cut
  the agent's heartbeats and policies too, so such a message is dropped and
  counted instead.
- **A publish the client refuses as invalid is not retried.** A publish that
  fails for another reason is retried with backoff, up to ten times; one message
  never holds the queue behind it for good.

Both listeners accept requests of up to 64 MiB, well above the cap, so a large
export reaches the bridge and is split rather than refused inside the backend.

### Pending queue

Messages wait in the bridge until the connection is up and the broker takes
them. The queue holds at most 1000 messages and `otlp_bridge_max_pending_bytes`
of payload. An export whose messages would pass either bound is refused whole,
with gRPC `ResourceExhausted` or HTTP 429, and the backend retries it later. One
larger than the whole queue could never be admitted, so it is dropped and
counted instead, with gRPC `InvalidArgument` or HTTP 400.

### What the bridge drops

`orb_agent_otlp_bridge_dropped_total` counts what the bridge could not publish,
as a cumulative sum from the agent's start, with two attributes:

| Attribute | Values |
|-----------|--------|
| `signal` | `metrics`, `logs`, `traces` |
| `reason` | `too_large`: an export, message or data point over the cap or the broker's limit. `publish_failed`: the broker refused the publish, or its retries ran out. |

The series rides with the agent's next metrics export on the telemetry topic, in
a resource with `service.name` `orb-agent` and a scope that names no policy, from
the first drop on. Each drop is also logged at WARN.
