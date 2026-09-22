# Netprobe input

The `netprobe` input is the one input that generates traffic rather than
observing it. Instead of watching packets on an interface, it runs an active
test against a list of targets on a schedule and reports how each one answered.

A netprobe tap declares the test type and the targets; the
[netprobe handler](handler_netprobe.md) turns the results into metrics.

The examples here declare the settings on the tap. Because they describe the
probe rather than the host the agent runs on, any of them can instead be set on
a policy's [`input.config`](inputs.md#input-in-a-policy), which overrides the
tap for that policy.

```yaml
orb:
  backends:
    pktvisor:
      taps:
        edge_probes:
          input_type: netprobe
          config:
            test_type: ping
            interval_msec: 5000
            targets:
              primary_site:
                target: www.example.com
          tags:
            netprobe: true
```

## Test types

`test_type` is required and selects which probe runs. It also decides which of
the settings below apply, in two different ways. The HTTP request `body`, the
HTTP response checks and the `proxy` and `tls` options are **rejected** when the
test type cannot use them, naming the offending key, so the input fails to
start. The packet pacing settings are **accepted by any test type** but only
`ping` acts on them, so on another test type they have no effect. They are still
validated: a `packets_per_test` of 0, or a pacing product that overruns
`interval_msec`, stops any input whatever its test type.

| `test_type` | Probe | Documented in |
|:--|:--|:--|
| `ping` | ICMP echo request and reply | [ICMP probes](#icmp-probes-test_type-ping) |
| `tcp` | TCP connection to a port | [TCP probes](#tcp-probes-test_type-tcp) |
| `http` | HTTP request, with optional response assertions | [HTTP probes](#http-probes-test_type-http) |
| `doh` | DNS over HTTPS query | [DNS over HTTPS probes](#dns-over-https-probes-test_type-doh) |
| `udp` | Not implemented | see below |

`udp` is accepted as a value but no probe is built for it, so an input that
sets it fails to start with `Test type currently not supported`. Use `tcp` to
test reachability of a service port.

## Targets

`targets` is required and is a map keyed by a name of your choosing. The name
becomes the `target` label on every metric that probe produces, so pick
something you will recognise in a dashboard.

Each entry accepts:

| Key | Type | Applies to | Description |
|:--|:--|:--|:--|
| `target` | str | all | What to probe. An IP address or hostname for `ping` and `tcp`; an `http://` or `https://` URL for `http` and `doh`. Required. |
| `port` | int | `tcp` | The TCP port to connect to. Required for `tcp`. |
| `ip_version` | int | all | `4` or `6`. Forces address family. |
| `resolve` | str[] | `http`, `doh` | Static DNS overrides, each `host:port:address`. |
| `headers` | map | `http` | Extra request headers, as `Header-Name: value`. Rejected for `doh`. |

```yaml
targets:
  web:
    target: 192.0.2.10
    port: 443
  api:
    target: api.example.com
    port: 443
    ip_version: 4
```

For `ping` and `tcp`, a `target` that is neither a valid IP literal nor a
hostname containing a dot is rejected; `localhost` is accepted as a special
case. Setting `ip_version` to a family that contradicts an IP literal is an
error.

## Timing

These apply to every test type unless noted.

| Config | Type | Default | Description |
|:--|:--|:--|:--|
| [`interval_msec`](#interval_msec) | int | 5000 | How often each test runs. |
| [`timeout_msec`](#timeout_msec) | int | 2000 | How long a single test may take. Must not exceed `interval_msec`. Enforced by the probe for `http` and `doh` only. |
| [`packets_per_test`](#packets_per_test) | int | 1 | `ping` only. Packets sent per test. Must be greater than 0. |
| [`packets_interval_msec`](#packets_interval_msec) | int | 25 | `ping` only. Gap between those packets. |
| [`packet_payload_size`](#packet_payload_size) | int | 48 | `ping` only. Payload bytes per packet. Maximum 65500. |

Two constraints are checked when the input starts, and either one failing stops
it:

- `timeout_msec` must not be greater than `interval_msec`.
- `packets_per_test` × `packets_interval_msec` must not be greater than
  `interval_msec`, so that one test finishes before the next begins.

Both are checked for every test type, using the defaults for any value not set,
and the `timeout_msec` one is checked first. So a `tcp` tap that lowers
`interval_msec` below 25 and lowers `timeout_msec` to match still fails, on the
second constraint and reported against a `packets_per_test` it never set,
because the default pacing of one packet every 25ms no longer fits the
interval.

How `timeout_msec` takes effect depends on the test type. For `http` and `doh`
it is the request timeout and the probe applies it directly. For `ping` and
`tcp` the probe does not enforce it at all; it is passed to the netprobe
handler as the transaction time to live, so an unanswered test is counted as
timed out once it elapses. A handler that sets its own [`xact_ttl_ms` or
`xact_ttl_secs`](handler_netprobe.md#configurations) takes precedence over it.

### interval_msec

How often each probe runs its test, in milliseconds.

```yaml
interval_msec: 5000
```

### timeout_msec

How long a single test may take before it is treated as failed, in
milliseconds.

```yaml
timeout_msec: 2000
```

### packets_per_test

`ping` only. How many echo requests each test sends. The send loop counts in a
single byte, so keep this at 255 or below; at 256 it wraps to zero and only one
packet is sent.

```yaml
packets_per_test: 5
```

### packets_interval_msec

`ping` only. The gap between the packets of one test, in milliseconds.

```yaml
packets_interval_msec: 25
```

### packet_payload_size

`ping` only. The payload carried by each echo request, in bytes, up to 65500.
Each packet begins with an 8-byte marker the probe uses to recognise its own
replies, so values below 8 are raised to 8 rather than rejected.

```yaml
packet_payload_size: 56
```

## ICMP probes (`test_type: ping`)

Sends ICMP echo requests to each target and measures the round trip. This is
the only test type that uses `packets_per_test`, `packets_interval_msec` and
`packet_payload_size`.

```yaml
orb:
  backends:
    pktvisor:
      taps:
        icmp_probes:
          input_type: netprobe
          config:
            test_type: ping
            interval_msec: 5000
            timeout_msec: 2000
            packets_per_test: 5
            packets_interval_msec: 25
            packet_payload_size: 56
            targets:
              gateway:
                target: 192.0.2.1
              remote_site:
                target: site.example.com
                ip_version: 4
```

Sending ICMP requires the agent to have permission to use raw sockets. See the
agent's [running instructions](../../../README.md#running-the-agent) for the
container options that grant it.

## TCP probes (`test_type: tcp`)

Opens a TCP connection to each target's `port` and measures how long the
handshake takes. `port` is required on every target; an input whose target
omits it fails to start.

A TCP probe tests reachability of the port, not the service behind it. It does
not send a request or read a response. To assert on what the service returns,
use an HTTP probe.

```yaml
orb:
  backends:
    pktvisor:
      taps:
        tcp_probes:
          input_type: netprobe
          config:
            test_type: tcp
            interval_msec: 10000
            timeout_msec: 2000
            targets:
              api_tls:
                target: api.example.com
                port: 443
              database:
                target: 192.0.2.20
                port: 5432
```

The packet pacing settings do not apply: a TCP test is one connection attempt
per interval.

## HTTP probes (`test_type: http`)

Issues an HTTP request to each target URL and reports the response, optionally
asserting on it. `target` must be an `http://` or `https://` URL, and an invalid
one is rejected when the input starts.

```yaml
orb:
  backends:
    pktvisor:
      taps:
        http_probes:
          input_type: netprobe
          config:
            test_type: http
            interval_msec: 30000
            timeout_msec: 5000
            http_method: GET
            expected_status:
              - 2xx
            expected_body: "\"status\":\"ok\""
            targets:
              health:
                target: https://api.example.com/health
                headers:
                  Accept: application/json
```

Note that this example sets a per-target header, which turns off redirect
following (see [Request](#request) below), so a redirect would be reported as
the response and scored against `expected_status`.

### Request

| Config | Type | Default | Description |
|:--|:--|:--|:--|
| `http_method` | str | `GET` | The HTTP method to use. |
| `body` | str | – | Request body. Requires `http_method` to be `POST`, `PUT` or `PATCH`. |
| `proxy` | str | – | Proxy to send the request through. Also valid for `doh`. |
| `tls` | map | – | TLS options, below. Also valid for `doh`. |

Per-target `headers` add request headers for that target only. The probe sets
its own `User-Agent` of the form `pktvisor/<version>`.

**Redirects are followed only when neither per-target `headers` nor a request
`body` is set.** Setting either one turns redirect following off, so that custom
headers are not leaked to a redirect target on another host and a body is not
re-sent, and the 30x response is reported as the result instead. If you set
headers or a body and the target redirects, include the redirect status in
`expected_status` or probe the final URL directly.

`tls` accepts:

| Key | Type | Default | Description |
|:--|:--|:--|:--|
| `verify` | bool | `true` | Whether to verify the server certificate. |
| `ca_file` | str | – | CA bundle to verify against. |
| `cert_file` | str | – | Client certificate. |
| `key_file` | str | – | Client key. |

`cert_file` and `key_file` must be set together, and every file named must
exist when the input starts.

```yaml
tls:
  verify: true
  ca_file: /opt/orb/ca.pem
```

### Response checks

Every key below is rejected unless `test_type` is `http`. When none is set, a
response is considered successful if its status is in the range 200 to 399.

| Config | Type | Description |
|:--|:--|:--|
| `expected_status` | str[] | Statuses that count as success. Each entry is an exact code (`200`), a range (`200-204`), or a class (`2xx`). |
| `failure_status` | str[] | Statuses that always count as failure. Checked before `expected_status`. |
| `expected_body` | str | Substring the body must contain. |
| `expected_body_regex` | str | Regular expression the body must match. |
| `not_contains` | str | Substring the body must not contain. |
| `body_not_matches_regex` | str | Regular expression the body must not match. |
| `json_path` | str | JSON Pointer (RFC 6901) that must resolve in the body. |
| `json_equals` | str | Value that `json_path` must equal. Requires `json_path`. A non-string value is compared against its compact JSON form, such as `true`, `42` or `{"a":1}`. |
| `min_response_size_bytes` | int | Smallest acceptable body size. |
| `max_response_size_bytes` | int | Largest acceptable body size. `0` requires an empty body. |
| `fail_if_header_matches` | map | Header name to regular expression; a match fails the check. |
| `fail_if_header_not_matches` | map | Header name to regular expression; failing to match fails the check. |
| `max_last_modified_diff_secs` | int | Largest acceptable age from the `Last-Modified` header. `0` disables the check. A response whose `Last-Modified` header is missing or unparseable fails it. |
| `valid_http_versions` | str[] | Accepted HTTP versions. Each entry is `1.0`, `1.1`, `2` or `3`. |
| `body_check_max_bytes` | int | How much of the body is captured for body checks. Default 524288. Must be greater than 0. |

Header names in `fail_if_header_matches` and `fail_if_header_not_matches` are
matched case insensitively, and the pattern is an unanchored search, so `MISS`
also matches `MISS-FROM-EDGE`. Anchor it with `^` and `$` for an exact match.

Order of evaluation: `failure_status` is matched first and a match always
fails. Otherwise `expected_status` decides if it is set, and the 200 to 399
range decides if it is not. Body, JSON and header assertions run only once the
status has passed.

If a body is larger than `body_check_max_bytes` it is truncated, and the body,
regular expression, JSON and negative checks are skipped rather than failed,
because a truncated body cannot settle them either way. The probe logs a warning
when it skips them. Raise `body_check_max_bytes` if you need to assert on
something beyond the default.

`not_contains` is the exception: a forbidden substring found inside the captured
prefix still fails the check, because its presence there does not depend on the
part that was dropped.

Response headers have their own capture limit, which is separate from
`body_check_max_bytes` and not configurable. When it is reached,
`fail_if_header_matches` is failed rather than passed, since a forbidden header
could be among the ones that were dropped. `fail_if_header_not_matches` is
unaffected.

`min_response_size_bytes` must not exceed `max_response_size_bytes`.

```yaml
expected_status:
  - 2xx
  - 304
failure_status:
  - 5xx
json_path: /data/status
json_equals: healthy
valid_http_versions:
  - "1.1"
  - "2"
fail_if_header_matches:
  X-Cache: "MISS"
```

A failed status check is counted as `netprobe_http_status_failures`, while a
response whose status passed but whose assertions failed is counted as
`netprobe_content_failures`, so the two causes stay distinguishable. See
[netprobe metrics](metrics.md#netprobe-metrics).

## DNS over HTTPS probes (`test_type: doh`)

Sends a DNS query over HTTPS to each target URL. As with HTTP probes, `target`
must be an `http://` or `https://` URL.

| Config | Type | Default | Description |
|:--|:--|:--|:--|
| `qname` | str | – | The name to query. Required for `doh`. |
| `qtype` | str | `A` | The query type. Case insensitive. |
| `http_method` | str | `POST` | `GET` or `POST` only. |

`qname` must be a valid DNS name: at most 253 characters, with no empty label
and no label longer than 63. A trailing dot is accepted and removed. The root,
`.`, is valid. `qtype` must be a DNS query type the binary knows.

`proxy` and `tls` work as they do for HTTP probes. Per-target `headers` are
rejected for `doh`; the response assertions listed under
[Response checks](#response-checks) are HTTP only and are rejected too.

```yaml
orb:
  backends:
    pktvisor:
      taps:
        doh_probes:
          input_type: netprobe
          config:
            test_type: doh
            qname: www.example.com
            qtype: A
            targets:
              resolver:
                target: https://dns.example.net/dns-query
```

## Filters

The netprobe input has no filters. What is probed is decided by `targets`.

## Metrics

All test types share the netprobe handler's core metrics: attempts, successes
and response times. Transport failures land in `netprobe_dns_lookup_failures`,
`netprobe_connect_failures` and `netprobe_packets_timeout` whatever the test
type.

HTTP and DoH probes add the status counters, the top status codes, the TLS
certificate expiry gauge and the `http_response_phases` metric group, which
breaks a response down into DNS, connect, TLS and time to first byte. Beyond
that the two differ:

- HTTP only: `netprobe_content_failures` for a response whose status passed but
  whose assertions failed, and `netprobe_response_size_bytes`.
- DoH only: `netprobe_dns_response_failures` and `netprobe_top_rcodes`, for a
  response whose HTTP status was a success but whose DNS payload was not
  NOERROR or would not parse.

See [netprobe metrics](metrics.md#netprobe-metrics) for the full list and
[the handler page](handler_netprobe.md) for enabling metric groups.
