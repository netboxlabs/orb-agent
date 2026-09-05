# gnmi-telemetry

Orb telemetry backend that subscribes to gNMI streaming telemetry from network
devices under policies and exports what arrives as OTLP metrics.

For each target the backend dials gNMI, asks the device for its Capabilities,
selects a metric profile from the vendor and network OS it reports, and opens
one subscription carrying every path that profile names. Each notification is
matched back to the profile, converted, and written into a last-value store that
observable instruments read on the export cadence. Every series carries
`device_ip` and `policy` attributes, plus `netbox_id` when the target sets an
`id` and whatever path keys its profile promotes, such as `interface_name`.
Metrics are sent only when `--otel-endpoint` is set; without it, targets are
still subscribed but nothing is exported.

`--otel-endpoint` accepts either a bare `host:port` (e.g. `localhost:4317`)
or a full URL with a scheme (e.g. `grpc://collector:4317`,
`https://collector.example.com:4317`). Both forms dial the given address.

The scheme decides transport security. `https://` and `grpcs://` connect over
TLS, verified against the host's root CAs; `http://` and `grpc://` connect in
plaintext. A bare `host:port` carries no scheme and connects in plaintext, the
same reading the agent applies to this value for its own exporters, so an
endpoint that must use TLS has to say so with a scheme.

### Usage
```sh
Usage of gnmi-telemetry:
  -help
    	show this help
  -host string
    	server host (default "localhost")
  -log-format string
    	log format (TEXT, JSON) (default "TEXT")
  -log-level string
    	log level (DEBUG, INFO, WARN, ERROR) (default "INFO")
  -otel-endpoint string
    	OpenTelemetry exporter endpoint (e.g. localhost:4317). Environment variable can be used by wrapping it in ${} (e.g. ${OTEL_ENDPOINT})
  -otel-export-period int
    	period in seconds between OpenTelemetry exports, from 1 to 31536000 (one year) (default 10)
  -policy-env-vars string
    	comma-separated environment variable names a policy may read through a ${NAME} reference in username, password or a tls file path. Empty, the default, rejects every reference.
  -port int
    	server port (default 8079)
  -profiles-dir string
    	directory of metric profile YAML files overlaid on the profiles bundled into the binary; a file replaces the bundled profile of the same name. Environment variable can be used by wrapping it in ${} (e.g. ${GNMI_PROFILES_DIR})
  -profiles-root string
    	directory a policy's own profiles_dir must resolve inside. A policy names an absolute path under it, or one relative to it. Empty, the default, rejects every per-policy profiles_dir. Environment variable can be used by wrapping it in ${} (e.g. ${GNMI_PROFILES_ROOT})
```

### Binding and access control

The policy API has no authentication. Anyone who can reach the listener can
create a policy, and a policy names the credentials to send and the host to send
them to, so reaching the listener is enough to make the backend dial arbitrary
hosts with whatever credentials the caller supplies. `--host` therefore defaults
to `localhost`: the agent runs this backend as a child process and reaches it
over the loopback interface, so nothing legitimate needs a wider bind. The API
listens on port 8079 by default.

Passing `--host 0.0.0.0` publishes that unauthenticated API on every interface.
Do it only behind access control of your own, such as a network policy or a
reverse proxy that authenticates callers.

An IPv6 address is passed as the bare literal, with no brackets: `--host ::1`
binds the IPv6 loopback and `--host ::` binds every interface, with the same
caveat as `0.0.0.0`.

This default differs from the discovery backends in `orb-discovery`, which still
default to `0.0.0.0`. The difference is deliberate rather than an oversight: the
agent passes `--host localhost` explicitly to every backend it launches, so the
wider default is what a standalone run gets, and there it is a listener nothing
is guarding.

This backend opens no listener of its own besides the policy API. Every gNMI
connection is outbound, dialed from this process to the device.

### What a subscription puts on the wire

The section above is about who can reach this backend. This one is about what
the backend sends outward, which is the part an operator has to reason about
before pointing a policy at a subnet.

Each target connection begins with a Capabilities RPC. Its answer supplies two
things: the vendor string, and the network OS when the device names one, which
select the profile unless the target pins one with `profile`, and the encodings
the device advertises. Subscriptions are requested as PROTO when the device
advertises it, because a target that serializes a stream as JSON emits a subtree
per update rather than one flat leaf per update; when PROTO is absent, the
negotiated Get encoding (JSON_IETF, or JSON for a device that offers only that)
is used instead. Encodings the backend does not know are ignored rather than
treated as a failure, since devices advertise private ones.

Then one STREAM subscription per target carries every path of its profile in a
single request, each path with the mode the profile gives it: `sample` paths at
the policy's `metrics_interval`, `on_change` paths as such, and each with its own
origin. TARGET_DEFINED is never requested, so a device's own idea of a sample
interval never replaces the policy's.

The first subscribe on a session probes each of those paths first, with a
one-path Get under that path's own origin, and leaves out the ones the target
rejects, logging each with the error it gave. A subscription is atomic on a
strict target, so one path the device does not carry would otherwise sink every
other path with it. The verdicts are remembered for the session, and a target
that rejects every probe is sent the full set rather than nothing.

A device that refuses that request is not abandoned. The delivery mode walks a
ladder, and each step down counts one `gnmi.mode_fallback_total`:

1. The profile's own modes, with `on_change` paths streaming on change.
2. Every path as SAMPLE at `metrics_interval`, which is where a device that
   rejects ON_CHANGE lands. A stream that ends before it delivers anything is
   read as a refusal too, since a device may accept the RPC and fail the
   subscription on the stream.
3. Get polling at `metrics_interval`, last. A subscription whose profile gives
   it an origin of its own is skipped here and logged once, because one Get
   carries one origin; a native path is reachable only by streaming.

A policy that names a mode chooses which of those rungs are tried. `mode:
on_change` keeps the mode the profile gives each path, so counters still stream
as SAMPLE, and skips the all-SAMPLE rung. `mode: sample` asks for SAMPLE on
every path. Both still fall to Get, on a request the device refuses and also on
a stream that ends before it delivers anything. The rung a target settled on is
reported as its `mode` in `GET /api/v1/status` and as the `mode` attribute of
that device's `gnmi.target_up` gauge.

A target's `host` may name more than one address, as a CIDR prefix or an address
range, and those are swept before anything is subscribed. A sweep probe is a
Capabilities call carrying no credentials, bounded by `probe_timeout_ms`
(3 seconds by default), and only the addresses that answered it are then dialed
with the policy's credentials. A single host is never probed; it is subscribed
directly. `rescan_interval_ms`, when set, re-probes the addresses the policy is
not subscribed to, so a device that comes up later is picked up; it is off by
default and must be at least 60000 when set.

The probe is what makes a wide target safe to write, and it is also why the
credential rule exists: **a CIDR or range target that carries a password is
rejected unless the policy's TLS block verifies the server, or the policy sets
`send_credentials_to_unverified_targets: true`.** Without verification, the sweep
admits whatever answered on the port, and an unrelated service inside the range
would be handed the credential. Name a CA (and leave `skip_verify` and
`insecure` off), or name the devices individually, or accept the risk
explicitly. A single-host target is not covered by the rule: an operator who
wrote one address chose the host the credential goes to.

The address budget bounds the rest: one target may expand to 1024 addresses, and
one policy's targets together to 65536 distinct addresses. Overlapping ranges
are bounded on top of that: every entry is expanded before the results are
deduplicated, and on every rescan tick, so a policy's targets may enumerate at
most 131072 addresses per sweep however few devices they describe. A host the
backend cannot expand, such as a malformed prefix, is rejected and the whole
policy fails to start rather than running with fewer targets than it names. Two
explicit targets naming the same device are rejected as well: a policy
subscribes to a device once.

### Policy Configuration

A policy names the targets to subscribe to and the credentials to reach them
with. Everything under `scope` is inherited by every target, and any target may
override a field with its own value.

```yaml
policies:
  core:
    config:
      metrics_interval: 30        # seconds, SAMPLE cadence; required
      mode: auto                  # auto | on_change | sample; optional
      profiles_dir: overlays      # optional, resolved inside --profiles-root
      send_credentials_to_unverified_targets: false
    scope:
      username: admin
      password: admin-pass
      port: 57400
      origin: openconfig          # request origin; "" for origin-less targets
      tls:
        skip_verify: false
        insecure: false
        ca: /opt/orb/ca.pem
        cert: ""
        key: ""
      targets:
        - host: 192.0.2.0/24
        - host: 192.0.2.11
          id: "42"                # exported as netbox_id
          username: other
          mode: sample
          profile: nokia_srlinux  # pins a profile; else auto-detect from Capabilities
```

A credential (`username`, `password`) or a TLS file path (`ca`, `cert`, `key`)
may be written as `${NAME}` instead of a literal, and is then read from the
environment, but only for a name the operator listed in `--policy-env-vars`. A
reference to any other name is rejected, and so is every reference when the flag
is unset; an allowed name that is unset in the environment is rejected too.

```sh
gnmi-telemetry --policy-env-vars GNMI_USERNAME,GNMI_PASSWORD
```

The list is a security boundary, not a convenience. A policy arrives over the
API and names both a credential and the host to send it to, and this backend
runs as a child of the agent and inherits its whole environment, so a resolver
that read any variable would let a policy send the agent's own secrets to a host
of the policy author's choosing. The names are matched exactly; there is no
prefix or pattern form. `--otel-endpoint`, `--profiles-dir` and
`--profiles-root` accept `${NAME}` too and are not restricted, because they are
set on the command line rather than by a policy.

#### `config`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `metrics_interval` | seconds, 1 to 31536000 | required | The SAMPLE cadence asked of the device, the Get polling interval on the last rung, and the basis of the staleness window. |
| `mode` | `auto`, `on_change` or `sample` | `auto` | Which rungs of the ladder above are tried. `auto` walks all three. `on_change` keeps the profile's own per-path modes and skips the all-SAMPLE rung; `sample` asks for SAMPLE on every path. Both still fall to Get, on a refused request and on a stream that ends before any data alike. |
| `profiles_dir` | path | none | A profile overlay directory for this policy alone, in place of `--profiles-dir`. Resolved inside `--profiles-root`; rejected when that flag is unset. |
| `probe_timeout_ms` | milliseconds, 0 to 31536000000 | `3000` | How long one sweep probe waits for an address to answer Capabilities. Zero takes the default. |
| `rescan_interval_ms` | milliseconds | `0` (off) | How often addresses the policy is not subscribed to are probed again. Must be from 60000 to 31536000000 when set. |
| `send_credentials_to_unverified_targets` | boolean | `false` | Permits a CIDR or range target to carry a password while TLS does not verify the server. |

#### `scope`

Every field here is a default for the policy's targets, and a target that sets
the same field keeps its own value, an explicitly empty one included.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `username` | string | none | The gNMI username sent to every target. |
| `password` | string | none | The password sent with it. See the credential rule above before pairing one with a CIDR or range target. |
| `port` | 1 to 65535 | `9339` | The port every target is dialed on. |
| `origin` | string | `openconfig` | The origin every request path is sent under. An explicit `""` uses the target's native schema. |
| `tls.skip_verify` | boolean | `false` | Keeps TLS but does not verify the server's certificate. |
| `tls.insecure` | boolean | `false` | Opts out of TLS entirely, in the clear. |
| `tls.ca` | path | none | The CA bundle the server certificate is verified against, instead of the host's roots. |
| `tls.cert`, `tls.key` | path | none | A client certificate and key, for a device that authenticates the caller with one. |
| `targets` | list | required | The devices, below. |

#### `targets`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `host` | address, hostname, CIDR prefix or range | required | One device, or a span of addresses to sweep. A port belongs in `port`, not in this string. |
| `id` | string | none | Exported as the `netbox_id` attribute of every series this target produces. |
| `username`, `password` | string | the scope's | This target's credentials. |
| `port` | 1 to 65535 | the scope's, else `9339` | This target's port. |
| `tls` | block | the scope's | This target's TLS settings, as a whole block. |
| `origin` | string | the scope's | This target's request origin. |
| `mode` | `auto`, `on_change` or `sample` | the policy's | The delivery mode for this target alone. |
| `profile` | profile name | auto-detect | Pins the metric profile instead of matching the NOS or vendor from Capabilities. An unknown name falls back to matching, with a warning. |

A policy request body is capped at 1 MiB, and a larger one is rejected with HTTP
413 before it is parsed. That ceiling is far above any policy this backend
expects: a target's `host` can be a CIDR prefix, so covering a whole `/16` costs
one line rather than 65536 of them.

That cap bounds how many bytes a request may carry, not how long they may take,
so the API also sets connection deadlines: 10 seconds to finish the request
headers, 30 seconds for headers and body together, 60 seconds from the headers
to the last byte of the response, and 60 seconds idle on a kept-alive
connection.

### Metrics

Every metric name comes from the profile: a metric named `if_in_octets` is
exported as `gnmi.if_in_octets`. Nothing derives a name from the device, so the
names a policy produces are known before it runs, from the profile it will
match.

Every series carries:

- `device_ip`, the target's host as the policy named it, and `policy`, the
  policy that created the series. Together they are the identity, so two
  policies watching one device keep separate series.
- `netbox_id`, when the target sets `id`.
- Whatever the profile's subscription promotes from the path keys:
  `interface_name` on the interface subtrees, `cpu_index`, `component_name`,
  and `slot` on the SR Linux native memory paths.

A profile metric of type `counter` becomes an observable counter reported as a
cumulative total, and one of type `gauge` becomes an observable gauge. A gauge
whose profile entry carries an `enum` maps the device's string to the integer
that entry names, and one carrying `bool: true` maps true to 1 and false to 0. A
value that fits none of those, such as an unmapped string, is dropped and
counted rather than exported as a zero.

Export runs on `--otel-export-period` (10 seconds by default), independently of
the sample cadence. What is exported is the last value of each series, whenever
it arrived: a 30 second SAMPLE subscription read every 10 seconds repeats a
value twice, and an ON_CHANGE leaf that changed three times between exports
reports the last of the three. The device timestamp is not exported, because the
SDK stamps an observation at collection time.

Staleness is what keeps a quiet device from reporting a stale value as current.
A SAMPLE or Get series is withheld from export and dropped from the store when
no update arrived for three `metrics_interval`s, and reappears when the device
sends the leaf again. The window is measured by arrival at the agent, not by
the device clock, so a device whose clock lags never blanks itself.

An ON_CHANGE series carries no window at all, because it refreshes only when
the leaf changes: it keeps its last value until the device deletes the element
or the policy stops, and `gnmi.target_up` is what says whether the stream is
still alive. A path the profile marks `on_change` is aged like any other when
the target settled on the SAMPLE rung or on Get, since there it arrives at the
interval. An ON_CHANGE series is also withdrawn when a reconnected stream's
initial dump no longer includes it: an element removed while the stream was
down is never deleted on the stream, so the dump the replacement opens with is
what says which elements the device still carries.

Two other things withdraw a series: a delete notification, which withdraws the
deleted element and everything under it, and stopping the policy, which
withdraws every series that policy wrote.

A counter whose new value is below the last is read as a device-side reset: the
series continues at the new value, and the consumer sees the drop as the reset
it is. A counter value that does not fit a signed 64-bit integer is dropped
rather than wrapped into a false reset.

Cardinality is bounded at ten thousand attribute sets per instrument, the SDK's
limit, and the backend holds its own series one short of it so a series it chose
is never the one folded into the SDK's overflow bucket. That bound is one for
the process: there is one instrument per metric name however many policies and
profile sets write to it, so every policy running draws on the same allowance.
Series are the product of the devices the policies name and the path keys their
profiles promote, so policies over a wide prefix whose devices each have
hundreds of interfaces are what approach it. An update refused by that bound is
counted, not exported.

Seven metrics describe the backend itself rather than a device:

| Metric | Kind | Attributes | Meaning |
| --- | --- | --- | --- |
| `gnmi.targets_active` | up-down counter | none | Targets with a running loop, across every policy. |
| `gnmi.target_up` | gauge | `device_ip`, `policy`, `mode` | 1 while the target has a live stream or poll, 0 while it is reconnecting. `mode` is the rung it settled on. |
| `gnmi.subscription_reconnects_total` | counter | none | Reconnects after a stream ended or failed. Backoff runs from one second to a thirty second cap, and resets after an attempt that delivered data. |
| `gnmi.notifications_total` | counter | none | Notifications received from any target. |
| `gnmi.updates_dropped_total` | counter | `reason` | Updates that produced no series: `unmatched_path` for a path no profile metric claims, `unconvertible_value` for a value the metric's type cannot take, `series_limit` for one refused by the cardinality bound. |
| `gnmi.mode_fallback_total` | counter | none | Delivery-mode downgrades, one per step down the ladder. |
| `gnmi.profile_fallback_total` | counter | none | Dial attempts whose NOS or vendor matched no overlay and used `_base`. One target counts once per attempt, so a device that reconnects counts again. |

`unmatched_path` is expected in small numbers: a subscription is to a subtree,
so a device that serves more leaves under it than the profile names counts one
drop per extra leaf per notification. A rate that matches the notification rate
is the signal worth reading, since it means the profile matches nothing the
device sends.

### Metric Profiles

A metric profile is one YAML file that says which paths to subscribe to, in
which mode, and which leaf under each becomes which metric. The bundled profiles
are embedded into the binary at build time, so the backend runs with a working
set out of the box.

```yaml
match: {}                          # nos, vendor aliases; empty matches nothing, _base is the fallback
subscriptions:
  - path: /interfaces/interface[name=*]/state/counters
    mode: sample                   # sample | on_change
    attributes:
      interface_name: name         # attribute name: path key name
    metrics:
      - {leaf: in-octets, name: if_in_octets, type: counter, unit: By}
      - {leaf: in-errors, name: if_in_errors, type: counter, unit: "{error}"}
  - path: /interfaces/interface[name=*]/state/oper-status
    mode: on_change
    attributes:
      interface_name: name
    metrics:
      - leaf: .
        name: if_oper_status
        type: gauge
        enum: {UP: 1, DOWN: 0, TESTING: 2, UNKNOWN: 3, DORMANT: 4, NOT_PRESENT: 5, LOWER_LAYER_DOWN: 6}
```

- The profile's name is its file name without `.yaml`, so `_base.yaml` is the
  profile `_base`. There is no `name` key in the file.
- `path` is the subscription, with `[key=*]` wildcards for keyed lists. `mode` is
  `sample` or `on_change` and decides what is asked of the device for that path.
- `leaf` is relative to `path` and may contain `/`, as `total/instant` does under
  a CPU's state. A `leaf` of `.` is the subscription path itself, for a
  subscription made directly to a leaf, and must then be the only metric in it.
- `name` is lower-case letters, digits and underscores, and is exported as
  `gnmi.<name>`. It must be unique within the resolved profile.
- `type` is `counter` or `gauge`. `unit` is a UCUM string handed to the
  instrument. `enum` and `bool` map non-numeric values and are valid on gauges
  only.
- `match.nos` names one network OS, compared whole and case-insensitively, and
  is tried ahead of `match.vendor`; a NOS is not a manufacturer, so a target that
  reports one still reports its hardware OEM as the vendor.
- `attributes` promotes path keys to attributes: `interface_name: name` reads the
  `name` key of the matched path element and exports it as `interface_name`. The
  key named on the right must be one the subscription path carries, and the
  attribute name on the left may not be `device_ip`, `policy` or `netbox_id`,
  which the collector sets itself.
- `origin` may be set per subscription, and overrides the target's for that path
  alone. `origin: ""` asks under the target's native schema, which is how the SR
  Linux overlay reads memory paths OpenConfig does not carry. A path with its own
  origin streams, but is skipped by Get polling.

An overlay names its parent with `extends` and inherits everything it does not
restate. A subscription whose `path` equals one of the parent's replaces that
one; any other path is added. An overlay that restates no `match` keeps its
parent's match criteria.

Profile selection per target, in order: the target's `profile` if it names a
loaded profile; else the profile whose `match.nos` equals the network OS from
Capabilities; else the vendor string from Capabilities matched against each
profile's `match.vendor` aliases, the longest matching alias winning; else
`_base`, which also counts one `gnmi.profile_fallback_total`. The choice is
reported per target in `GET /api/v1/status`.

`--profiles-dir` overlays a directory of `.yaml` files on the bundled set. A
file there whose name matches a bundled profile replaces it, and a file with any
other name is added as a new profile. An override that fails to parse, fails to
resolve its `extends`, or breaks a schema rule is logged and the bundled profile
it displaced is restored, so one bad file cannot take down a working set.

A policy may set `profiles_dir` under `config` to use a directory of its own
instead. That value arrives over the API and names a tree the backend reads, so
it is confined to `--profiles-root`. Without that flag no policy may set
`profiles_dir` at all; with it, a policy names either an absolute path inside the
root or a path relative to it, and anything else is rejected, `..` included. The
root confines the resolved path as well as the name, so a symlink inside the root
pointing out of it is refused rather than followed.

```sh
gnmi-telemetry --profiles-root /opt/orb/gnmi-profiles \
               --profiles-dir /opt/orb/gnmi-profiles/default
```

Policies naming one directory share a single loaded profile set. It is loaded on
the first policy to use it and released with the last, so a directory no running
policy names is not held.

The bundled set:

| Profile | Vendor match | Contents |
| --- | --- | --- |
| `_base` | none, it is the fallback | Interface counters and admin and oper status, system CPU and memory, component temperature and oper status, over OpenConfig paths. |
| `nokia_srlinux` | `nokia` | Extends `_base` with the native `/platform/control[slot=*]/memory` paths for free memory and utilization, which OpenConfig does not carry here. Validated against a device. |
| `arista_eos` | `arista` | Inherits `_base` unchanged, not yet validated against a device. |
| `cisco` | `cisco` | Inherits `_base` unchanged, not yet validated against a device. |
| `juniper` | `juniper` | Inherits `_base` unchanged, not yet validated against a device. |

The three placeholders exist so that a target of that vendor selects a named
profile rather than falling back, and so that vendor-specific paths have a file
to be added to. Until then they export exactly what `_base` exports, and only
the paths a given platform actually serves within it.
