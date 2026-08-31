# snmp-telemetry

Orb telemetry backend that collects SNMP operational metrics using
[ktranslate-compatible profiles](https://github.com/kentik/snmp-profiles) and
exports them as OTLP metrics.

For each target, the backend walks the device over SNMP, matches its
`sysObjectID` against the loaded profiles, and emits the matched profile's
metrics as OTLP gauges. Each gauge carries `device_ip`, `device_port` and
`policy` attributes, plus `netbox_id` when the target sets an `id` and
`snmp_context` when its authentication sets a `context_name`. Together they are
the device identity, so two policies polling one device, one host answering on
two ports, or one policy naming an endpoint twice under different IDs or
contexts, stay distinct series. Metrics are sent only when
`--otel-endpoint` is set; without it, targets are still polled but nothing is
exported.

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
Usage of snmp-telemetry:
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
    	period in seconds between OpenTelemetry exports, greater than 0 (default 10)
  -policy-env-vars string
    	comma-separated environment variable names a policy may read through a ${NAME} reference in community, username, auth_passphrase or priv_passphrase. Empty, the default, rejects every reference.
  -port int
    	server port (default 8078)
  -snmp-profiles-dir string
    	directory of ktranslate-compatible SNMP profile YAML files to overlay on the profiles bundled into the binary. Files here replace bundled ones with the same relative path; everything else is unaffected. Environment variable can be used by wrapping it in ${} (e.g. ${SNMP_PROFILES_DIR})
  -snmp-profiles-root string
    	directory a policy's own profiles_dir must resolve inside. A policy names an absolute path under it, or one relative to it. Empty, the default, rejects every per-policy profiles_dir. Environment variable can be used by wrapping it in ${} (e.g. ${SNMP_PROFILES_ROOT})
```

### Binding and access control

The policy API has no authentication. Anyone who can reach the listener can
create a policy, and a policy names the SNMP credentials to send and the host to
send them to, so reaching the listener is enough to make the backend poll
arbitrary hosts with whatever credentials the caller supplies. `--host`
therefore defaults to `localhost`: the agent runs this backend as a child
process and reaches it over the loopback interface, so nothing legitimate needs
a wider bind.

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

### Policy Configuration

A policy names the targets to poll and the SNMP credentials to use. Each
policy needs `metrics_interval`, the number of seconds between collection
runs for every target in that policy.

Credentials go under `authentication`. Set it at the scope level as a
fallback for every target, on individual targets, or both; a target with its
own `authentication` block uses it instead of the scope-level one.

```yaml
policies:
  snmp_metrics_1:
    config:
      metrics_interval: 60
      snmp_timeout: 5
      retries: 1
    scope:
      targets:
        - host: "192.168.1.1"
        - host: "192.168.1.2"
          authentication:
            protocol_version: "v3"
            security_level: "authPriv"
            username: "netbox-poller"
            auth_protocol: "SHA"
            auth_passphrase: "authpass123"
            priv_protocol: "AES"
            priv_passphrase: "privpass123"
            context_name: "vlan-100"
      authentication:
        protocol_version: "v2c"
        community: "public"
```

`snmp_timeout` sets how long one SNMP request may take, in seconds, and
`retries` how many times a timed-out request is retried. Both are optional:
`snmp_timeout` defaults to 5 seconds and `retries` to none. A collection run is
bounded by `metrics_interval`. A policy whose `snmp_timeout` reaches its
`metrics_interval` is rejected, because a single attempt filling the
interval can never produce a sample.

Retries raise the ceiling for one request to `snmp_timeout` times `retries`
plus one. A ceiling that reaches `metrics_interval` is warned about rather
than rejected: it is only reached against a device that never answers, so
refusing it would turn away a policy that collects normally from the devices
that do. The run's deadline is handed to the SNMP client, so against an
unresponsive device the retry sequence is cut short when the interval runs out
rather than outliving it, and the policy keeps running.

A target's `host` can be a single address, a hostname, a CIDR prefix, or an
address range, and each address it expands to becomes its own recurring poll
job. Two entries naming the same device, such as a prefix and an address inside
it, get one job between them: the repeat has nothing of its own to poll, and a
second job for the same device would overwrite the first's results. Entries
given different `id` or `context_name` values are different devices and each
keep a job. A host the backend cannot expand, such as a malformed prefix like
`10.0.0.1/99` or an IPv6 CIDR, is rejected and the whole policy fails to
start, rather than being dropped so the policy runs with fewer targets than it
names. A policy whose targets together expand to more than 65536 addresses is
rejected. The budget spans the whole policy rather than each entry, so several
prefixes that each fit on their own are still refused once their total passes
it. It is counted before the repeats are collapsed, so naming one span as two
overlapping prefixes costs both. That ceiling is a guard against a policy wide enough to exhaust memory
before polling starts, not a recommended size: polling tens of thousands of
devices from one policy is far past what one agent should carry.

`community`, `username`, `auth_passphrase`, and `priv_passphrase` accept
`${VARNAME}` environment variable references, but only for a variable the
operator listed in `--policy-env-vars`. A reference to any other name is
rejected, and so is every reference when the flag is unset. If an allowed
variable is unset, the policy is rejected too.

```sh
snmp-telemetry --policy-env-vars SNMP_COMMUNITY,SNMP_AUTH_PASS,SNMP_PRIV_PASS
```

The list is a security boundary, not a convenience. A policy arrives over the
API and names both a credential and the host to send it to, and this backend
runs as a child of the agent and inherits its whole environment, so a resolver
that read any variable would let a policy send the agent's own secrets to a host
of the policy author's choosing. The names are matched exactly; there is no
prefix or pattern form. `--otel-endpoint` and `--snmp-profiles-dir` accept
`${VARNAME}` too and are not restricted, because they are set on the command
line rather than by a policy.

Every SNMPv3 authentication block needs a `username`, whatever its
`security_level`: the SNMP client refuses the connection without one, so a
policy that omits it can never collect.

An SNMPv3 target can set `context_name` to poll a named context instead of
the device's default one. `context_name` is valid only inside an SNMPv3
authentication block; setting it under `protocol_version: v1` or
`protocol_version: v2c` is rejected.

A policy request body is capped at 1 MiB, and a larger one is rejected with
HTTP 413 before it is parsed. That ceiling is far above any policy this backend
expects: the sample above weighs about 600 bytes, and a target's `host` can be a
CIDR prefix, so covering a whole /16 costs one line rather than 65536 of them.

That cap bounds how many bytes a request may carry, not how long they may take,
so the API also sets connection deadlines: 10 seconds to finish the request
headers, 30 seconds for headers and body together, 60 seconds from the headers
to the last byte of the response, and 60 seconds idle on a kept-alive
connection. The write deadline covers the handler, and the slowest one is a
policy delete waiting on its scheduler to unwind, which takes at most 24
seconds.

A policy can also set `profiles_dir` under `config` to overlay a directory of
profiles for that policy only, instead of the one passed to
`--snmp-profiles-dir`. That value arrives over the API and names a tree the
backend reads, so it is confined to `--snmp-profiles-root`. Without that flag no
policy may set `profiles_dir` at all; with it, a policy names either an absolute
path inside the root or a path relative to it, and anything else is rejected,
`..` included. The root confines the resolved path as well as the name, so a
symlink inside the root that points out of it is refused rather than followed.

```sh
snmp-telemetry --snmp-profiles-root /opt/orb/snmp-profiles \
               --snmp-profiles-dir /opt/orb/snmp-profiles/default
```

```yaml
config:
  profiles_dir: vendor-a          # /opt/orb/snmp-profiles/vendor-a
```

The two flags do different jobs. `--snmp-profiles-dir` is the overlay every
policy uses unless it names its own, and it is set on the command line, so it is
not confined to the root. `--snmp-profiles-root` bounds only what a policy may
name. Pointing `--snmp-profiles-dir` at a directory under the root, as above, is
the tidy arrangement, but it is not required.

Policies naming one directory share a single loaded profile set. It is loaded on
the first policy to use it and released with the last, so a directory no running
policy names is not held.

### SNMP Profiles

Profile YAML files are embedded into the binary at build time, so the backend
runs with a working profile set out of the box. `--snmp-profiles-dir` overlays
an additional directory on top of the bundled set. A file there replaces the
bundled file at the same relative path, and every other bundled file stays
available.

An override file's path must match the bundled file's path exactly, including
its subdirectory. For example, overriding the bundled
`_general/system-mib.yml` requires placing the replacement at
`_general/system-mib.yml` under the override directory.

A file at any other path is still loaded, but it does not replace the bundled
file. One placed at the override directory's root under a bundled profile's
filename, such as `system-mib.yml`, leaves `_general/system-mib.yml` in place
and does not become the parent of the bundled profiles carrying
`extends: system-mib.yml`: an `extends` reference naming a bare filename always
resolves to the bundled profile of that name.

It does take over a `matches:` redirect naming that filename. A `matches:`
entry names its target by bare filename, and there the override outranks the
bundled profile of the same name, so a `pf_sense.yml` at the override root
serves the redirects the bundled profiles point at `pf_sense.yml`. The backend
logs one warning naming the path that would have replaced the bundled profile
and another naming each filename the misplaced file took over, so check the log
after adding an override.

Adding a profile for a device the bundled set does not cover needs no matching
bundled path. Its filename appears nowhere in the bundled set, so it replaces
nothing by design and loads without a warning.

Where an override and a bundled profile declare the same `sysobjectid`, the
override wins and the collision is logged. A pattern ending in `*` counts as
the same only when the whole pattern is identical.

That tiebreak runs per declared OID, not per device. Matching itself is
unchanged: an exact OID still beats every wildcard, and a longer wildcard
prefix still beats a shorter one, whatever the profiles' origins. An override
declaring `1.3.6.1.4.1.9.*` therefore leaves a device covered by a bundled
`1.3.6.1.4.1.9.1.*` with the bundled profile, and nothing is logged, because
the two never claim the same pattern. To take a device from a bundled profile,
declare the OID or the pattern that profile declares.

Each symbol becomes one metric, named `snmp.` followed by the symbol name in
lower case, so `hrProcessorLoad` is exported as `snmp.hrprocessorload`.

A symbol's `tag:` renames the metric. It is not an attribute: a symbol carrying
`tag: CPU` is exported as `snmp.cpu` rather than under the name it declares,
which is how the same reading arrives under one name across vendors that each
name it differently. The attributes derived from the metric name follow it, so
an enum label on that symbol is written to `CPU_status` and a converted text
value to `CPU_value`. 96 bundled profile files tag a symbol, and once
inheritance is resolved 156 of the 205 bundled profiles carry at least one:
`_general/if-mib.yml` tags `ifOperStatus` `if_OperStatus`, so 146 profiles
export that reading as `snmp.if_operstatus`.

Where two symbols of a resolved profile resolve to one metric name, only one of
them is collected. They would otherwise share a series and export whichever
value was written last. The symbol the profile declares in its own file beats
one it inherited through `extends:`, so a vendor profile's own CPU reading
displaces the generic one it inherits; where that does not separate them the
longer OID wins, so a fully qualified instance beats the column it sits in. A
symbol declaring `allow_duplicate: true` is never dropped, which is how a
profile offers alternative OIDs for one reading so that a device answering
either of them reports it. Dropping a symbol is logged at debug level, naming
the metric, the symbol dropped and the symbol kept.

A device may answer more than one of those alternatives. Each row then keeps a
single reading, chosen by the same two rules: the profile's own declaration
before an inherited one, then the longer OID, and where neither separates them
the first declared. A device answering both therefore reports the same source on
every poll and across restarts, and the readings the alternatives differ on are
not exported side by side. The reading kept brings its own `CPU_status` and
`CPU_value` attributes with it, so the two are never mixed. Dropping a reading
is logged at debug level, naming the metric and both values. The bundled
`dell/dell-powerconnect.yml` is the case to picture: it reads CPU from a RADLAN
OID and from a DNOS one, for switch generations that answer one or the other.

A profile symbol may declare a `conversion` to turn a non-numeric OID value
into a metric. The collector implements `to_one`, `hextoip`, `hwaddr`,
`hextoint:<endianness>:<type>` and `regexp:<pattern>`. A symbol declaring
anything else is skipped, and so is one whose `hextoint:` endianness or width
is unrecognised or whose `regexp:` pattern does not compile, since neither can
be applied to any value. The backend logs one warning naming the conversion,
the symbol and the profile the first time a device matches that profile.
`powerset_status` is the only conversion the bundled set declares that the
collector does not implement, on the APC UPS `upsBasicStateOutputState` symbol.

A symbol that is collected can still yield no point, if the device answers with
a type its conversion cannot be applied to. `hextoint:` and `regexp:` recover a
number from text, so a device that answers with a number has already supplied
what they produce and the value is kept as it stands. `hextoip` and `hwaddr`
produce an address instead, which a bare number is not, so a numeric answer to
one of those is dropped rather than exported undecoded under a metric named for
an address.

Once a profile matches, its tables are walked with GETBULK, 25 values per
request, rather than one GETNEXT per value. A profile that sets
`no_use_bulkwalkall: true` is walked with GETNEXT instead, and so is everything
that `extends` it; the bundled set uses this for `_general/net-snmp.yml`,
`elemental/elemental-device.yml` and `sunbird/power-iq.yml`. SNMPv1 has no
GETBULK, so a v1 target always uses GETNEXT. The two walks that read
`sysObjectID` and `sysDescr` come before a profile is known and use GETNEXT
as well.

The bundled profiles are copied from
[kentik/snmp-profiles](https://github.com/kentik/snmp-profiles) under the
Apache 2.0 license. See [profiles/PROVENANCE.md](./profiles/PROVENANCE.md)
for the exact upstream commit and sync process.
