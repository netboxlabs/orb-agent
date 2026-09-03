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
    	period in seconds between OpenTelemetry exports, from 1 to 31536000 (one year) (default 10)
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
arbitrary hosts with whatever credentials the caller supplies. A policy body
also makes the process bind a UDP socket, on any local address and port it is
permitted to bind, one per distinct `listen` string and with no cap on how many
it opens. `--host` therefore defaults to `localhost`: the agent runs this
backend as a child process and reaches it over the loopback interface, so
nothing legitimate needs a wider bind.

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

A trap socket, when a policy declares one, is the one listener in this process
that has to be reachable from the device network, since devices send traps to
it. No socket is open until a policy asks for one. What it accepts and what
protects it are described under **Receiving traps** below.

### What a poll puts on the wire

The section above is about who can reach this backend. This one is about what
the backend sends outward, which is the part an operator has to reason about
before pointing a policy at a subnet.

`protocol_version` decides how the credential travels:

- **SNMPv1 and SNMPv2c** put the community string in every request, in the
  clear. It is a shared secret with no integrity protection, so anyone able to
  observe or inject traffic on the path reads it from the first packet and can
  replay it. There is no version of v1 or v2c that avoids this.
- **SNMPv3** depends on `security_level`. `noAuthNoPriv` sends the username in
  the clear and authenticates nothing, so it protects no better than v2c.
  `authNoPriv` authenticates each message but sends the values in the clear.
  `authPriv` authenticates and encrypts, and is the only configuration here
  that keeps both the credential and the readings off the wire in the clear.

A target's `host` may name more than one address, and every address it expands
to is polled with the policy's credentials. A `/24` is 254 credentialed
requests, one to each host address in the prefix, whether or not anything is
listening there. With v1 or v2c that means the community string is delivered to
every address the notation covers, not only to the devices you meant to poll.

Two details of that expansion are worth knowing. A CIDR prefix excludes its
network and broadcast addresses, for a `/30` and wider, so a poll is never
addressed to the segment's broadcast address, where it would be delivered to
every host at once. An address range such as `192.168.1.0-255` keeps every
address written, including the `.0` and the `.255`, because an operator who
enumerated them meant them. The two notations differ here on purpose.

There is also no probe stage. This backend does not sweep for devices and then
authenticate to what it found; the first request it sends to an address is a
credentialed one. Narrowing a policy is therefore the only thing that narrows
where the credential goes.

On a segment you do not control, use SNMPv3 with `authPriv`, or name targets
individually rather than by prefix, or both. A v2c policy over a wide prefix is
the case that hands one shared secret to the largest number of hosts.

### Receiving traps

A policy receives SNMP traps and informs from the devices its targets expand
to by declaring the address they arrive on:

```yaml
policies:
  core:
    config:
      metrics_interval: 60
    scope:
      authentication:
        protocol_version: "v3"
        security_level: "authPriv"
        username: "netbox-poller"
        auth_protocol: "SHA"
        auth_passphrase: "authpass123"
        priv_protocol: "AES"
        priv_passphrase: "privpass123"
      targets:
        - host: "10.0.0.0/24"
      traps:
        listen: "0.0.0.0:162"
```

Without `traps`, a policy receives nothing and no socket is opened. `listen`
is `host:port`; an empty host binds every interface, and the host must be an
address, not a name. Port 162 is privileged; run with `CAP_NET_BIND_SERVICE`
or choose a higher port and redirect to it. Do not run the backend as root to
bind it.

Policies naming the same `listen` string share one socket, opened when the
first of them starts and closed when the last stops, the way pktvisor shares
one input stream between the policies that name one tap. The string is the
identity: `0.0.0.0:162` twice is one socket, while `0.0.0.0:162` and `:162`
are two attempts at one port, and the second policy fails to start with the
bind error in the API response. A policy on one socket never sees traps
arriving on another.

A policy may receive traps without polling. Omit `metrics_interval` and the
policy schedules no collection at all; its targets are still expanded, because
they are the addresses the socket accepts traps from, and its authentication
still supplies the v3 users. A policy with neither `metrics_interval` nor
`traps` is rejected as having nothing to do.

A trap is counted, not stored. Three metrics describe what arrived:

- `snmp.traps_received{device_ip, policy, trap_name, version}` counts traps
  from a device a policy on that socket names, once per policy naming it,
  with the same `device_ip` and `policy` labels every polled series carries.
  The counter is monotonic: a deleted policy's series stop being exported but
  keep their totals, so a policy recreated under the same name continues
  the count rather than restarting it, and nothing downstream sees a
  decrease. A trap that was already in hand when its policy was deleted is
  kept the same way and stays unexported until the policy comes back. A
  retained series that has to make way for a live one leaves its total in a
  baseline tier of the same size as the series ceiling, from which it
  resumes if it reappears, so the backend holds at most twice the ceiling
  in memory. Only once more than ten thousand distinct withdrawn series
  have been evicted does the oldest baseline go, and a series returning
  after that restarts, which a consumer reads as a counter reset.
- `snmp.traps_dropped{reason}` counts datagrams that produced no trap:
  `unknown_source`, `oversized`, `malformed`, `unsupported_pdu`,
  `unsupported_version`, `v3_unauthenticated`, `v3_not_in_time_window`,
  `no_trap_oid` or `series_limit`. `unsupported_version` is a wire version other than 1, 2c
  and 3, such as SNMPv2u's 2, which is never counted as 2c. Hostile v3 traffic lands under
  `malformed` when it names a username no policy carries and under
  `v3_unauthenticated` when it names a known one without asking to be
  authenticated, and the second is the one worth looking at, since it may mean
  someone holds a valid username. It has a benign cause too: a v3 target polled
  at `noAuthNoPriv` is a supported configuration, and every trap it sends
  carries no authentication either, so all of its traps are dropped under this
  reason. This release cannot count them. `v3_not_in_time_window` is an
  authenticated v3 trap whose engine boots are lower than last seen from that
  engine, or whose engine time is more than 150 seconds behind the clock the
  receiver keeps for it: RFC 3414's bound on replaying a captured message. The
  clocks are learned per sending address and engine, in memory, and relearned
  after a restart, so a device can only ever poison its own clock.
- `snmp.traps_datagrams` counts every datagram read from any socket. Every
  datagram read ends as one drop or as one trap, so `traps_datagrams` equals
  `traps_dropped` plus the datagrams that produced a trap. `traps_received` is
  not that second number: a trap counts once under every policy on the socket
  that names its source, so when two policies name the same device the
  per-policy series add up to more than the datagrams behind them. Use
  `traps_datagrams` as the rate the sockets are being read at, against what
  your devices send; a datagram the kernel discarded before the read appears
  in none of the three.

`trap_name` is drawn from a closed set: the six standard traps of RFC 1215 and
the trap definitions in the policy's own profile set, the bundled ones plus
whatever its `profiles_dir` adds or overrides, about two hundred names. Two
policies on one socket may therefore name one OID differently, each under
its own `policy` label; the RFC 1215 names win over any profile's spelling.
Any other trap is labelled `other`. A raw OID never appears as a label, because a
sender chooses its own trap OID and a metric label a sender controls is
unbounded.

There is still a ceiling on how many distinct series one metric can carry: ten
thousand attribute sets per instrument, after which the SDK folds every new
series into a single `otel.metric.overflow` bucket and the metric stops
answering questions about any of them. Trap series are the product of the
addresses your policies name, the trap names above and the three SNMP
versions, so a policy naming a whole `/16` whose every host sends every kind of
trap is past what that ceiling accommodates. Name the devices you expect traps
from. The backend bounds its own series at that ceiling: real series stop a
hundred short of it, a trap for a series that does not exist yet is then
counted under its policy with `device_ip` and `trap_name` both `other`, and
once that room is used up too a trap whose policy has no overflow series yet
is counted as a `series_limit` drop rather than under a series no policy
owns. A sender spoofing addresses inside a wide prefix can fill the ceiling
but cannot grow memory past it, the SDK never folds a series the backend
chose to keep, and every series is withdrawn with the policy that made it. The clocks the receiver keeps for v3 engines are bounded the
same way, at ten thousand engines, evicting the one used longest ago, in an
order kept as they are used so an eviction costs no scan.

**What the source address list is, and is not.** A trap from an address that
no policy on that socket names is dropped and counted as `unknown_source`,
before it is parsed. That is a noise filter and an attribution rule. It is
not authentication and it is not access control. SNMP traps are one-way UDP
with no handshake, so anyone able to emit a packet with a chosen source
address, which on a network without egress filtering is anyone, can have a
trap accepted and attributed to any device a policy names. The addresses are
not secret; they are the ones this backend visibly polls. Informs from
unknown addresses are never acknowledged, so the socket does not answer
strangers.

**Trap contents are unauthenticated unless the sender uses SNMPv3 with
authentication**, in which case the backend authenticates it with the USM
users the policies naming that device poll it with, and no others: a
credential a policy assigned to a different device is not tried. Two targets
kept at one address under different IDs or contexts contribute both their
credentials. An authenticated v3 trap is then counted only under the policies
holding the credential that verified it; a policy naming the same device with
v1, v2c or a different v3 user counts the device's v1 and v2c traps and not
its authenticated v3 ones. The policies a trap is counted under are resolved
when it is counted, so a policy deleted while a datagram was being parsed is
not counted and a replacement is counted only if it names the device. No trap-specific credentials are configured. v1 and v2c traps are never authenticated by any setting: the
community they carry is not checked, because a check would be mistaken for
authentication and would protect nothing against a sender who can read the
community off the wire.

The actual boundary is a network control on the trap port, a firewall rule
or a management VRF, the same way the actual boundary for polling is the
segment the credentials cross.

Three limits in this release. SNMPv3 informs are not supported: an inform
makes the receiver the authoritative engine, so the sender first probes for
the receiver's engine ID and localises its keys against it, and this receiver
has no engine ID to offer. The probe carries no username and is dropped as
`malformed`, and the inform is never acknowledged, so the sender retries and
gives up. SNMPv3 traps are authenticated and counted, and v1 and v2c informs
are acknowledged; a device that must use informs sends them as v2c for now.
A link-local IPv6 device is matched with the interface zone the socket
saw it on, so two devices at `fe80::1` on different interfaces are two
devices; a target written without a zone matches the address on any
interface, alongside any target written with one, and `device_ip` carries
the zone. A policy target written as a
hostname rather than an address is not matched against trap sources, so its traps count as
`unknown_source`; a policy declaring `traps` whose targets are all hostnames
starts with a warning saying so, and its USM user is never tried, since it
claims no device for the user to authenticate. And a device behind a trap relay or NAT
arrives as the relay's address; a v1 trap whose agent-addr field names a
polled device is attributed to that device, but v2c and v3 traps are
attributed to the address they arrive from.

### Policy Configuration

A policy names the targets to poll and the SNMP credentials to use. Each
policy that polls needs `metrics_interval`, the number of seconds between
collection runs for every target in that policy; a policy may omit it to
receive traps only, as described under **Receiving traps**.

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
interval can never produce a sample. Both are capped at 31536000 seconds, one
year: a larger number does not fit the duration they are converted to, and
would wrap to a fraction of a second. `retries` is capped at 10, which is a
bound on a count rather than on a duration: the SNMP client sizes a
per-request allocation with it, and ten attempts at the default timeout
already fill a minute.

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
`..` included. The root itself may be given relative to the working directory
and is resolved before a policy is checked against it, so both policy forms work
either way. The root confines the resolved path as well as the name, so a
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

A profile's `metric_tags` become attributes beside the ones above, on the device
or on the row. A tag that takes one of the device identity names, or
`row_index`, is dropped rather than applied: a duplicate attribute resolves to
whichever value came last, so honouring it would replace the value that tells
two devices or two rows apart. The profile still loads and every metric it
declares is still collected, since a bundled profile is vendored and cannot be
edited. The backend logs one warning naming the tag and the profile the first
time a device matches that profile. No bundled profile declares such a tag, so
only an override reaches this, and renaming the tag applies it.

A reading also derives attributes of its own, under the export name of the
symbol that produced it: `<name>_status` for the enum member its value falls on,
and `<name>_value` for the text a conversion rendered it as. A profile declaring
a tag under either name keeps the tag, and the derived attribute is dropped
instead. The tag carries a reading of another column that appears nowhere else
on the point and is part of what tells two rows apart, while the derived
attribute renders the value the point already exports. Whether a reading fills
either one takes a device answer, but whether a symbol can derive the name at
all is a property of the profile, so the backend logs one warning naming the
attribute, the symbol and the profile the first time a device matches it. A
device-level tag is checked against every symbol and a row-level tag against
the entry that declares it. No bundled profile collides, so only an override
reaches this.

Once a profile matches, its tables are walked with GETBULK, 25 values per
request, rather than one GETNEXT per value. A profile that sets
`no_use_bulkwalkall: true` is walked with GETNEXT instead, and so is everything
that `extends` it; the bundled set uses this for `_general/net-snmp.yml`,
`elemental/elemental-device.yml` and `sunbird/power-iq.yml`. SNMPv1 has no
GETBULK, so a v1 target always uses GETNEXT. The two walks that read
`sysObjectID` and `sysDescr` come before a profile is known and use GETNEXT
as well.

An OID is walked once per collection however many declarations name it, and
they all read that one answer. A column read as a metric and as a tag, a
column two entries share, and two declarations of one column that differ only
in their `condition:` are one request each. Declarations that agree on
exported name, OID and poll period also share one poll window, so serving them
from one walk is what keeps a window from being marked by a request the other
declaration never got.

The bundled profiles are copied from
[kentik/snmp-profiles](https://github.com/kentik/snmp-profiles) under the
Apache 2.0 license. See [profiles/PROVENANCE.md](./profiles/PROVENANCE.md)
for the exact upstream commit and sync process.
