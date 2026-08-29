# snmp-telemetry

Orb telemetry backend that collects SNMP operational metrics using
[ktranslate-compatible profiles](https://github.com/kentik/snmp-profiles) and
exports them as OTLP metrics.

For each target, the backend walks the device over SNMP, matches its
`sysObjectID` against the loaded profiles, and emits the matched profile's
metrics as OTLP gauges. Each gauge carries `device_ip`, `device_port` and
`policy` attributes, plus `netbox_id` when the target sets an `id`. The first
three are the device identity, so two policies polling one device, or one host
answering on two ports, stay distinct series. Metrics are sent only when
`--otel-endpoint` is set; without it, targets are still polled but nothing is
exported.

`--otel-endpoint` accepts either a bare `host:port` (e.g. `localhost:4317`)
or a full URL with a scheme (e.g. `grpc://collector:4317`,
`http://0.0.0.0:4319`). Both forms dial the given address.

### Usage
```sh
Usage of snmp-telemetry:
  -help
    	show this help
  -host string
    	server host (default "0.0.0.0")
  -log-format string
    	log format (TEXT, JSON) (default "TEXT")
  -log-level string
    	log level (DEBUG, INFO, WARN, ERROR) (default "INFO")
  -otel-endpoint string
    	OpenTelemetry exporter endpoint (e.g. localhost:4317). Environment variable can be used by wrapping it in ${} (e.g. ${OTEL_ENDPOINT})
  -otel-export-period int
    	period in seconds between OpenTelemetry exports (default 10)
  -port int
    	server port (default 8078)
  -snmp-profiles-dir string
    	directory of ktranslate-compatible SNMP profile YAML files to overlay on the profiles bundled into the binary. Files here replace bundled ones with the same relative path; everything else is unaffected. Environment variable can be used by wrapping it in ${} (e.g. ${SNMP_PROFILES_DIR})
```

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
`snmp_timeout` defaults to 5 seconds and `retries` to none. Because a
collection run is bounded by `metrics_interval`, a policy whose `snmp_timeout`
is not below its `metrics_interval` is rejected.

A target's `host` can be a single address, a hostname, a CIDR prefix, or an
address range, and each address it expands to becomes its own recurring poll
job. A target that expands to more than 65536 addresses (a /16) is rejected.
That ceiling is a guard against a prefix wide enough to exhaust memory before
polling starts, not a recommended size: polling tens of thousands of devices
from one policy is far past what one agent should carry.

`community`, `username`, `auth_passphrase`, and `priv_passphrase` accept
`${VARNAME}` environment variable references. If the referenced variable is
unset, the policy is rejected.

An SNMPv3 target can set `context_name` to poll a named context instead of
the device's default one. `context_name` is valid only inside an SNMPv3
authentication block; setting it under `protocol_version: v1` or
`protocol_version: v2c` is rejected.

A policy can also set `profiles_dir` under `config` to overlay a directory of
profiles for that policy only, instead of the one passed to
`--snmp-profiles-dir`. That value arrives over the API, so a path containing
`..` is rejected: give an absolute path, or one relative to the working
directory.

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

The bundled profiles are copied from
[kentik/snmp-profiles](https://github.com/kentik/snmp-profiles) under the
Apache 2.0 license. See [profiles/PROVENANCE.md](./profiles/PROVENANCE.md)
for the exact upstream commit and sync process.
