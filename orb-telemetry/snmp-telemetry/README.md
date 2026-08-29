# snmp-telemetry

Orb telemetry backend that collects SNMP operational metrics using
[ktranslate-compatible profiles](https://github.com/kentik/snmp-profiles) and
exports them as OTLP metrics.

For each target, the backend walks the device over SNMP, matches its
`sysObjectID` against the loaded profiles, and emits the matched profile's
metrics as OTLP gauges. Each gauge carries a `device_ip` attribute, plus
`netbox_id` when the target sets an `id`. Metrics are sent only when
`--otel-endpoint` is set; without it, targets are still polled but nothing is
exported.

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

`community`, `username`, `auth_passphrase`, and `priv_passphrase` accept
`${VARNAME}` environment variable references. If the referenced variable is
unset, the policy is rejected.

An SNMPv3 target can set `context_name` to poll a named context instead of
the device's default one. `context_name` is valid only inside an SNMPv3
authentication block; setting it under `protocol_version: v1` or
`protocol_version: v2c` is rejected.

A policy can also set `profiles_dir` under `config` to overlay a directory of
profiles for that policy only, instead of the one passed to
`--snmp-profiles-dir`.

### SNMP Profiles

Profile YAML files are embedded into the binary at build time, so the backend
runs with a working profile set out of the box. `--snmp-profiles-dir` overlays
an additional directory on top of the bundled set: files there replace
bundled files at the same relative path, and everything else bundled stays
available.

The bundled profiles are copied from
[kentik/snmp-profiles](https://github.com/kentik/snmp-profiles) under the
Apache 2.0 license. See [profiles/PROVENANCE.md](./profiles/PROVENANCE.md)
for the exact upstream commit and sync process.
