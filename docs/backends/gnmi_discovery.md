# gNMI Discovery
The gNMI discovery backend is an event-driven network discovery service that maintains long-lived [gNMI](https://github.com/openconfig/gnmi) subscriptions and ingests device, interface, and hardware-inventory changes into NetBox via Diode within seconds of them occurring.

Unlike SNMP/NAPALM-based polling, `gnmi_discovery` reacts to `ON_CHANGE` notifications from the device itself (with `SAMPLE` and `GET` fallback for devices that don't support streaming), so NetBox stays up to date continuously rather than on a polling interval.

## Diode Entities
The gNMI discovery backend uses the [Diode Go SDK](https://github.com/netboxlabs/diode-sdk-go) to ingest the following entities:

* Device (with `DeviceType`, `Platform`, and serial/manufacturer enrichment)
* Interface
* Module / ModuleBay (hardware inventory)
* IP Address
* VRF

## Configuration
The `gnmi_discovery` backend requires no special configuration; `host` and `port` may be overridden. It uses the `diode` settings from the `common` subsection to forward discovery results.

```yaml
orb:
  backends:
    common:
      diode:
        target: grpc://192.168.0.100:8080/diode
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
        agent_name: agent01
    gnmi_discovery:
      host: 192.168.5.11 # default localhost
      port: 8076 # default 8075
      log_level: ERROR # default INFO
      log_format: JSON # default TEXT
      profiles_dir: /opt/orb/gnmi-profiles # optional: directory of gNMI profile overrides
      otel_export_period: 30 # optional: seconds between OpenTelemetry metric exports (default 10)
```

| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| host | str | no | REST API host (default `localhost`) |
| port | int | no | REST API port (default `8075`) |
| log_level | str | no | Log level: `DEBUG`/`INFO`/`WARN`/`ERROR` (default `INFO`) |
| log_format | str | no | Log format: `TEXT` or `JSON` (default `TEXT`) |
| profiles_dir | str | no | Directory of gNMI profile overrides (empty = embedded profiles only) |
| otel_export_period | int | no | Seconds between OpenTelemetry metric exports (default `10`) |

## Policy
gNMI discovery policies are broken into two subsections: `config` and `scope`.

### Config
`config` defines behavior for the whole policy and is optional overall.

| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| mode | str | no | Delivery mode: `auto` (default), `on_change`, `sample`, or `get`. `auto` negotiates the best mode per target (`ON_CHANGE → SAMPLE → GET`). |
| debounce_ms | int | no | Flush delay in ms after the last notification before a snapshot is ingested (default `2000`). |
| sample_interval_ms | int | no | `SAMPLE` subscription interval in ms (default `300000` = 5m). |
| get_interval_ms | int | no | `GET` poll interval in ms (default `900000` = 15m). |
| probe_timeout_ms | int | no | How long a sweep waits for one address to answer (default `3000`). Too low and a whole subnet reports as absent with no failure signal. |
| rescan_interval_ms | int | no | Re-probe addresses this policy is not subscribed to, picking up devices that were down when the policy was applied. Unset or `0` disables it; a non-zero value below `60000` is rejected. |
| send_credentials_to_unverified_targets | bool | no | Permit a CIDR or range target to carry a password when TLS does not verify the server. Off by default. See [Credentials and ranges](#credentials-and-ranges). |
| options | map | no | Per-policy toggles. `capture_config` (bool) captures the CONFIG datastore into `Device.config.running` (default off). `emit_lag_membership` (bool) links each LAG member port to its aggregate (default on; see [LAG membership](#lag-membership)). |
| defaults | map | no | NetBox defaults applied to discovered entities (see below). |

#### Defaults
| Key | Type | Description |
|:---:|:----:|:-----------:|
| site | str | NetBox site (default `undefined`) |
| role | str | NetBox device role (default `undefined`) |
| location | str | NetBox location (optional) |
| rack | str | NetBox rack name (optional). Sent with the device's site and location. See [Rack placement](#rack-placement) |
| tags | list | NetBox tags applied to all entities |
| device | map | Device overrides: `manufacturer`, `model`, `platform`, `comments`, `tags` |
| interface | map | Interface defaults: `if_type` (fallback type, default `other`), `description`, `tags` |
| ip_address | map | IP address defaults: `role`, `tenant`, `description`, `comments`, `tags` |
| vrf | map | VRF defaults: `tenant`, `description`, `comments`, `tags` (name/RD come from discovery) |
| vlan | map | VLAN defaults: `group` (see [VLAN group](#vlan-group)), `tenant`, `role`, `description`, `tags` |
| interface_patterns | list | Name-regex → NetBox type, highest precedence (first match wins). |
| interface_exclude_patterns | list | Name-regex; matching interfaces are skipped entirely. |

##### VLAN group
`vlan.group` attaches every emitted VLAN to an `ipam.vlangroup`. Diode matches a VLAN group on its name and scope, so the group must be scoped the way it is in NetBox. A bare name scopes the group to the device's site. When VLANs are shared across several sites, scope the group to the site group, region or location that holds them instead:

```yaml
defaults:
  site: "mysite01"
  vlan:
    group:
      name: "Brussels VLAN Group"
      scope_site_group: "Brussels"
```

| Key | Type | Description |
|:---:|:----:|:-----------:|
| name | str | VLAN group name (required in the map form) |
| scope_site | str | Scope the group to this site instead of the device's site |
| scope_site_group | str | Scope the group to a site group |
| scope_region | str | Scope the group to a region |
| scope_location | str | Scope the group to a location. Locations are unique per site in NetBox, so the device's site is sent with it |

Only one `scope_*` may be set; a map with none behaves like the bare name. An unknown key in the map, two scopes, or a missing name rejects the policy rather than falling back to a site-scoped group. In a per-target `override_defaults`, the group replaces the policy value as a whole. Rack and cluster scopes are not supported.

### Scope
`scope` defines the list of gNMI targets to discover.

| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| targets | list | yes | The gNMI endpoints to discover (see target fields below). |
| username | str | no | Default gNMI username for every target that does not set its own. `${ENV_VAR}` syntax is supported. |
| password | str | no | Default gNMI password for every target that does not set its own. `${ENV_VAR}` syntax is supported. |
| port | int | no | Default port for every target whose `host` carries no port and that sets no `port` of its own (default `9339`). |
| origin | str | no | Default gNMI path origin. A target that sets `origin: ""` keeps origin-less paths rather than inheriting. |
| tls | map | no | Default TLS settings. A target's own `tls` block **replaces** this one entirely rather than merging field by field, because a bool cannot distinguish "unset" from "false". |

Scope-level settings are defaults, not overrides: a target that sets a field keeps
its own value. What counts is that the field is present, not that it is non-empty,
so a target inside a credentialed scope can connect anonymously by writing
`username: ""` and `password: ""`. `mode`, `profile` and `override_defaults` are deliberately not
scope fields. `mode` and `override_defaults` duplicate the policy-level `config`
knobs, and a scope-level `profile` would pin one vendor profile onto every device
in a range whose contents are not known in advance.

#### Target
| Key | Type | Required | Description |
|:---:|:----:|:--------:|:-----------:|
| host | str | yes | A single endpoint (`10.0.0.11`, `10.0.0.11:6030`, `switch-a.example.com`), a CIDR (`10.0.0.0/24`), or a range (`10.1.0.0-50`, `10.2.0.0-10.2.0.9`). A CIDR or range cannot carry an inline `:port`; use the `port` field. |
| port | int | no | Port for this target, used when `host` carries no inline port (default `9339`). An inline `host:port` wins over this field, which wins over the scope's. |
| username | str | no | gNMI username. `${ENV_VAR}` syntax is supported. Set it to `""` to connect anonymously from inside a scope that sets one. An omitted field inherits; an explicitly empty one does not. |
| password | str | no | gNMI password. `${ENV_VAR}` syntax is supported. Set it to `""` to block the scope's, as with `username`. |
| tls | map | no | TLS settings: `skip_verify` (keep TLS, don't verify the cert), `insecure` (opt-in PLAINTEXT, off by default), `ca`/`cert`/`key` (optional mTLS). TLS with system root CAs is the default. |
| mode | str | no | Per-target delivery mode override (`auto`/`on_change`/`sample`/`get`). |
| profile | str | no | Pin a gNMI profile (auto-detected when omitted). |
| origin | str | no | gNMI path origin (default `openconfig`); set `""` for origin-less paths. |
| netbox_id | int | no | Pin discovery to an existing NetBox device ID. Silently ignored when `host` is a CIDR or range: one NetBox device ID cannot describe a range. |
| override_defaults | map | no | Per-target overrides of the policy `defaults`. Also takes `position` and `face`, which are valid only here (see [Rack placement](#rack-placement)). |

#### Ranges and subnets
A `host` covering more than one address is expanded, and each address is probed
once before anything subscribes. Only addresses that answer get a subscription.
A gNMI subscription is a persistent stream rather than a poll, so without the
probe a `/24` would leave around 250 goroutines redialling empty addresses for
the life of the policy.

A CIDR excludes its network and broadcast addresses, so `10.0.0.0/24` is 254
addresses and `10.0.0.0/22` is 1022. A `/31` and a `/32` have no such pair to
exclude and stay 2 and 1. A range excludes nothing, so `10.0.0.0-255` is 256.
A policy may expand to at most 1024 addresses in total, counted across all its
targets before any expansion happens.

A probe establishes only whether something is listening on the gNMI port. Any
response admits the address, including a rejected RPC or a failed TLS handshake,
so an mTLS device probed without a client certificate and a device with a
self-signed certificate both count as present. Only silence counts as absent.
Probes carry no credentials.

A single named host is not probed. It is subscribed to directly and retried for
the life of the policy, so a device that is rebooting when the policy is applied
is not dropped.

#### Credentials and ranges
A probe carries no credentials, but the subscription that follows one does. A
probe admits anything that answers, so a range with a password and either
`skip_verify` or `insecure` sends that password to any service listening on the
gNMI port in that range, including services that are not network devices. A range
that overlaps a server VLAN is enough to cause this.

That combination is refused:

| Target | Password | TLS verification | Result |
|:------:|:--------:|:----------------:|:------:|
| explicit host | yes | any | allowed |
| CIDR / range | no | any | allowed |
| CIDR / range | yes | verified (`ca`, or system roots) | allowed |
| CIDR / range | yes | `skip_verify` | refused |
| CIDR / range | yes | `insecure` | refused |

Naming a host explicitly is not affected. The credential goes where the operator
said it should, and collecting it requires intercepting that connection rather
than listening on an unused address in a range.

The check is on the password, not on every credential. A client certificate is
not a bearer secret, because TLS ties possession to the session and an endpoint
that receives one cannot reuse it. mTLS over a range without a password is
allowed, and so is a username without a password.

For credentialed range discovery, give the scope a `ca` so the server is
verified. If the devices use per-device self-signed certificates with no shared
CA, verification is not possible; either name the hosts explicitly or set
`config.send_credentials_to_unverified_targets: true`. Setting it logs a warning
each time the policy is applied.

#### Interface type discovery
Each interface's NetBox type is resolved per interface, in precedence order:
1. `interface_exclude_patterns` — a name matching any regex is skipped (no interface emitted).
2. `interface_patterns` — the first matching regex assigns its `type` (wins over the rest).
3. OpenConfig `state/type` — the discovered identityref maps to a NetBox type for structural families (LAG → `lag`; loopback/VLAN/tunnel/prop-virtual → `virtual`).
4. Built-in name rules — media from names such as `GigabitEthernet` or `xe-`, and LAGs (see below); used only when `state/type` gave no structural family.
5. Port speed — `ethernet/state/port-speed` picks a media type.
6. The policy's `interface.if_type` default, else `other`.

#### LAG membership
With `options.emit_lag_membership` on (the default), a port whose OpenConfig `ethernet/state/aggregate-id` names an aggregate gets `Interface.lag` set to it. Nothing is created: the link is made only when the aggregate was discovered in the same cycle and typed `lag`, so an aggregate that is absent or excluded by `interface_exclude_patterns` leaves the member without a LAG and logs a warning. An aggregate is typed `lag` by its OpenConfig `state/type`, by a built-in name rule (`Port-Channel`/`po`, `ae`, `Bundle-Ether`, `Eth-Trunk`, `PortChannel`, `lag`/`lag-`, `bond`) or by `interface_patterns`; add an `interface_patterns` rule for an aggregate name none of these cover. A member typed `virtual` is skipped too, since NetBox refuses a LAG parent on one, and so is a member typed `bridge` or `lag`. device-discovery applies the same membership rules, with a shorter list of built-in LAG names.

#### Rack placement
`rack` places discovered devices in a NetBox rack. It is a literal rack name, set
in the policy `defaults` or in a target's `override_defaults`, where it replaces
the policy value. The rack is sent with the device's site and, when `location` is
set, its location.

A target's `override_defaults` can also place its device at a U in that rack:

```yaml
targets:
  - host: 192.0.2.10
    override_defaults:
      rack: R12
      position: 40.5
      face: front
```

| Key | Type | Description |
|:---:|:----:|:-----------:|
| position | number | Rack unit the device sits at: at least `1`, in steps of `0.5` (`40.5` is a half U). |
| face | str | `front` or `rear`, in any case. |

The policy is rejected when:
- `position` or `face` is set in the policy `defaults`. They describe one device, so they are set per target.
- only one of `position` and `face` is set. NetBox requires a face for any position.
- `position` and `face` are set but neither the target nor the policy sets a `rack`.
- `face` is not `front` or `rear`.
- `position` is below `1` or not a multiple of `0.5`. There is no upper bound check, since only NetBox knows the rack's height.
- the target's `host` is a CIDR or range covering more than one address. A range or subnet would place every device at the same U. `rack` alone is allowed on such a target.
- two targets with the same `netbox_id`, or the same literal `asset_tag`, send that device different placements: both update one device. A rack without a position counts too. Only a target written as a single address keeps its `netbox_id`; a `/32` or a one-address range drops it, as discovery does. An `asset_tag` in the policy `defaults` reaches every target, and every device of a subnet, so it makes all of them one device; a tag read from a path is only known at discovery time and is not compared. Two targets count as one device at a U only when they share their strongest identifier, in the order Diode matches on (`netbox_id`, then `asset_tag`): two targets with different `netbox_id`s are two devices even when they send the same tag.
- two targets are placed at the same U: the same site, location, rack, position and face. A device sent without a location (none on the target or in the policy `defaults`) counts as any location, since its rack is matched by name across the site. Two half-depth devices may share a U on opposite faces. Overlaps between devices taller than one U are left to NetBox, which knows their heights. Targets naming one address count once, as discovery runs it once: a target written as that single address wins over a `/32`, range or subnet covering it.

Quote a numeric rack name (`rack: "01"`). The agent passes the policy through YAML, so an unquoted `01` would arrive as the number 1 and `010` as 8; a rack that is not text is refused rather than guessed at.

How the placement behaves:
- A rack name that doesn't exist in the site is created by Diode, like any other referenced object. Use the exact NetBox name, and set `location` when racks in different locations share a name.
- A placement NetBox can't accept (the U is taken, the device doesn't fit, or the position is beyond the rack's height): NetBox rejects the device's own record that cycle, and its reason appears in the Diode ingestion logs. Its interfaces and addresses are separate records and still go in.
- A device that isn't in NetBox yet, sent to a U another device already occupies, updates that other device, because Diode matches devices by rack, position and face. Make sure the U is free before setting it.
- The position is re-applied every run, so a device moved in NetBox moves back on the next run unless its override is updated.

### Sample
A sample policy exercising the common gNMI discovery parameters.
```yaml
orb:
  ...
  policies:
    gnmi_discovery:
      gnmi_fabric:
        config:
          mode: auto
          debounce_ms: 2000
          defaults:
            site: New York NY
            role: Router
            tags: [gnmi-discovery, orb-agent]
            interface_patterns:
              - match: "^Ethernet"
                type: 10gbase-x-sfpp
            interface_exclude_patterns:
              - "^Management"
          rescan_interval_ms: 3600000    # re-probe hourly for devices that were down
        scope:
          username: ${GNMI_USER}         # inherited by every target below
          password: ${GNMI_PASS}
          port: 6030                     # Arista EOS default gNMI port
          tls:
            ca: /run/secrets/ca.pem      # prefer a CA over skip_verify
          targets:
            - host: 10.0.0.0/24          # swept: only addresses that answer subscribe
            - host: 10.1.0.0-50
            - host: 10.0.0.11            # a named host is subscribed without probing
              profile: arista_eos
              override_defaults:         # place this device at U40, front, in rack R12
                rack: R12
                position: 40
                face: front
            - host: 10.0.0.21            # Nokia SR-OS
              port: 57400
              username: admin
              netbox_id: 42              # honoured: a bare address, not a range
```

## Delivery mode in the log

In `auto` mode the agent tries `ON_CHANGE` first and steps down to `SAMPLE`, then
`GET`, for devices that do not offer streaming. Many platforms serve `GET` and
`SAMPLE` but not `ON_CHANGE`, so a downgrade is expected rather than an error.
The step down and the first successful ingest are each logged once per
connection:

```
INFO  on_change not available, using sample  policy=… host=… reason=…
INFO  discovery flushed                      policy=… host=… active_mode=sample entities=47
```

The second line is the one that confirms the target is discovering. After it the
target stays quiet, since the line is per connection rather than per flush.
