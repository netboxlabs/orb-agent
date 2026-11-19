# Repo-maintained SNMP profiles

This directory holds profiles maintained in this repository, in the same
ktranslate YAML the bundled Kentik mirror uses. It is bundled into the binary
next to `../snmp-profiles/` and loaded by the same reader, so a file here is
addressed by the same relative path an override would use.

Nothing here is a mirror. The Kentik sync (`rsync --delete` into
`../snmp-profiles/`, see `../PROVENANCE.md`) never touches this directory.
Files here are updated by hand.

## Upstream

| | |
|---|---|
| Source | https://github.com/DataDog/integrations-core |
| Path | `snmp/datadog_checks/snmp/data/default_profiles/` |
| Commit | `c545ca5b168e1ccbffba82121cda46fa09459a46` |
| Date | 2026-09-04 |
| Licence | BSD-3-Clause (`LICENSE` in this directory) |

BSD-3-Clause requires the copyright notice, the conditions and the disclaimer
to travel with source and binary distributions. `LICENSE` is embedded into the
binary with the profiles. It does not require modification notices, so the
files here are edited freely.

## Files

Two kinds of file live here.

A **converted profile** carries metrics translated from an upstream file, for a
device the Kentik tree has no profile for. It claims sysObjectIDs the matcher
would otherwise route to Kentik's generic catch-all.

| File | Upstream file(s) | Claims |
|---|---|---|
| `chatsworth/chatsworth-pdu.yml` | `chatsworth_pdu.yaml` | `1.3.6.1.4.1.30932.*` |
| `hpe/hpe-proliant.yml` | `hpe-proliant.yaml`, `_hp.yaml` (metadata only, nothing carried), `_hp-base.yaml`, `_hp-compaq-health.yaml`, `_hp-driver-stats.yaml` | `1.3.6.1.4.1.232.*` (Kentik's `hp/hp-ilo.yml` and `hpe/hpe-cambium.yml` claim longer prefixes and keep winning) |
| `netscout/netscout-switch.yml` | `netscout-switch.yaml` | `1.3.6.1.4.1.21671`, `1.3.6.1.4.1.21671.*` |

A **model stub** adds sysObjectIDs to a bundled Kentik profile. It `extends`
that profile by bare basename, copies its `provider`, and declares nothing
else, so the device exports exactly what the Kentik profile exports.

One exception: `cisco/cisco-wlc-models.yml` redeclares the parent's own CPU
scalar. Every entry a stub inherits ranks as inherited in the metric-name
contest, and that parent relies on its own declaration outranking a generic
Cisco CPU symbol for the `snmp.cpu` name. Redeclaring the entry restores the
parent's outcome; `TestOrbProfiles_StubInheritsParentMetrics` compares the
exported symbol sets of every stub and its parent to catch the next case.

A stub also inherits whatever the collector already reports about its parent.
The WLC parent carries an enum member with no value, which the collector's
profile review warns about once per profile; the stub earns the same warning.
That is why the collector's review test covers the converted profiles only,
and why `TestEnum_BundledMembersWithNoValue` lists the stub beside its parent.

| File | Extends | Upstream file(s) |
|---|---|---|
| `avtech/roomalert-32s-models.yml` | `roomalert-32s.yml` | `avtech-roomalert-32s.yaml` |
| `cisco/cisco-asr-models.yml` | `cisco-asr.yml` | `cisco-asr.yaml`, `cisco-isr.yaml` |
| `cisco/cisco-catalyst-models.yml` | `cisco-catalyst.yml` | `cisco-catalyst.yaml` |
| `cisco/cisco-nexus-models.yml` | `cisco-nexus.yml` | `cisco-nexus.yaml` |
| `cisco/cisco-sb-models.yml` | `cisco-sb.yml` | `cisco-sb.yaml` |
| `cisco/cisco-wlc-models.yml` | `cisco-wlc.yml` | `cisco-catalyst-wlc.yaml`, `cisco-legacy-wlc.yaml` |
| `juniper/juniper-ex-models.yml` | `juniper-ex-switches.yml` | `juniper-ex.yaml` |
| `juniper/juniper-mx-models.yml` | `juniper-mx-router.yml` | `juniper-mx.yaml` |
| `juniper/juniper-srx-models.yml` | `juniper-srx-firewalls.yml` | `juniper-srx.yaml` |
| `netapp/netapp-ontap-models.yml` | `netapp-cluster.yml` | `netapp.yaml` |

Every sysObjectID an upstream family file lists that the bundled matcher would
otherwise route to a generic catch-all is included, wildcards too. Five Cisco
IDs the upstream Catalyst file lists are left out because Kentik already
routes them to its ASR or CSR profile; stubs fill gaps and never reclassify.

- `1.3.6.1.4.1.9.1.1189` (`cat2960xs48tsL`): routed to `cisco/cisco-asr.yml`.
- `1.3.6.1.4.1.9.1.2819` (`ciscoC850012X`): routed to `cisco/cisco-asr.yml`.
- `1.3.6.1.4.1.9.1.2961` (`ciscoC82001N4T`): routed to `cisco/cisco-asr.yml`.
- `1.3.6.1.4.1.9.1.2989` (`ciscoC83001N1S6T`): routed to `cisco/cisco-asr.yml`.
- `1.3.6.1.4.1.9.1.3004` (`ciscoC8000V`): routed to `cisco/cisco-csr.yml`.

## Rules every file follows

- No basename equals a basename under `../snmp-profiles/`. `extends` resolves
  by bare basename and the loader keeps the first one it reads.
- No sysObjectID, exact or wildcard, equals one a Kentik file claims. The
  matcher settles equal claims by read order and logs the loser at Debug.
  A claim may sit under a Kentik wildcard (an exact ID wins) or be a longer or
  shorter wildcard than a Kentik one (the longest prefix wins).
- `profiles/orb_profiles_test.go` enforces both, plus: every file resolves to at
  least one symbol with an OID, every stub's parent is a Kentik file, and
  loading the bundled set warns about nothing here.

## Conversion rules (upstream schema to ktranslate)

| Upstream | Here |
|---|---|
| `extends: _base.yaml` | `extends: system-mib.yml` |
| `_generic-if.yaml`, `_generic-ip.yaml`, `_generic-tcp.yaml`, `_generic-udp.yaml`, `_generic-host-resources*.yaml`, `_generic-ucd*.yaml` | Kentik `if-mib.yml`, `ip-mib.yml`, `tcp-mib.yml`, `udp-mib.yml`, `host-resources-mib.yml`, `ucd-mib.yml` |
| vendor `_` base files | inlined into the one profile that uses them |
| `metadata:`, `device:` | dropped; fields that read an OID become device-level `metric_tags` columns |
| `metric_type:` | dropped, every metric is a gauge |
| `metric_tags[].mapping: {int: name}` | `column.enum: {name: int}` |
| `metric_tags[].symbol: {OID, name}` | `column: {OID, name}` |
| top-level `metric_tags[] {OID, symbol: name, tag}` | `column: {OID, name}` with `tag:` beside it |
| `symbols[].constant_value_one` | dropped; the `mapping` on its tag columns becomes `enum` on the status symbol the same table polls |
| `symbol.format: mac_address` / `ip_address` | `conversion: hwaddr` / `hextoip` |
| `scale_factor` | dropped; the unit is noted in a comment |
| positional `index: N` tags | dropped; rows stay distinct by `row_index` |
| one table declared twice to force a type | one entry |
| `# NOTE: other(1), ok(2), ...` on a status symbol | `enum:` on that symbol, members from the comment |
| status symbol with no upstream `mapping` or comment, but the same column enumerated in a bundled Kentik profile | `enum:` copied from that Kentik profile (hpe-proliant `cpqSeCpuStatus`, from `hp/hp-ilo.yml`) |
| MAC address column with no upstream `format:` | `conversion: hwaddr` when the MIB types it as MacAddress (hpe-proliant `cpqNicIfPhysAdapterMACAddress`) |

## Maintenance

There is no sync. To refresh a converted file, diff it against the upstream
file at the recorded commit, apply the rules above, and update the commit and
date here. To add a file, add it to `TestOrbProfiles_ExactFileSet` and to the
tables above. If a Kentik sync brings a profile for one of these devices,
delete the file here in the same change; the claim test fails until you do.
