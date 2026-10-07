# Network Discovery
The network discovery backend leverages [NMAP](https://nmap.org/) to scan networks and discover IP information.

## Diode Entities
The network discovery backend uses [Diode Go SDK](https://github.com/netboxlabs/diode-sdk-go) to ingest the following entities:

* [IP Address](https://github.com/netboxlabs/diode-sdk-go/blob/develop/docs/examples/ip_address/main.go)

IP addresses support VRF, Tenant, Role, Description, Comments and Tags via `defaults`.

The name a reverse lookup returns for an address becomes the IP's `dns_name`,
lowercased. NetBox accepts only letters, digits, hyphens and underscores in a
label. nmap, which does the lookup, prints an asterisk in place of any
character it will not pass, a space inside a DNS label for instance, and lets
a few others through that NetBox rejects; every such character becomes a
hyphen, so a name nmap printed as `abc1234-vendor*model*unit.example.net`
arrives as `abc1234-vendor-model-unit.example.net`. A name with no form
NetBox accepts, one with an empty label, longer than 255 characters or left
with no letter or digit, is left off; the address is still sent, and a
`dns_name` NetBox already holds for it stays as it is. In either case the
name as nmap gave it is kept under `hostnames` in the IP's comments, unless
the policy sets `defaults.comments`, which the backend does not add to. A
name that needed no change is not recorded, so this changes nothing in the
comments of an IP whose name was already acceptable. Each run logs how many
names it replaced or left off. A name that was already accepted with an
asterisk, which NetBox allows as a leading wildcard label, changes on the
next run, since nmap's asterisk never marks a wildcard.

## Configuration
The `network_discovery` backend does not require any special configuration, though overriding `host` and `port` values can be specified. The backend will use the `diode` settings specified in the `common` subsection to forward discovery results.


```yaml
orb:
  backends:
    common:
      diode:
        target: grpc://192.168.0.100:8080/diode
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
        agent_name: agent01
    network_discovery:
      host: 192.168.5.11 # default 0.0.0.0
      port: 8863 # default 8073
      log_level: ERROR # default INFO
      log_format: JSON # default TEXT

```

## Policy
Network discovery policies are broken down into two subsections: `config` and `scope`.

### Config
Config defines data for the whole scope and is optional overall.

| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| schedule | cron format | no  |  If defined, it will execute scope following cron schedule time. If not defined, it will execute scope only once  |
| defaults | map | no  |  key value pair that defines default values  |
| timeout | int | no | Timeout in minutes for the nmap scan operation. The default value is 5 minutes.

#### Defaults
Current supported defaults:

|  Key  | Type | Description  |
|:-----:|:----:|:-------------:|
| vrf | string \| map | VRF to assign to discovered IP addresses. Accepts a bare VRF name or a map with `name` + optional `rd` / `tenant` / `description` / `comments` / `tags` (see [VRF map](#vrf-map) below). Use the map form with `tenant` when the VRF belongs to a tenant in NetBox, so Diode matches it instead of creating a second VRF. |
| rd | str | Route Distinguisher (RD) for the VRF (only used when `vrf` is set). Optional; when omitted the VRF is emitted without an RD so NetBox can match an existing VRF whose `rd` is null. Equivalent to `vrf.rd`; a policy that sets both to different values is refused. |
| tenant | string \| map | Tenant to assign to discovered IP addresses. Accepts a bare tenant name or a map with `name` + optional `group` / `description` / `comments` / `tags` (see [Tenant map](#tenant-map) below). Use the map form when the tenant already exists in a tenant group so Diode matches it instead of planning a create. |
| role | str | Role to assign to discovered IP addresses |
| comments | str | NetBox Comments information to be added to discovered IP |
| description | str | NetBox Description data to be added to discovered IP |
| tags | list | NetBox Tags to be added to discovered IP |
| network_mask | int | Default network mask to be applied to IPv4 (default: 32) |

##### Tenant map
The `defaults.tenant` field accepts either a bare string (tenant name) or a map:

| Parameter | Type | Description |
|---------|----|-----------|
| name | string | Tenant name (required when using the map form) |
| group | string | Tenant group name |
| description | string | Tenant description |
| comments | string | Tenant comments |
| tags | list | Tenant tags |

Example — match an existing grouped tenant:

```yaml
defaults:
  tenant:
    name: "Example Tenant GmbH"
    group: "Example Group"
```

##### VRF map
The `defaults.vrf` field accepts either a bare string (VRF name) or a map:

| Parameter | Type | Description |
|---------|----|-----------|
| name | string | VRF name (required when using the map form) |
| rd | string | Route Distinguisher, equivalent to `defaults.rd` |
| tenant | string \| map | Tenant the VRF belongs to, in the same form as `defaults.tenant` (see [Tenant map](#tenant-map)) |
| description | string | VRF description, written to the VRF on every run |
| comments | string | VRF comments, written to the VRF on every run |
| tags | list | VRF tags, added to the VRF's existing tags |

Any other key in the map, or in its tenant map, is refused, so a misspelt `tenant` or `group` cannot leave the VRF without its tenant.

`defaults.tenant` applies to the discovered IP addresses only and does not set the VRF's tenant. Diode matches a VRF without an RD by its name and tenant, so when the VRF belongs to a tenant in NetBox, name that tenant under `vrf`. Otherwise Diode creates a second VRF with the same name and no tenant.

When the VRF has an RD in NetBox, set `rd` too. Diode then finds the VRF by its RD alone and writes the policy's VRF name, and tenant when set, onto it, so both must match what NetBox holds.

When `defaults.tenant` and `vrf.tenant` name the same tenant, write them identically, for example with the anchor below. Diode trims names and finds a tenant by its slug whatever its group, so names that differ only in case, spacing or punctuation are one tenant to it. If the two copies of that tenant disagree on its name, group, `description`, `comments` or `tags`, Diode refuses every address or rewrites the tenant on every run, so such a policy is refused, as is one that writes a tenant group two ways.

If an earlier run already created the extra tenant-less VRF, discovered addresses are created again in the tenant's VRF once the policy names its tenant. Reassign or delete the addresses left in the extra VRF, then delete that VRF.

Example: match an existing VRF that belongs to a grouped tenant:

```yaml
defaults:
  vrf:
    name: "Example VRF"
    tenant:
      name: "Example Tenant GmbH"
      group: "Example Group"
```

When the IP addresses and the VRF share a tenant, a YAML anchor avoids repeating it:

```yaml
defaults:
  tenant: &owner
    name: "Example Tenant GmbH"
    group: "Example Group"
  vrf:
    name: "Example VRF"
    tenant: *owner
```

### Scope
The scope defines a list of targets to be scanned.

| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| targets | list | yes  | The targets that NMAP will scan. These can be specified as IP addresses (192.168.1.1), IP ranges (192.168.1.10-20), IP subnets with mask (192.168.1.0/24) or resolvable domain names. |
| fast_mode | bool | no | Fast mode - Scan fewer ports than the default scan (-F). |
| timing | int | no | Set timing template, higher is faster (-T<0-5>). |
| ports | list | no | Only scan specified ports (-p). Sample: [22,161,162,443,500-600,8080]. |
| exclude_ports | list | no | Exclude the specified ports from scanning. Sample: [23, 9000-12000]. |
| ping_scan | bool | no | Ping Scan (-sn) - disable port scan. If `scan_types` is defined, `ping_scan` will be ignored. |
| top_ports | int | no | Scan <number> most common ports (--top-ports). |
| max_retries | int | no | Caps number of port scan probe retransmissions (--max-retries). |
| scan_types | list | no | Scan technique to be used by NMAP. Supports [udp,connect,syn,ack,window,null,fin,xmas,maimon,sctp_init,sctp_cookie_echo,ip_protocol]. If more than one TCP scan type (`connect,syn,ack,window,null,fin,xmas,maimon`) is defined, only the fist one will be applied. |
| dns_servers | list | no | Specify alternate DNS servers for DNS resolution (--dns-servers). |
| os_detection | bool | no | Enables NMAP OS detection (-O). |
| use_target_masks | bool | no | When enabled (default: True), applies the most specific subnet mask from the defined targets to discovered IPs. Only affects targets defined as subnets (e.g., 192.168.1.0/24), not ranges or individual IPs. |
| icmp_echo      | bool | no | Enables ICMP Echo discovery (-PE). Sends ICMP Echo Request (ping) probes to detect live hosts. |
| icmp_timestamp | bool | no | Enables ICMP Timestamp discovery (-PP). Uses ICMP Timestamp Requests to discover hosts that respond to this type of probe. |
| icmp_netmask   | bool | no | Enables ICMP Netmask discovery (-PM). Sends ICMP Address Mask Request packets to identify responsive hosts. |
| skip_host      | bool | no | Enables skip host discovery (-Pn). This option skips the host discovery stage altogether. |

### Sample
A sample policy including all parameters supported by the network discovery backend.
```yaml
orb:
  ...
  policies:
    network_discovery:
      discovery_1:
        config:
          schedule: "* * * * *"
          timeout: 5
          defaults:
            description: IP discovered by network discovery
            tags: [net-discovery, orb-agent]
            # tenant: customer-a
            # tenant: { name: customer-a, group: customers }
            # vrf: { name: example-vrf, tenant: customer-a }
        scope:
          targets: 
            - 192.168.7.32
            - 192.168.7.30-40 # IP range
            - 192.168.7.0/24 # IP subnet
            - google.com # dns lookup
          fast_mode: True
          max_retries: 0

```
### ⚠️ Warning
Be **AWARE** that executing a policy with only targets defined is equivalent to running `nmap <targets>`, which in turn is the same as executing `nmap -sS -p1-1000 --open -T3 <target>`:

- `-sS` → SYN scan (stealth scan, requires root privileges)
- `-p1-1000` → Scans the top 1000 most common ports
- `--open` → Only shows open ports
- `-T3` → Uses the default timing template (T3 is the standard speed)

## Rootless Podman Deployment

Network discovery can be run with podman in two modes: privileged (with sudo) or rootless (without sudo). The choice depends on your security requirements and the scan types you need.

### Limitations

NMAP's default behavior uses privileged network operations that require raw socket access:
- **SYN scans** (`-sS`) require `CAP_NET_RAW` capability
- **ICMP host discovery** (ping scans) requires raw socket creation
- **Rootless containers** cannot obtain true privileged capabilities, even with `--privileged` flag

When running podman without root privileges, these operations will fail with "Operation not permitted" errors.

### Option 1: Privileged Mode (with sudo)

For full NMAP functionality including SYN scans, ICMP discovery, and OS detection, run podman with sudo:

```bash
sudo podman run -d --privileged --net=host \
  --name orb \
  -v /home/user/orb:/opt/orb \
  -e DIODE_CLIENT_ID \
  -e DIODE_CLIENT_SECRET \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

**Advantages:**
- All NMAP scan types available
- ICMP host discovery works
- OS detection supported
- No configuration restrictions

**Disadvantages:**
- Requires sudo/root access
- Higher security risk

### Option 2: Rootless Mode (without sudo)

For rootless operation, use TCP connect scans which don't require raw sockets:

```bash
podman run -d --privileged --net=host \
  --name orb \
  -v /home/user/orb:/opt/orb \
  -e DIODE_CLIENT_ID \
  -e DIODE_CLIENT_SECRET \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

**Required Configuration:**

Your policy **must** include these settings:

```yaml
orb:
  policies:
    network_discovery:
      rootless_policy:
        scope:
          targets: [192.168.1.0/24]
          scan_types: [connect]  # TCP connect scan only
          skip_host: true         # Skip ICMP host discovery
          # fast_mode must be false (default) or omitted
          ports: [22, 80, 443, 8080]  # Recommended: specify ports
```

**Critical Requirements:**
1. `scan_types: [connect]` - Uses TCP connect scan (`-sT`) which doesn't require raw sockets
2. `skip_host: true` - Skips ICMP host discovery (`-Pn` flag), assumes all hosts are up
3. `fast_mode` must be `false` or omitted - Fast mode triggers operations requiring privileges

**Advantages:**
- No sudo/root required
- Lower security risk
- Suitable for restricted environments

**Disadvantages:**
- TCP connect scan only (slower, more detectable)
- No ICMP host discovery
- No OS detection
- Must manually specify or skip certain scan options

### Troubleshooting

**Error: "Couldn't open a raw socket. Error: Operation not permitted"**
- Cause: NMAP trying to use privileged scan types in rootless mode
- Solution: Ensure `scan_types: [connect]` and `skip_host: true` are set

**Error: "dnet: Failed to open device eth0"**
- Cause: NMAP attempting ICMP or privileged operations
- Solution: Add `skip_host: true` to skip host discovery

**Error: "exit status 1" in logs**
- Cause: NMAP command failed, often due to privilege issues
- Solution: Check that `fast_mode` is not set to `true`, verify rootless configuration

**Scan completes but finds no hosts:**
- Cause: `skip_host: false` (default) attempts ICMP discovery which fails silently
- Solution: Set `skip_host: true` to assume all targets are up
