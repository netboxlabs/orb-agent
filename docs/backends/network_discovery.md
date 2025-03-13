# Network Discovery
The network discovery backend leverages [NMAP](https://nmap.org/) to scan networks and discover IP information.

## Diode Entities
The network discovery backend uses [Diode Go SDK](https://github.com/netboxlabs/diode-sdk-go) to ingest discover IP Address entities with Global VRF and allows defining Description, Comments and Tags for them.

## Configuration
The `network_discovery` backend does not require any special configuration, though overriding `host` and `port` values can be specified. The backend will use the `diode` settings specified in the `common` subsection to forward discovery results.


```yaml
orb:
  backends:
    common:
      diode:
        target: grpc://192.168.0.100:8080/diode
        api_key: ${DIODE_API_KEY}
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
| timeout | int | no | Timeout in minutes for the nmap scan operation. The default value is 2 minutes.

#### Defaults
Current supported defaults:

|  Key  | Type | Description  |
|:-----:|:----:|:-------------:|
| comments | str | NetBox Comments information to be added to discovered IP |
| description | str | NetBox Description data to be added to discovered IP |
| tags | list | NetBox Tags to be added to discovered IP |

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
            comments: none
            description: IP discovered by network discovery
            tags: [net-discovery, orb-agent]
        scope:
          targets: 
            - 192.168.7.32
            - 192.168.7.30-40 # IP range
            - 192.168.7.0/24 # IP subnet
            - google.com # dns lookup
          fast_mode: True
          max_retries: 0

```
