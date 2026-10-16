# Device Discovery Optional Arguments

`optional_args` on a scope entry is passed to the NAPALM driver. What a key
does depends on how the driver reaches the device:

- **SSH drivers**, which is most of them: `ios`, `iosxr`, `nxos_ssh`, every
  `*_ssh` driver, the other CLI drivers, and `eos` with `transport: ssh`.
  They connect with [Netmiko](https://github.com/ktbyers/netmiko), which opens
  the SSH session with [paramiko](https://www.paramiko.org/). NAPALM forwards
  every Netmiko connection argument it finds in `optional_args`, except the six
  it sets itself: `ip`, `host`, `username`, `password`, `device_type` and
  `timeout`. The keys in [Connection settings](#connection-settings-ssh-drivers)
  work on every SSH driver.
- **API and NETCONF drivers**: `nxos`, `eos` over eAPI (its default), `junos`,
  `iosxr_netconf`, `nokia_sros`, `aruba_aoscx`, `aruba_osswitch`, `cisco_asa`
  and `paloalto_panos`. They read only their own keys: the custom drivers'
  under [Driver-specific keys](#driver-specific-keys), the core drivers' in
  NAPALM's list. A key with a Netmiko name keeps the driver's meaning there:
  `port` is the API or NETCONF port on most of them, and `junos` also reads
  `ssh_config_file`, `key_file` and `keepalive` (30 by default), so jumphosts
  set up with `ProxyCommand` work with it too. Its NETCONF client ignores
  `ProxyJump` and connects directly, and so does `iosxr_netconf`'s. The other
  Netmiko keys are ignored, except by `iosxr_netconf` (see
  [iosxr_netconf](#iosxr_netconf)).

Apart from `iosxr_netconf`, a key a driver does not know is ignored without a
warning.

```yaml
scope:
  - hostname: 192.0.2.10
    driver: ios
    username: admin
    password: ${DEVICE_PASSWORD}
    optional_args:
      ssh_config_file: /opt/orb/ssh-napalm.conf
      read_timeout_override: 30
```

## Connection settings (SSH drivers)

| Key | Default | What it does |
|:----|:--------|:-------------|
| `port` | 22 | SSH port. device-discovery also uses it to tell apart two targets on the same host (see [Rack placement](./README.md#rack-placement)). |
| `secret` | none | Enable password, for devices that need one. |
| `ssh_config_file` | none | OpenSSH configuration file, for jumphosts and per-host settings. See [SSH Configuration](./ssh.md). |
| `use_keys` | `false` | Also try the default keys in `~/.ssh`. It needs `key_file` set to an existing file, and a `key_file` is used even without it. |
| `key_file` | none | Path to the private key inside the container. See [SSH Key Permissions](./ssh.md#ssh-key-permissions). |
| `passphrase` | none | Passphrase of an encrypted key. If it is not set, the password is used to decrypt the key. |
| `allow_agent` | `false` | Use an SSH agent. |
| `read_timeout_override` | none | Seconds to wait for each command's output. See [Timeouts](#timeouts). |
| `conn_timeout` | 10 | Seconds for the TCP connect and the whole SSH handshake, banner included. |
| `banner_timeout` | 15 | Seconds to wait for the SSH banner, within `conn_timeout`. |
| `auth_timeout` | 30 | Seconds to wait for the authentication response. |
| `keepalive` | 0 | Seconds between SSH keepalives. 0 sends none. |
| `disabled_algorithms` | none | SSH algorithms paramiko must not offer, as a map in [paramiko's format](https://docs.paramiko.org/en/stable/api/transport.html#paramiko.transport.Transport.__init__). For example, `{pubkeys: [rsa-sha2-512, rsa-sha2-256]}` for an old device that only accepts `ssh-rsa` key signatures. |
| `ssh_strict` | `false` | Reject host keys that are not already known. By default an unknown host key is accepted. |
| `system_host_keys` | `false` | Load known host keys from the user's `known_hosts`. |
| `alt_host_keys`, `alt_key_file` | `false`, none | Load known host keys from the file in `alt_key_file`. |

These are the commonly useful ones. Any other argument of Netmiko's
`BaseConnection` is forwarded the same way.

## Timeouts

Netmiko waits 10 seconds for each command's output (`iosxr` waits the
target's `timeout`, 60 seconds by default), so a device that answers more
slowly can fail discovery with a read timeout. Raise the wait with
`read_timeout_override`, as in the example above.

It replaces every read wait the driver uses, including the longer ones some
drivers set for heavy commands, such as the 120 seconds `hp_procurve` allows
for `show running-config`. A value below those shortens them. On `iosxr` it
replaces the target's `timeout` too, so keep it above that, or raise
`timeout` instead.

When it is the connection that is slow, for example through a jumphost, raise
`conn_timeout` and `banner_timeout` together. `conn_timeout` bounds the whole
handshake, banner included, and `banner_timeout` bounds the banner on its own,
so raising only one gains a few seconds at most.

`timeout` has no effect inside `optional_args` on the SSH drivers: NAPALM
drops it there. The target's own `timeout`, beside `hostname`, applies to most
API and NETCONF drivers (not `aruba_aoscx` or `paloalto_panos`) and to `iosxr`
as its per-command wait, but not to the other SSH drivers.

## iosxr_netconf

`iosxr_netconf` reads `port` (830 by default), `key_file`, `ssh_config_file`,
`config_lock` and `config_encoding`, and passes every other key to its NETCONF
client, ncclient, which accepts only its own (such as `hostkey_verify`,
`look_for_keys`, `allow_agent` and `keepalive`) and refuses the rest. `timeout`
and most Netmiko keys, such as `read_timeout_override`, `conn_timeout`,
`banner_timeout`, `secret` or `use_keys`, therefore stop it from connecting.
By default it is one of the drivers tried when a target has no `driver`, so set
`driver` on a target that uses those keys, or leave `iosxr_netconf` out of
`discovery_drivers`.

## Driver-specific keys

| Driver | Key | Default | What it does |
|:-------|:----|:--------|:-------------|
| `aruba_aoscx` | `verify_ssl` | `false` | Verify the switch's TLS certificate on API requests. The login, which sends the credentials, is never verified. |
| `aruba_osswitch` | `api` | `v6` | REST API version in the URL. |
| | `ssl` | `true` | Use HTTPS. `false` uses HTTP. |
| | `port` | protocol default | REST API port. |
| | `ssl_verify` | `true` | Verify the switch's TLS certificate. |
| | `disable_ssl_warnings` | `false` | Silence the warning for an unverified certificate. |
| `ciena_saos` | `saos_version` | `"6"` | Set to `"10"` for SAOS 10. |
| `cisco_asa` | `port` | 443 | REST API port. |
| | `ssl_verify` | `false` | Verify the firewall's TLS certificate. |
| `huawei_vrp` | `transport` | `ssh` | `ssh` or `telnet`. With `telnet` the default port is 23. |
| `nokia_sros` | `port` | 830 | NETCONF port. |
| | `hostkey_verify` | `false` | Verify the router's SSH host key. `host_key_verify` is accepted too. |
| `paloalto_panos` | `api_key` | none | XML API key, used instead of the username and password. |

The core NAPALM drivers (`ios`, `iosxr`, `iosxr_netconf`, `nxos`, `nxos_ssh`,
`eos` and `junos`) also take the keys in
[NAPALM's list](https://napalm.readthedocs.io/en/latest/support/#list-of-supported-optional-arguments),
such as `transport` for `eos` and `canonical_int` for `ios`.
