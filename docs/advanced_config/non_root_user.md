# Running as a Non-Root User

The Orb agent container image, `netboxlabs/orb-agent`, runs as root by default. If your security policy does not allow containers to run as root, you can run the agent as another user ID (UID) instead.

This mostly works the same as if run with a non-root user: device discovery over direct SSH, SNMP discovery, and network discovery's default scan. 

However, a few features need root, a named user, or a writable home directory. 

## Features that need root

Check this list before you switch. If you use any of these features, keep running the agent as root.

| Feature | Why it needs root |
|:--|:--|
| `pktvisor` | Packet capture needs privileges that a non-root user does not have. |
| Some network discovery scans | With no `scan_types` set, nmap runs a TCP connect scan. This works as a non-root user. SYN and other raw scan types, and `os_detection`, need raw sockets and fail. |
| SNMP traps on a port below 1024, with host networking | SNMP traps usually arrive on port 162. With `--net=host`, the host's `net.ipv4.ip_unprivileged_port_start` setting decides whether a non-root user can listen on a port that low. If it can't, listen on port 1024 or higher, or keep root. Docker's default bridge network has no such limit. |

:::note

Rootless Podman is a different case: nmap runs as root there, but without raw sockets. See [Rootless Podman Deployment](../backends/network_discovery.md#rootless-podman-deployment).

:::

## Run the agent as another user

Set the UID, and optionally the group ID, when you start the container. These examples use `1000:1000`.

With `docker run`:

```sh
docker run --user 1000:1000 --net=host \
  -v /local/orb:/opt/orb \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

With Docker Compose:

```yaml
services:
  orb-agent:
    image: netboxlabs/orb-agent:latest
    user: "1000:1000"
    volumes:
      - ./orb:/opt/orb
    command: run -c /opt/orb/agent.yaml
```

The UID does not need to exist in the container. A bare UID is enough unless you use SSH config files or install packages at startup, both described below.

## Give the user access to its files

Everything in the image under `/opt/orb` is owned by root, so mount a directory there that the UID owns. The UID must be able to:

- **Read** the agent configuration file, and any file a policy points to, such as an SSH config file or a private key.
- **Write** to `/opt/orb/files`, where the agent stores files delivered by Fleet. Set `files_manager.root` to use another directory.
- **Write** to the dry-run output directory, if `dry_run` is enabled.
- **Write** to its home directory, if it needs one (see below).

For example, to prepare the host directory used in the `docker run` example above:

```sh
sudo mkdir -p /local/orb
sudo chown -R 1000:1000 /local/orb
```

## SSH config files

SSH config files need a named user. 

A device discovery target that sets `optional_args.ssh_config_file`, for example to reach devices through a jumphost, needs the UID to have an entry in `/etc/passwd`. See [SSH Configuration](../backends/device_discovery/ssh.md). Without one, you'll see one of these errors:

- `No username set in the environment`, from the SSH config parser
- `No user exists for uid`, from the OpenSSH client when it runs a `ProxyJump` hop

Setting the `USER` environment variable fixes the first error but not the second. Give the UID a passwd entry instead.

On a Linux host, the simplest way is to mount the host's user database read-only, and set `HOME` to a directory the UID can write:

```yaml
services:
  orb-agent:
    image: netboxlabs/orb-agent:latest
    user: "1000:1000"
    environment:
      HOME: /opt/orb/home
    volumes:
      - /etc/passwd:/etc/passwd:ro
      - /etc/group:/etc/group:ro
      - ./orb:/opt/orb
    command: run -c /opt/orb/agent.yaml
```

Make `./orb` and `./orb/home` writable by the UID before you start the container. Alternatively, build your own image from `netboxlabs/orb-agent` that adds the user with `adduser`.

OpenSSH stores `known_hosts` in the home directory from the passwd entry, not in `HOME`. With the host's passwd file mounted, that is the user's home directory on the host, which usually does not exist in the container. Set `UserKnownHostsFile` in your SSH config to a writable path, such as `/opt/orb/home/known_hosts`.

Private keys must be owned by the UID the agent runs as, with mode `600` or `400`. See [SSH Key Permissions](../backends/device_discovery/ssh.md#ssh-key-permissions).

## Installing drivers or workers at startup

`INSTALL_DRIVERS_PATH` and `INSTALL_WORKERS_PATH` install Python packages when the container starts.

A non-root user cannot write to the image's Python packages directory, so pip installs into `$HOME/.local` instead. Set `HOME` to a directory the UID can write. Otherwise, the installation fails and the agent does not start.

When the agent runs as a non-root user, it prints these lines at startup:

```text
gzip: asn.mmdb: Permission denied
gzip: city.mmdb: Permission denied
```

You can ignore these. They come from unpacking GeoIP databases that only `pktvisor` uses. If you need `pktvisor`, you should not be running as a non-root user anyway. 

pip may also warn that its cache directory is not writable. You can ignore that warning too.
