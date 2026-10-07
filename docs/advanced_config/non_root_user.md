# Running as a Non-Root User

The `netboxlabs/orb-agent` image runs the agent as root by default. It can run as any other user ID instead, with `user:` in Docker Compose or `--user` on `docker run`. That UID does not need an entry in the container's `/etc/passwd` for most of what the agent does: device discovery over SSH, SNMP discovery and network discovery all run unchanged as a bare UID such as `1000:1000`.

A few features depend on the UID having a name, a writable home directory, or root privileges. They are listed below.

## Files and directories

Everything the agent reads must be readable by that UID, and everything it writes must be writable by it:

- the agent configuration and any file a policy points to, such as an SSH config or private key
- the dry-run output directory, when `dry_run` is enabled
- the home directory, when one is needed (see below)

At startup the agent prints two lines like these:

```
gzip: asn.mmdb: Permission denied
gzip: city.mmdb: Permission denied
```

They come from unpacking the GeoIP databases that only the pktvisor backend uses, and are harmless when pktvisor is not configured.

## SSH configuration files need a passwd entry

A device discovery target that sets `optional_args.ssh_config_file`, for example to reach devices through a jumphost (see [SSH Configuration](../backends/device_discovery/ssh.md)), needs the UID to have an entry in `/etc/passwd`:

- the SSH config parser used by device discovery looks up the current user name, and fails with `No username set in the environment`
- the OpenSSH client that runs a `ProxyJump` hop refuses to start with `No user exists for uid`

Setting the `USER` environment variable gets past the first lookup but not the second, so the device still cannot be reached. Give the UID a passwd entry instead, and a home directory it can write, which OpenSSH uses for `known_hosts`. On a Linux host, the simplest way is to mount the host's user database read-only:

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

Create `./orb/home` on the host, owned by that UID, before starting the container. A derived image that adds the user with `adduser` works just as well.

Private keys must be owned by the UID the agent runs as, with mode `600` or `400`. See [SSH Key Permissions](../backends/device_discovery/ssh.md#ssh-key-permissions).

## Installing drivers or workers at startup

`INSTALL_DRIVERS_PATH` and `INSTALL_WORKERS_PATH` install Python packages when the container starts. As a non-root user, pip cannot write to the image's site-packages and installs into `$HOME/.local` instead, so `HOME` must point at a directory the UID can write. Without one, the installation fails and the agent does not start. pip also warns that its cache directory is not writable; the warning is harmless.

## Features that need root or extra privileges

- **Network discovery.** nmap's SYN scans and OS detection need raw sockets. As a non-root user, nmap falls back to TCP connect scans. See [Rootless Podman Deployment](../backends/network_discovery.md#rootless-podman-deployment) for the scan options that work without privileges.
- **pktvisor.** Packet capture needs privileges that a non-root user does not have. Run the agent as root when pktvisor is configured.
- **SNMP traps on a port below 1024.** In Docker's default bridge network, a non-root process can bind any port inside the container. With `--net=host`, binding a port below 1024, such as the conventional trap port 162, depends on the host's `net.ipv4.ip_unprivileged_port_start`. Listen on a higher port, or keep root, if the host does not allow it.
