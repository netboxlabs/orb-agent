# Running Orb Agent as a Service

Orb Agent is a **long-running process**. It stays resident and executes each policy on the `schedule` (a cron expression) defined for it, so the container is expected to remain up between discovery runs rather than exiting after one.

The `docker run` commands in the [README](../../README.md#running-the-agent) and the [configuration samples](../config_samples.md) run the agent in the foreground, which is useful for validating a new `agent.yaml` while watching the logs. For an ongoing deployment the agent should be started detached and restarted automatically, so that no interactive session has to stay logged in and the agent returns after a crash or a host reboot.

This guide covers three ways to do that. They are alternatives, not steps: pick one.

## Prerequisite: the container runtime must restart containers at boot

A container restart policy is enforced by the container runtime, so the runtime has to be configured to act on it at boot. Without this the agent will not come back after a reboot no matter which option below is used.

### Docker

Enabling the Docker daemon is sufficient; it restarts containers according to their restart policy when it starts.

```sh
sudo systemctl enable --now docker
```

### Podman

Podman has no long-running daemon, so restart policies are applied at boot by a separate unit, `podman-restart.service`. Enabling `podman.socket` does **not** do this: that socket only provides the Podman API.

```sh
sudo systemctl enable --now podman-restart.service
```

For rootless Podman, enable the unit for the user and allow the user's services to run without an active login session:

```sh
systemctl --user enable --now podman-restart.service
sudo loginctl enable-linger "$USER"
```

> **Podman treats `unless-stopped` as a synonym for `always`.** Every released Podman version documents the policy that way, so unlike Docker, a container stopped by hand before a reboot is started again by `podman-restart.service`. To take the agent down for maintenance on Podman, disable the restart path rather than relying on the policy, or use the [Quadlet](#podman-quadlet) approach where systemd owns the lifecycle. Podman's development documentation has since changed this, so check `podman run --help` for the version in use.

Alternatively, skip this unit entirely and use the [Quadlet](#podman-quadlet) approach below, where systemd starts the container directly. That section has both a rootful and a rootless variant; the rootless one still needs lingering enabled.

## Option 1: Detached container with a restart policy

The smallest change to the foreground command: add `-d` to detach and `--restart` to have the runtime bring the container back.

```sh
docker run -d --name orb-agent --restart unless-stopped \
  --stop-timeout 60 \
  --net=host \
  -v /local/orb:/opt/orb/ \
  --env-file /local/orb/.env \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

The same flags work with `podman run`.

### Why `--stop-timeout`

The agent stops its backends one at a time. Only once every backend is down does it finalize in-flight policy runs and stop the config manager. The discovery backends (`network_discovery`, `snmp_discovery`, `device_discovery`, `gnmi_discovery`) and `worker` each allow their process 5 seconds to exit after `SIGTERM` before escalating to `SIGKILL`, so with several of them enabled the teardown can take longer than Docker's default 10 second stop timeout. The agent is then killed partway through, leaving policy runs unfinalized.

Raising the timeout gives the sequence room to complete. 60 seconds covers any combination of those backends, and the agent exits as soon as it is done, so a generous value costs nothing in the common case.

> **The `pktvisor` and `opentelemetry_infinity` backends are not bounded this way.** Their stop path waits for the process to exit without a timeout of its own. If one of those processes does not exit on `SIGTERM`, no `--stop-timeout` value will produce a clean shutdown: the runtime's timer expires and the container is killed with policy runs unfinalized. Raising the timeout is still worthwhile, but treat clean shutdown as best effort when either backend is enabled.

### Choosing a restart policy

| Policy | Restarts after a crash | Restarts after a host reboot | Notes |
|--------|------------------------|------------------------------|-------|
| `unless-stopped` | Yes | Yes, unless it was stopped manually | Recommended. A container taken down for maintenance stays down across a reboot. On Podman this policy behaves like `always`; see [Podman](#podman) above. |
| `always` | Yes | Yes, always | Use when the agent must come back even if someone stopped it by hand. |
| `on-failure` | Only on a non-zero exit | No | Not recommended here: the agent will not survive a reboot. |

### Managing the agent

```sh
docker logs -f orb-agent          # tail the logs
docker restart orb-agent          # apply a change to agent.yaml
docker stop orb-agent             # take it down (unless-stopped keeps it down)
docker start orb-agent            # bring it back
```

To update to a newer image, pull and recreate the container:

```sh
docker pull netboxlabs/orb-agent:latest
docker stop orb-agent
docker rm orb-agent
# re-run the docker run command above
```

Use `docker stop` rather than `docker rm -f`: the latter sends `SIGKILL` immediately, bypassing the stop timeout and leaving any in-flight policy runs unfinalized.

### Log rotation

A long-running container accumulates logs indefinitely under Docker's default JSON file driver. Cap them so the agent cannot fill the host's disk:

```sh
docker run -d --name orb-agent --restart unless-stopped \
  --stop-timeout 60 \
  --log-opt max-size=10m --log-opt max-file=3 \
  --net=host \
  -v /local/orb:/opt/orb/ \
  --env-file /local/orb/.env \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

## Option 2: Docker Compose

Compose keeps the run configuration in a file that can be version-controlled and reviewed, rather than in a shell history. Create `docker-compose.yaml` next to your `agent.yaml`:

```yaml
services:
  orb-agent:
    image: netboxlabs/orb-agent:latest
    container_name: orb-agent
    restart: unless-stopped
    stop_grace_period: 60s
    network_mode: host
    volumes:
      - /local/orb:/opt/orb
    env_file: /local/orb/.env
    command: run -c /opt/orb/agent.yaml
    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: "3"
```

```sh
docker compose up -d          # start
docker compose logs -f        # tail the logs
docker compose restart        # apply a change to agent.yaml
docker compose pull && docker compose up -d   # update to a newer image
docker compose down           # take it down
```

## Option 3: systemd unit

Use this when the agent should be managed alongside the host's other services, so that `systemctl status orb-agent` and `journalctl -u orb-agent` work as an operator would expect.

Run the container in the **foreground** here (no `-d`) and with `--rm`, so that systemd owns the process and supervises it directly. Delegating the restart to both systemd and a container restart policy at once produces confusing behavior, so the container gets no `--restart` flag.

Create `/etc/systemd/system/orb-agent.service`:

```ini
[Unit]
Description=NetBox Labs Orb Agent
After=docker.service
Requires=docker.service

[Service]
Restart=always
RestartSec=10
TimeoutStartSec=0
TimeoutStopSec=90
ExecStartPre=-/usr/bin/docker rm -f orb-agent
ExecStart=/usr/bin/docker run --rm --name orb-agent \
  --log-opt max-size=10m --log-opt max-file=3 \
  --net=host \
  -v /local/orb:/opt/orb/ \
  --env-file /local/orb/.env \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
ExecStop=/usr/bin/docker stop -t 60 orb-agent

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now orb-agent
sudo systemctl status orb-agent
sudo journalctl -u orb-agent -f
```

Note that the agent's output is stored twice here: systemd captures the attached output into the journal, and the Docker daemon separately writes it through its default `json-file` driver, which does not rotate on its own. The `--log-opt` flags above cap the second copy. To keep only the journal's copy, add `--log-driver none` instead, at the cost of `docker logs` no longer working for this container.

### Podman (Quadlet)

Podman can generate the unit rather than having it written by hand. On Podman 4.4 and later, use [Quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html): drop a `.container` file in a directory systemd reads, and the service is generated at boot.

Where that file goes, and which systemd instance manages it, differs between rootful and rootless Podman. Using the rootful path as a rootless user creates a system-level container owned by root, not the user's own.

#### Rootful

Create `/etc/containers/systemd/orb-agent.container`:

```ini
[Unit]
Description=NetBox Labs Orb Agent

[Container]
Image=docker.io/netboxlabs/orb-agent:latest
ContainerName=orb-agent
Network=host
Volume=/local/orb:/opt/orb:Z
EnvironmentFile=/local/orb/.env
StopTimeout=60
Exec=run -c /opt/orb/agent.yaml

[Service]
Restart=always
RestartSec=10
TimeoutStopSec=90

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl start orb-agent
sudo systemctl status orb-agent
sudo journalctl -u orb-agent -f
```

#### Rootless

Create `~/.config/containers/systemd/orb-agent.container` (that is `$XDG_CONFIG_HOME/containers/systemd/`). The unit is the same except for the install target, which is the user manager's `default.target`, and the paths, which must be readable by the user rather than root:

```ini
[Unit]
Description=NetBox Labs Orb Agent

[Container]
Image=docker.io/netboxlabs/orb-agent:latest
ContainerName=orb-agent
Network=host
Volume=%h/orb:/opt/orb:Z
EnvironmentFile=%h/orb/.env
StopTimeout=60
Exec=run -c /opt/orb/agent.yaml

[Service]
Restart=always
RestartSec=10
TimeoutStopSec=90

[Install]
WantedBy=default.target
```

Manage it with the user instance of systemd, and enable lingering so it starts at boot without the user being logged in:

```sh
sudo loginctl enable-linger "$USER"
systemctl --user daemon-reload
systemctl --user start orb-agent
systemctl --user status orb-agent
journalctl --user -u orb-agent -f
```

`%h` expands to the user's home directory, so the same file works for any user.

On Podman versions without Quadlet, generate the unit from an already-running container instead. `--files` only writes `container-orb-agent.service` into the current directory, so it still has to be installed and enabled.

Run the generate step in the same context that owns the container. Rootful and rootless Podman keep separate container stores, so an unprivileged `podman generate systemd` cannot see a container started with `sudo podman`, and vice versa.

Rootful:

```sh
sudo podman generate systemd --new --name orb-agent --files
sudo install -m 644 container-orb-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now container-orb-agent.service
```

Rootless, as the user that owns the container:

```sh
podman generate systemd --new --name orb-agent --files
mkdir -p ~/.config/systemd/user
install -m 644 container-orb-agent.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now container-orb-agent.service
sudo loginctl enable-linger "$USER"
```

Rootless Podman has additional constraints for network discovery; see the [Network Discovery backend documentation](../backends/network_discovery.md#rootless-podman-deployment).

## Handling credentials

Pass Diode credentials and device secrets through an environment file rather than inline on the command line or in the unit file. Command lines are visible to any user via `ps`, and files under `/etc/systemd/system/` are world-readable by default.

Create `/local/orb/.env`:

```sh
DIODE_CLIENT_ID=your-diode-client-id
DIODE_CLIENT_SECRET=your-diode-client-secret
```

Restrict it to the user that runs the agent:

```sh
sudo chmod 600 /local/orb/.env
```

Note that `docker --env-file` does not expand `${...}`, so the file must contain concrete values.

For production deployments, prefer a secrets manager over a file on disk. See the [Secrets Manager documentation](../../README.md#secrets-manager) and the per-provider guides under [`docs/secretsmgr/`](../secretsmgr/).

## Verifying

After starting the agent by any of the above methods, confirm that it is running and that it survives a reboot:

```sh
docker ps --filter name=orb-agent          # or: systemctl status orb-agent
docker logs orb-agent | tail -20
```

The agent logs each policy run as its schedule fires. A policy with `schedule: "*/5 * * * *"` should produce a run within five minutes of startup.
