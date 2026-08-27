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

`podman-restart.service` honors both `always` and `unless-stopped`, and a container explicitly stopped with `podman stop` before the reboot stays down under `unless-stopped`.

Alternatively, skip this unit entirely and use the [Quadlet](#podman-quadlet) approach below, where systemd starts the container directly.

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

The agent stops its backends one at a time, allowing each up to 5 seconds to exit after `SIGTERM` before escalating to `SIGKILL`. Only once every backend is down does it finalize in-flight policy runs and stop the config manager. With several backends enabled, that teardown can take longer than Docker's default 10 second stop timeout, and the agent is killed partway through, leaving policy runs unfinalized.

Raising the timeout gives the sequence room to complete. 60 seconds is comfortable for any supported backend count; the agent exits as soon as it is done, so a generous value costs nothing in the common case.

### Choosing a restart policy

| Policy | Restarts after a crash | Restarts after a host reboot | Notes |
|--------|------------------------|------------------------------|-------|
| `unless-stopped` | Yes | Yes, unless it was stopped manually | Recommended. A container taken down for maintenance stays down across a reboot. |
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
docker rm -f orb-agent
# re-run the docker run command above
```

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

### Podman (Quadlet)

Podman can generate the unit rather than having it written by hand.

On Podman 4.4 and later, use [Quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html): create `/etc/containers/systemd/orb-agent.container` and let systemd generate the service at boot.

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
```

On older Podman versions, `podman generate systemd --new --name orb-agent --files` writes an equivalent unit for an already-running container.

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
