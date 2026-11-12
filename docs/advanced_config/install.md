# Install and Run the Agent

The Orb agent runs as a Docker container. It is a long-running process and stays up and runs each policy on the schedule set for it, rather than exiting after one discovery run.

:::note[Before you begin]

Before you begin, review [Getting started](../../getting-started.md) for information on finding your Diode credentials and creating your first `agent.yaml`

:::

## 1. Get the Docker image

The image is published on [Docker Hub](https://hub.docker.com/r/netboxlabs/orb-agent):

```sh
docker pull netboxlabs/orb-agent:latest
```

Each release is also tagged with its version number, for example `netboxlabs/orb-agent:2.17.0`.

## 2. Prepare the configuration

The image contains only the agent itself. You will need to create two files that tell the agent what to do: 


- **`agent.yaml`**

  The agent's configuration file. It sets which backends to run, how to reach Diode, and the policies that say what to discover and when. The agent won't start without it. For more information, see [Agent Configuration File](../configs/agent_yaml.md) and [Environment-Driven Configuration](../configs/env_config.md)

- **`.env`**

  Environment variables for the container, such as your Diode credentials. Keeping secrets here, rather than in `agent.yaml`, means you can share or version the configuration file safely.

Put both files in one directory on the host, for example `/local/orb`. The commands on this page mount that directory into the container at `/opt/orb`, which is where the agent looks for `agent.yaml`.

### `agent.yaml`

This file runs network discovery on one subnet every two hours and sends the results to Diode:

```yaml
orb:
  backends:
    common:
      diode:
        target: grpc://diode.example.com:8080/diode
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
        agent_name: agent01
    network_discovery:
  policies:
    network_discovery:
      office_scan:
        config:
          schedule: "0 */2 * * *"
        scope:
          targets: [192.168.1.0/24]
```

Set `target` to your Diode endpoint. `${DIODE_CLIENT_ID}` and `${DIODE_CLIENT_SECRET}` are filled in from the environment when the agent starts.

For every key the file supports, see [Agent Configuration File](../configs/agent_yaml.md). For complete examples with other backends, see [Configuration Samples](../config_samples.md).

### `.env`

```sh
DIODE_CLIENT_ID=your-client-id
DIODE_CLIENT_SECRET=your-client-secret
```

Write the values without quotes. Docker reads them literally, so quotes would become part of the value.

## 3. Test in the foreground

Run the agent in the foreground to check a new `agent.yaml` while you watch the logs:

```sh
docker run --net=host \
  -v /local/orb:/opt/orb/ \
  --env-file /local/orb/.env \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

Add `-d` after `run` for debug logging. Press Ctrl+C to stop the agent.

With Podman:

```sh
podman run --privileged --net=host \
  -v /local/orb:/opt/orb/ \
  --env-file /local/orb/.env \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

:::note

Network discovery sends ICMP and TCP packets, so the container needs host networking or root. The image runs as root by default. To run as another user, or with rootless Podman, see [Running as a Non-Root User](non_root_user.md) and [Rootless Podman deployment](../backends/network_discovery.md#rootless-podman-deployment).

:::

## 4. Run as a service

Once the configuration works, start the agent detached and with a restart policy:

```sh
docker run -d --name orb-agent --restart unless-stopped \
  --stop-timeout 60 \
  --log-driver local \
  --net=host \
  -v /local/orb:/opt/orb/ \
  --env-file /local/orb/.env \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

Where:

| Option | What it does |
|:--|:--|
| `-d` and `--name orb-agent` | Runs the container in the background, with a name you can use in later commands. |
| `--restart unless-stopped` | Restarts the agent if it crashes or the host reboots, unless you stopped it yourself. |
| `--stop-timeout 60` | Gives the agent 60 seconds to shut down. It stops its backends one at a time and finishes policy runs in progress, which can take longer than Docker's default of 10 seconds. |
| `--log-driver local` | Rotates the logs. Docker's default `json-file` driver never rotates them, so an agent that runs for months can fill the disk. The `local` driver keeps five compressed files of 20 MB each. |
| `--env-file` | Reads environment variables, such as Diode credentials, from a file. See [Environment-Driven Configuration](env_config.md). |

### Start the container runtime at boot

The container runtime applies the restart policy, so it must start when the host boots.

**Docker**

For Docker, enable the Docker daemon:

```sh
sudo systemctl enable --now docker
```

**Podman**

Podman has no daemon. Instead, a separate unit restarts containers at boot:

```sh
sudo systemctl enable --now podman-restart.service
```

For rootless Podman, enable the unit for your user. Then let your services run when you aren't logged in:

```sh
systemctl --user enable --now podman-restart.service
sudo loginctl enable-linger "$USER"
```

:::note

Podman treats `unless-stopped` the same as `always`. A container you stopped by hand still starts again after a reboot.

:::

### Docker Compose

If you use Docker Compose, you can write the options from the `docker run` command above into a file instead. 

Create a file named `compose.yaml`, for example in `/local/orb` next to `agent.yaml`, with this content:

```yaml
services:
  orb-agent:
    image: netboxlabs/orb-agent:latest
    command: run -c /opt/orb/agent.yaml
    restart: unless-stopped
    stop_grace_period: 60s
    network_mode: host
    logging:
      driver: local
    volumes:
      - /local/orb:/opt/orb/
    env_file:
      - /local/orb/.env
```

Then start the agent from the directory that holds `compose.yaml`:

```sh
docker compose up -d
```
:::warning

Use either Compose or the `docker run` command, not both. Running both starts two agents, and the second one fails because the first is already using the backend ports.

You can also wrap the container in your own systemd unit, if that fits your environment better.

:::

## Basic commands

| Task | Command |
|:--|:--|
| Follow the logs | `docker logs -f orb-agent` |
| Apply a change to `agent.yaml` | `docker restart orb-agent` |
| Stop the agent | `docker stop orb-agent` |
| Start it again | `docker start orb-agent` |

## Upgrade the agent

1. Pull the new image, either `latest` or a new version tag:

   ```sh
   docker pull netboxlabs/orb-agent:latest
   ```

2. Stop and remove the old container:

   ```sh
   docker stop orb-agent && docker rm orb-agent
   ```

3. Run the same `docker run` command as before. If you use a version tag, change it to the new one.

With Docker Compose, update the tag if needed, then run `docker compose pull` and `docker compose up -d`.

:::note

Don't use `docker rm -f` to remove a running agent. It kills the agent immediately, without letting it shut down its backends.

:::
