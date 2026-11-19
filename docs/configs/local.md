# Local

With the local config manager, the Orb agent reads its policies from `orb.policies` in its own configuration file, `agent.yaml`. Nothing else is contacted, and no credentials are needed.

Use it when one agent runs a fixed set of policies, or to try the agent out. To manage policies for several agents from one place, use [Git](git.md) instead.

## Example

This file enables device discovery and defines one policy for it:

```yaml
orb:
  config_manager:
    active: local
  backends:
    common:
      diode:
        target: grpc://192.168.0.100:8080/diode
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
        agent_name: agent01
    device_discovery:
  policies:
    device_discovery:
      my_policy:
        config:
          schedule: "0 * * * *"
          defaults:
            site: New York NY
        scope:
          - hostname: 192.168.0.5
            username: admin
            password: ${PASS}
            driver: ios
```

`local` is the default, so you can leave out `config_manager` entirely.

## Rules

- **Define at least one policy.** Otherwise, the agent stops with `no policies specified`.
- **Enable each backend you write policies for.** A policy under `device_discovery` needs a `device_discovery` key under `backends`. Otherwise, the agent stops with `backend not found: device_discovery`.

For how to name policies and what each backend's policy contains, see [`orb.policies`](agent_yaml.md#orbpolicies).

## Changing policies

The agent reads policies once, at startup. To apply a change, edit the file and restart the agent. For example, if the agent runs in a container named `orb-agent`:

```sh
docker restart orb-agent
```
