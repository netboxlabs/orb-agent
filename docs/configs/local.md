# Local

The local config manager reads policies directly from the agent config file (`agent.yaml`) under `orb.policies`. No external sources or credentials are required.

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

Policies are loaded once at startup. To apply policy changes, restart the agent with an updated config file.

For the full `agent.yaml` schema — including all top-level keys, backends, secrets manager, and environment variable substitution — see the [Agent Configuration File reference](agent-yaml.md).

