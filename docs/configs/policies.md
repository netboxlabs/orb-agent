# Policies

A policy tells one of the Orb agent's backends what to do and when. For example, a network discovery policy might scan two subnets every four hours, and a device discovery policy might connect to a set of switches once a day.

Backends do nothing until they have a policy. An agent can run many policies at once, across several backends.

## Where policies are defined

You can keep policies in `agent.yaml` or in a Git repository. You set this in [`orb.config_manager.active` in `agent.yaml`](agent_yaml.md#orbconfig_manager):

- **[`local`](local.md)**
  Policies are in the `policies` section of `agent.yaml`. This is the default, so you can leave out `config_manager` entirely.
- **[`git`](git.md)**
  Policies are in files in a Git repository. The agent ignores the `policies` section of `agent.yaml`.

In both cases, a policy looks the same.

## Policy structure

Policies are grouped under the backend that runs them. Each key beneath a backend is the name of one policy:

```yaml
orb:
  policies:
    network_discovery:          # The backend that runs these policies
      office_scan:              # The policy name
        config:                 # How the policy runs
          schedule: "0 */4 * * *"
          defaults:
            site: New York NY
        scope:                  # What the policy discovers
          targets:
            - 192.168.1.0/24
            - 10.0.10.0/24
      lab_scan:                 # A second policy for the same backend
        scope:
          targets: [10.0.99.0/24]
```

Each backend you write policies for must also be turned on under `backends` in `agent.yaml`. With policies in `agent.yaml`, the agent otherwise stops with `backend not found`.

Most policies have two parts:

- **`config`**
  How the policy runs. Typically this includes when it runs (`schedule`), the `defaults` to apply in NetBox, and backend-specific options such as timeouts.
- **`scope`**
  What the policy works on. For discovery backends, this is the list of targets, such as subnets, IP addresses or devices, along with any credentials needed to reach them.

The pktvisor and OpenTelemetry Infinity backends use their own policy formats. For details, see [pktvisor](../backends/pktvisor/README.md#policy-structure) and [OpenTelemetry Infinity](../backends/opentelemetry_infinity.md#policies).

## Policy schedule

For network discovery, device discovery, SNMP discovery and the worker, `config.schedule` decides when the policy runs:

- **With a schedule**
  The policy runs each time the schedule comes round. It doesn't run when it's first applied, so the first run happens at the next scheduled time.
- **Without a schedule**
  The policy runs once, about a second after it's applied, and then stops.

A schedule is a standard five-field cron expression. 

| Schedule | Runs |
|:--|:--|
| `"*/30 * * * *"` | Every 30 minutes |
| `"0 */4 * * *"` | Every four hours, on the hour |
| `"0 2 * * *"` | Every day at 02:00 |
| `"0 6 * * 1"` | Every Monday at 06:00 |

Quote the expression, because YAML treats a value that starts with `*` as special.

If a run is still going when the next one is due, the agent skips that run rather than starting a second copy. Schedules use the container's clock, which is UTC unless you change it.

:::note
gNMI discovery and the telemetry backends don't use `schedule`. They stay connected to their targets and collect data at an interval that you set in `config`, such as `metrics_interval` for SNMP telemetry and gNMI telemetry.
:::

## Defaults

Discovery policies can set `defaults` under `config`. These are values the backend adds to the objects it creates in NetBox, for fields that discovery can't find out for itself. Examples are the site a device belongs to, or tags for every discovered IP address:

```yaml
config:
  defaults:
    site: New York NY
    tags: [discovered, office]
```

Device discovery, SNMP discovery and gNMI discovery also let you override the defaults for a single target, with `override_defaults` on that target. For example, a policy can put most devices in one site and one device in another.

The supported defaults differ between [backends](#policy-settings-for-each-backend). See the backend's page.

## Credentials in policies

Policies often need credentials, such as device passwords or SNMP communities. To keep them out of the policy, use one of these:

- **A secrets manager**
  Refer to a secret with a placeholder such as `${vault://secret//devices/password}`. The agent fetches the value from the secrets store. See [Secrets managers](../secretsmgr/README.md).
- **An environment variable**
  Some backends replace `${VAR}` with the environment variable `VAR`. Which values support this depends on the backend. See [Where placeholders work](../advanced_config/env_config.md#where-placeholders-work).

## Policy names

The agent uses the name exactly as written, in backend status and in telemetry.

- **Any characters except `/`.** Spaces, `#`, `?`, `%` and non-ASCII characters all work. A policy whose name contains `/` fails to apply.
- **Unique within a backend.** A duplicate name is a YAML error, and the agent rejects the whole file.
- **Best kept unique across backends.** If two backends have a policy with the same name, their telemetry can be mixed up.

Choose names that say what the policy does, such as `ams02_core_switches`. They appear in logs, so a clear name makes problems easier to trace.

## Changing and removing policies

How a change takes effect depends on where the policies are kept:

- **Local**
  The agent reads `agent.yaml` once, at startup. Edit the file, then restart the agent.
- **Git**
  The agent checks the repository on its schedule. It applies new and changed policies, and stops policies that were removed or no longer match the agent's labels. You don't need to restart it.

A changed policy starts again from the beginning. With a schedule, its next run is at the next scheduled time. Without one, it runs once more.

## Policy settings for each backend

| Backend | Runs on | Scope contains |
|:--|:--|:--|
| [Network discovery](../backends/network_discovery.md#policy) | `schedule` | IP addresses, ranges, subnets or hostnames to scan, plus nmap options |
| [Device discovery](../backends/device_discovery/README.md#policy) | `schedule` | Devices to connect to, with their driver and credentials |
| [SNMP discovery](../backends/snmp_discovery/README.md#policy) | `schedule` | Devices to query, with SNMP credentials |
| [Worker](../backends/worker.md#policy) | `schedule` | Whatever your custom worker package expects |
| [gNMI discovery](../backends/gnmi_discovery.md#policy) | Continuous subscription | Devices to subscribe to, with credentials and TLS settings |
| [SNMP telemetry](../backends/snmp_telemetry.md#policy) | `metrics_interval`, or incoming traps | Devices to poll, with SNMP credentials |
| [gNMI telemetry](../backends/gnmi_telemetry.md#policy) | `metrics_interval` | Devices to subscribe to, with credentials and TLS settings |
| [pktvisor](../backends/pktvisor/README.md#policy-structure) | Continuous | Its own format |
| [OpenTelemetry Infinity](../backends/opentelemetry_infinity.md#policies) | Continuous | Its own format |

For complete policy examples, see [Configuration Samples](../config_samples.md).
