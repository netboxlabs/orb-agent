# Git

With the Git config manager, the Orb agent reads its policies from a Git repository instead of from its own configuration file. One repository can hold policies for many agents. Each agent picks the policies meant for it by matching its labels, and picks up changes when you push them.

## How it works

1. The agent starts and reads `agent.yaml`, which sets its labels, its backends and the repository to use.
2. It clones the repository and reads `selector.yaml` from the root.
3. It finds every selector that matches its labels, and applies the policies in the files those selectors list.
4. On the `schedule` you set, it checks the repository for new commits. If `selector.yaml` or one of its policy files changed, it applies the new and changed policies, and removes any it no longer matches.

Without a `schedule`, the agent reads the repository once, at startup.

## Git and agent.yaml responsibilities

Only policies come from Git. Everything else stays in `agent.yaml` on the agent's host, and changes to it need a restart.

| Setting | Where it lives | Why |
|:--|:--|:--|
| `orb.config_manager` | `agent.yaml` | The agent needs it before it can reach Git. |
| `orb.backends` | `agent.yaml` | Backends are set up at startup. |
| `orb.labels` | `agent.yaml` | Labels identify the agent to `selector.yaml`. |
| Diode `target`, `client_id`, `client_secret` | `agent.yaml`, using environment variables | Credentials must not be committed to Git. |
| `selector.yaml` | Git | Maps agent labels to policy files. |
| Policy files | Git | Applied according to `selector.yaml`. |

## Set up the repository

The repository needs a `selector.yaml` file in its root, and one or more policy files anywhere in the repository:

```text
.
├── selector.yaml
├── policy1.yaml
├── folder2
│   ├── policy2.yaml
│   └── folder3
│       └── policy3.yaml
└── folder4
    └── policy4.yaml
```

### `selector.yaml`

Each entry in `selector.yaml` pairs a set of labels with a list of policy files:

```yaml
eu_agents:
  selector:
    region: EU
    pop: ams02
  policies:
    policy1:
      path: policy1.yaml
    policy2:
      enabled: false
      path: folder2/policy2.yaml
us_agents:
  selector:
    region: US
    pop: nyc02
  policies:
    policy1:
      path: policy1.yaml
    policy3:
      path: folder2/folder3/policy3.yaml
all_agents:
  selector:
  policies:
    policy4:
      path: folder4/policy4.yaml
```

- **`selector`** matches an agent when every label it lists has the same value in the agent's `orb.labels`. The agent can have other labels too. An empty selector matches every agent.
- **`policies`** lists policy files by `path`, relative to the repository root. The key above each `path`, such as `policy1`, is only a label for you to read; the agent doesn't use it.
- **`enabled: false`** skips a file. Files are enabled by default.

An agent can match several entries. It applies the files from all of them.

### Policy files

A policy file groups policies by backend, in the same format as `orb.policies` in `agent.yaml`:

```yaml
device_discovery:
  discovery_1:
    config:
      schedule: "* * * * *"
      defaults:
        site: New York NY
    scope:
      - driver: ios
        hostname: 192.168.0.5
        username: admin
        password: ${PASS}
```

- **The policy name is the key under the backend**, here `discovery_1`. The agent uses it in status and telemetry.
- **Names must be unique per backend, across all files an agent matches.** If two files define `discovery_1` for `device_discovery`, the agent applies neither.
- **The agent must have each backend enabled.** A file with `device_discovery` policies fails on an agent without `device_discovery` under `backends`.

## Configure the agent

Set `config_manager.active` to `git`, and give the repository's details under `sources.git`. This example reads a public repository every five minutes:

```yaml
orb:
  labels:
    region: EU
    pop: ams02
  config_manager:
    active: git
    sources:
      git:
        url: "https://github.com/myorg/policyrepo"
        branch: main
        schedule: "*/5 * * * *"
  backends:
    network_discovery:
    device_discovery:
```

| Parameter | Type | Required | Description |
|:--|:--|:--|:--|
| `url` | string | Yes | Repository URL. |
| `branch` | string | No | Branch to read. Defaults to the repository's default branch. |
| `schedule` | cron | No | How often to check for changes. If unset, the repository is read once at startup. |
| `auth` | string | No | `basic`, `ssh` or `github_app`. Omit for a public repository. |
| `username` | string | No | Username for `basic`. |
| `password` | string | No | Password or token for `basic`, or the key passphrase for `ssh`. |
| `private_key` | string | No | Path to the SSH private key, for `ssh`. |
| `skip_tls` | bool | No | Skip TLS certificate verification, for example with a self-signed certificate. Defaults to `false`. |
| `github_app.client_id` | string | With `github_app` | The app's Client ID. The numeric App ID also works. |
| `github_app.installation_id` | string | With `github_app` | The numeric ID of the app's installation. |
| `github_app.private_key` | string | With `github_app` | Path to the app's `.pem` key, or the key itself. |

## Authentication

Choose the method that matches your repository, and set only the fields that method uses.

### Basic

Use a username with a password or a personal access token, over HTTPS:

```yaml
orb:
  config_manager:
    active: git
    sources:
      git:
        url: "https://github.com/myorg/policyrepo"
        branch: main
        schedule: "*/5 * * * *"
        auth: basic
        username: git-user
        password: ${GIT_TOKEN}
```

### SSH

Use an SSH private key:

```yaml
orb:
  config_manager:
    active: git
    sources:
      git:
        url: "git@github.com:myorg/policyrepo.git"
        branch: main
        schedule: "*/5 * * * *"
        auth: ssh
        private_key: /opt/orb/id_ed25519
        password: ${SSH_PASSPHRASE}  # only if the key has a passphrase
```

If `private_key` is not set, the agent tries to use a running SSH agent instead.

**Create a key pair** and add the public key, `id_ed25519.pub`, to your Git provider:

```sh
ssh-keygen -t ed25519 -f /local/orb/id_ed25519 -N ""
```

:::note
Azure DevOps requires RSA keys. Use `ssh-keygen -t rsa -b 4096` instead.
:::

**Trust the Git server's host key.** The agent checks the server against a `known_hosts` file, to protect against a server impersonating yours. Create the file with `ssh-keyscan`:

```sh
ssh-keyscan github.com > /local/orb/known_hosts         # GitHub
ssh-keyscan gitlab.com > /local/orb/known_hosts         # GitLab
ssh-keyscan ssh.dev.azure.com > /local/orb/known_hosts  # Azure DevOps
```

Then point `SSH_KNOWN_HOSTS` at it when you start the agent. Without it, the agent looks for `~/.ssh/known_hosts`.

```sh
docker run \
  -v /local/orb:/opt/orb \
  -e SSH_KNOWN_HOSTS=/opt/orb/known_hosts \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

### GitHub App

The agent can sign in as a GitHub App instead of as a user. Compared with a personal access token, an app's credentials:

- aren't tied to a person
- can be limited to the policy repository
- expire after an hour; the agent renews them automatically

This method works with github.com, including GitHub Enterprise Cloud. It doesn't work with GitHub Enterprise Server or with GitHub Enterprise Cloud data residency (`*.ghe.com`). For those, use `basic` with a personal access token.

```yaml
orb:
  config_manager:
    active: git
    sources:
      git:
        url: "https://github.com/myorg/policyrepo"
        branch: main
        schedule: "*/5 * * * *"
        auth: github_app
        github_app:
          client_id: "Iv23liAbCdEfGhIjKlMn"
          installation_id: "78901234"
          private_key: /opt/orb/github-app.pem
```

#### Create and install the app

1. In GitHub, go to **Settings > Developer settings > GitHub Apps > New GitHub App**. If the policy repository belongs to an organization, do this in the organization's settings.
2. Under **Repository permissions**, set **Contents** to **Read**. The agent needs no other permissions.
3. Under **Webhook**, clear **Active**. The agent checks for changes on its schedule, so it doesn't use webhooks.
4. Create the app. Under **Private keys**, select **Generate a private key**. GitHub downloads a `.pem` file.
5. Select **Install App** and install it on the account that owns the policy repository. Choose **Only select repositories**, and select the policy repository.

#### Find the IDs

- **`client_id`**: the **Client ID** on the app's settings page, which starts with `Iv23li`. The numeric App ID also works for now, but GitHub recommends the Client ID.
- **`installation_id`**: the number at the end of the installation's settings page URL. For `https://github.com/organizations/myorg/settings/installations/78901234`, it's `78901234`.

:::note
A common mistake is to put the App ID or Client ID in `installation_id`. The agent rejects a value that isn't a number when it starts.
:::

#### Provide the private key

Mount the `.pem` file read-only, rather than building it into an image:

```sh
docker run \
  -v /local/orb:/opt/orb \
  -v /local/orb/github-app.pem:/opt/orb/github-app.pem:ro \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

`private_key` can also hold the key itself, so you can supply it from an environment variable or a secrets manager without writing it to disk:

```yaml
        github_app:
          client_id: "Iv23liAbCdEfGhIjKlMn"
          installation_id: "78901234"
          private_key: ${GITHUB_APP_KEY}
          # or, from Vault: ${vault://secret//github-app/pem}
```

The agent accepts PKCS#1 keys (`-----BEGIN RSA PRIVATE KEY-----`, which GitHub issues) and PKCS#8 keys (`-----BEGIN PRIVATE KEY-----`). It doesn't accept keys with a passphrase. Remove the passphrase first:

```sh
openssl rsa -in key.pem -out key-decrypted.pem
```

The agent never logs the private key or its access tokens.

#### How tokens are renewed

The agent gets an access token when it starts, so a wrong ID or an unreadable key stops it right away with a specific error. Tokens last one hour, and the agent gets a new one when less than five minutes remain. You don't need to rotate anything.

:::note
With `github_app`, `skip_tls: true` also turns off certificate checks for GitHub's token service, not only for the repository.
:::

#### Troubleshooting GitHub App sign-in

| Error | Likely cause |
|:--|:--|
| `GitHub rejected the app JWT (HTTP 401…)` | The host's clock is wrong, or `client_id` doesn't match the private key. The error shows GitHub's time and the agent's time, so you can compare them. |
| `installation … was not found (HTTP 404…)` | `installation_id` holds the App ID, or the app was uninstalled. |
| `GitHub refused the token request (HTTP 403…)` | The app is suspended, blocked by an organization policy, or rate limited. |
| Clone fails with 404 after the token is issued | The app is installed on the account, but the policy repository wasn't selected. |
| `holds an OpenSSH key, not a GitHub App key` | `private_key` points to an SSH key instead of the app's `.pem` file. |

## Keep secrets out of Git

Don't commit credentials to the repository. That includes Diode secrets, device passwords and API tokens.

- **In `agent.yaml`,** use `${VAR}` placeholders, as in the examples above.
- **In policy files,** whether `${VAR}` works depends on the backend. Device discovery accepts it in any `scope` or `defaults` value. SNMP discovery accepts it only in credential fields. Network discovery doesn't accept it. See [Environment variables in the file](agent_yaml.md#environment-variables-in-the-file).
- **Anywhere else,** use a [secrets manager](agent_yaml.md#orbsecrets_manager).

## Example

This setup gives one agent in Amsterdam a device discovery policy.

`agent.yaml`, on the agent's host:

```yaml
orb:
  labels:
    region: EU
    pop: ams02
  config_manager:
    active: git
    sources:
      git:
        url: "https://github.com/myorg/policyrepo"
        schedule: "*/5 * * * *"
        branch: main
        auth: basic
        username: git-user
        password: ${GIT_TOKEN}
  backends:
    common:
      diode:
        target: grpc://192.168.0.100:8080/diode
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
        agent_name: agent-eu-ams02
    device_discovery:
```

`selector.yaml`, in the repository:

```yaml
eu_agents:
  selector:
    region: EU
    pop: ams02
  policies:
    ams02_devices:
      path: policies/eu-ams02.yaml
```

`policies/eu-ams02.yaml`, in the repository:

```yaml
device_discovery:
  discovery_1:
    config:
      schedule: "0 * * * *"
      defaults:
        site: Amsterdam AMS02
        role: switch
    scope:
      - driver: ios
        hostname: 192.168.10.5
        username: admin
        password: ${DEVICE_PASS}
```

The agent's labels match `eu_agents`, so it applies `discovery_1` from `policies/eu-ams02.yaml`. `DEVICE_PASS` comes from the environment on the agent's host, so the password is never stored in Git.

## Troubleshooting

| Error | Cause |
|:--|:--|
| `selector.yaml not found in repository root` | The repository, or the branch you set, has no `selector.yaml` at its root. |
| `no policies match the selector; skipping policy application` | No selector matches the agent's labels, and no `schedule` is set. With a `schedule`, the agent keeps checking instead. |
| `policy file not found: <path>` | A `path` in `selector.yaml` doesn't exist in the repository. |
| `backend not found: <backend>` | A policy file has policies for a backend that isn't enabled in `agent.yaml`. |
| `policy already exists for backend: <name>` | Two matched files define a policy with the same name for the same backend. |
