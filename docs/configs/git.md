# Git
The Git configuration manager outlines a policy management system where an agent fetches policies from a Git repository.

**Important**: The `config_manager` and `backends` sections must still be passed directly to the agent via the config file at startup time. These components are not yet dynamically reconfigurable, so ensure the relevant settings are correctly defined before launching the agent.

### Config

The `config_manager.sources.git` section supports four authentication modes. Pick the snippet that matches your repository and omit the fields you do not use — mixing basic, SSH and GitHub App fields in the same config is not needed.

**Public repository (no auth):**
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
        schedule: "* * * * *"
        branch: develop
  backends:
    network_discovery:
    device_discovery:
```

**Basic authentication** (HTTPS with username + password or personal access token):
```yaml
orb:
  config_manager:
    active: git
    sources:
      git:
        url: "https://github.com/myorg/policyrepo"
        schedule: "* * * * *"
        branch: develop
        auth: basic
        username: git-user
        password: ${GIT_TOKEN}
        skip_tls: false  # optional; set true for self-signed certificates
```

**SSH authentication** (private key):
```yaml
orb:
  config_manager:
    active: git
    sources:
      git:
        url: "git@github.com:myorg/policyrepo.git"
        schedule: "* * * * *"
        branch: develop
        auth: ssh
        private_key: /opt/orb/id_ed25519
        password: ${SSH_PASSPHRASE}  # optional; omit if the key is unprotected
```
See [SSH Authentication](#ssh-authentication) below for the required `known_hosts` setup.

**GitHub App authentication** (short-lived installation tokens, github.com only):
```yaml
orb:
  config_manager:
    active: git
    sources:
      git:
        url: "https://github.com/myorg/policyrepo"
        schedule: "* * * * *"
        branch: develop
        auth: github_app
        github_app:
          app_id: "Iv23liAbCdEfGhIjKlMn"
          installation_id: "78901234"
          private_key: /opt/orb/github-app.pem
```
See [GitHub App Authentication](#github-app-authentication) below for how to create and install the app.

| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| url | string | yes  |  the url of the repository  that contain agent policies  |
| schedule | cron format | no  |  If defined, it will execute fetch remote changes on cron schedule time. If not defined, it will execute the match and apply policies only once  |
| branch | string | no  |  the git branch that should be used by the agent. If not specified, the default branch will be used   |
| auth | string | no | it can be 'basic', 'ssh' or 'github_app'. The basic authentication supports both password or token. If not specified, no auth will be used (public repository) |
| username | string | no | username used for authentication |
| password | string | no | the password used for authentication. If the auth method is 'basic' it should contain the password or auth token. If the method is 'ssh' it should contain the passphrase for the private key file (leave empty for unprotected keys) |
| private_key | string | no | the path to the SSH private key file |
| skip_tls | bool | no | skip TLS certificate verification when connecting to the repository (default: false). Useful for self-signed or private CA certificates |
| github_app.app_id | string | yes, when auth is 'github_app' | the GitHub App's Client ID (preferred) or its numeric App ID |
| github_app.installation_id | string | yes, when auth is 'github_app' | the numeric id of the app's installation on the account that owns the repository |
| github_app.private_key | string | yes, when auth is 'github_app' | the path to the app's `.pem` private key, or the PEM content itself |

## SSH Authentication

When using `auth: ssh`, the agent uses the configured private key to authenticate with the Git server.

### Known Hosts

SSH connections require host key verification to prevent man-in-the-middle attacks. The agent reads known hosts from a file specified by the `SSH_KNOWN_HOSTS` environment variable. If the variable is not set, the agent looks for the standard `~/.ssh/known_hosts` file.

To generate a `known_hosts` file for your Git server:

```bash
# GitHub
ssh-keyscan github.com > /opt/orb/known_hosts

# GitLab
ssh-keyscan gitlab.com > /opt/orb/known_hosts

# Azure DevOps
ssh-keyscan -p 22 ssh.dev.azure.com > /opt/orb/known_hosts

# Any other host
ssh-keyscan your.git.host >> /opt/orb/known_hosts
```

Then pass the file to the container:

```bash
docker run \
  -v /local/orb:/opt/orb \
  -e SSH_KNOWN_HOSTS=/opt/orb/known_hosts \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

### Generating an SSH Key Pair

```bash
ssh-keygen -t ed25519 -f /local/orb/id_ed25519 -N ""
# Then add the contents of /local/orb/id_ed25519.pub to your Git provider's SSH keys
```

> **Note:** Azure DevOps requires RSA keys. Use `ssh-keygen -t rsa -b 4096` instead.

## GitHub App Authentication

When using `auth: github_app`, the agent authenticates as a GitHub App installation rather than as a
user. Compared to a personal access token this gives you a credential that is not tied to a person,
is scoped to exactly the repositories the app is installed on, and is short-lived — the agent mints a
one-hour installation access token and refreshes it automatically.

This mode supports **github.com only**, which includes GitHub Enterprise Cloud (served from
`github.com`). It does **not** support GitHub Enterprise Server or GitHub Enterprise Cloud with data
residency (`*.ghe.com`) — use `auth: basic` with a personal access token for those.

### Creating the App

1. Go to **Settings > Developer settings > GitHub Apps > New GitHub App** (under your organization if
   the policy repo is org-owned).
2. Under **Repository permissions**, grant **`Contents: Read`**. Nothing else is required — the agent
   only reads `selector.yaml` and the policy files, and never writes to the repository.
3. Uncheck **Webhook > Active**; the agent polls on the configured `schedule` and does not receive
   webhooks.
4. Create the app, then under **Private keys** click **Generate a private key**. This downloads a
   PKCS#1 `.pem` file.
5. Click **Install App** and install it on the account that owns the policy repo, choosing **Only
   select repositories** and selecting just that repo.

### Finding the IDs

- **`app_id`** — use the app's **Client ID** (`Iv23li…`), shown on the app's settings page. This is
  the form the GitHub API documentation specifies, and the numeric App ID looks likely to be dropped
  in a future API version. The numeric App ID still works today.
- **`installation_id`** — the number at the end of the URL of the *installation's* settings page,
  e.g. `https://github.com/organizations/myorg/settings/installations/78901234` → `78901234`.
  Putting the App ID or Client ID here is the most common misconfiguration; the agent rejects a
  non-numeric value at startup with a message saying so.

### Supplying the private key

Mount the `.pem` **read-only** and keep it out of the image:

```bash
docker run \
  -v /local/orb:/opt/orb \
  -v /local/orb/github-app.pem:/opt/orb/github-app.pem:ro \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

`private_key` accepts either a path or the PEM content itself, so the key can also come from an
environment variable or a secrets manager without ever being written to disk:

```yaml
        github_app:
          app_id: "Iv23liAbCdEfGhIjKlMn"
          installation_id: "78901234"
          private_key: ${GITHUB_APP_KEY}          # PEM content in an env var
          # private_key: ${vault://secret/github-app#pem}
```

Both PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`, what GitHub issues) and PKCS#8
(`-----BEGIN PRIVATE KEY-----`) are accepted. Passphrase-protected keys are not; decrypt first with
`openssl rsa -in key.pem -out key-decrypted.pem`.

The agent never logs the private key or the minted token — both are redacted from any config dump.

### Token lifetime

Installation access tokens last one hour. The agent mints one at startup — so a wrong App ID, a wrong
installation ID or an unreadable key fails startup immediately with a specific error — and re-mints
automatically once fewer than five minutes of validity remain. There is nothing to schedule or rotate.

### Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `GitHub rejected the app JWT (HTTP 401…)` | Host clock skew, or `app_id` does not match the private key. The error prints GitHub's time next to the agent's — compare them. |
| `installation … was not found (HTTP 404…)` | `installation_id` holds the App ID, or the app was uninstalled. |
| `GitHub refused the token request (HTTP 403…)` | The app is suspended, blocked by an org policy, or rate limited. |
| Clone fails with 404 after a successful token mint | The app is installed on the account but the policy repo was not selected during installation. |
| `holds an OpenSSH key, not a GitHub App key` | `private_key` points at an SSH key instead of the app's `.pem`. |

> **Note:** `skip_tls: true` also disables TLS verification for the api.github.com token exchange, not
> just for the git connection.

## What Goes in Git vs. the Local Agent Config

The agent config file (passed with `-c`) and the Git repository serve different purposes and must be kept separate.

| Setting | Where it lives | Reason |
|---------|---------------|--------|
| `orb.backends` | **Local agent config only** | Backends are loaded at startup and cannot be reloaded dynamically |
| `orb.config_manager` | **Local agent config only** | Must be present before the agent can fetch anything from Git |
| `orb.labels` | **Local agent config only** | Identifies the agent; used to match selectors in the Git repo |
| Diode target, `client_id`, `client_secret` | **Local agent config only** (use env vars) | Sensitive credentials; must not be committed to Git |
| Policy files (`device_discovery`, `network_discovery`, …) | **Git repo** | Fetched and applied dynamically according to `selector.yaml` |
| `selector.yaml` | **Git repo** | Maps agent labels to policy files |

### Handling Secrets

Never commit credentials (Diode secrets, device passwords, API tokens) to Git. Reference them as environment variables using `${VAR_NAME}` syntax in both the local agent config and policy files:

```yaml
# agent.yaml (local) — Diode credentials via env vars
orb:
  backends:
    common:
      diode:
        target: grpc://192.168.0.100:8080/diode
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
        agent_name: agent01
```

```yaml
# policy.yaml (in Git) — device_discovery credentials via env vars
# Note: ${VAR} substitution in policy files is backend-specific.
# device_discovery (Python) resolves it for all scope/defaults fields.
# snmp_discovery resolves it only for credential fields (community, username, passphrases).
# network_discovery does not resolve ${VAR} in policy scope — use a secrets manager instead.
device_discovery:
  discovery_1:
    scope:
      - hostname: 192.168.0.5
        username: admin
        password: ${DEVICE_PASS}
```

### End-to-End Example

The following shows how the local agent config, the Git repository's `selector.yaml`, and a policy file all fit together.

**Local `agent.yaml`** (never committed to Git):
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

**Git repo `selector.yaml`**:
```yaml
eu_agents:
  selector:
    region: EU
    pop: ams02
  policies:
    network_policy:
      path: policies/eu-ams02.yaml
```

**Git repo `policies/eu-ams02.yaml`**:
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

When the agent starts, it reads `agent.yaml` locally, connects to Git, and applies the policies that match its labels. Device credentials are resolved from the environment where the agent runs — they are never stored in Git.

## Git Repository Structure

The Orb Agent requires the Git repository containing its policies to have the following structure:
- A `selector.yaml` file in the root folder of the repository
- Policy files that define agent policies

### Sample Structure
```
.
├── .git
├── selector.yaml
├── policy1.yaml
├── folder2
│   ├── policy2.yaml
│   └── folder3
│       └── policy3.yaml
└── folder4
    └── policy4.yaml
```

### selector.yaml 
The `selector.yaml` file must include the `selector` and `policies` sections:
 - `selector`: Defines key-value pairs that identify agents based on their labels. If the selector is empty, it matches all agents.
 - `policies`: Specifies policy file paths and their enabled or disabled state. If the `enabled` field is not provided, the policy is enabled by default


```yaml
agent_selector_1:
  selector:
    region: EU
    pop: ams02
  policies:
    policy1:
      path: policy1.yaml
    policy2:
      enabled: false
      path: folder2/policy2.yaml
agent_selector_2:
  selector:
    region: US
    pop: nyc02
  policies:
    policy1:
      enabled: true
      path: policy1.yaml
    policy3:
      path: folder2/folder3/policy3.yaml
agent_selector_matches_all:
  selector:
  policies:
    policy4:
      path: folder4/policy4.yaml
```

### policy.yaml
Each policy file should explicitly declare the backend it applies to within the policy data itself. For example, a `policy.yaml` that targets the `device_discovery` backend might look like this:

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
