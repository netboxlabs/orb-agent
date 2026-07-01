# Environment-Driven Configuration and Secrets Manager Selection

Orb Agent's configuration always starts from the YAML file(s) passed with `-c`. On top of that file, the agent layers environment variables so an operator can select and configure the **secrets manager** independently of the **config manager** — without editing or templating the YAML — which is especially useful for injecting secrets via Kubernetes/Docker at deploy time.

This page covers the layering model, the generic `ORB_*` override scheme, the friendly secrets-manager aliases, and two worked examples (Docker and Kubernetes).

## Layering and precedence

Configuration is assembled in three layers, lowest to highest precedence:

1. **File** — the YAML file(s) passed via `-c`, decoded as today. This is the base configuration.
2. **Friendly aliases** — a fixed set of conventional secrets-manager env vars (e.g. `VAULT_ADDR`, `DOPPLER_TOKEN`), described below.
3. **Generic `ORB_*` overrides** — env vars that address any key in the config tree directly.

Each layer is applied on top of the previous one. If the same key is set by both the friendly aliases and a generic `ORB_*` override, **the generic override wins**. Keys not touched by any env layer keep their file value — the overlay does not reset or clear the rest of the configuration.

## Generic `ORB_*` overrides

Any config key can be set directly with an `ORB_`-prefixed environment variable. The name after `ORB_` maps to a dot-delimited path rooted at `orb.`:

- `__` (double underscore) is the path delimiter — it moves down one level in the config tree.
- `_` (single underscore) stays inside a key segment (so `secrets_manager`, `auth_args`, etc. are unaffected).
- The whole name is lower-cased when mapped to the config path.
- A bare `ORB_` name with no `__` (for example `ORB_SECRETS_MANAGER`) is **not** treated as a generic override — those are reserved for the friendly aliases below, so a short alias name can't accidentally clobber a whole subtree.

**Example:** to set the Vault request timeout (`orb.secrets_manager.sources.vault.timeout` in the YAML) directly:

```sh
ORB_SECRETS_MANAGER__SOURCES__VAULT__TIMEOUT=45
```

`ORB_` → root `orb`, then `SECRETS_MANAGER` → `secrets_manager` (single `_` preserved), `SOURCES` → `sources`, `VAULT` → `vault`, `TIMEOUT` → `timeout`.

## Friendly aliases

For the common case of selecting and configuring a secrets manager, the following conventional environment variables are recognized without needing the `ORB_*__` scheme:

| Variable | Maps to | Notes |
|----------|---------|-------|
| `ORB_SECRETS_MANAGER` | `orb.secrets_manager.active` | One of `vault`, `doppler`, `delinea`, `cyberark`, `fleet` |
| `VAULT_ADDR` | `orb.secrets_manager.sources.vault.address` | |
| `VAULT_TOKEN` | `orb.secrets_manager.sources.vault.auth` = `token`, `orb.secrets_manager.sources.vault.auth_args.token` | Mutually exclusive with `VAULT_K8S_ROLE` |
| `VAULT_NAMESPACE` | `orb.secrets_manager.sources.vault.namespace` | |
| `VAULT_MOUNT` | `orb.secrets_manager.sources.vault.mount` | |
| `VAULT_K8S_ROLE` | `orb.secrets_manager.sources.vault.auth` = `kubernetes`, `orb.secrets_manager.sources.vault.auth_args.role` | Mutually exclusive with `VAULT_TOKEN`; no static token in the environment — Vault authenticates using the pod's ServiceAccount token |
| `DOPPLER_TOKEN` | `orb.secrets_manager.sources.doppler.token` | |

Setting both `VAULT_TOKEN` and `VAULT_K8S_ROLE` at the same time fails startup with a clear error — pick the auth method that fits the deployment (static token, or Kubernetes ServiceAccount).

### The `*_FILE` convention

Any alias above that carries a secret value also accepts a `_FILE` suffix that points at a file instead of embedding the value in the environment: `VAULT_TOKEN_FILE`, `DOPPLER_TOKEN_FILE`. When the `_FILE` variant is set, the agent reads that file's contents (trimmed of surrounding whitespace) and uses it as the value; it takes precedence over the corresponding non-`_FILE` variable if both happen to be set. This is the standard way to feed secrets mounted from a Kubernetes `Secret` volume or a Docker secret without putting the raw value in the process environment.

## Worked examples

### Docker: Fleet config manager, Vault secrets via static token

The config manager stays on `fleet` (from the file); only the secrets manager is selected and configured entirely from the environment.

`agent.yaml`:

```yaml
version: 1.0
orb:
  config_manager:
    active: fleet
    sources:
      fleet:
        url: "http://fleet.example.com:8080"
        token_url: "http://fleet.example.com:8080/auth/token"
        client_id: "${FLEET_CLIENT_ID}"
        client_secret: "${FLEET_CLIENT_SECRET}"
  backends:
    network_discovery:
```

```sh
docker run --net=host \
  -v ${PWD}:/opt/orb/ \
  -e FLEET_CLIENT_ID=your-fleet-client-id \
  -e FLEET_CLIENT_SECRET=your-fleet-client-secret \
  -e ORB_SECRETS_MANAGER=vault \
  -e VAULT_ADDR=https://vault.example.com:8200 \
  -e VAULT_TOKEN=s.abcdefghijklmnop \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

The agent starts with `secrets_manager.active=vault`, a populated Vault source (token auth), and the Fleet config manager untouched — policies can then reference `${vault://...}` secrets as usual.

### Kubernetes: Vault via pod ServiceAccount (no static token)

Use `VAULT_K8S_ROLE` instead of `VAULT_TOKEN` so no long-lived Vault token needs to be provisioned to the pod — Vault's Kubernetes auth method verifies the pod's own ServiceAccount token.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: orb-agent
spec:
  serviceAccountName: orb-agent
  containers:
    - name: orb-agent
      image: netboxlabs/orb-agent:latest
      args: ["run", "-c", "/opt/orb/agent.yaml"]
      env:
        - name: ORB_SECRETS_MANAGER
          value: "vault"
        - name: VAULT_ADDR
          value: "https://vault.example.com:8200"
        - name: VAULT_K8S_ROLE
          value: "orb-agent"
      volumeMounts:
        - name: agent-config
          mountPath: /opt/orb/agent.yaml
          subPath: agent.yaml
  volumes:
    - name: agent-config
      configMap:
        name: orb-agent-config
```

No `VAULT_TOKEN` (or `VAULT_TOKEN_FILE`) is set. The agent configures the Vault source with `auth: kubernetes` and `auth_args.role: orb-agent`; Vault's Kubernetes auth backend validates the pod's projected ServiceAccount token against that role.

## Operator caveats

- **A generic `ORB_*` override into a `backends` or `policies` entry replaces that entry — it does not deep-merge.** `backends` and `policies` are untyped maps in the config tree, so an override that reaches inside one (for example `ORB_BACKENDS__PKTVISOR__FOO=bar`) replaces the whole `pktvisor` entry with `{foo: bar}`; any sibling keys the file set under that same entry (`tap`, policy definitions, etc.) are dropped. Keep the full backend/policy configuration in the YAML file, and reserve `ORB_*` overrides for scalar and manager-selection keys (config/secrets manager selection and their source settings), which are typed struct fields and merge onto the file value field-by-field instead of replacing wholesale.
- **A malformed `ORB_*` value fails startup with a clear error.** If a value can't be coerced to the target field's type (for example a non-numeric `TIMEOUT`), or an override adds an extra `__` segment underneath what the file defines as a scalar (nesting a map under a string leaf), `Load` returns an error and the agent does not start. This is intentional — a deliberate override should never be silently swallowed. Only unrecognized `ORB_*` key *names* are ignored, and that is logged at debug level, not treated as an error.
- **`ORB_*` booleans accept only `true`/`false`/`1`/`0`.** YAML 1.1 boolean spellings such as `yes`/`on`/`no`/`off` are valid inside the config file itself, but an `ORB_*` env override for a boolean field must use `true`, `false`, `1`, or `0`.

## See also

- [HashiCorp Vault secrets manager](./vault.md)
- [Doppler secrets manager](./doppler.md)
- [Delinea Secret Server secrets manager](./delinea.md)
- [CyberArk (CCP) secrets manager](./cyberark.md)
- [Agent Configuration File reference](../configs/agent_yaml.md)
