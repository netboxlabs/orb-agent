# Environment-Driven Configuration

Orb Agent's configuration always starts from the YAML file(s) passed with `-c`. On top of that file, the agent layers a generic environment-variable overlay so an operator can set or override **any** `orb.*` config value with `ORB_*` environment variables — without editing or templating the YAML. The primary use case is selecting and configuring the **secrets manager** independently of the **config manager**, especially useful for injecting secrets via Kubernetes/Docker at deploy time — but the mechanism works for any config key, not just secrets-manager selection.

This page covers the layering model, the generic `ORB_*` override scheme, and two worked examples (Docker and Kubernetes).

## Layering and precedence

Configuration is assembled in two layers, lowest to highest precedence:

1. **File** — the YAML file(s) passed via `-c`, decoded as today. This is the base configuration.
2. **Generic `ORB_*` overrides** — env vars that address any key in the config tree directly.

The overlay is applied on top of the file. Keys not touched by the overlay keep their file value — it does not reset or clear the rest of the configuration.

## Generic `ORB_*` overrides

Any config key can be set directly with an `ORB_`-prefixed environment variable. The name after `ORB_` maps to a dot-delimited path rooted at `orb.`:

- `__` (double underscore) is the path delimiter — it moves down one level in the config tree.
- `_` (single underscore) stays inside a key segment (so `secrets_manager`, `auth_args`, etc. are unaffected).
- The whole name is lower-cased when mapped to the config path.
- A bare `ORB_` name with no `__` (for example `ORB_FOO`) is **not** treated as an override and is skipped — only names containing the `__` delimiter are applied.

**Example:** to select Vault as the active secrets manager and set its address (`orb.secrets_manager.active` and `orb.secrets_manager.sources.vault.address` in the YAML):

```sh
ORB_SECRETS_MANAGER__ACTIVE=vault
ORB_SECRETS_MANAGER__SOURCES__VAULT__ADDRESS=http://127.0.0.1:8200
```

`ORB_` → root `orb`, then `SECRETS_MANAGER` → `secrets_manager` (single `_` preserved), `SOURCES` → `sources`, `VAULT` → `vault`, `ADDRESS` → `address`. `ORB_SECRETS_MANAGER__ACTIVE` accepts one of `vault`, `doppler`, `delinea`, `cyberark`, `fleet`.

The same scheme applies to any other `orb.*` key — for example `ORB_CONFIG_MANAGER__ACTIVE` or `ORB_BACKENDS__...` — not just the secrets manager.

## Worked examples

### Docker: config file for the config manager, Vault secrets via static token

The config manager is whatever the file specifies (`local`, `git`, or another supported manager); only the secrets manager is selected and configured entirely from the environment.

`agent.yaml`:

```yaml
version: 1.0
orb:
  config_manager:
    active: local
    sources:
      local:
        config: /opt/orb/agent.yaml
  backends:
    network_discovery:
```

```sh
docker run --net=host \
  -v ${PWD}:/opt/orb/ \
  -e ORB_SECRETS_MANAGER__ACTIVE=vault \
  -e ORB_SECRETS_MANAGER__SOURCES__VAULT__ADDRESS=http://127.0.0.1:8200 \
  -e ORB_SECRETS_MANAGER__SOURCES__VAULT__AUTH=token \
  -e ORB_SECRETS_MANAGER__SOURCES__VAULT__AUTH_ARGS__TOKEN=s.abcdefghijklmnop \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

The agent starts with `secrets_manager.active=vault`, a populated Vault source (token auth), and the config manager untouched — policies can then reference `${vault://...}` secrets as usual. The config manager's own secrets (for example a Git deploy key, or a Fleet client ID/secret if using the Fleet config manager) can still be injected into the YAML file with the `${VAR}` placeholder mechanism, resolved from the environment at runtime; that mechanism is unrelated to the `ORB_*` overlay described here and is unchanged.

### Kubernetes: Vault via pod ServiceAccount (no static token)

Set `AUTH=kubernetes` and `AUTH_ARGS__ROLE` instead of a static token, so no long-lived Vault token needs to be provisioned to the pod — Vault's Kubernetes auth method verifies the pod's own ServiceAccount token (read from disk, not from the environment).

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
        - name: ORB_SECRETS_MANAGER__ACTIVE
          value: "vault"
        - name: ORB_SECRETS_MANAGER__SOURCES__VAULT__ADDRESS
          value: "http://vault:8200"
        - name: ORB_SECRETS_MANAGER__SOURCES__VAULT__AUTH
          value: "kubernetes"
        - name: ORB_SECRETS_MANAGER__SOURCES__VAULT__AUTH_ARGS__ROLE
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

No static token is set anywhere. The agent configures the Vault source with `auth: kubernetes` and `auth_args.role: orb-agent`; Vault's Kubernetes auth backend validates the pod's projected ServiceAccount token against that role. For secrets that do need to be injected via the environment instead, the `${VAR}` mechanism in the YAML file combined with a Kubernetes `secretKeyRef` covers that case — it is independent of the `ORB_*` overlay described here.

## Operator caveats

- **A generic `ORB_*` override into a `backends` or `policies` entry replaces that entry — it does not deep-merge.** `backends` and `policies` are untyped maps in the config tree, so an override that reaches inside one (for example `ORB_BACKENDS__PKTVISOR__FOO=bar`) replaces the whole `pktvisor` entry with `{foo: bar}`; any sibling keys the file set under that same entry (`tap`, policy definitions, etc.) are dropped. Keep the full backend/policy configuration in the YAML file, and reserve `ORB_*` overrides for scalar and manager-selection keys (config/secrets manager selection and their source settings), which are typed struct fields and merge onto the file value field-by-field instead of replacing wholesale.
- **A malformed `ORB_*` value fails startup with a clear error.** If a value can't be coerced to the target field's type (for example a non-numeric value into a field typed `*int`), or an override sets the same path both as a scalar value and as the parent of a deeper key (nesting a map under what is otherwise a leaf), `Load` returns an error and the agent does not start — this collision is rejected deterministically regardless of environment variable ordering. This is intentional — a deliberate override should never be silently swallowed. Only unrecognized `ORB_*` key *names* are ignored, and that is logged at debug level, not treated as an error.
- **`ORB_*` booleans accept only `true`/`false`/`1`/`0`.** YAML 1.1 boolean spellings such as `yes`/`on`/`no`/`off` are valid inside the config file itself, but an `ORB_*` env override for a boolean field must use `true`, `false`, `1`, or `0`.

## See also

- [HashiCorp Vault secrets manager](./secretsmgr/vault.md)
- [Doppler secrets manager](./secretsmgr/doppler.md)
- [Delinea Secret Server secrets manager](./secretsmgr/delinea.md)
- [CyberArk (CCP) secrets manager](./secretsmgr/cyberark.md)
- [Agent Configuration File reference](./configs/agent_yaml.md)
