# Environment-Driven Configuration

Orb Agent's configuration always starts from the YAML file(s) passed with `-c`. On top of that file, the agent layers a generic environment-variable overlay so an operator can set or override **any** `orb.*` config value with `ORB_*` environment variables — without editing or templating the YAML. The primary use case is selecting and configuring the **secrets manager** independently of the **config manager**, especially useful for injecting secrets via Kubernetes/Docker at deploy time — but the mechanism works for any config key, not just secrets-manager selection.

This page covers the layering model, the generic `ORB_*` override scheme, and two worked examples (Docker and Kubernetes).

## Layering and precedence

Configuration is assembled in two layers, lowest to highest precedence:

1. **File** — the YAML file(s) passed via `-c`, decoded with the agent's standard YAML decoding; behavior is identical to releases without the env overlay. This is the base configuration.
2. **Generic `ORB_*` overrides** — env vars that address any key in the config tree directly.

The overlay is applied on top of the file. Keys not touched by the overlay keep their file value — it does not reset or clear the rest of the configuration.

## Generic `ORB_*` overrides

Any config key can be set directly with an `ORB_`-prefixed environment variable. The name after `ORB_` maps to a dot-delimited path rooted at `orb.`:

- `__` (double underscore) is the path delimiter — it moves down one level in the config tree.
- `_` (single underscore) stays inside a key segment (so `secrets_manager`, `auth_args`, etc. are unaffected).
- The whole name is lower-cased when mapped to the config path.
- A bare `ORB_` name with no `__` (for example `ORB_FOO`), a name with an empty path segment (a trailing or doubled `__`), or a name containing a literal `.` is **not** treated as an override and is skipped — only well-formed names containing the `__` delimiter are applied. Skipped names are logged at debug level.
- An `ORB_*` name that IS well-formed but is set to an **empty** value is treated as unset (ignored), not as an override to a zero value — so it never clobbers a file-set value. This is also logged at debug level.

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
  policies:
    network_discovery:
      policy_1:
        config:
          schedule: "0 */2 * * *"
          timeout: 5
        scope:
          targets: [192.168.1.1/22]
```

(The `local` config manager requires at least one policy, so a minimal `policies` block is included; without it the agent exits with `no policies specified`. A `git` or `fleet` config manager fetches policies elsewhere and would not need them inline.)

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
- **An `ORB_*` variable set to an empty value is ignored, not applied as a zero value.** `ORB_SECRETS_MANAGER__ACTIVE=` (set but empty) leaves `secrets_manager.active` at its file value instead of overwriting it with an empty string. This is logged at debug level.
- **A name that doesn't parse into a config path is ignored, not applied.** This covers a bare `ORB_` name with no `__` delimiter, a name with an empty path segment (trailing or doubled `__`), and a name containing a literal `.` (a `.` would be indistinguishable from the internal path separator once the name is lower-cased and joined). All of these are logged at debug level.
- **Two `ORB_*` names that map to the same config path fail startup with a clear error.** Names are lower-cased before being turned into a path, so `ORB_SECRETS_MANAGER__ACTIVE` and `ORB_SECRETS_MANAGER__Active` both target `orb.secrets_manager.active`; setting both is always a real conflict (a single name can't appear twice in the environment), so `Load` rejects it deterministically rather than picking whichever happened to come last in `os.Environ`.
- **A malformed `ORB_*` value fails startup with a clear error.** If a value can't be coerced to the target field's type (for example a non-numeric value into a field typed `*int`), or an override sets the same path both as a scalar value and as the parent of a deeper key (nesting a map under what is otherwise a leaf), `Load` returns an error and the agent does not start — this collision is rejected deterministically regardless of environment variable ordering. This is intentional — a deliberate override should never be silently swallowed. Only unrecognized `ORB_*` key *names* are ignored (not treated as an error) — and, because a typo'd override silently failing to apply is operator-relevant, that is now logged at **warning** level, not debug.
- **Booleans and integers behave differently depending on whether the destination is a typed field or an untyped map slot.** A *typed* boolean config field (for example `config_manager.sources.git.skip_tls` or a secrets-manager `skip_tls_verify` field) accepts any spelling Go's `strconv.ParseBool` understands: `true`/`false`, `1`/`0`, `t`/`T`, `f`/`F`, `TRUE`/`FALSE`, and so on. YAML 1.1 words like `yes`/`on`/`no`/`off` are accepted only inside the config file itself — not via an `ORB_*` override. Integer (and unsigned integer) fields are always parsed as base-10 decimal (see above), regardless of a leading zero.
- **A value placed into an untyped map via `ORB_*` is always stored as a string — it is never type-guessed.** `auth_args`, `backends`, and `policies` entries are untyped (`map[string]any`) slots in the config tree, so the loader has no schema to tell it whether a given leaf should be a bool, an int, or a string; guessing would risk corrupting a string credential whose literal value happens to look like a bool (for example a password of `0`). So `ORB_SECRETS_MANAGER__SOURCES__VAULT__AUTH_ARGS__ROLE_ID=0123` and `ORB_SECRETS_MANAGER__SOURCES__VAULT__AUTH_ARGS__PASSWORD=0` are both stored as the strings `"0123"` and `"0"`, unchanged. In practice the only non-string `auth_args` field is Vault AppRole's `wrapping_token` (a bool) — it must be set in the config file, where YAML's own typing applies, rather than via an `ORB_*` override.
- **An `ORB_*` name is always lower-cased, so it cannot target a key containing uppercase letters inside an untyped map slot.** `backends`, `policies`, and `auth_args` entries are keyed however the YAML file spells them; if a file uses an uppercase or mixed-case key under one of those entries, there is no `ORB_*` name that can address it (the override path is always lower-case). Keep such keys in the YAML file rather than trying to override them from the environment.

## See also

- [HashiCorp Vault secrets manager](../secretsmgr/vault.md)
- [Doppler secrets manager](../secretsmgr/doppler.md)
- [Delinea Secret Server secrets manager](../secretsmgr/delinea.md)
- [CyberArk (CCP) secrets manager](../secretsmgr/cyberark.md)
- [Agent Configuration File reference](../configs/agent_yaml.md)
