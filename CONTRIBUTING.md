# Contributing to orb-agent

orb-agent hosts the discovery backends (device, network, snmp, gnmi) and the
worker alongside the agent in a single repository. To keep versioning and
release notes coherent across all of these, the release pipeline keys off
**PR titles** — so titles must follow the convention below.

## How releases work

- PRs are **squash-merged into `develop`**; the PR title becomes the single
  commit message. `develop` is later promoted to `release`.
- **A versioned agent release fires only on agent-scoped changes** (under
  `agent/` or `cmd/`) or via a manual `workflow_dispatch`. A backend-only change
  does **not** cut a new agent version — backends release on their own cadence,
  and a small backend release should not force an agent version bump.
- When an agent release does fire, it **aggregates everything**: the release
  notes include every commit since the last `vX.Y.Z` tag — agent changes and any
  interim backend changes — grouped by type and scope.
- **Per-backend releases** cut their own version from commits scoped to that
  backend (filtered by `orb-discovery/<backend>/**` or
  `orb-telemetry/<backend>/**`, whichever holds it), tagged
  `<backend>/v<version>` (e.g. `snmp-discovery/v1.2.3`). The
  `semantic-release-monorepo` plugin renders the GitHub Release *title* with a
  dash (`snmp-discovery-v1.2.3`); this is cosmetic — the git tag and ref keep the
  slash form. `worker` and `device-discovery` also publish to PyPI.
- Pushing to `develop` rebuilds and publishes the `orb-agent:develop` image.
  This fires on changes under `agent/`, `cmd/`, **or** `orb-discovery/` (the
  backends), so a backend-only change still refreshes the develop image
  continuously.
- The **Validate PR title** check runs on every PR targeting `develop`. Once it
  is marked a required status check in branch protection, it blocks merge when
  the title doesn't match the convention; until then it reports status without
  blocking.

## PR title convention (enforced)

Use a Conventional Commits title with **one scope** from the allowlist:

```
<type>(<scope>): <subject>
```

The automated check requires an allowlisted scope and rejects unknown scopes or
a subject that starts with an uppercase letter.

### Allowed types

`feat`, `fix`, `perf`, `refactor`, `chore`, `docs`, `test`, `build`, `ci`, `revert`

### Allowed scopes

Agent:

- `agent` — the orb-agent itself. `feat`/`fix`/`perf` here cuts an agent release.

Releasable backends (each cuts its own release and contributes to the
aggregated agent release):

- `device-discovery`
- `gnmi-discovery` *(experimental)*
- `network-discovery`
- `snmp-discovery`
- `snmp-telemetry`
- `worker`

Other scopes:

- `deps` / `deps-dev` — dependency bumps (e.g. from Dependabot). `chore(deps)`
  cuts a **patch**; `chore(deps-dev)` does not release.
- `ci` — CI / workflow changes (no release)
- `docs` — documentation (no release)
- `repo` — repo-wide / cross-cutting changes (no release)

### Type → release mapping

| Type / commit | Release |
|---------------|---------|
| breaking (`!` suffix or `BREAKING CHANGE:` footer) | major |
| `feat` | minor |
| `fix` | patch |
| `perf` | patch |
| `chore(deps)` | patch |
| everything else (`docs`, `ci`, `test`, `refactor`, `build`, other `chore`) | none |

> **Agent version vs. non-agent scopes.** The mapping above is the per-component
> rule. For the **agent** release specifically, both the backend scopes
> (`device-discovery`, `network-discovery`, `snmp-discovery`, `gnmi-discovery`,
> `snmp-telemetry`, `worker`) and the no-release scopes (`repo`, `ci`, `docs`,
> `deps-dev`) are set to `release: false`, so even a releasing *type* on those
> scopes (e.g. `feat(repo)`, `fix(ci)`) does **not** bump the agent version.
> Backend commits still appear in the aggregated agent release notes. The one
> exception is a backend **breaking change** (`BREAKING CHANGE:` footer), which
> `semantic-release` always treats as major; such a change bumps the agent to a
> major as well.

### Keep PRs scoped

Prefer one component per PR so the scope is unambiguous. Cross-cutting work
should use the `repo` scope or be split into per-component PRs.

## Examples

- `feat(agent): add fleet-mode backend restart backoff`
- `fix(agent): respect context cancellation in policy apply`
- `docs(device-discovery): lead with supported driver and vendor counts`
- `chore(deps): bump go.opentelemetry.io/otel/sdk`
- `ci(repo): bump GitHub Actions to Node 24-compatible releases`
