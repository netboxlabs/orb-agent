# orb-discovery — contributor & agent guide

`orb-discovery` is a multi-backend monorepo. Each backend is versioned and
released independently, and the release pipeline keys off **PR titles** — so
titles must follow the convention below.

## How releases work

- PRs are **squash-merged into `develop`**; the PR title becomes the single
  commit message. `develop` is later promoted to `release`, which triggers each
  backend's release workflow.
- A backend only releases from commits scoped to it; the version bump and the
  changelog are computed from that backend's commits alone (filtered by the
  files the commits touched under `<backend>/**`).
- A required check (**Validate PR title**) blocks merge into `develop` when the
  title doesn't match the convention.

> Note: git tags use the `<backend>/v<version>` form (e.g. `snmp-discovery/v1.2.3`).
> The `semantic-release-monorepo` plugin renders the GitHub Release *title* with a
> dash (`snmp-discovery-v1.2.3`); this is cosmetic — the tag and release ref keep
> the slash form. This is intentional and not a bug.

## PR title convention (enforced)

Use a Conventional Commits title with **one scope** from the allowlist:

```
<type>(<scope>): <subject>
```

Prefer a single scope. The automated check requires at least one allowlisted
scope and rejects unknown scopes or a subject that starts with an uppercase
letter.

### Allowed types

`feat`, `fix`, `perf`, `refactor`, `chore`, `docs`, `test`, `build`, `ci`, `revert`

### Allowed scopes

Releasable backends — `feat`/`fix`/`perf` here cuts a release for that backend:

- `device-discovery`
- `gnmi-discovery` *(reserved; backend and its release workflow land separately)*
- `network-discovery`
- `snmp-discovery`
- `worker`

Other scopes:

- `deps` / `deps-dev` — dependency bumps (e.g. from Dependabot). `chore(deps)`
  cuts a **patch** for the backend whose files the bump touched
  (e.g. `<backend>/go.mod`); `chore(deps-dev)` does not release.
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

### Keep PRs scoped

Prefer one backend per PR so the scope is unambiguous. Cross-cutting work should
use the `repo` scope or be split into per-backend PRs.

## Examples

- `feat(snmp-discovery): add VLAN membership translation`
- `fix(gnmi-discovery): guard against self-referential LAG`
- `perf(network-discovery): batch NAPALM getters`
- `chore(deps): bump go.opentelemetry.io/otel/sdk`
- `ci(repo): scope releases to per-backend commits`
