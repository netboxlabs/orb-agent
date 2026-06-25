# orb-agent — contributor & agent guide

This is the canonical guide for both humans and coding agents (Claude Code,
Codex, etc.) working in this repository. `CLAUDE.md` points here.

`orb-agent` runs network-discovery backends as managed subprocesses. The
discovery backends (device, network, snmp, gnmi) and the worker live in this
repo under `orb-discovery/`; the agent talks to them only by exec'ing binaries
on PATH.

## Contributing & releases

- PRs are **squash-merged into `develop`**; the PR title becomes the commit
  message and must follow Conventional Commits with **one allowlisted scope**
  (e.g. `feat(agent): …`). The **Validate PR title** check enforces this.
- A versioned **agent release** is cut only from agent-scoped changes (`agent/`,
  `cmd/`) or a manual `workflow_dispatch` — not from backend-only changes.
- See **[CONTRIBUTING.md](CONTRIBUTING.md)** for the full scope allowlist and the
  type→release mapping.

## Commands

```bash
# Build binary
make agent_bin              # output: build/orb-agent

# Build Docker image
make agent                  # docker build --no-cache (clean build)
make agent_fast             # docker build (uses layer cache)

# Test
make test                   # go test -race ./...
go test -race -run TestName ./agent/configmgr/...  # single test or package

# Lint
make lint                   # golangci-lint (config: .github/golangci.yaml)
make fix-lint               # lint with --fix (gci + gofumpt formatters)

# Dependencies
make deps                   # go mod tidy

# Local multi-module workspace (agent + Go discovery backends)
make work                   # generate a git-ignored go.work for local dev
                            # use GOWORK=off for single-module commands
```

The discovery backends live in their own modules under `orb-discovery/`. `go.work`
is a local convenience only — it is git-ignored, and the agent image and CI build
the agent as a single module. If your global `go env` sets `GOFLAGS=-mod=mod`, clear
it (`go env -u GOFLAGS`): `-mod=mod` is invalid in workspace mode and breaks
gopls/govulncheck while a `go.work` exists. `make` targets are unaffected — they run
with `GOWORK=off`.

After editing, always run `make fix-lint` — gci (import ordering) and gofumpt (formatting) are enforced in CI.

## Architecture

**Module:** `github.com/netboxlabs/orb-agent` (Go 1.26)

### Agent Lifecycle

`cmd/main.go` → parses YAML config(s) + flags → calls `agent.New()` then `agent.Start()`.

`agent.New()` wires together five subsystems:
1. **SecretManager** — resolves `${VAR}` placeholders (vault / fleet / dummy)
2. **FilesManager** — fetches, verifies, and tracks files on disk at runtime (binaries, plugin bundles)
3. **PolicyManager** — owns the in-memory `PolicyRepo`, applies policies to backends
4. **BackendStateManager** — tracks backend health; triggers restarts in fleet mode (no-op in local/git mode); also restarts backends when their managed file changes via FilesManager events
5. **ConfigManager** — drives policy lifecycle (local / git / fleet strategies)

`agent.Start()` sequences: start secrets → start backends → start config manager. The config manager is started *last* so all backends are ready to receive the initial policy push.

`agent.Stop()` sequences: stop backends → `FailNonTerminalRuns` (marks in-flight runs as failed) → stop config manager.

### Key Interfaces

All five subsystems are consumed through interfaces, making them easily swappable and mockable in tests:

| Interface | Defined in |
|---|---|
| `Agent` | `agent/agent.go` |
| `backend.Backend` | `agent/backend/backend.go` |
| `configmgr.Manager` | `agent/configmgr/manager.go` |
| `filesmgr.Manager` | `agent/filesmgr/manager.go` |
| `policymgr.PolicyManager` | `agent/policymgr/manager.go` |
| `secretsmgr.Manager` | `agent/secretsmgr/manager.go` |
| `policies.PolicyRepo` | `agent/policies/repo.go` |

### Backend Plugin Registry

`cmd/main.go` has its own `init()` that explicitly calls each backend's `Register()` function. When adding a new backend, import its package and add a `Register()` call there.

### Policy Federation via Datasets

A policy can belong to multiple *datasets* (fleet groups). `PolicyRepo.EnsureDataset` / `RemoveDataset` manage this. When `RemoveDataset` removes the *last* dataset from a policy, the policy itself is deleted and removed from the backend. This means fleet can manage multiple agent instances without each instance needing to know about others.

### Config Manager Strategies

**Local:** Reads policies from the YAML config file at startup, assigns random UUIDs for policy IDs.

**Git:** Polls a git repo on a schedule; diffs policy state between polls.

### Secret Solving

Secrets are solved at *apply time*, not at *store time*. `SolvePolicySecrets` is called each time a policy is applied to a backend. This allows dynamic secret rotation: when the secret manager refreshes credentials, it fires a callback → policy manager re-applies all affected policies.

### Context Pattern in Backends

Each backend's `Start(ctx, cancelFunc)` receives a context derived from the root context with a `"routine"` key set to the backend name. Backends must respect cancellation; `cancelFunc` is called by the backend itself if it encounters a fatal error (self-termination pattern).

## Testing Patterns

Tests use `testify/assert` + `testify/require`. Mocks are interface-based, defined inline in `_test.go` files (no generated mocks).
