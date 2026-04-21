# OBS-2704: Echo Run Targets in Heartbeat Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the orb-agent echo per-run `targets` strings in heartbeats by reading the `target:` field that orb-pro injects into policy scope entries, and bump the heartbeat schema version from `"1.0"` to `"1.1"`.

**Architecture:** The agent does not parse policy scope today — policy `Data` flows through as `map[string]any` from MQTT YAML into the policy manager and then verbatim into backend binaries. We add a small target-extraction helper in the fleet package that inspects `PolicyData.Data` (already an `any`) per-backend to pull out canonical target strings. At heartbeat construction time, `getPolicyState` computes the targets once per policy and attaches the same list to every `RunStateInfo` for that policy. Because a run currently covers the whole scope (external backends don't yet track per-target runs), policy-scope-level attribution is correct. The schema version is bumped to `"1.1"` in one constant.

**Tech Stack:** Go, testify (`github.com/stretchr/testify`), standard library. No new dependencies.

---

## Background (read this before starting)

**The `target:` field is canonical.** orb-pro injects it into each scope entry of the policy YAML. Never derive the target string from `hostname` / `host` — those may be CIDR-stripped (e.g. `192.168.1.0/24` → `192.168.1.0`) so they are *not* suitable as identifiers.

**Three backends, three scope shapes:**

- **`device-discovery`** — `scope` is a top-level list; each entry has a `target` string:
  ```yaml
  scope:
    - hostname: 192.168.1.1
      target: "192.168.1.1"      # use THIS
      username: admin
      password: secret
      netbox_id: 42
      driver: ios
  ```

- **`snmp-discovery`** — `scope.targets` is a list of objects with `target` strings:
  ```yaml
  scope:
    targets:
      - host: 10.0.0.5
        target: "10.0.0.5"       # use THIS
        port: 161
    authentication:
      protocol_version: "2c"
      community: public
  ```

- **`network-discovery`** — `scope.targets` is a plain `[]string` (each element IS the canonical target, no `target:` sub-field):
  ```yaml
  scope:
    targets:
      - "10.0.0.0/24"
      - "10.0.1.0/24"
  ```

**`omitempty` is required.** A run with no targets (unsupported backend, malformed scope, empty list) must omit the field entirely — do NOT emit `"targets": null` or `"targets": []` for a "no information" case. Empty `[]` is reserved for "the run genuinely covered no targets".

**Data shape.** `PolicyData.Data` is set by `agent/configmgr/fleet/from_rpc.go:166-181` which yaml-unmarshals the payload into `map[string]any`. So in Go, after unmarshal:
- objects become `map[string]any`
- arrays become `[]any`
- strings stay `string`

Defensively check types — a malformed `Data` must never panic the heartbeat goroutine.

**Backend names.** The task description above uses human-friendly hyphenated names (`device-discovery`, `snmp-discovery`, `network-discovery`), but the **actual backend identifier strings used over the wire and stored in `policies.PolicyData.Backend`** are underscored:

- `device_discovery` — registered at `agent/backend/devicediscovery/device_discovery.go:67`
- `snmp_discovery` — registered at `agent/backend/snmpdiscovery/snmp_discovery.go:69`
- `network_discovery` — registered at `agent/backend/networkdiscovery/network_discovery.go:69`

The `policyState.Backend` value you'll be switching on is whatever the fleet RPC delivered, which must match one of these registry keys (otherwise `ApplyPolicy` would never find the backend to run). So **match on the underscore form** in `extractTargets`.

---

## File Structure

**Modify:**
- `agent/configmgr/fleet/messages/fleet_messages.go` — bump schema constant, add `Targets` field to `RunStateInfo`.
- `agent/configmgr/fleet/heartbeats.go` — compute targets per policy in `getPolicyState`, thread through `convertRunsToStateInfo`.

**Create:**
- `agent/configmgr/fleet/targets.go` — extraction helpers, one exported entry point + three internal per-backend helpers.
- `agent/configmgr/fleet/targets_test.go` — unit tests for each backend's extractor plus the dispatch function.

**Test:**
- `agent/configmgr/fleet/heartbeats_test.go` — update existing tests that assert schema version, add new tests for targets round-tripping through JSON.

Responsibilities:
- `targets.go` owns all scope-shape knowledge. `heartbeats.go` stays free of backend-specific logic — it just calls `extractTargets(backend, data)`.
- `RunStateInfo`'s `Targets` field is emitted with `omitempty`; the struct stays the single source of truth for the wire shape.

---

## Before starting: verify current state

- [ ] **Run the existing heartbeat tests to confirm a clean baseline**

```bash
cd /Users/jamesjeffries/workspace/orb-agent
go test ./agent/configmgr/fleet/... -count=1
```

Expected: PASS. If any test fails before you've made changes, stop and investigate — something in the tree is already broken.

- [ ] **Confirm the backend registry keys you'll match on**

```bash
cd /Users/jamesjeffries/workspace/orb-agent
grep -n 'backend.Register(' agent/backend/devicediscovery/device_discovery.go agent/backend/snmpdiscovery/snmp_discovery.go agent/backend/networkdiscovery/network_discovery.go
```

Expected output (underscored names):
```
agent/backend/devicediscovery/device_discovery.go:67:	backend.Register("device_discovery", ...
agent/backend/snmpdiscovery/snmp_discovery.go:69:	backend.Register("snmp_discovery", ...
agent/backend/networkdiscovery/network_discovery.go:69:	backend.Register("network_discovery", ...
```

These are the exact strings you match against in Task 2's dispatch.

---

## Task 1: Add `Targets` field to `RunStateInfo` and bump schema version

**Files:**
- Modify: `agent/configmgr/fleet/messages/fleet_messages.go` (lines 9, 34-42)

- [ ] **Step 1: Write failing tests for the wire-shape contract**

Append to `agent/configmgr/fleet/messages/fleet_messages_test.go` (create the file if it doesn't exist — there is no existing test file for this package; check with `ls agent/configmgr/fleet/messages/`):

```go
package messages

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCurrentHeartbeatSchemaVersion_IsOneOne(t *testing.T) {
	assert.Equal(t, "1.1", CurrentHeartbeatSchemaVersion)
}

func TestRunStateInfo_TargetsOmittedWhenNil(t *testing.T) {
	r := RunStateInfo{ID: "run-1", PolicyID: "policy-1", Status: "running"}

	body, err := json.Marshal(r)
	require.NoError(t, err)

	assert.NotContains(t, string(body), "targets")
}

func TestRunStateInfo_TargetsOmittedWhenEmptySlice(t *testing.T) {
	r := RunStateInfo{ID: "run-1", PolicyID: "policy-1", Status: "running", Targets: []string{}}

	body, err := json.Marshal(r)
	require.NoError(t, err)

	// omitempty on a slice omits both nil AND empty — this is what the contract requires.
	assert.NotContains(t, string(body), "targets")
}

func TestRunStateInfo_TargetsIncludedWhenPresent(t *testing.T) {
	r := RunStateInfo{
		ID:       "run-1",
		PolicyID: "policy-1",
		Status:   "completed",
		Targets:  []string{"10.0.0.1", "10.0.0.2"},
	}

	body, err := json.Marshal(r)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(body, &decoded))

	targets, ok := decoded["targets"].([]any)
	require.True(t, ok, "expected targets to be a JSON array")
	require.Len(t, targets, 2)
	assert.Equal(t, "10.0.0.1", targets[0])
	assert.Equal(t, "10.0.0.2", targets[1])
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/jamesjeffries/workspace/orb-agent
go test ./agent/configmgr/fleet/messages/... -run 'TestCurrentHeartbeatSchemaVersion_IsOneOne|TestRunStateInfo_Targets' -v
```

Expected: FAIL — `TestCurrentHeartbeatSchemaVersion_IsOneOne` fails because the constant is still `"1.0"`; the `Targets` tests fail to compile because the field doesn't exist yet.

- [ ] **Step 3: Bump the schema version constant**

Edit `agent/configmgr/fleet/messages/fleet_messages.go`. Change line 9 from:

```go
// CurrentHeartbeatSchemaVersion defines the current version of the heartbeat schema
const CurrentHeartbeatSchemaVersion = "1.0"
```

to:

```go
// CurrentHeartbeatSchemaVersion defines the current version of the heartbeat schema
const CurrentHeartbeatSchemaVersion = "1.1"
```

- [ ] **Step 4: Add `Targets` field to `RunStateInfo`**

Edit `agent/configmgr/fleet/messages/fleet_messages.go`. Replace the `RunStateInfo` struct (lines 33-42):

```go
// RunStateInfo contains state information for a run
type RunStateInfo struct {
	ID          string    `json:"id"`
	PolicyID    string    `json:"policy_id"`
	Status      string    `json:"status"`
	Reason      string    `json:"reason,omitempty"`
	EntityCount int64     `json:"entity_count,omitzero"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
```

with:

```go
// RunStateInfo contains state information for a run
type RunStateInfo struct {
	ID          string    `json:"id"`
	PolicyID    string    `json:"policy_id"`
	Status      string    `json:"status"`
	Reason      string    `json:"reason,omitempty"`
	EntityCount int64     `json:"entity_count,omitzero"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Targets     []string  `json:"targets,omitempty"`
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd /Users/jamesjeffries/workspace/orb-agent
go test ./agent/configmgr/fleet/messages/... -v
```

Expected: PASS for all three new tests.

- [ ] **Step 6: Run the full fleet package to catch regressions**

```bash
cd /Users/jamesjeffries/workspace/orb-agent
go test ./agent/configmgr/fleet/... -count=1
```

Expected: PASS. Heartbeat-test assertions already reference the constant (`messages.CurrentHeartbeatSchemaVersion`) at `heartbeats_test.go:174, 307, 509, 577`, so they automatically follow the bump. If any test does fail, investigate — don't just rewrite assertions to match.

The hard-coded `"1.0"` strings in `connection_test.go` and `from_rpc_test.go` are **RPC schema version** payloads (`CurrentRPCSchemaVersion`), a separate constant. Leave them alone.

- [ ] **Step 7: Commit**

```bash
cd /Users/jamesjeffries/workspace/orb-agent
git add agent/configmgr/fleet/messages/fleet_messages.go agent/configmgr/fleet/messages/fleet_messages_test.go
git commit -m "feat(OBS-2704): bump heartbeat schema to 1.1 and add Targets to RunStateInfo"
```

---

## Task 2: Create target-extraction helpers

**Files:**
- Create: `agent/configmgr/fleet/targets.go`
- Create: `agent/configmgr/fleet/targets_test.go`

The extractor is deliberately defensive: it takes `any`-typed scope data (from YAML-to-`map[string]any` unmarshal) and returns `[]string`. Any malformed input → empty result, never a panic.

- [ ] **Step 1: Write failing tests for the extractor**

Create `agent/configmgr/fleet/targets_test.go`:

```go
package fleet

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// --- device-discovery ---

func TestExtractTargets_DeviceDiscovery_SingleEntry(t *testing.T) {
	data := map[string]any{
		"scope": []any{
			map[string]any{
				"hostname": "192.168.1.0",
				"target":   "192.168.1.0/24",
				"username": "admin",
			},
		},
	}

	got := extractTargets("device_discovery", data)

	assert.Equal(t, []string{"192.168.1.0/24"}, got)
}

func TestExtractTargets_DeviceDiscovery_MultipleEntries(t *testing.T) {
	data := map[string]any{
		"scope": []any{
			map[string]any{"target": "10.0.0.1"},
			map[string]any{"target": "10.0.0.2"},
			map[string]any{"target": "10.0.0.3"},
		},
	}

	got := extractTargets("device_discovery", data)

	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, got)
}

func TestExtractTargets_DeviceDiscovery_SkipsEntryMissingTarget(t *testing.T) {
	data := map[string]any{
		"scope": []any{
			map[string]any{"target": "10.0.0.1"},
			map[string]any{"hostname": "10.0.0.2"}, // no target — skip
			map[string]any{"target": "10.0.0.3"},
		},
	}

	got := extractTargets("device_discovery", data)

	assert.Equal(t, []string{"10.0.0.1", "10.0.0.3"}, got)
}

func TestExtractTargets_DeviceDiscovery_EmptyScope(t *testing.T) {
	data := map[string]any{"scope": []any{}}

	got := extractTargets("device_discovery", data)

	assert.Empty(t, got)
}

func TestExtractTargets_DeviceDiscovery_MissingScope(t *testing.T) {
	data := map[string]any{"config": map[string]any{}}

	got := extractTargets("device_discovery", data)

	assert.Empty(t, got)
}

// --- snmp-discovery ---

func TestExtractTargets_SNMPDiscovery_SingleTarget(t *testing.T) {
	data := map[string]any{
		"scope": map[string]any{
			"targets": []any{
				map[string]any{
					"host":   "10.0.0.5",
					"target": "10.0.0.5",
					"port":   161,
				},
			},
		},
	}

	got := extractTargets("snmp_discovery", data)

	assert.Equal(t, []string{"10.0.0.5"}, got)
}

func TestExtractTargets_SNMPDiscovery_MultipleTargets(t *testing.T) {
	data := map[string]any{
		"scope": map[string]any{
			"targets": []any{
				map[string]any{"target": "10.0.0.1"},
				map[string]any{"target": "10.0.0.2"},
			},
		},
	}

	got := extractTargets("snmp_discovery", data)

	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, got)
}

func TestExtractTargets_SNMPDiscovery_SkipsEntryMissingTarget(t *testing.T) {
	data := map[string]any{
		"scope": map[string]any{
			"targets": []any{
				map[string]any{"host": "10.0.0.1"}, // no target — skip
				map[string]any{"target": "10.0.0.2"},
			},
		},
	}

	got := extractTargets("snmp_discovery", data)

	assert.Equal(t, []string{"10.0.0.2"}, got)
}

func TestExtractTargets_SNMPDiscovery_EmptyTargets(t *testing.T) {
	data := map[string]any{
		"scope": map[string]any{"targets": []any{}},
	}

	got := extractTargets("snmp_discovery", data)

	assert.Empty(t, got)
}

func TestExtractTargets_SNMPDiscovery_MissingScope(t *testing.T) {
	data := map[string]any{"config": map[string]any{}}

	got := extractTargets("snmp_discovery", data)

	assert.Empty(t, got)
}

// --- network-discovery ---

func TestExtractTargets_NetworkDiscovery_SingleTarget(t *testing.T) {
	data := map[string]any{
		"scope": map[string]any{
			"targets": []any{"10.0.0.0/24"},
		},
	}

	got := extractTargets("network_discovery", data)

	assert.Equal(t, []string{"10.0.0.0/24"}, got)
}

func TestExtractTargets_NetworkDiscovery_MultipleTargets(t *testing.T) {
	data := map[string]any{
		"scope": map[string]any{
			"targets": []any{"10.0.0.0/24", "10.0.1.0/24", "example.com"},
		},
	}

	got := extractTargets("network_discovery", data)

	assert.Equal(t, []string{"10.0.0.0/24", "10.0.1.0/24", "example.com"}, got)
}

func TestExtractTargets_NetworkDiscovery_SkipsNonStringElements(t *testing.T) {
	data := map[string]any{
		"scope": map[string]any{
			"targets": []any{"10.0.0.1", 42, "10.0.0.2", nil},
		},
	}

	got := extractTargets("network_discovery", data)

	// Defensive: non-string elements are silently skipped, not a panic.
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, got)
}

func TestExtractTargets_NetworkDiscovery_EmptyTargets(t *testing.T) {
	data := map[string]any{
		"scope": map[string]any{"targets": []any{}},
	}

	got := extractTargets("network_discovery", data)

	assert.Empty(t, got)
}

// --- dispatch and malformed-input defense ---

func TestExtractTargets_UnknownBackend(t *testing.T) {
	data := map[string]any{"scope": []any{map[string]any{"target": "x"}}}

	got := extractTargets("pktvisor", data)

	assert.Empty(t, got)
}

func TestExtractTargets_NilData(t *testing.T) {
	got := extractTargets("device_discovery", nil)

	assert.Empty(t, got)
}

func TestExtractTargets_StringDataFallsThrough(t *testing.T) {
	// If YAML unmarshal failed upstream, Data may still be a raw string.
	// We must not panic — just return empty.
	got := extractTargets("device_discovery", "scope:\n  - target: 10.0.0.1")

	assert.Empty(t, got)
}

func TestExtractTargets_WrongScopeType(t *testing.T) {
	// device_discovery expects scope to be a list, not a map
	data := map[string]any{"scope": map[string]any{"not": "a list"}}

	got := extractTargets("device_discovery", data)

	assert.Empty(t, got)
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/jamesjeffries/workspace/orb-agent
go test ./agent/configmgr/fleet/... -run TestExtractTargets -v
```

Expected: FAIL — `extractTargets` is not defined.

- [ ] **Step 3: Write the extractor**

Create `agent/configmgr/fleet/targets.go`:

```go
package fleet

// extractTargets pulls canonical target strings out of a policy's scope data.
// Returns nil when the backend is unsupported, data shape is unexpected, or no
// targets are present. The caller must emit the heartbeat field with omitempty.
func extractTargets(backend string, data any) []string {
	root, ok := data.(map[string]any)
	if !ok {
		return nil
	}

	switch backend {
	case "device_discovery":
		return extractDeviceDiscoveryTargets(root)
	case "snmp_discovery":
		return extractSNMPDiscoveryTargets(root)
	case "network_discovery":
		return extractNetworkDiscoveryTargets(root)
	default:
		return nil
	}
}

// device-discovery: scope is a top-level []any of map[string]any, each with "target".
func extractDeviceDiscoveryTargets(root map[string]any) []string {
	scope, ok := root["scope"].([]any)
	if !ok {
		return nil
	}
	return collectTargetField(scope)
}

// snmp-discovery: scope.targets is a []any of map[string]any, each with "target".
func extractSNMPDiscoveryTargets(root map[string]any) []string {
	scope, ok := root["scope"].(map[string]any)
	if !ok {
		return nil
	}
	targets, ok := scope["targets"].([]any)
	if !ok {
		return nil
	}
	return collectTargetField(targets)
}

// network-discovery: scope.targets is a []any of strings — each element IS the canonical target.
func extractNetworkDiscoveryTargets(root map[string]any) []string {
	scope, ok := root["scope"].(map[string]any)
	if !ok {
		return nil
	}
	targets, ok := scope["targets"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		if s, ok := t.(string); ok {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// collectTargetField walks a list of scope entries (each an object) and pulls
// out the "target" string field. Entries missing the field or with the wrong
// type are silently skipped.
func collectTargetField(entries []any) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		obj, ok := e.(map[string]any)
		if !ok {
			continue
		}
		t, ok := obj["target"].(string)
		if !ok {
			continue
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/jamesjeffries/workspace/orb-agent
go test ./agent/configmgr/fleet/... -run TestExtractTargets -v
```

Expected: PASS for all 18 extractor tests.

- [ ] **Step 5: Commit**

```bash
cd /Users/jamesjeffries/workspace/orb-agent
git add agent/configmgr/fleet/targets.go agent/configmgr/fleet/targets_test.go
git commit -m "feat(OBS-2704): add scope target extraction for discovery backends"
```

---

## Task 3: Wire extractor into heartbeat construction

**Files:**
- Modify: `agent/configmgr/fleet/heartbeats.go` (lines 144-183)

- [ ] **Step 1: Write a failing heartbeat integration test for targets**

Append to `agent/configmgr/fleet/heartbeats_test.go`:

```go
func TestHeartbeater_GetPolicyState_PopulatesTargetsForDeviceDiscovery(t *testing.T) {
	testTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{
		{
			ID:      "policy-1",
			Name:    "dev-policy",
			Backend: "device_discovery",
			Version: 1,
			State:   policies.Running,
			Data: map[string]any{
				"scope": []any{
					map[string]any{"target": "192.168.1.1", "hostname": "192.168.1.0"},
					map[string]any{"target": "10.0.0.5"},
				},
			},
			Runs: []policies.RunData{
				{ID: "run-1", Status: "running", CreatedAt: testTime, UpdatedAt: testTime},
				{ID: "run-2", Status: "completed", CreatedAt: testTime, UpdatedAt: testTime.Add(5 * time.Minute)},
			},
		},
	}, nil)

	hb := createTestHeartbeaterWithPolicyManager(&mockBackendState{}, mockPMgr)

	ps := hb.getPolicyState()

	require.Len(t, ps, 1)
	require.Len(t, ps["policy-1"].Runs, 2)
	assert.Equal(t, []string{"192.168.1.1", "10.0.0.5"}, ps["policy-1"].Runs[0].Targets)
	assert.Equal(t, []string{"192.168.1.1", "10.0.0.5"}, ps["policy-1"].Runs[1].Targets)

	mockPMgr.AssertExpectations(t)
}

func TestHeartbeater_GetPolicyState_PopulatesTargetsForSNMPDiscovery(t *testing.T) {
	testTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{
		{
			ID:      "policy-1",
			Name:    "snmp-policy",
			Backend: "snmp_discovery",
			Version: 1,
			State:   policies.Running,
			Data: map[string]any{
				"scope": map[string]any{
					"targets": []any{
						map[string]any{"target": "10.0.0.1", "host": "10.0.0.1", "port": 161},
						map[string]any{"target": "10.0.0.2"},
					},
				},
			},
			Runs: []policies.RunData{
				{ID: "run-1", Status: "running", CreatedAt: testTime, UpdatedAt: testTime},
			},
		},
	}, nil)

	hb := createTestHeartbeaterWithPolicyManager(&mockBackendState{}, mockPMgr)

	ps := hb.getPolicyState()

	require.Len(t, ps["policy-1"].Runs, 1)
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, ps["policy-1"].Runs[0].Targets)

	mockPMgr.AssertExpectations(t)
}

func TestHeartbeater_GetPolicyState_PopulatesTargetsForNetworkDiscovery(t *testing.T) {
	testTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{
		{
			ID:      "policy-1",
			Name:    "net-policy",
			Backend: "network_discovery",
			Version: 1,
			State:   policies.Running,
			Data: map[string]any{
				"scope": map[string]any{
					"targets": []any{"10.0.0.0/24", "10.0.1.0/24"},
				},
			},
			Runs: []policies.RunData{
				{ID: "run-1", Status: "completed", CreatedAt: testTime, UpdatedAt: testTime},
			},
		},
	}, nil)

	hb := createTestHeartbeaterWithPolicyManager(&mockBackendState{}, mockPMgr)

	ps := hb.getPolicyState()

	require.Len(t, ps["policy-1"].Runs, 1)
	assert.Equal(t, []string{"10.0.0.0/24", "10.0.1.0/24"}, ps["policy-1"].Runs[0].Targets)

	mockPMgr.AssertExpectations(t)
}

func TestHeartbeater_GetPolicyState_OmitsTargetsForUnsupportedBackend(t *testing.T) {
	testTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{
		{
			ID:      "policy-1",
			Name:    "pkt-policy",
			Backend: "pktvisor",
			Version: 1,
			State:   policies.Running,
			Data:    map[string]any{"scope": []any{map[string]any{"target": "ignored"}}},
			Runs: []policies.RunData{
				{ID: "run-1", Status: "running", CreatedAt: testTime, UpdatedAt: testTime},
			},
		},
	}, nil)

	hb := createTestHeartbeaterWithPolicyManager(&mockBackendState{}, mockPMgr)

	ps := hb.getPolicyState()

	require.Len(t, ps["policy-1"].Runs, 1)
	assert.Nil(t, ps["policy-1"].Runs[0].Targets)

	mockPMgr.AssertExpectations(t)
}

func TestHeartbeater_SendSingleHeartbeat_SerializesTargets(t *testing.T) {
	testTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{
		{
			ID:      "policy-1",
			Name:    "dev-policy",
			Backend: "device_discovery",
			Version: 1,
			State:   policies.Running,
			Data: map[string]any{
				"scope": []any{map[string]any{"target": "10.0.0.1"}},
			},
			Runs: []policies.RunData{
				{ID: "run-1", Status: "completed", CreatedAt: testTime, UpdatedAt: testTime},
			},
		},
	}, nil)

	hb := createTestHeartbeaterWithPolicyManager(&mockBackendState{}, mockPMgr)

	var capturedPayload []byte
	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	hb.sendSingleHeartbeat(context.Background(), "test/topic", publishFunc, "agent-id", testTime, messages.Online, nil)

	require.NotNil(t, capturedPayload)

	var hb2 messages.Heartbeat
	require.NoError(t, json.Unmarshal(capturedPayload, &hb2))

	assert.Equal(t, "1.1", hb2.SchemaVersion)
	require.Len(t, hb2.PolicyState["policy-1"].Runs, 1)
	assert.Equal(t, []string{"10.0.0.1"}, hb2.PolicyState["policy-1"].Runs[0].Targets)

	// And confirm the omitempty contract on the raw JSON: the field IS present
	// because the slice is non-empty.
	assert.Contains(t, string(capturedPayload), `"targets":["10.0.0.1"]`)

	mockPMgr.AssertExpectations(t)
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/jamesjeffries/workspace/orb-agent
go test ./agent/configmgr/fleet/ -run 'TestHeartbeater_GetPolicyState_PopulatesTargets|TestHeartbeater_GetPolicyState_OmitsTargets|TestHeartbeater_SendSingleHeartbeat_SerializesTargets' -v
```

Expected: FAIL — `Runs[i].Targets` is always empty because `convertRunsToStateInfo` doesn't set it.

- [ ] **Step 3: Thread targets through `getPolicyState` and `convertRunsToStateInfo`**

Edit `agent/configmgr/fleet/heartbeats.go`. Replace `getPolicyState` (lines 144-163):

```go
func (hb *heartbeater) getPolicyState() map[string]messages.PolicyStateInfo {
	policyStates, err := hb.policyManager.GetPolicyState()
	if err != nil {
		hb.logger.Error("error getting policy state", "error", err)
		return make(map[string]messages.PolicyStateInfo)
	}
	ps := make(map[string]messages.PolicyStateInfo)
	for _, policyState := range policyStates {
		ps[policyState.ID] = messages.PolicyStateInfo{
			Name:     policyState.Name,
			Datasets: policyState.GetDatasetIDs(),
			State:    policyState.State.String(),
			Error:    policyState.BackendErr,
			Version:  policyState.Version,
			Backend:  policyState.Backend,
			Runs:     convertRunsToStateInfo(policyState.Runs),
		}
	}
	return ps
}
```

with:

```go
func (hb *heartbeater) getPolicyState() map[string]messages.PolicyStateInfo {
	policyStates, err := hb.policyManager.GetPolicyState()
	if err != nil {
		hb.logger.Error("error getting policy state", "error", err)
		return make(map[string]messages.PolicyStateInfo)
	}
	ps := make(map[string]messages.PolicyStateInfo)
	for _, policyState := range policyStates {
		targets := extractTargets(policyState.Backend, policyState.Data)
		ps[policyState.ID] = messages.PolicyStateInfo{
			Name:     policyState.Name,
			Datasets: policyState.GetDatasetIDs(),
			State:    policyState.State.String(),
			Error:    policyState.BackendErr,
			Version:  policyState.Version,
			Backend:  policyState.Backend,
			Runs:     convertRunsToStateInfo(policyState.Runs, targets),
		}
	}
	return ps
}
```

Now replace `convertRunsToStateInfo` (lines 165-183):

```go
// convertRunsToStateInfo converts policies.RunData to messages.RunStateInfo
func convertRunsToStateInfo(runs []policies.RunData) []messages.RunStateInfo {
	if len(runs) == 0 {
		return nil
	}
	runInfos := make([]messages.RunStateInfo, len(runs))
	for i, run := range runs {
		runInfos[i] = messages.RunStateInfo{
			ID:          run.ID,
			PolicyID:    run.PolicyID,
			Status:      run.Status,
			Reason:      run.Reason,
			EntityCount: run.EntityCount,
			CreatedAt:   run.CreatedAt,
			UpdatedAt:   run.UpdatedAt,
		}
	}
	return runInfos
}
```

with:

```go
// convertRunsToStateInfo converts policies.RunData to messages.RunStateInfo.
// targets is the per-policy canonical target list echoed into every run; pass
// nil to omit the field entirely from the emitted heartbeat.
func convertRunsToStateInfo(runs []policies.RunData, targets []string) []messages.RunStateInfo {
	if len(runs) == 0 {
		return nil
	}
	runInfos := make([]messages.RunStateInfo, len(runs))
	for i, run := range runs {
		runInfos[i] = messages.RunStateInfo{
			ID:          run.ID,
			PolicyID:    run.PolicyID,
			Status:      run.Status,
			Reason:      run.Reason,
			EntityCount: run.EntityCount,
			CreatedAt:   run.CreatedAt,
			UpdatedAt:   run.UpdatedAt,
			Targets:     targets,
		}
	}
	return runInfos
}
```

- [ ] **Step 4: Run the new tests to verify they pass**

```bash
cd /Users/jamesjeffries/workspace/orb-agent
go test ./agent/configmgr/fleet/ -run 'TestHeartbeater_GetPolicyState_PopulatesTargets|TestHeartbeater_GetPolicyState_OmitsTargets|TestHeartbeater_SendSingleHeartbeat_SerializesTargets' -v
```

Expected: PASS for all 5 new tests.

- [ ] **Step 5: Run the full fleet package to catch regressions**

```bash
cd /Users/jamesjeffries/workspace/orb-agent
go test ./agent/configmgr/fleet/... -count=1
```

Expected: PASS. `convertRunsToStateInfo` has only one call site (`heartbeats.go:159`, which you just updated); nothing else needs touching.

- [ ] **Step 6: Commit**

```bash
cd /Users/jamesjeffries/workspace/orb-agent
git add agent/configmgr/fleet/heartbeats.go agent/configmgr/fleet/heartbeats_test.go
git commit -m "feat(OBS-2704): echo canonical scope targets in heartbeat run state"
```

---

## Task 4: End-to-end validation

**Files:**
- No new code. Just verification.

- [ ] **Step 1: Run the full agent test suite**

```bash
cd /Users/jamesjeffries/workspace/orb-agent
go test ./... -count=1
```

Expected: PASS. If anything unrelated to the fleet package fails because of the schema bump, investigate — nothing else should be coupled to the heartbeat constant.

- [ ] **Step 2: Run `go vet` and the linter**

```bash
cd /Users/jamesjeffries/workspace/orb-agent
go vet ./...
```

Expected: no output. If the repo uses `golangci-lint`, run it as well:

```bash
command -v golangci-lint && golangci-lint run ./agent/configmgr/fleet/... || echo "golangci-lint not installed locally — relying on CI"
```

- [ ] **Step 3: Manually inspect a heartbeat payload**

Start the agent against a fleet config that has at least one discovery policy applied, and watch the debug logs:

```bash
cd /Users/jamesjeffries/workspace/orb-agent
# Adjust this to whatever local fleet harness the team uses; the important part
# is the debug log line "heartbeat sent" in agent/configmgr/fleet/heartbeats.go:124
go run ./cmd/orb-agent -c ./docs/sample-fleet-config.yaml --log-level debug 2>&1 | grep -A1 'heartbeat sent'
```

Expected: the logged `payload` includes `"schema_version":"1.1"` and, for any policy whose scope parsed correctly, each run in `policy_state.<id>.runs[]` contains a `"targets":[...]` array of canonical strings matching the `target:` fields orb-pro injected.

**If no local fleet harness is available**, skip this step and note it in the PR description. CI + the unit tests cover the wire shape.

- [ ] **Step 4: Final commit sweep**

Confirm no stray changes are unstaged:

```bash
cd /Users/jamesjeffries/workspace/orb-agent
git status
```

Expected: clean working tree. If anything is outstanding (test tweaks, lint fixes), commit with a `chore(OBS-2704): …` message.

---

## Out of scope

The task description mentions:

> The backend stores the last non-empty `targets` value it receives for a given run ID, so partial updates are safe — a later heartbeat with no `targets` will not clear a previously reported value.

That's a backend (orb-pro) guarantee, not an agent responsibility. The agent always emits the best information it has on every heartbeat; idempotency is handled server-side.

We are also explicitly NOT:
- Changing the external discovery binaries (device-discovery / snmp-discovery / network-discovery) to emit per-run target breakdowns. Per-run (as opposed to per-policy) target attribution is a future change that would require extending `backend.PolicyStatusRun` and the `/api/v1/status` response shape in each external backend.
- Touching `policies.RunData` — targets are a heartbeat-shape concern only, not persisted state.
- Modifying CIDR parsing or hostname handling anywhere. `target:` is a verbatim echo.
