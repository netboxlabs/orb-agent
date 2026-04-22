# OBS-2704: Echo Run Targets in Heartbeat Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Propagate per-run `Targets []string` from the external discovery backends' `/api/v1/status` response all the way through to orb-pro via the agent heartbeat, and bump the heartbeat schema version from `"1.0"` to `"1.1"`.

**Architecture (end-to-end data flow):**

```
external discovery binary       /api/v1/status  →  backend.PolicyStatusRun.Targets      [agent/backend/backend.go]
          ↓ (polled every 10s by agent)
backend state manager            convertToRunData  →  policies.RunData.Targets          [agent/backend/backend_state.go]
          ↓
policy repo                      UpdateRuns  →  merges with last-non-empty rule          [agent/policies/repo.go]
          ↓
heartbeat construction           convertRunsToStateInfo  →  messages.RunStateInfo.Targets [agent/configmgr/fleet/heartbeats.go]
          ↓
MQTT heartbeat payload           "targets": [...]  (omitempty)
          ↓
orb-pro fleet manager            stores last non-empty targets per run ID
```

Each layer adds or copies the field. The agent itself does not parse policy scope — that's the backend's responsibility. The agent is a faithful pipe.

**Tech Stack:** Go, testify (`github.com/stretchr/testify`), standard library. No new dependencies.

---

## Background (read this before starting)

**Task 1 already landed in commit `ab32c60`** — the heartbeat schema constant is at `"1.1"` and `messages.RunStateInfo` has the `Targets []string \`json:"targets,omitempty"\`` field. This plan revision covers only the per-run propagation work still to do.

**The wire contract from backends to agent:**

Each external discovery backend emits run status like:

```json
{
  "policies": [{
    "name": "my-policy",
    "status": "running",
    "runs": [{
      "id": "<run-uuid>",
      "status": "running|completed|failed",
      "reason": "...",
      "entity_count": 42,
      "created_at": 1700000000000000000,
      "updated_at": 1700000000000000000,
      "targets": ["192.168.1.1", "10.0.0.5"]
    }]
  }]
}
```

`targets` is a plain `[]string` of canonical target identifiers and is `omitempty` at this layer — a backend that hasn't started reporting targets simply won't include the field. The agent must tolerate both shapes.

**The `UpdateRuns` merge rule we're adopting:** if a backend reports a run with `targets == nil` (field absent), we preserve the previously-stored non-empty targets for that run ID. This mirrors the guarantee orb-pro applies on its side and protects against:
- A backend that reports targets once, then drops the field on subsequent status polls (would otherwise erase known state).
- Older backend builds that haven't been updated to emit targets (never clears the slot so a future update can populate it).

If a backend reports `targets == []` (empty but non-nil), that signals "run genuinely covered no targets" — we store empty as-is and don't preserve a stale value. In practice the JSON `omitempty` tag means `nil` and `[]` are indistinguishable on the wire (both omit the field), so on the Go side we treat "field absent" as `nil`; the merge rule reduces to: non-empty incoming wins, empty/nil incoming preserves existing.

**What gets deleted from the previous approach:**
- `agent/configmgr/fleet/targets.go` — scope-parsing helper (wrong layer).
- `agent/configmgr/fleet/targets_test.go` — its tests.
- The `targets` parameter added to `convertRunsToStateInfo` (goes back to one argument, reads `run.Targets` directly).

---

## File Structure

**Modify:**
- `agent/backend/backend.go` — add `Targets []string` field to `PolicyStatusRun`.
- `agent/backend/backend_state.go` — copy `Targets` through `convertToRunData`.
- `agent/backend/convert_to_run_data_test.go` — extend existing test to cover targets.
- `agent/policies/types.go` — add `Targets []string` field to `RunData`.
- `agent/policies/repo.go` — `UpdateRuns` preserves last non-empty targets.
- `agent/policies/repo_test.go` — add tests for preservation behavior.
- `agent/configmgr/fleet/heartbeats.go` — `convertRunsToStateInfo` reads `run.Targets` directly (no separate parameter).
- `agent/configmgr/fleet/heartbeats_test.go` — tests exercise the propagation path (runs with `Targets` set on `RunData`).

Each file change is self-contained and lands in its own commit. This produces a reviewable, per-layer history.

---

## Before starting: verify current state

- [ ] **Confirm we are on the feature branch at the Task 1 commit**

```bash
cd /Users/jamesjeffries/workspace/orb-agent
git log --oneline -3
```

Expected: `HEAD` is `ab32c60` (Task 1). Prior commit is `6c84e3d` (plan). Tracking branch is `origin/feat/OBS-2704-echo-run-targets`.

- [ ] **Confirm `agent/configmgr/fleet/targets.go` and `targets_test.go` do NOT exist**

```bash
ls agent/configmgr/fleet/targets*.go 2>&1
```

Expected: `ls: No such file or directory`. If present, the reset didn't take — investigate before continuing.

- [ ] **Run baseline tests for packages we'll touch**

```bash
go test ./agent/backend/... ./agent/policies/... ./agent/configmgr/fleet/... -count=1
```

Expected: all PASS.

---

## Task 2: Propagate `Targets` through the backend layer

**Files:**
- Modify: `agent/backend/backend.go` (`PolicyStatusRun` struct, ~line 14)
- Modify: `agent/backend/backend_state.go` (`convertToRunData`, ~line 174)
- Modify: `agent/backend/convert_to_run_data_test.go` (append tests)

- [ ] **Step 1: Extend existing conversion test to cover Targets**

Find `agent/backend/convert_to_run_data_test.go` and append these tests (adapt struct initialization to match whatever import alias the existing file uses — don't rewrite imports, just add tests):

```go
func TestConvertToRunData_CopiesTargets(t *testing.T) {
	statusRuns := []PolicyStatusRun{
		{
			ID:      "run-1",
			Status:  "completed",
			Targets: []string{"10.0.0.1", "10.0.0.2"},
		},
	}

	runs := convertToRunData(statusRuns)

	require.Len(t, runs, 1)
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, runs[0].Targets)
}

func TestConvertToRunData_NilTargetsStaysNil(t *testing.T) {
	statusRuns := []PolicyStatusRun{
		{ID: "run-1", Status: "running"}, // no Targets
	}

	runs := convertToRunData(statusRuns)

	require.Len(t, runs, 1)
	assert.Nil(t, runs[0].Targets)
}

func TestPolicyStatusRun_TargetsOmittedWhenEmptyOnWire(t *testing.T) {
	// Incoming backend JSON with NO targets field must unmarshal cleanly and leave Targets nil.
	payload := []byte(`{"id":"run-1","status":"running","created_at":0,"updated_at":0}`)

	var r PolicyStatusRun
	require.NoError(t, json.Unmarshal(payload, &r))

	assert.Nil(t, r.Targets)
}

func TestPolicyStatusRun_TargetsUnmarshaledWhenPresent(t *testing.T) {
	payload := []byte(`{"id":"run-1","status":"completed","targets":["10.0.0.1","10.0.0.2"],"created_at":0,"updated_at":0}`)

	var r PolicyStatusRun
	require.NoError(t, json.Unmarshal(payload, &r))

	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, r.Targets)
}
```

If the existing test file doesn't already import `encoding/json`, `testify/assert`, `testify/require`, add those to the import block. If you need the exact existing imports, read the file first.

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./agent/backend/ -run 'TestConvertToRunData_CopiesTargets|TestConvertToRunData_NilTargetsStaysNil|TestPolicyStatusRun_Targets' -v
```

Expected: FAIL — `PolicyStatusRun.Targets` field doesn't exist yet; `RunData.Targets` doesn't either so the assignment in Task 2 Step 3 wouldn't compile. (Actually, this step's tests reference `runs[0].Targets` which will fail to compile until Task 3 adds the field to `RunData`.) So expected failure in Step 2 is a compile error.

Note: this is a cross-task compile dependency. It's OK to land Task 2 with the struct fields in both layers added together; alternatively, land the `PolicyStatusRun.Targets` field first, verify the unmarshal tests pass, then complete Task 3 which adds `RunData.Targets` and makes the conversion tests compile. The plan takes the second path for cleanest per-layer commits — see Task 2 Step 3a.

- [ ] **Step 3a: Add `Targets` to `PolicyStatusRun` (wire-shape only)**

Edit `agent/backend/backend.go`. Change:

```go
// PolicyStatusRun represents a run in the backend status response
type PolicyStatusRun struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	EntityCount int64  `json:"entity_count,omitzero"`
	CreatedAt   int64  `json:"created_at"` // nanoseconds since epoch
	UpdatedAt   int64  `json:"updated_at"` // nanoseconds since epoch
}
```

to:

```go
// PolicyStatusRun represents a run in the backend status response
type PolicyStatusRun struct {
	ID          string   `json:"id"`
	Status      string   `json:"status"`
	Reason      string   `json:"reason"`
	EntityCount int64    `json:"entity_count,omitzero"`
	CreatedAt   int64    `json:"created_at"` // nanoseconds since epoch
	UpdatedAt   int64    `json:"updated_at"` // nanoseconds since epoch
	Targets     []string `json:"targets,omitempty"`
}
```

(Note the struct-tag alignment — Go's gofmt will normalize, but use the shape above as a starting point.)

- [ ] **Step 3b: Run just the unmarshal tests to verify the wire shape**

```bash
go test ./agent/backend/ -run 'TestPolicyStatusRun_Targets' -v
```

Expected: PASS. The conversion tests will still fail to compile because `RunData.Targets` doesn't exist yet — that's fine, Task 3 adds it.

- [ ] **Step 4: Commit the backend-layer wire-shape change**

```bash
git add agent/backend/backend.go agent/backend/convert_to_run_data_test.go
git commit -m "$(cat <<'EOF'
feat(OBS-2704): accept Targets on PolicyStatusRun from backend status

Co-Authored-By: Claude Sonnet 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Store `Targets` in the policies layer with last-non-empty merge

**Files:**
- Modify: `agent/policies/types.go` (`RunData` struct, ~line 9)
- Modify: `agent/backend/backend_state.go` (`convertToRunData`, ~line 174)
- Modify: `agent/policies/repo.go` (`UpdateRuns`, ~line 153)
- Modify: `agent/policies/repo_test.go` (append merge tests)

- [ ] **Step 1: Write failing tests for the policies layer**

Append to `agent/policies/repo_test.go`:

```go
func TestUpdateRuns_NewRunStoresTargets(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	pd := policies.PolicyData{
		ID:      "test-id",
		Name:    "test-policy",
		Backend: "test-backend",
		Version: 1,
		State:   policies.Unknown,
	}
	require.NoError(t, repo.Update(pd))

	err = repo.UpdateRuns("test-policy", []policies.RunData{
		{ID: "run-1", Status: "running", Targets: []string{"10.0.0.1", "10.0.0.2"}},
	})
	require.NoError(t, err)

	got, err := repo.Get("test-id")
	require.NoError(t, err)
	require.Len(t, got.Runs, 1)
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, got.Runs[0].Targets)
}

func TestUpdateRuns_PreservesTargetsWhenBackendOmitsThem(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	pd := policies.PolicyData{
		ID:      "test-id",
		Name:    "test-policy",
		Backend: "test-backend",
		Version: 1,
		State:   policies.Unknown,
	}
	require.NoError(t, repo.Update(pd))

	// First update: run reports targets.
	require.NoError(t, repo.UpdateRuns("test-policy", []policies.RunData{
		{ID: "run-1", Status: "running", Targets: []string{"10.0.0.1"}},
	}))

	// Second update: same run, NO targets reported (backend omitted them).
	require.NoError(t, repo.UpdateRuns("test-policy", []policies.RunData{
		{ID: "run-1", Status: "completed"}, // Targets is nil
	}))

	got, err := repo.Get("test-id")
	require.NoError(t, err)
	require.Len(t, got.Runs, 1)
	assert.Equal(t, "completed", got.Runs[0].Status)
	assert.Equal(t, []string{"10.0.0.1"}, got.Runs[0].Targets, "targets should be preserved when backend omits the field")
}

func TestUpdateRuns_UpdatesTargetsWhenBackendReportsNewNonEmptyList(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	pd := policies.PolicyData{
		ID:      "test-id",
		Name:    "test-policy",
		Backend: "test-backend",
		Version: 1,
		State:   policies.Unknown,
	}
	require.NoError(t, repo.Update(pd))

	require.NoError(t, repo.UpdateRuns("test-policy", []policies.RunData{
		{ID: "run-1", Status: "running", Targets: []string{"10.0.0.1"}},
	}))

	require.NoError(t, repo.UpdateRuns("test-policy", []policies.RunData{
		{ID: "run-1", Status: "running", Targets: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}},
	}))

	got, err := repo.Get("test-id")
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, got.Runs[0].Targets, "non-empty update should replace existing")
}
```

(Note: `repo_test.go` is in `package policies_test`, so reference types via the `policies.` qualifier. `NewMemRepo()` takes no arguments and returns `(PolicyRepo, error)`.)

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./agent/policies/ -run 'TestUpdateRuns_NewRunStoresTargets|TestUpdateRuns_PreservesTargetsWhenBackendOmitsThem|TestUpdateRuns_UpdatesTargetsWhenBackendReportsNewNonEmptyList' -v
```

Expected: FAIL — `RunData.Targets` field doesn't exist.

- [ ] **Step 3: Add `Targets` to `RunData`**

Edit `agent/policies/types.go`. Change:

```go
// RunData represents run information for a policy
type RunData struct {
	ID          string    `json:"id"`
	PolicyID    string    `json:"policy_id,omitempty"`
	Status      string    `json:"status"`
	Reason      string    `json:"reason,omitempty"`
	EntityCount int64     `json:"entity_count,omitzero"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
```

to:

```go
// RunData represents run information for a policy
type RunData struct {
	ID          string    `json:"id"`
	PolicyID    string    `json:"policy_id,omitempty"`
	Status      string    `json:"status"`
	Reason      string    `json:"reason,omitempty"`
	EntityCount int64     `json:"entity_count,omitzero"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Targets     []string  `json:"targets,omitempty"`
}
```

- [ ] **Step 4: Thread `Targets` through `convertToRunData`**

Edit `agent/backend/backend_state.go`. In `convertToRunData`, add the `Targets: sr.Targets` field copy:

```go
// convertToRunData converts backend PolicyStatusRun to policies.RunData.
// All discovery backends emit created_at/updated_at as nanoseconds since epoch;
// convert them to time.Time here so the rest of the agent works with time.Time.
func convertToRunData(statusRuns []PolicyStatusRun) []policies.RunData {
	runs := make([]policies.RunData, len(statusRuns))
	for i, sr := range statusRuns {
		runs[i] = policies.RunData{
			ID:          sr.ID,
			Status:      sr.Status,
			Reason:      sr.Reason,
			EntityCount: sr.EntityCount,
			CreatedAt:   nsToTime(sr.CreatedAt),
			UpdatedAt:   nsToTime(sr.UpdatedAt),
			Targets:     sr.Targets,
		}
	}
	return runs
}
```

- [ ] **Step 5: Implement last-non-empty merge in `UpdateRuns`**

Edit `agent/policies/repo.go`. In `UpdateRuns`, inside the `if existing, ok := existingByID[runs[i].ID]; ok {` branch (which currently preserves `CreatedAt` and handles `UpdatedAt`), add target preservation. After the existing timestamp logic:

```go
if existing, ok := existingByID[runs[i].ID]; ok {
	// Existing run: always preserve CreatedAt
	runs[i].CreatedAt = existing.CreatedAt

	if IsTerminalRunStatus(existing.Status) {
		runs[i].UpdatedAt = existing.UpdatedAt
	} else {
		runs[i].UpdatedAt = now
	}

	// Preserve last-known non-empty Targets when the backend omits them.
	// Orb-pro applies the same rule server-side; this keeps agent and fleet
	// manager in sync during transient / partial status updates.
	if len(runs[i].Targets) == 0 {
		runs[i].Targets = existing.Targets
	}
} else {
	// ... existing new-run logic unchanged ...
}
```

Note: the comparison is `len(runs[i].Targets) == 0` — this covers both `nil` (field absent from JSON) and `[]` (explicit empty slice). The orb-pro contract says both cases preserve existing state; we match that.

- [ ] **Step 6: Run policies-layer tests to verify they pass**

```bash
go test ./agent/policies/ -run 'TestUpdateRuns' -v -count=1
```

Expected: all existing `TestUpdateRuns_*` tests PASS (no regressions), new three tests PASS.

- [ ] **Step 7: Run backend-layer conversion tests (should now compile and pass)**

```bash
go test ./agent/backend/ -run 'TestConvertToRunData' -v -count=1
```

Expected: all PASS, including the new `TestConvertToRunData_CopiesTargets` and `TestConvertToRunData_NilTargetsStaysNil`.

- [ ] **Step 8: Commit the policies-layer change**

```bash
git add agent/policies/types.go agent/policies/repo.go agent/policies/repo_test.go agent/backend/backend_state.go
git commit -m "$(cat <<'EOF'
feat(OBS-2704): add per-run Targets on RunData and preserve last non-empty across merges

Co-Authored-By: Claude Sonnet 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Emit `run.Targets` in the heartbeat

**Files:**
- Modify: `agent/configmgr/fleet/heartbeats.go` (`convertRunsToStateInfo`, ~line 166)
- Modify: `agent/configmgr/fleet/heartbeats_test.go` (update tests to use `RunData.Targets`)

- [ ] **Step 1: Write failing heartbeat test**

Append to `agent/configmgr/fleet/heartbeats_test.go`:

```go
func TestHeartbeater_GetPolicyState_PropagatesTargetsFromRunData(t *testing.T) {
	testTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{
		{
			ID:      "policy-1",
			Name:    "dev-policy",
			Backend: "device_discovery",
			Version: 1,
			State:   policies.Running,
			Runs: []policies.RunData{
				{
					ID:        "run-a",
					Status:    "running",
					CreatedAt: testTime,
					UpdatedAt: testTime,
					Targets:   []string{"192.168.1.1"},
				},
				{
					ID:        "run-b",
					Status:    "completed",
					CreatedAt: testTime,
					UpdatedAt: testTime.Add(5 * time.Minute),
					Targets:   []string{"10.0.0.5", "10.0.0.6"},
				},
				{
					ID:        "run-c",
					Status:    "running",
					CreatedAt: testTime,
					UpdatedAt: testTime,
					// No Targets — must be nil in the heartbeat.
				},
			},
		},
	}, nil)

	hb := createTestHeartbeaterWithPolicyManager(&mockBackendState{}, mockPMgr)

	ps := hb.getPolicyState()

	require.Len(t, ps["policy-1"].Runs, 3)
	assert.Equal(t, []string{"192.168.1.1"}, ps["policy-1"].Runs[0].Targets)
	assert.Equal(t, []string{"10.0.0.5", "10.0.0.6"}, ps["policy-1"].Runs[1].Targets)
	assert.Nil(t, ps["policy-1"].Runs[2].Targets)

	mockPMgr.AssertExpectations(t)
}

func TestHeartbeater_SendSingleHeartbeat_SerializesPerRunTargets(t *testing.T) {
	testTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{
		{
			ID:      "policy-1",
			Name:    "dev-policy",
			Backend: "device_discovery",
			Version: 1,
			State:   policies.Running,
			Runs: []policies.RunData{
				{
					ID:        "run-1",
					Status:    "completed",
					CreatedAt: testTime,
					UpdatedAt: testTime,
					Targets:   []string{"10.0.0.1"},
				},
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
	assert.Contains(t, string(capturedPayload), `"targets":["10.0.0.1"]`)

	mockPMgr.AssertExpectations(t)
}
```

- [ ] **Step 2: Run to confirm they fail**

```bash
go test ./agent/configmgr/fleet/ -run 'TestHeartbeater_GetPolicyState_PropagatesTargetsFromRunData|TestHeartbeater_SendSingleHeartbeat_SerializesPerRunTargets' -v
```

Expected: FAIL — `convertRunsToStateInfo` doesn't copy `Targets` from `RunData` to `RunStateInfo`.

- [ ] **Step 3: Update `convertRunsToStateInfo` to read per-run Targets**

Edit `agent/configmgr/fleet/heartbeats.go`. Replace:

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
// Targets is copied through verbatim; the policies repo is responsible for
// preserving last-known-non-empty targets across backend status polls, so by
// the time runs reach this function they carry the authoritative list.
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
			Targets:     run.Targets,
		}
	}
	return runInfos
}
```

(The function signature is unchanged from the original — we did not introduce the `targets []string` parameter at all. The earlier draft that did is being discarded.)

- [ ] **Step 4: Run new heartbeat tests to verify they pass**

```bash
go test ./agent/configmgr/fleet/ -run 'TestHeartbeater_GetPolicyState_PropagatesTargetsFromRunData|TestHeartbeater_SendSingleHeartbeat_SerializesPerRunTargets' -v
```

Expected: both PASS.

- [ ] **Step 5: Run the full fleet + backend + policies packages for regressions**

```bash
go test ./agent/configmgr/fleet/... ./agent/backend/... ./agent/policies/... -count=1
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add agent/configmgr/fleet/heartbeats.go agent/configmgr/fleet/heartbeats_test.go
git commit -m "$(cat <<'EOF'
feat(OBS-2704): emit per-run Targets in heartbeat run state

Co-Authored-By: Claude Sonnet 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: End-to-end validation

- [ ] **Step 1: Full agent test suite**

```bash
go test ./... -count=1
```

Expected: PASS for every package we touched (`agent/backend/...`, `agent/policies/...`, `agent/configmgr/fleet/...`). Pre-existing Docker-dependent Vault failures in `agent/secretsmgr` are unrelated and may remain.

- [ ] **Step 2: `go vet`**

```bash
go vet ./...
```

Expected: no output.

- [ ] **Step 3: Force-push the draft PR branch**

The branch `feat/OBS-2704-echo-run-targets` was force-reset during this rework. Update origin:

```bash
git push --force-with-lease origin feat/OBS-2704-echo-run-targets
```

`--force-with-lease` is safer than `--force`: it refuses the push if someone else has updated the remote since our last fetch.

- [ ] **Step 4: Update the PR description**

The PR description should now reference per-run backend propagation, not scope parsing. Use the `gh pr edit` command to sync:

```bash
gh pr edit <PR-number> --body-file <(cat <<'EOF'
## Summary

Implements the agent-side half of [OBS-2704](https://linear.app/netboxlabs/issue/OBS-2704): propagate per-run canonical target strings from the external discovery backends' status API through the agent heartbeat to orb-pro.

- Bump heartbeat `schema_version` from `"1.0"` to `"1.1"`.
- Add `Targets []string` to `backend.PolicyStatusRun`, `policies.RunData`, and `messages.RunStateInfo` — all with `json:"targets,omitempty"`.
- `UpdateRuns` preserves the last-known non-empty targets when a backend update omits them (matches orb-pro's server-side contract).
- `convertRunsToStateInfo` copies `run.Targets` into each emitted `RunStateInfo`.

## Wire contract

Each discovery backend's `/api/v1/status` response must emit `targets` on each run. Agents with this change will propagate them unchanged:

```json
{"id":"<run>","status":"completed","targets":["10.0.0.1","10.0.0.2"]}
```

orb-pro accepts `"1.0"` and `"1.1"` during rollout. Agents whose backends haven't started emitting targets yet will send `"1.1"` with no targets field — forward-compatible.

## Plan

`docs/superpowers/plans/2026-04-21-obs-2704-echo-run-targets.md`.

## Test plan

- [x] `go test ./agent/backend/... ./agent/policies/... ./agent/configmgr/fleet/... -count=1` — PASS
- [x] `go vet ./...` — clean
- [ ] Manual: run agent against a fleet policy whose discovery backend emits `targets`; confirm heartbeat payload contains `"schema_version":"1.1"` and per-run `"targets":[...]`

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)
```

---

## Out of scope

- Modifying external discovery binaries (device-discovery / snmp-discovery / network-discovery) to start emitting `targets` — handled by the backend teams separately.
- Any scope YAML parsing in the agent. The previous approach that did this (commits `811195a` and `e335faf` on an earlier state of this branch) has been discarded.
- Persisting runs across agent restarts. `policies.RunData` still lives in the in-memory repo (`policyMemRepo`), same as before.
