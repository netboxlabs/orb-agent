package policymgr

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/secretsmgr"
)

// PolicyManager is the interface for managing policies
type PolicyManager interface {
	ManagePolicy(payload config.PolicyPayload)
	RemovePolicyDataset(policyID string, datasetID string, beName string, be backend.Backend)
	GetPolicyState() ([]policies.PolicyData, error)
	GetRepo() policies.PolicyRepo
	ApplyBackendPolicies(ctx context.Context, name string, be backend.Backend) error
	RemoveBackendPolicies(name string, be backend.Backend, permanently bool) error
	RemovePolicy(policyID string, policyName string, beName string) error
	SetStarter(starter BackendStarter)
}

// StartState is what a BackendStarter reports for a backend.
type StartState int

const (
	// StartRunning means the backend is running and can take a policy now.
	StartRunning StartState = iota
	// StartStarting means a start is in flight or was just launched; the
	// policy is stored and applied by the starter's applier once the
	// backend is running.
	StartStarting
)

// BackendStarter starts a backend on demand for a policy that needs it. The
// supervisor implements it; until one is set, every backend is assumed to be
// started at agent start, as before.
//
// EnsureStarted is called while the policy manager holds that backend's apply
// mutex, so it must not block: it launches the start and reports StartStarting,
// it never waits for one to finish. It must also never call back into the
// policy manager, which would deadlock on that mutex.
type BackendStarter interface {
	EnsureStarted(name string) (StartState, error)
}

var _ PolicyManager = (*policyManager)(nil)

// policyManager keeps the agent's policies and applies them to backends.
//
// One mutex per backend name serialises every operation on that backend's
// policies: a manage, a remove, a dataset removal, a whole-backend removal
// and the applier. Each exported operation is a locking wrapper over an
// unexported body, and the bodies call each other, so nothing re-enters a
// mutex. Lock order: the agent's per-backend restart mutex is taken before
// this one; this mutex is taken before any supervisor entry mutex when both
// are needed, never the reverse; the repo's own lock is innermost and never
// held across a call out.
type policyManager struct {
	logger *slog.Logger
	config config.Config

	repo    policies.PolicyRepo
	secrets secretsmgr.Manager
	starter BackendStarter

	applyMu sync.Map // backend name -> *sync.Mutex
}

// applyLock returns the mutex serialising every policy operation on one
// backend. Entries are never deleted, same race rationale as the agent's
// backendRestartLock.
func (a *policyManager) applyLock(backendName string) *sync.Mutex {
	v, _ := a.applyMu.LoadOrStore(backendName, &sync.Mutex{})
	mu, _ := v.(*sync.Mutex) // LoadOrStore stored a *sync.Mutex; assertion cannot fail.
	return mu
}

// New creates a new instance of PolicyManager
func New(logger *slog.Logger, secrets secretsmgr.Manager, c config.Config) (PolicyManager, error) {
	repo, err := policies.NewMemRepo()
	if err != nil {
		return nil, err
	}
	policyManager := &policyManager{logger: logger, config: c, repo: repo, secrets: secrets}
	policyManager.secrets.RegisterUpdatePoliciesCallback(policyManager.policiesChanged)
	return policyManager, nil
}

func (a *policyManager) GetRepo() policies.PolicyRepo {
	return a.repo
}

func (a *policyManager) GetPolicyState() ([]policies.PolicyData, error) {
	return a.repo.GetAll()
}

// SetStarter installs the starter consulted before a policy is applied. It
// is called once, after construction, before any policy can arrive.
func (a *policyManager) SetStarter(starter BackendStarter) {
	a.starter = starter
}

// ReasonBackendStarting is the operator-facing reason stored on a policy
// whose apply was deferred because the starter reported the backend starting.
const ReasonBackendStarting = "backend starting"

// backendReady consults the starter for the policy's backend. It returns
// true when the apply may proceed; otherwise it has set the policy's state
// and reason and the caller persists the record.
func (a *policyManager) backendReady(name string, pd *policies.PolicyData) bool {
	if a.starter == nil {
		return true
	}
	state, err := a.starter.EnsureStarted(name)
	switch {
	case err != nil:
		pd.State = policies.FailedToApply
		pd.BackendErr = err.Error()
		return false
	case state == StartStarting:
		pd.State = policies.FailedToApply
		pd.BackendErr = ReasonBackendStarting
		return false
	}
	return true
}

// ManagePolicy serialises the manage or remove under the mutex of the
// backend the stored record names. The key is read before the lock and
// checked again under it: a record created, removed or re-created meanwhile
// changes the key, and the wrapper starts over on the right mutex. A manage
// that names a backend other than the stored one is refused with the record
// untouched, since the two backends' mutexes could otherwise leave the
// policy running on both with nothing left to remove the old copy.
func (a *policyManager) ManagePolicy(payload config.PolicyPayload) {
	for {
		key, ok := a.policyLockKey(payload)
		if !ok {
			return
		}
		if a.manageUnderLock(key, payload) {
			return
		}
	}
}

// manageUnderLock runs the manage under key's mutex, reporting whether the
// operation is finished; false means the key changed and the caller retries.
func (a *policyManager) manageUnderLock(key string, payload config.PolicyPayload) bool {
	mu := a.applyLock(key)
	mu.Lock()
	defer mu.Unlock()
	current, ok := a.policyLockKey(payload)
	if !ok {
		return true
	}
	if current != key {
		return false
	}
	a.managePolicyLocked(payload)
	return true
}

// policyLockKey returns the backend whose mutex an operation on this payload
// must hold: the stored record's backend when there is one, else the
// payload's. A manage that would move the policy to another backend is
// refused here (ok false) and logged.
func (a *policyManager) policyLockKey(payload config.PolicyPayload) (string, bool) {
	stored, err := a.repo.Get(payload.ID)
	if err != nil || stored.Backend == "" {
		return payload.Backend, true
	}
	if payload.Action == "manage" && stored.Backend != payload.Backend {
		a.logger.Warn("policy names a different backend than the one it runs on; ignoring",
			"policy_id", payload.ID, "policy_name", payload.Name, "stored_backend", stored.Backend, "backend", payload.Backend)
		return "", false
	}
	return stored.Backend, true
}

func (a *policyManager) managePolicyLocked(payload config.PolicyPayload) {
	a.logger.Info("managing agent policy from core",
		"action", payload.Action,
		"name", payload.Name,
		"dataset", payload.DatasetID,
		"backend", payload.Backend,
		"id", payload.ID,
		"version", int(payload.Version))

	switch payload.Action {
	case "manage":
		pd := policies.PolicyData{
			ID:      payload.ID,
			Name:    payload.Name,
			Backend: payload.Backend,
			Version: payload.Version,
			Data:    payload.Data,
			State:   policies.Unknown,
		}
		var updatePolicy bool
		if a.repo.Exists(payload.ID) {
			// we have already processed this policy id before (it may be running or failed)
			// ensure we are associating this dataset with this policy, if one was specified
			// note the usual case is dataset id is NOT passed during policy updates
			if payload.DatasetID != "" {
				err := a.repo.EnsureDataset(payload.ID, payload.DatasetID)
				if err != nil {
					a.logger.Warn("policy failed to ensure dataset id", "policy_id", payload.ID,
						"policy_name", payload.Name, "dataset_id", payload.DatasetID, "error", err)
				}
			}

			if payload.AgentGroupID != "" {
				err := a.repo.EnsureGroupID(payload.ID, payload.AgentGroupID)
				if err != nil {
					a.logger.Warn("policy failed to ensure agent group id", "policy_id", payload.ID,
						"policy_name", payload.Name, "agent_group_id", payload.AgentGroupID, "error", err)
				}
			}

			// if policy already exist and has no version upgrade, has no need to apply it again
			currentPolicy, err := a.repo.Get(payload.ID)
			if err != nil {
				a.logger.Error("failed to retrieve policy", "policy_id", payload.ID, "error", err)
				return
			}
			if currentPolicy.Backend == pd.Backend && currentPolicy.Version >= pd.Version && currentPolicy.State == policies.Running {
				a.logger.Info("a better version of this policy has already been applied, skipping", "policy_id", pd.ID, "policy_name", pd.Name,
					"attempted_version", fmt.Sprint(pd.Version), "current_version", fmt.Sprint(currentPolicy.Version))
				return
			}
			updatePolicy = true
			if currentPolicy.PreviousPolicyData != nil {
				// a rename is already pending: the persisted PreviousPolicyData names
				// the policy the backend actually runs; keep it through stacked
				// renames until an apply succeeds
				pd.PreviousPolicyData = currentPolicy.PreviousPolicyData
			} else if currentPolicy.Name != pd.Name {
				pd.PreviousPolicyData = &policies.PolicyData{Name: currentPolicy.Name}
			}
			pd.Datasets = currentPolicy.Datasets
			pd.GroupIDs = currentPolicy.GroupIDs
		} else {
			// new policy we have not seen before, associate with this dataset
			// on first time we see policy, we *require* dataset
			if payload.DatasetID == "" {
				a.logger.Error("policy RPC for unseen policy did not include dataset ID, skipping", "policy_id", payload.ID, "policy_name", payload.Name)
				return
			}
			pd.Datasets = map[string]bool{payload.DatasetID: true}

			if payload.AgentGroupID != "" {
				pd.GroupIDs = map[string]bool{payload.AgentGroupID: true}
			}

		}
		if !backend.HaveBackend(payload.Backend) {
			a.logger.Warn("policy failed to apply because backend is not available", "policy_id", payload.ID, "policy_name", payload.Name)
			pd.State = policies.FailedToApply
			pd.BackendErr = "backend not available"
		} else if a.backendReady(payload.Backend, &pd) {
			// attempt to apply the policy to the backend. status of policy application (running/failed) is maintained there.
			be := backend.GetBackend(payload.Backend)
			newPayload, err := a.secrets.SolvePolicySecrets(payload)
			if err != nil {
				a.logger.Error("failed to solve secrets", "policy_id", payload.ID, "policy_name", payload.Name, "error", err)
				pd.State = policies.FailedToApply
				pd.BackendErr = secretsFailureReason(err)
			} else {
				pd.Data = newPayload.Data
				a.applyPolicy(payload, be, &pd, updatePolicy)
				pd.Data = payload.Data
			}
		}
		if pd.State == policies.Running {
			// A successful apply clears any pending rename, so persisted
			// PreviousPolicyData means exactly "rename pending".
			//
			// Caveat: State==Running proves only that the NEW-name apply
			// succeeded. Backends swallow the update-embedded RemovePolicy
			// error for the OLD name (they log it and proceed to apply), so a
			// rename whose old-name delete transiently failed can leave the old
			// policy installed while we drop its cleanup reference here. This
			// orphan-on-failed-delete predates this change — the old name was
			// likewise dropped on the following manage — and closing it needs
			// the backend to report the delete outcome separately from the apply.
			pd.PreviousPolicyData = nil
		}
		// save policy (with latest status) to local policy db
		err := a.repo.Update(pd)
		if err != nil {
			a.logger.Error("got error in update last status", "error", err)
			return
		}
		return
	case "remove":
		err := a.removePolicyLocked(payload.ID, payload.Name, payload.Backend)
		if err != nil {
			a.logger.Error("policy failed to be removed", "policy_id", payload.ID, "policy_name", payload.Name, "error", err)
		}
		return
	default:
		a.logger.Error("unknown policy action, ignored", "action", payload.Action)
	}
}

// RemovePolicy removes a policy under the mutex of the backend the stored
// record names (the argument when there is no record), so a remove naming
// the wrong backend cannot run beside a manage on the right one. The key is
// a best-effort read; the body re-reads the record under the lock, and a
// remove is idempotent, so no re-validation loop is needed. Every caller is
// expected to pass the backend the repo already names for this policy; a
// caller passing a different name breaks the mutex invariant this wrapper
// exists to enforce.
func (a *policyManager) RemovePolicy(policyID string, policyName string, beName string) error {
	key := beName
	if stored, err := a.repo.Get(policyID); err == nil && stored.Backend != "" {
		key = stored.Backend
	}
	mu := a.applyLock(key)
	mu.Lock()
	defer mu.Unlock()
	return a.removePolicyLocked(policyID, policyName, beName)
}

func (a *policyManager) removePolicyLocked(policyID string, policyName string, beName string) error {
	pd := policies.PolicyData{
		ID:   policyID,
		Name: policyName,
	}
	if stored, err := a.repo.Get(policyID); err == nil {
		// use the stored record so the backend's remove honors a pending rename
		// (PreviousPolicyData) recorded by a manage that never reached it
		pd = stored
	}
	if !backend.HaveBackend(beName) {
		return errors.New("policy remove for a backend we do not have, ignoring")
	}
	be := backend.GetBackend(beName)
	err := removeFromBackend(be, pd)
	if err != nil {
		var httpErr *backend.HTTPError
		switch {
		case errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound:
			// Expected for run-once policies the backend already dropped after
			// completion: the desired state (policy absent) is reached, so this
			// is a no-op. Kept at WARN (not DEBUG) because a 404 here can also
			// signal a rename-bookkeeping bug leaving a stale policy running
			// under another name on the backend.
			a.logger.Warn("policy not present on backend at removal; treating as already removed",
				"policy_id", policyID, "policy_name", pd.Name, "error", err)
		case errors.Is(err, errBackendNeverStarted):
			// The agent never started the backend, so nothing runs the policy:
			// the desired state is reached the same way.
			a.logger.Warn("backend never started; treating policy as already removed",
				"policy_id", policyID, "policy_name", pd.Name, "backend", beName)
		default:
			a.logger.Error("backend remove policy failed: will still remove from PolicyManager", "policy_id", policyID, "error", err)
		}
	}
	// Remove policy from orb-agent local repo
	err = a.repo.Remove(pd.ID)
	if err != nil {
		return err
	}
	return nil
}

// RemovePolicyDataset removes a dataset under the mutex of the backend the
// stored record names, with the caller's name as the fallback; both callers
// read the name from the repo right before calling. Every caller is expected
// to pass the backend the repo already names for this policy; a caller
// passing a different name breaks the mutex invariant this wrapper exists to
// enforce.
func (a *policyManager) RemovePolicyDataset(policyID string, datasetID string, beName string, be backend.Backend) {
	key := beName
	if stored, err := a.repo.Get(policyID); err == nil && stored.Backend != "" {
		key = stored.Backend
	}
	mu := a.applyLock(key)
	mu.Lock()
	defer mu.Unlock()
	a.removePolicyDatasetLocked(policyID, datasetID, be)
}

func (a *policyManager) removePolicyDatasetLocked(policyID string, datasetID string, be backend.Backend) {
	policyData, err := a.repo.Get(policyID)
	if err != nil {
		a.logger.Warn("failed to retrieve policy data", "policy_id", policyID, "policy_name", policyData.Name, "error", err)
		return
	}
	removePolicy, err := a.repo.RemoveDataset(policyID, datasetID)
	if err != nil {
		a.logger.Warn("failed to remove policy dataset", "dataset_id", datasetID, "policy_name", policyData.Name, "error", err)
		return
	}
	if removePolicy {
		// Remove policy via http request
		err := removeFromBackend(be, policyData)
		if err != nil {
			a.logger.Warn("policy failed to remove", "policy_id", policyID, "policy_name", policyData.Name, "error", err)
		}
		// Remove policy from orb-agent local repo
		err = a.repo.Remove(policyData.ID)
		if err != nil {
			a.logger.Warn("policy failed to remove local", "policy_id", policyData.ID, "policy_name", policyData.Name, "error", err)
		}
	}
}

func (a *policyManager) applyPolicy(payload config.PolicyPayload, be backend.Backend, pd *policies.PolicyData, updatePolicy bool) {
	// A name the agent cannot address over a backend's API is refused before
	// the policy is created rather than when it is removed. Removal is the
	// wrong place to find out: RemovePolicy discards the local record even
	// when the backend refuses, so a policy applied under such a name would
	// be left running with no state to retry its removal from. Checked here
	// rather than per backend because the constraint is the agent's, and this
	// is the one path every apply goes through.
	if _, err := backend.PolicyPathSegment(pd.Name); err != nil {
		a.logger.Warn("policy name cannot address a policy on the backend; not applying",
			"policy_id", payload.ID, "policy_name", payload.Name, "backend", pd.Backend, "error", err)
		pd.State = policies.FailedToApply
		pd.BackendErr = err.Error()
		return
	}

	state, detail, err := be.GetRunningStatus()
	if state != backend.Running || err != nil {
		pd.State = policies.FailedToApply
		switch {
		case err != nil:
			pd.BackendErr = err.Error()
		case detail != "":
			pd.BackendErr = detail
		default:
			pd.BackendErr = fmt.Sprintf("backend state: %s", state)
		}

		a.logger.Warn(
			"backend is not ready to apply policy",
			"backend", pd.Backend,
			"policy_id", payload.ID,
			"policy_name", payload.Name,
			"backend_state", state.String(),
			"detail", detail,
			"error", err,
		)
		return
	}

	err = be.ApplyPolicy(*pd, updatePolicy)
	if err != nil {
		a.logger.Warn("policy failed to apply", "policy_id", payload.ID, "policy_name", payload.Name,
			"backend", pd.Backend, "error", err)
		pd.State = policies.FailedToApply
		pd.BackendErr = err.Error()
	} else {
		a.logger.Info("policy applied successfully", "policy_id", payload.ID, "policy_name", payload.Name,
			"backend", pd.Backend)
		pd.State = policies.Running
		pd.BackendErr = ""
	}
}

// errBackendNeverStarted stands in for a call to a backend the agent never
// started; callers treat it like a backend that answered the policy is not
// there.
var errBackendNeverStarted = errors.New("backend never started; nothing to remove from")

// removeFromBackend asks the backend to remove a policy, unless the agent
// never started it. Every bundled backend is registered, but only the ones
// the configuration names are configured and started; one never started has
// no process to ask and no logger to log the call with. A backend that was
// started is asked whatever its state, since a live process whose status
// probe timed out may still hold the policy, and the request's own timeout
// bounds the wait.
func removeFromBackend(be backend.Backend, pd policies.PolicyData) error {
	if state, _, _ := be.GetRunningStatus(); state == backend.Unknown {
		return errBackendNeverStarted
	}
	return be.RemovePolicy(pd)
}

// RemoveBackendPolicies removes the named backend's policies, and only its
// own: the repo holds every backend's policies, and a restart of one backend
// must not take the others' with it.
func (a *policyManager) RemoveBackendPolicies(name string, be backend.Backend, permanently bool) error {
	mu := a.applyLock(name)
	mu.Lock()
	defer mu.Unlock()
	return a.removeBackendPoliciesLocked(name, be, permanently)
}

func (a *policyManager) removeBackendPoliciesLocked(name string, be backend.Backend, permanently bool) error {
	plcies, err := a.repo.GetAll()
	if err != nil {
		a.logger.Error("failed to retrieve list of policies", "error", err)
		return err
	}

	for _, plcy := range plcies {
		if plcy.Backend != name {
			continue
		}
		err := removeFromBackend(be, plcy)
		if err != nil {
			a.logger.Error("failed to remove policy from backend", "policy_id", plcy.ID, "policy_name", plcy.Name, "error", err)
			// note we continue here: even if the backend failed to remove, we update our policy repo to remove it
		}
		if permanently {
			err = a.repo.Remove(plcy.ID)
			if err != nil {
				return err
			}
		} else {
			plcy.State = policies.Unknown
			if err := a.persistApplyOutcome(plcy); err != nil {
				return err
			}
		}
	}
	return nil
}

// ErrBackendNotRunning is returned by ApplyBackendPolicies when the backend
// cannot take an apply at that moment; its policies are left as they are,
// for the next start or restart, rather than stamped failed. Its intended
// consumer is the supervisor's retry loop; today's only consumer logs it.
var ErrBackendNotRunning = errors.New("backend is not running; its policies are left for its next start")

// ApplyBackendPolicies applies every policy the repo holds for the named
// backend, the way a manage does: secrets solved for the call and the
// unsolved references persisted, the name checked, and updatePolicy true,
// the remove-then-apply form every backend implements, which is safe
// against a name the backend already runs. It gates on the backend running
// before it touches anything: a backend that does not answer at that moment
// keeps its policies untouched and the caller learns why. A backend that
// stops mid-loop is caught by applyPolicy's own check, which does stamp the
// policy failed; that per-policy check is a second GetRunningStatus call,
// an HTTP round trip for every policy in the loop, and is not redundant
// with the gate above, so do not remove either thinking the other covers it.
//
// The context is checked before every policy, not only once on entry: a
// caller whose shutdown begins mid-loop must stop launching further HTTP
// calls, including one-shot policies, rather than run the whole backlog
// because the loop was already past the first check. A cancellation ends
// the loop and is returned, leaving whatever policies were not yet reached
// as they were (most often unknown) for a later replay to pick up.
//
// Only a record deferredByRestart is applied: one marked unknown, one
// marked offline while the process was down, or one stored failed to apply
// because the starter reported the backend starting. A record already
// Running reflects this process's own prior apply, and a record failed for
// any other reason failed in this same replay or in a manage this process
// already answered; applying either again could run a one-shot policy
// twice. Excluding both is what lets a manage that lands directly on the
// backend, once the restart's marker has cleared, coexist safely with the
// replay racing for the same apply mutex: whichever gets in first is not
// re-applied by the other.
func (a *policyManager) ApplyBackendPolicies(ctx context.Context, name string, be backend.Backend) error {
	mu := a.applyLock(name)
	mu.Lock()
	defer mu.Unlock()
	return a.applyBackendPoliciesLocked(ctx, name, be)
}

func (a *policyManager) applyBackendPoliciesLocked(ctx context.Context, name string, be backend.Backend) error {
	if state, detail, err := be.GetRunningStatus(); state != backend.Running || err != nil {
		a.logger.Warn("backend is not running; its policies are left for its next start",
			"backend", name, "backend_state", state.String(), "detail", detail, "error", err)
		return fmt.Errorf("%w: %s", ErrBackendNotRunning, name)
	}
	plcies, err := a.repo.GetAll()
	if err != nil {
		a.logger.Error("failed to retrieve list of policies", "error", err)
		return err
	}
	for _, policy := range plcies {
		if policy.Backend != name {
			continue
		}
		if err := ctx.Err(); err != nil {
			a.logger.Info("shutting down; remaining backend policies left unknown", "backend", name, "error", err)
			return err
		}
		if !deferredByRestart(policy) {
			continue
		}
		a.applyStoredPolicy(&policy, be)
		if err := a.persistApplyOutcome(policy); err != nil {
			return err
		}
	}
	return nil
}

// deferredByRestart reports whether a replay must hand this record to the
// backend: a record the restart marked unknown, one the state monitor marked
// offline while the previous process was down, or one stored as starting
// because a manage arrived while the restart was in flight. A running record
// reflects this process's own apply, and a record that failed for any other
// reason failed in this same replay or in a manage this process already
// answered; applying either again could run a one-shot policy twice.
func deferredByRestart(policy policies.PolicyData) bool {
	switch policy.State {
	case policies.Unknown, policies.Offline:
		return true
	case policies.FailedToApply:
		return policy.BackendErr == ReasonBackendStarting
	default:
		return false
	}
}

// persistApplyOutcome writes a policy back after an apply or a removal that
// keeps the record, without discarding the run updates the state monitor may
// have written while the backend was being called: only the apply outcome
// (state, reason, data, rename) comes from the snapshot; the store merges in
// the runs it already holds under its own lock, so a run update written
// while the caller held its snapshot is not lost between a read and a write.
func (a *policyManager) persistApplyOutcome(policy policies.PolicyData) error {
	return a.repo.UpdateKeepingRuns(policy)
}

// applyStoredPolicy applies a policy the repo already holds to its backend:
// secrets are solved for the call, the policy is applied with updatePolicy
// true, the unsolved data is put back for the caller to persist, and a
// successful apply clears a pending rename. The caller persists the record.
func (a *policyManager) applyStoredPolicy(policy *policies.PolicyData, be backend.Backend) {
	payload := config.PolicyPayload{ID: policy.ID, Name: policy.Name, Backend: policy.Backend, Version: policy.Version, Data: policy.Data}
	solved, err := a.secrets.SolvePolicySecrets(payload)
	if err != nil {
		a.logger.Error("failed to solve secrets", "policy_id", policy.ID, "policy_name", policy.Name, "error", err)
		policy.State = policies.FailedToApply
		policy.BackendErr = secretsFailureReason(err)
	} else {
		policy.Data = solved.Data
		a.applyPolicy(payload, be, policy, true)
		policy.Data = payload.Data
	}
	if policy.State == policies.Running {
		// see ManagePolicy: clearing on Running assumes the rename delete
		// succeeded, which backends do not confirm (swallowed remove error)
		policy.PreviousPolicyData = nil
	}
}

func (a *policyManager) policiesChanged(policiesIDs map[string]bool) {
	for id, valid := range policiesIDs {
		policy, err := a.repo.Get(id)
		if err != nil {
			a.logger.Error("failed to get policy", "error", err)
			continue
		}
		a.refreshPolicy(policy.Backend, id, valid)
	}
}

// refreshPolicy re-applies or removes one policy after a secrets change,
// under its backend's mutex. The record is re-read under the lock: the
// pre-lock read only chose the mutex, and a remove that landed meanwhile
// must not be undone by a stale copy.
func (a *policyManager) refreshPolicy(backendName, id string, valid bool) {
	mu := a.applyLock(backendName)
	mu.Lock()
	defer mu.Unlock()
	a.refreshPolicyLocked(backendName, id, valid)
}

// refreshPolicyLocked re-reads the record under backendName's mutex and bails
// if it no longer names backendName: a remove followed by a re-create on
// another backend between the pre-lock read that chose the mutex and this
// re-read would otherwise apply the policy to a different backend than the
// one whose mutex is held.
func (a *policyManager) refreshPolicyLocked(backendName, id string, valid bool) {
	policy, err := a.repo.Get(id)
	if err != nil {
		a.logger.Info("policy changed by the secrets provider is no longer stored, skipping", "policy_id", id)
		return
	}
	if policy.Backend != backendName {
		a.logger.Info("policy moved backends since the secrets change, skipping",
			"policy_id", id, "locked_backend", backendName, "backend", policy.Backend)
		return
	}
	if !valid {
		if err := a.removePolicyLocked(policy.ID, policy.Name, policy.Backend); err != nil {
			a.logger.Error("failed to remove policy", "error", err)
		}
		return
	}
	if !backend.HaveBackend(policy.Backend) {
		a.logger.Warn("policy failed to apply because backend is not available", "policy_id", policy.ID, "policy_name", policy.Name)
		policy.State = policies.FailedToApply
		policy.BackendErr = "backend not available"
	} else if a.backendReady(policy.Backend, &policy) {
		a.applyStoredPolicy(&policy, backend.GetBackend(policy.Backend))
	}
	if err := a.persistApplyOutcome(policy); err != nil {
		a.logger.Error("got error in update last status", "error", err)
	}
}

// maxSecretsFailureReasonLen bounds the operator-facing reason: provider errors
// can embed raw HTTP response bodies, and the reason rides in every heartbeat.
const maxSecretsFailureReasonLen = 1024

// secretsFailureReason builds the operator-facing reason for a failed secret
// resolution. It contains secret references from the policy body and provider
// error messages, never resolved secret values.
func secretsFailureReason(err error) string {
	const truncationMarker = "... (truncated)"
	reason := "failed to resolve policy secrets: " + err.Error()
	if len(reason) > maxSecretsFailureReasonLen {
		// keep the TOTAL length within maxSecretsFailureReasonLen, marker included,
		// so the reason rides every heartbeat with a bounded payload
		reason = reason[:maxSecretsFailureReasonLen-len(truncationMarker)] + truncationMarker
	}
	return reason
}
