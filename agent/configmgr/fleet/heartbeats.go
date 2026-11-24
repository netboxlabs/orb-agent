package fleet

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

const (
	heartbeatFreq = 5 * time.Second
	// maxCollectionErrorsLen is the most the collection errors of the running
	// policies take of a heartbeat together. Each is kept to 1 KB as it is
	// stored, but Fleet drops a heartbeat larger than 25 KiB whole, and with it
	// the state of every policy, so the errors of many failing policies are
	// kept to this between them (see boundCollectionErrors).
	maxCollectionErrorsLen = 8 * 1024
	// collectionErrorCut ends a collection error a heartbeat cuts.
	collectionErrorCut = "... (truncated)"
)

// heartbeatTickInterval is the delay between periodic heartbeats. Tests shorten it.
var heartbeatTickInterval = heartbeatFreq

// BundleStateRetriever provides read-only access to installed, installing,
// and failed bundle state for heartbeats. Satisfied by filesmgr.Manager.
type BundleStateRetriever interface {
	List() []filesmgr.FileEntry
	// ListPending reports bundles currently installing or whose most recent
	// install attempt failed. See filesmgr.FileEntry's doc comment for why
	// this is in-memory only.
	ListPending() []filesmgr.FileEntry
}

type heartbeater struct {
	logger          *slog.Logger
	backendState    backend.StateRetriever
	policyManager   policymgr.PolicyManager
	groupRetriever  GroupRetriever
	bundleRetriever BundleStateRetriever
	lastRestartTS   time.Time

	mu            sync.Mutex
	sessionCancel context.CancelFunc
	wg            sync.WaitGroup
}

func newHeartbeater(logger *slog.Logger, backendState backend.StateRetriever, policyManager policymgr.PolicyManager, groupRetriever GroupRetriever, bundleRetriever BundleStateRetriever) *heartbeater {
	return &heartbeater{
		logger:          logger,
		backendState:    backendState,
		policyManager:   policyManager,
		groupRetriever:  groupRetriever,
		bundleRetriever: bundleRetriever,
		lastRestartTS:   time.Now().UTC(),
	}
}

// StartHeartbeats begins a heartbeat session: it cancels any prior session, waits for it to exit,
// then starts a new loop with its own ticker until the session context is cancelled or stop() runs.
func (hb *heartbeater) StartHeartbeats(parentCtx context.Context, heartbeatTopic string, agentID string, publishFunc func(ctx context.Context, topic string, payload []byte) error, onFailure func()) {
	hb.mu.Lock()
	if hb.sessionCancel != nil {
		prev := hb.sessionCancel
		// Keep sessionCancel set until wg.Wait() completes so concurrent stop()
		// still observes an active session and cancels the same context instead of
		// treating the heartbeater as idle (OBS-2315 review).
		hb.mu.Unlock()
		prev()
		hb.wg.Wait()
		hb.mu.Lock()
	}
	childCtx, cancel := context.WithCancel(parentCtx)
	hb.sessionCancel = cancel
	hb.wg.Add(1)
	hb.mu.Unlock()

	go func() {
		defer hb.wg.Done()
		ticker := time.NewTicker(heartbeatTickInterval)
		defer ticker.Stop()
		hb.runHeartbeatLoop(childCtx, ticker, heartbeatTopic, agentID, publishFunc, onFailure)
	}()
}

func (hb *heartbeater) stop(heartbeatTopic string, publishFunc func(ctx context.Context, topic string, payload []byte) error) {
	hb.mu.Lock()
	cancel := hb.sessionCancel
	hb.sessionCancel = nil
	hb.mu.Unlock()

	if cancel != nil {
		cancel()
		hb.wg.Wait()
	}

	// Always send the offline heartbeat here. The goroutine exits cleanly on
	// ctx.Done() without sending it, so stop() is the sole sender — called only
	// when the MQTT connection is still alive (before connectionManager.Disconnect).
	hb.sendSingleHeartbeat(context.Background(), heartbeatTopic, publishFunc, "", time.Now(), messages.HeartbeatState(messages.Offline), nil)
}

func (hb *heartbeater) runHeartbeatLoop(ctx context.Context, ticker *time.Ticker, heartbeatTopic string, agentID string, publishFunc func(ctx context.Context, topic string, payload []byte) error, onFailure func()) {
	// The connection can be closed before its heartbeats start: the agent
	// can disconnect it as soon as it is up, before OnConnectionUp runs.
	if ctx.Err() != nil {
		hb.logger.Debug("connection closed before its heartbeats started")
		return
	}
	hb.logger.Debug("start heartbeats routine")
	hb.sendSingleHeartbeat(ctx, heartbeatTopic, publishFunc, agentID, time.Now(), messages.Online, onFailure)

	for {
		select {
		case <-ctx.Done():
			hb.logger.Debug("context done, stopping heartbeats routine")
			return
		case t := <-ticker.C:
			hb.sendSingleHeartbeat(ctx, heartbeatTopic, publishFunc, agentID, t, messages.Online, onFailure)
		}
	}
}

func (hb *heartbeater) sendSingleHeartbeat(ctx context.Context, heartbeatTopic string, publishFunc func(ctx context.Context, topic string, payload []byte) error, _ string, _ time.Time, state messages.HeartbeatState, onFailure func()) {
	// The offline heartbeat comes after the agent stopped its backends, so
	// the processes the monitor finds ended then are no failure.
	endedUnknown := state != messages.Offline
	hbData := messages.Heartbeat{
		SchemaVersion: messages.CurrentHeartbeatSchemaVersion,
		TimeStamp:     time.Now().UTC(),
		State:         messages.State(state),
		LastRestartTS: hb.lastRestartTS,
		BackendState:  hb.getBackendState(),
		PolicyState:   hb.policyState(endedUnknown),
		GroupState:    hb.getGroupState(),
		BundleState:   hb.getBundleState(),
	}

	body, err := json.Marshal(hbData)
	if err != nil {
		hb.logger.Error("error marshalling heartbeat", "error", err)
		return
	}

	if err := publishFunc(ctx, heartbeatTopic, body); err != nil {
		hb.logger.Error("error sending heartbeat", "error", err)
		if onFailure != nil {
			onFailure()
		}
	} else {
		hb.logger.Debug("heartbeat sent", "payload", string(body))
	}
}

func (hb *heartbeater) getBackendState() map[string]messages.BackendStateInfo {
	bes := make(map[string]messages.BackendStateInfo)
	backendStates := hb.backendState.Get()
	for name, state := range backendStates {
		bes[name] = messages.BackendStateInfo{
			State:             state.Status.String(),
			Error:             state.LastError,
			RestartCount:      state.RestartCount,
			LastError:         state.LastError,
			LastRestartTS:     state.LastRestartTS,
			LastRestartReason: state.LastRestartReason,
		}
	}
	return bes
}

func (hb *heartbeater) getPolicyState() map[string]messages.PolicyStateInfo {
	return hb.policyState(true)
}

// policyState is each policy's state as the heartbeat reports it. With
// endedUnknown, a running policy whose backend's process the monitor last
// found gone is reported unknown instead.
func (hb *heartbeater) policyState(endedUnknown bool) map[string]messages.PolicyStateInfo {
	policyStates, err := hb.policyManager.GetPolicyState()
	if err != nil {
		hb.logger.Error("error getting policy state", "error", err)
		return make(map[string]messages.PolicyStateInfo)
	}
	backendStates := hb.backendState.Get()
	ps := make(map[string]messages.PolicyStateInfo)
	var collecting []string
	for _, policyState := range policyStates {
		info := messages.PolicyStateInfo{
			Name:     policyState.Name,
			Datasets: policyState.GetDatasetIDs(),
			State:    policyState.State.String(),
			Error:    policyError(policyState),
			Version:  policyState.Version,
			Backend:  policyState.Backend,
			Runs:     convertRunsToStateInfo(policyState.Runs),
		}
		if endedUnknown && policyState.State == policies.Running && processEnded(backendStates, policyState.Backend) {
			// The policy was running in a process the monitor now finds
			// gone: until the restart brings it back, nothing runs it, and
			// the restart marks it unknown anyway.
			info.State = policies.Unknown.String()
			info.Error = fmt.Sprintf("backend %s is not running: its process ended", policyState.Backend)
		} else if policyState.BackendErr == "" && policyState.State == policies.Running && info.Error != "" {
			collecting = append(collecting, policyState.ID)
		}
		ps[policyState.ID] = info
	}
	boundCollectionErrors(ps, collecting)
	return ps
}

// processEnded reports whether the health monitor's last check found the
// named backend's process gone. One that runs but did not answer that check
// may still run its policies, and one the monitor has not checked since its
// start or last restart is not known to be gone.
func processEnded(states map[string]*backend.State, name string) bool {
	st, ok := states[name]
	return ok && st != nil && st.Ended
}

// boundCollectionErrors keeps the collection errors of the policies
// collecting names in ps to maxCollectionErrorsLen together. When they add
// up to more, the space is shared evenly: an error shorter than its share is
// kept whole, and what it leaves goes to the others, which are cut to their
// share, ending with collectionErrorCut. Why a policy failed to apply is not
// cut: it stays as the policy manager bounded it.
func boundCollectionErrors(ps map[string]messages.PolicyStateInfo, collecting []string) {
	total := 0
	for _, id := range collecting {
		total += len(ps[id].Error)
	}
	if total <= maxCollectionErrorsLen {
		return
	}
	slices.SortFunc(collecting, func(a, b string) int {
		return cmp.Or(cmp.Compare(len(ps[a].Error), len(ps[b].Error)), cmp.Compare(a, b))
	})
	left := maxCollectionErrorsLen
	for i, id := range collecting {
		info := ps[id]
		info.Error = cutCollectionError(info.Error, left/(len(collecting)-i))
		left = max(left-len(info.Error), 0)
		ps[id] = info
	}
}

// cutCollectionError returns message, or, when it is longer than limit, its
// start, cut where a character starts and followed by collectionErrorCut, in
// limit bytes, or in those of collectionErrorCut alone when limit is less.
func cutCollectionError(message string, limit int) string {
	if len(message) <= limit {
		return message
	}
	n := max(limit-len(collectionErrorCut), 0)
	for n > 0 && !utf8.RuneStart(message[n]) {
		n--
	}
	return message[:n] + collectionErrorCut
}

// policyError is the error a policy's state carries: why it failed to apply,
// or, for a running policy, the error its backend reports for its last
// collection (a telemetry policy whose device times out keeps running, with
// the device's error), which is masked and bounded as it is stored. It is ""
// for a running policy collecting without errors.
func policyError(policy policies.PolicyData) string {
	if policy.BackendErr == "" && policy.State == policies.Running {
		return policy.CollectionErr
	}
	return policy.BackendErr
}

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
			ID:            run.ID,
			PolicyID:      run.PolicyID,
			Status:        run.Status,
			Reason:        run.Reason,
			EntityCount:   run.EntityCount,
			CreatedAt:     run.CreatedAt,
			UpdatedAt:     run.UpdatedAt,
			Targets:       run.Targets,
			Driver:        run.Driver,
			Kind:          run.Kind,
			PolicyVersion: run.PolicyVersion,
		}
	}
	return runInfos
}

func (hb *heartbeater) getGroupState() map[string]messages.GroupStateInfo {
	gs := make(map[string]messages.GroupStateInfo)
	for _, group := range hb.groupRetriever.GetAll() {
		gs[group.GroupID] = messages.GroupStateInfo{
			GroupName: group.Name,
			GroupID:   group.GroupID,
		}
	}
	return gs
}

// getBundleState reports, per bundle name, installed/installing/failed state,
// following the same State+Error pattern as getPolicyState/getBackendState: a
// name that has successfully installed at least once but whose most recent
// attempt (e.g. a re-fetch on reconnect) is in flight or failed reports State
// as BundleStateInstalling/BundleStateFailed with Version updated to that
// attempt's version and Error set (when failed), while still retaining
// SHA256/InstalledAt from the last successful install — mirroring how
// BackendStateInfo keeps LastRestartTS/LastRestartReason alongside a current
// Error. A name with no successful install at all reports State/Version/Error
// from the pending entry only.
func (hb *heartbeater) getBundleState() map[string]messages.BundleStateInfo {
	bs := make(map[string]messages.BundleStateInfo)
	if hb.bundleRetriever == nil {
		return bs
	}
	for _, entry := range hb.bundleRetriever.List() {
		bs[entry.Name] = messages.BundleStateInfo{
			State:       messages.BundleStateInstalled,
			Version:     entry.Version,
			SHA256:      entry.SHA256,
			InstalledAt: entry.InstalledAt,
		}
	}
	for _, p := range hb.bundleRetriever.ListPending() {
		info := bs[p.Name] // zero value if no prior successful install
		switch p.State {
		case filesmgr.FileEntryStateInstalling:
			info.State = messages.BundleStateInstalling
		case filesmgr.FileEntryStateFailed:
			info.State = messages.BundleStateFailed
			info.Error = p.Error
		}
		info.Version = p.Version
		info.StateChangedAt = p.UpdatedAt
		bs[p.Name] = info
	}
	return bs
}
