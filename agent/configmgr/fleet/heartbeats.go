package fleet

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

const (
	heartbeatFreq = 5 * time.Second
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
	hbData := messages.Heartbeat{
		SchemaVersion: messages.CurrentHeartbeatSchemaVersion,
		TimeStamp:     time.Now().UTC(),
		State:         messages.State(state),
		BackendState:  hb.getBackendState(),
		PolicyState:   hb.getPolicyState(),
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
			Driver:      run.Driver,
			Kind:        run.Kind,
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
