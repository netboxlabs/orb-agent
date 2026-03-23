package fleet

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

const (
	heartbeatFreq = 5 * time.Second
)

// heartbeatTickInterval is the delay between periodic heartbeats. Tests shorten it.
var heartbeatTickInterval = heartbeatFreq

type heartbeater struct {
	logger         *slog.Logger
	heartbeatCtx   context.Context
	backendState   backend.StateRetriever
	policyManager  policymgr.PolicyManager
	groupRetriever GroupRetriever

	mu            sync.Mutex
	sessionCancel context.CancelFunc
	wg            sync.WaitGroup
}

func newHeartbeater(logger *slog.Logger, backendState backend.StateRetriever, policyManager policymgr.PolicyManager, groupRetriever GroupRetriever) *heartbeater {
	return &heartbeater{
		logger:         logger,
		heartbeatCtx:   context.Background(),
		backendState:   backendState,
		policyManager:  policyManager,
		groupRetriever: groupRetriever,
	}
}

// StartHeartbeats begins a heartbeat session: it cancels any prior session, waits for it to exit,
// then starts a new loop with its own ticker until the session context is cancelled or stop() runs.
func (hb *heartbeater) StartHeartbeats(parentCtx context.Context, heartbeatTopic string, agentID string, publishFunc func(ctx context.Context, topic string, payload []byte) error, onFailure func()) {
	hb.mu.Lock()
	if hb.sessionCancel != nil {
		prev := hb.sessionCancel
		hb.sessionCancel = nil
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
		return
	}

	hb.sendSingleHeartbeat(context.Background(), heartbeatTopic, publishFunc, "", time.Now(), messages.HeartbeatState(messages.Offline), nil)
}

func (hb *heartbeater) runHeartbeatLoop(ctx context.Context, ticker *time.Ticker, heartbeatTopic string, agentID string, publishFunc func(ctx context.Context, topic string, payload []byte) error, onFailure func()) {
	hb.heartbeatCtx = ctx

	hb.logger.Debug("start heartbeats routine")
	hb.sendSingleHeartbeat(ctx, heartbeatTopic, publishFunc, agentID, time.Now(), messages.Online, onFailure)

	for {
		select {
		case <-ctx.Done():
			hb.logger.Debug("context done, stopping heartbeats routine")
			hb.sendSingleHeartbeat(context.Background(), heartbeatTopic, publishFunc, agentID, time.Now(), messages.Offline, nil)
			hb.heartbeatCtx = nil
			return
		case t := <-ticker.C:
			hb.sendSingleHeartbeat(ctx, heartbeatTopic, publishFunc, agentID, t, messages.Online, onFailure)
		}
	}
}

func (hb *heartbeater) sendSingleHeartbeat(ctx context.Context, heartbeatTopic string, publishFunc func(ctx context.Context, topic string, payload []byte) error, _ string, _ time.Time, _ messages.HeartbeatState, onFailure func()) {
	hbData := messages.Heartbeat{
		SchemaVersion: messages.CurrentHeartbeatSchemaVersion,
		TimeStamp:     time.Now().UTC(),
		State:         messages.State(messages.Online),
		BackendState:  hb.getBackendState(),
		PolicyState:   hb.getPolicyState(),
		GroupState:    hb.getGroupState(),
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
