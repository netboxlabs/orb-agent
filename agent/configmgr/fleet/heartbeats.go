package fleet

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

const (
	heartbeatFreq = 5 * time.Second
)

type heartbeater struct {
	logger         *slog.Logger
	hbTicker       *time.Ticker
	heartbeatCtx   context.Context
	backendState   backend.StateRetriever
	policyManager  policymgr.PolicyManager
	groupRetriever GroupRetriever
}

func newHeartbeater(logger *slog.Logger, backendState backend.StateRetriever, policyManager policymgr.PolicyManager, groupRetriever GroupRetriever) *heartbeater {
	return &heartbeater{
		logger:         logger,
		hbTicker:       time.NewTicker(heartbeatFreq),
		heartbeatCtx:   context.Background(),
		backendState:   backendState,
		policyManager:  policyManager,
		groupRetriever: groupRetriever,
	}
}

func (hb *heartbeater) stop(heartbeatTopic string, publishFunc func(ctx context.Context, topic string, payload []byte) error) {
	hb.hbTicker.Stop()
	hb.sendSingleHeartbeat(hb.heartbeatCtx, heartbeatTopic, publishFunc, "", time.Now(), messages.HeartbeatState(messages.Offline))
}

func (hb *heartbeater) sendSingleHeartbeat(ctx context.Context, heartbeatTopic string, publishFunc func(ctx context.Context, topic string, payload []byte) error, _ string, _ time.Time, _ messages.HeartbeatState) {
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
		}
	}
	return ps
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

// sendHeartbeats starts a goroutine that periodically issues heartbeats until the
// supplied context is cancelled.  The cancelFunc parameter is ignored by the
// implementation but is accepted for backward-compatibility with unit tests
// that expect to pass it.
func (hb *heartbeater) sendHeartbeats(ctx context.Context, _ context.CancelFunc, heartbeatTopic string, agentID string, publishFunc func(ctx context.Context, topic string, payload []byte) error) {
	// Update our internal reference so other methods that read hb.heartbeatCtx
	// (if any) remain accurate.
	hb.heartbeatCtx = ctx

	hb.logger.Debug("start heartbeats routine")
	hb.sendSingleHeartbeat(ctx, heartbeatTopic, publishFunc, agentID, time.Now(), messages.Online)

	for {
		select {
		case <-ctx.Done():
			hb.logger.Debug("context done, stopping heartbeats routine")
			hb.sendSingleHeartbeat(ctx, heartbeatTopic, publishFunc, agentID, time.Now(), messages.Offline)
			hb.heartbeatCtx = nil
			return
		case t := <-hb.hbTicker.C:
			hb.sendSingleHeartbeat(ctx, heartbeatTopic, publishFunc, agentID, t, messages.Online)
		}
	}
}
