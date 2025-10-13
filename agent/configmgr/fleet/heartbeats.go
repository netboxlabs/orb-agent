package fleet

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
)

const (
	heartbeatFreq = 5 * time.Second
)

type heartbeater struct {
	logger       *slog.Logger
	hbTicker     *time.Ticker
	heartbeatCtx context.Context
	backendState backend.BackendState
}

func newHeartbeater(logger *slog.Logger, backendState backend.BackendState) *heartbeater {
	return &heartbeater{
		logger:       logger,
		hbTicker:     time.NewTicker(heartbeatFreq),
		heartbeatCtx: context.Background(),
		backendState: backendState,
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
		PolicyState:   make(map[string]messages.PolicyStateInfo),
		GroupState:    make(map[string]messages.GroupStateInfo),
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
