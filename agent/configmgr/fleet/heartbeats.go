package fleet

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
)

const (
	heartbeatFreq = 5 * time.Second
)

type heartbeater struct {
	logger       *slog.Logger
	hbTicker     *time.Ticker
	heartbeatCtx context.Context
}

func newHeartbeater(logger *slog.Logger) *heartbeater {
	return &heartbeater{
		logger:       logger,
		hbTicker:     time.NewTicker(heartbeatFreq),
		heartbeatCtx: context.Background(),
	}
}

func (hb *heartbeater) stop() {
	hb.hbTicker.Stop()
}

func (hb *heartbeater) sendSingleHeartbeat(ctx context.Context, publishFunc func(ctx context.Context, payload []byte) error, _ string, _ time.Time, _ messages.HeartbeatState) {
	hbData := messages.Heartbeat{
		SchemaVersion: messages.CurrentHeartbeatSchemaVersion,
		TimeStamp:     time.Now().UTC(),
		State:         1,
	}

	body, err := json.Marshal(hbData)
	if err != nil {
		hb.logger.Error("error marshalling heartbeat", "error", err)
		return
	}

	if err := publishFunc(ctx, body); err != nil {
		hb.logger.Error("error sending heartbeat", "error", err)
	} else {
		hb.logger.Debug("heartbeat sent", "payload", string(body))
	}
}

// sendHeartbeats starts a goroutine that periodically issues heartbeats until the
// supplied context is cancelled.  The cancelFunc parameter is ignored by the
// implementation but is accepted for backward-compatibility with unit tests
// that expect to pass it.
func (hb *heartbeater) sendHeartbeats(ctx context.Context, _ context.CancelFunc, publishFunc func(ctx context.Context, payload []byte) error, agentID string) {
	// Update our internal reference so other methods that read hb.heartbeatCtx
	// (if any) remain accurate.
	hb.heartbeatCtx = ctx

	hb.logger.Debug("start heartbeats routine")
	hb.sendSingleHeartbeat(ctx, publishFunc, agentID, time.Now(), messages.Online)

	for {
		select {
		case <-ctx.Done():
			hb.logger.Debug("context done, stopping heartbeats routine")
			hb.sendSingleHeartbeat(ctx, publishFunc, agentID, time.Now(), messages.Offline)
			hb.heartbeatCtx = nil
			return
		case t := <-hb.hbTicker.C:
			hb.sendSingleHeartbeat(ctx, publishFunc, agentID, t, messages.Online)
		}
	}
}
