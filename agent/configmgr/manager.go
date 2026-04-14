package configmgr

import (
	"context"
	"log/slog"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// Manager is the interface for configuration manager
type Manager interface {
	Start(ctx context.Context, cfg config.Config, backends map[string]backend.Backend) error
	GetContext(ctx context.Context) context.Context
	Stop(ctx context.Context) error
}

// New creates a new instance of ConfigManager that is bound to the
// supplied context.
func New(logger *slog.Logger, pMgr policymgr.PolicyManager, active string, backendState backend.StateRetriever) Manager {
	switch active {
	case "local":
		return &localConfigManager{logger: logger, pMgr: pMgr}
	case "git":
		return &gitConfigManager{logger: logger, pMgr: pMgr}
	case "fleet":
		return newFleetConfigManager(logger, pMgr, backendState)
	default:
		return &localConfigManager{logger: logger, pMgr: pMgr}
	}
}
