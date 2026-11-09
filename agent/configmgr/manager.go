package configmgr

import (
	"context"
	"log/slog"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// Manager is the interface for configuration manager
type Manager interface {
	Start(ctx context.Context, cfg config.Config, backends map[string]backend.Backend) error
	GetContext(ctx context.Context) context.Context
	Stop(ctx context.Context) error
}

// ConfigReporter is a config manager that reports the agent's config. The
// agent hands it the config as written, before it resolves the secret
// references in it, and the manager reports that one: a value read from a
// secrets manager never leaves the agent in its reported config.
type ConfigReporter interface {
	ReportConfig(cfg config.Config)
}

// New creates a new instance of ConfigManager that is bound to the
// supplied context.
func New(logger *slog.Logger, pMgr policymgr.PolicyManager, active string, backendState backend.StateRetriever, fm filesmgr.Manager) Manager {
	switch active {
	case "local":
		return &localConfigManager{logger: logger, pMgr: pMgr} // fm unused: local/git mode has no fleet bundle delivery
	case "git":
		return &gitConfigManager{logger: logger, pMgr: pMgr}
	case "fleet":
		return newFleetConfigManager(logger, pMgr, backendState, fm)
	default:
		return &localConfigManager{logger: logger, pMgr: pMgr} // fm unused: local/git mode has no fleet bundle delivery
	}
}
