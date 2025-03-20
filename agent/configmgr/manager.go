package configmgr

import (
	"context"

	"go.uber.org/zap"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// Manager is the interface for configuration manager
type Manager interface {
	Start(cfg config.Config, backends map[string]backend.Backend) error
	GetContext(ctx context.Context) context.Context
}

// New creates a new instance of ConfigManager based on the configuration
func New(logger *zap.Logger, mgr policymgr.PolicyManager, c config.ManagerConfig) Manager {
	switch c.Active {
	case "local":
		return &localConfigManager{logger: logger, pMgr: mgr, config: c.Sources.Local}
	case "git":
		return &gitConfigManager{logger: logger, pMgr: mgr, config: c.Sources.Git}
	default:
		return &localConfigManager{logger: logger, pMgr: mgr, config: c.Sources.Local}
	}
}
