package configmgr

import (
	"context"

	"go.uber.org/zap"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
	"github.com/netboxlabs/orb-agent/agent/secretsmgr"
)

// Manager is the interface for configuration manager
type Manager interface {
	Start(cfg config.Config, backends map[string]backend.Backend) error
	GetContext(ctx context.Context) context.Context
}

// New creates a new instance of ConfigManager based on the configuration
func New(logger *zap.Logger, pMgr policymgr.PolicyManager, sMgr secretsmgr.Manager, c config.ManagerConfig) Manager {
	switch c.Active {
	case "local":
		return &localConfigManager{logger: logger, pMgr: pMgr, sMgr: sMgr, config: c.Sources.Local}
	case "cloud":
		return &cloudConfigManager{logger: logger, pMgr: pMgr, config: c.Sources.Cloud}
	case "git":
		return &gitConfigManager{logger: logger, pMgr: pMgr, sMgr: sMgr, config: c.Sources.Git}
	default:
		return &localConfigManager{logger: logger, pMgr: pMgr, sMgr: sMgr, config: c.Sources.Local}
	}
}
