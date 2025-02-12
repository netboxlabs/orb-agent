package configmgr

import (
	"context"

	"go.uber.org/zap"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/storage/memory"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

var _ Manager = (*gitConfigManager)(nil)

type gitConfigManager struct {
	logger *zap.Logger
	pMgr   policymgr.PolicyManager
	config config.Git
}

func (oc *gitConfigManager) Start(_ config.Config, _ map[string]backend.Backend) error {

	r, err := git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
		URL: "https://github.com/go-git/go-billy",
	})
	if err != nil {
		return err
	}

	ref, err := r.Head()

	if err != nil {
		return err
	}
	oc.logger.Info("Current HEAD: %s", zap.String("ref", ref.Name().String()))
	return nil
}

func (oc *gitConfigManager) GetContext(ctx context.Context) context.Context {
	return ctx
}
