package config

import (
	"context"

	"go.uber.org/zap"
)

var _ Manager = (*gitConfigManager)(nil)

type gitConfigManager struct {
	logger *zap.Logger
	config Git
}

func (oc *gitConfigManager) GetConfig() (MQTTConfig, error) {
	return MQTTConfig{Connect: false}, nil
}

func (oc *gitConfigManager) GetContext(ctx context.Context) context.Context {
	return ctx
}
