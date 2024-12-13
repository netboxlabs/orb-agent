package config

import (
	"context"

	"go.uber.org/zap"
)

var _ ConfigManager = (*localConfigManager)(nil)

type localConfigManager struct {
	logger *zap.Logger
	config Local
}

func (oc *localConfigManager) GetConfig() (MQTTConfig, error) {
	return MQTTConfig{Connect: false}, nil
}

func (oc *localConfigManager) GetContext(ctx context.Context) context.Context {
	return ctx
}
