package config

import (
	"context"

	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
)

var _ ConfigManager = (*localConfigManager)(nil)

type localConfigManager struct {
	logger *zap.Logger
	config Config
	db     *sqlx.DB
}

func (oc *localConfigManager) GetConfig() (MQTTConfig, error) {
	return MQTTConfig{Connect: false}, nil
}

func (oc *localConfigManager) GetContext(ctx context.Context) context.Context {
	return ctx
}
