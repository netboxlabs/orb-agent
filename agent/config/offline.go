package config

import (
	"context"

	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
)

var _ ConfigManager = (*offlineConfigManager)(nil)

type offlineConfigManager struct {
	logger *zap.Logger
	config Config
	db     *sqlx.DB
}

func (oc *offlineConfigManager) GetConfig() (MQTTConfig, error) {
	return MQTTConfig{}, nil
}

func (oc *offlineConfigManager) GetContext(ctx context.Context) context.Context {
	return ctx
}
