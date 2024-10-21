package config

import (
	"context"

	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
)

type ConfigManager interface {
	GetConfig() (MQTTConfig, error)
	GetContext(ctx context.Context) context.Context
}

func New(t string, logger *zap.Logger, c Config, db *sqlx.DB) ConfigManager {
	switch t {
	case "offline":
		return &offlineConfigManager{logger: logger, config: c, db: db}
	case "cloud":
		return &cloudConfigManager{logger: logger, config: c, db: db}
	default:
		return &offlineConfigManager{logger: logger, config: c, db: db}
	}
}
