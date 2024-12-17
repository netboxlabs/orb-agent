package config

import (
	"context"

	"go.uber.org/zap"
)

// ConfigManager is the interface for configuration manager
type ConfigManager interface {
	GetConfig() (MQTTConfig, error)
	GetContext(ctx context.Context) context.Context
}

// New creates a new instance of ConfigManager based on the configuration
func New(logger *zap.Logger, c ManagerConfig) ConfigManager {
	switch c.Active {
	case "local":
		return &localConfigManager{logger: logger, config: c.Backends.Local}
	case "cloud":
		return &cloudConfigManager{logger: logger, config: c.Backends.Cloud}
	default:
		return &localConfigManager{logger: logger, config: c.Backends.Local}
	}
}
