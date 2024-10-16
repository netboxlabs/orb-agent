package config

type ConfigManager interface {
	GetConfig() (MQTTConfig, error)
}
