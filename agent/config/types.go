package config

// ContextKey represents the key for the context
type ContextKey string

// APIConfig represents the configuration for the API connection
type APIConfig struct {
	Address string `mapstructure:"address"`
	Token   string `mapstructure:"token"`
}

// MQTTConfig represents the configuration for the MQTT connection
type MQTTConfig struct {
	Connect   bool   `mapstructure:"connect"`
	Address   string `mapstructure:"address"`
	ID        string `mapstructure:"id"`
	Key       string `mapstructure:"key"`
	ChannelID string `mapstructure:"channel_id"`
}

// CloudConfig represents the configuration for the cloud agent
type CloudConfig struct {
	AgentName     string `mapstructure:"agent_name"`
	AutoProvision bool   `mapstructure:"auto_provision"`
}

// Cloud represents the cloud  ConfigManager configuration
type Cloud struct {
	Config CloudConfig `mapstructure:"config"`
	API    APIConfig   `mapstructure:"api"`
	MQTT   MQTTConfig  `mapstructure:"mqtt"`
	TLS    struct {
		Verify bool `mapstructure:"verify"`
	} `mapstructure:"tls"`
	DB struct {
		File string `mapstructure:"file"`
	} `mapstructure:"db"`
	Tags map[string]string `mapstructure:"tags"`
}

// Local represents the local ConfigManager configuration.
type Local struct {
	Config string `mapstructure:"config"`
}

// ManagerBackends represents the configuration for manager backends, including cloud and local.
type ManagerBackends struct {
	Cloud Cloud `mapstructure:"orbcloud"`
	Local Local `mapstructure:"local"`
}

// ManagerConfig represents the configuration for the Config Manager
type ManagerConfig struct {
	Active   string          `mapstructure:"active"`
	Backends ManagerBackends `mapstructure:"backends"`
}

// BackendCommons represents common configuration for backends
type BackendCommons struct {
	Otel struct {
		Host      string            `mapstructure:"host"`
		Port      int               `mapstructure:"port"`
		AgentTags map[string]string `mapstructure:"agent_tags"`
	} `mapstructure:"otel"`
	Diode struct {
		Target    string `mapstructure:"target"`
		APIKey    string `mapstructure:"api_key"`
		AgentName string `mapstructure:"agent_name"`
	}
}

// OrbAgent represents the configuration for the Orb agent
type OrbAgent struct {
	Backends      map[string]map[string]interface{} `mapstructure:"backends"`
	Policies      map[string]map[string]interface{} `mapstructure:"policies"`
	Tags          map[string]string                 `mapstructure:"tags"`
	ConfigManager ManagerConfig                     `mapstructure:"config_manager"`
	Debug         struct {
		Enable bool `mapstructure:"enable"`
	} `mapstructure:"debug"`
	ConfigFile string `mapstructure:"config_file"`
}

// Config represents the overall configuration
type Config struct {
	Version  float64  `mapstructure:"version"`
	OrbAgent OrbAgent `mapstructure:"orb"`
}
