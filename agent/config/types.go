package config

// ContextKey represents the key for the context
type ContextKey string

// PolicyPayload represents the payload for the agent policy
type PolicyPayload struct {
	Action       string      `json:"action"`
	ID           string      `json:"id"`
	DatasetID    string      `json:"dataset_id"`
	AgentGroupID string      `json:"agent_group_id"`
	Name         string      `json:"name"`
	Backend      string      `json:"backend"`
	Format       string      `json:"format"`
	Version      int32       `json:"version"`
	Data         interface{} `json:"data"`
}

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

// CloudManager represents the cloud  ConfigManager configuration
type CloudManager struct {
	Config struct {
		AgentName     string `mapstructure:"agent_name"`
		AutoProvision bool   `mapstructure:"auto_provision"`
	} `mapstructure:"config"`
	API  APIConfig  `mapstructure:"api"`
	MQTT MQTTConfig `mapstructure:"mqtt"`
	TLS  struct {
		Verify bool `mapstructure:"verify"`
	} `mapstructure:"tls"`
	DB struct {
		File string `mapstructure:"file"`
	} `mapstructure:"db"`
	Labels map[string]string `mapstructure:"labels"`
}

// LocalManager represents the local ConfigManager configuration.
type LocalManager struct {
	Config string `mapstructure:"config"`
}

// GitManager represents the Git ConfigManager configuration.
type GitManager struct {
	URL        string  `mapstructure:"url"`
	Branch     string  `mapstructure:"branch"`
	Auth       string  `mapstructure:"auth"`
	Schedule   *string `mapstructure:"schedule, omitempty"`
	Username   string  `mapstructure:"username"`
	Password   string  `mapstructure:"password"`
	PrivateKey string  `mapstructure:"private_key"`
}

// ManagerBackends represents the configuration for manager backends, including cloud and local.
type ManagerBackends struct {
	Cloud CloudManager `mapstructure:"orbcloud"`
	Local LocalManager `mapstructure:"local"`
	Git   GitManager   `mapstructure:"git"`
}

// ManagerConfig represents the configuration for the Config Manager
type ManagerConfig struct {
	Active   string          `mapstructure:"active"`
	Backends ManagerBackends `mapstructure:"backends"`
}

// BackendCommons represents common configuration for backends
type BackendCommons struct {
	Otel struct {
		Host        string            `mapstructure:"host"`
		Port        int               `mapstructure:"port"`
		AgentLabels map[string]string `mapstructure:"agent_labels"`
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
	Labels        map[string]string                 `mapstructure:"labels"`
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
