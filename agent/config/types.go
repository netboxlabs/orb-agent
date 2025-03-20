package config

// ContextKey represents the key for the context
type ContextKey string

// PolicyPayload represents the payload for the agent policy
type PolicyPayload struct {
	Action       string `json:"action"`
	ID           string `json:"id"`
	DatasetID    string `json:"dataset_id"`
	AgentGroupID string `json:"agent_group_id"`
	Name         string `json:"name"`
	Backend      string `json:"backend"`
	Format       string `json:"format"`
	Version      int32  `json:"version"`
	Data         any    `json:"data"`
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

// ManagerSources represents the configuration for manager sources, including cloud, local and git.
type ManagerSources struct {
	Local LocalManager `mapstructure:"local"`
	Git   GitManager   `mapstructure:"git"`
}

// ManagerConfig represents the configuration for the Config Manager
type ManagerConfig struct {
	Active  string         `mapstructure:"active"`
	Sources ManagerSources `mapstructure:"sources"`
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
	Backends      map[string]map[string]any `mapstructure:"backends"`
	Policies      map[string]map[string]any `mapstructure:"policies"`
	Labels        map[string]string         `mapstructure:"labels"`
	ConfigManager ManagerConfig             `mapstructure:"config_manager"`
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
