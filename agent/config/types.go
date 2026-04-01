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
	Config string `yaml:"config"`
}

// GitManager represents the Git ConfigManager configuration.
type GitManager struct {
	URL        string  `yaml:"url"`
	Branch     string  `yaml:"branch"`
	Auth       string  `yaml:"auth"`
	Schedule   *string `yaml:"schedule,omitempty"`
	Username   string  `yaml:"username"`
	Password   string  `yaml:"password"`
	PrivateKey string  `yaml:"private_key"`
	SkipTLS    bool    `yaml:"skip_tls"`
}

// FleetManager represents the Fleet ConfigManager configuration.
type FleetManager struct {
	URL                      string `yaml:"url"`
	TokenURL                 string `yaml:"token_url"`
	Timeout                  *int   `yaml:"timeout,omitempty"`
	SkipTLS                  bool   `yaml:"skip_tls"`
	ClientID                 string `yaml:"client_id"`
	ClientSecret             string `yaml:"client_secret"`
	TokenExpiryCheckInterval *int   `yaml:"token_expiry_check_interval,omitempty"` // Check interval in seconds (default: 30)
	TokenReconnectBuffer     *int   `yaml:"token_reconnect_buffer,omitempty"`      // Reconnect buffer in seconds before expiry (default: 120)
	OTLPBridgeGRPCPort       *int   `yaml:"otlp_bridge_grpc_port,omitempty"`       // GRPC port for the OTLP bridge (default: 4317)
	DebugPort                *int   `yaml:"debug_port,omitempty"`                  // Debug HTTP server port (default: OS-assigned); set to enable debug endpoints
}

// Sources represents the configuration for manager sources, including cloud, local and git.
type Sources struct {
	Local LocalManager `yaml:"local"`
	Git   GitManager   `yaml:"git"`
	Fleet FleetManager `yaml:"fleet"`
}

// ManagerConfig represents the configuration for the Config Manager
type ManagerConfig struct {
	Active  string  `yaml:"active"`
	Sources Sources `yaml:"sources"`
}

// VaultManager represents the configuration for the Vault manager
type VaultManager struct {
	Auth      string         `yaml:"auth"`
	AuthArgs  map[string]any `yaml:"auth_args"`
	Address   string         `yaml:"address"`
	Namespace string         `yaml:"namespace"`
	Timeout   *int           `yaml:"timeout,omitempty"`
	Schedule  *string        `yaml:"schedule,omitempty"`
}

// FleetSecretsManager represents the configuration for the Fleet secrets manager
type FleetSecretsManager struct {
	Timeout *int `yaml:"timeout,omitempty"` // Request timeout in seconds
}

// SecretsSources represents the configuration for manager sources, including vault and fleet.
type SecretsSources struct {
	Vault VaultManager        `yaml:"vault"`
	Fleet FleetSecretsManager `yaml:"fleet"`
}

// ManagerSecrets represents the configuration for the Secrets Manager
type ManagerSecrets struct {
	Active  string         `yaml:"active"`
	Sources SecretsSources `yaml:"sources"`
}

// BackendCommons represents common configuration for backends
type BackendCommons struct {
	Otlp struct {
		Grpc        string            `yaml:"grpc"`
		HTTP        string            `yaml:"http"`
		AgentLabels map[string]string `yaml:"agent_labels"`
	} `yaml:"otlp"`
	Diode struct {
		Target          string `yaml:"target"`
		ClientID        string `yaml:"client_id"`
		ClientSecret    string `yaml:"client_secret"`
		AgentName       string `yaml:"agent_name"`
		DryRun          bool   `yaml:"dry_run"`
		DryRunOutputDir string `yaml:"dry_run_output_dir"`
	}
	Debug bool // Debug flag from CLI (not from YAML config)
}

// OrbAgent represents the configuration for the Orb agent
type OrbAgent struct {
	Backends       map[string]any    `yaml:"backends"`
	Policies       map[string]any    `yaml:"policies"`
	Labels         map[string]string `yaml:"labels"`
	ConfigManager  ManagerConfig     `yaml:"config_manager"`
	SecretsManager ManagerSecrets    `yaml:"secrets_manager"`
	Debug          struct {
		Enable bool `yaml:"enable"`
	} `yaml:"debug"`
	ConfigFile string `yaml:"config_file"`
}

// Config represents the overall configuration
type Config struct {
	Version  float64  `yaml:"version"`
	OrbAgent OrbAgent `yaml:"orb"`
}
