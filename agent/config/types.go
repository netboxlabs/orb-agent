package config

type APIConfig struct {
	Address string `mapstructure:"address"`
	Token   string `mapstructure:"token"`
}

type MQTTConfig struct {
	Connect   bool   `mapstructure:"connect"`
	Address   string `mapstructure:"address"`
	Id        string `mapstructure:"id"`
	Key       string `mapstructure:"key"`
	ChannelID string `mapstructure:"channel_id"`
}

type CloudConfig struct {
	AgentName     string `mapstructure:"agent_name"`
	AutoProvision bool   `mapstructure:"auto_provision"`
}

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

type Local struct {
	Config string `mapstructure:"config"`
}

type ManagerBackends struct {
	Cloud Cloud `mapstructure:"orbcloud"`
	Local Local `mapstructure:"local"`
}

type ManagerConfig struct {
	Active   string          `mapstructure:"active"`
	Backends ManagerBackends `mapstructure:"backends"`
}

type BackendCommons struct {
	Otel struct {
		Host      string            `mapstructure:"host"`
		Port      int               `mapstructure:"port"`
		AgentTags map[string]string `mapstructure:"agent_tags"`
	} `mapstructure:"otel"`
	Diode struct {
		Target string `mapstructure:"target"`
		APIKey string `mapstructure:"api_key"`
	}
}
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

type Config struct {
	Version  float64  `mapstructure:"version"`
	OrbAgent OrbAgent `mapstructure:"orb"`
}
