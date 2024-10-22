package config

type TLS struct {
	Verify bool `mapstructure:"verify"`
}

type APIConfig struct {
	Address string `mapstructure:"address"`
	Token   string `mapstructure:"token"`
}

type DBConfig struct {
	File string `mapstructure:"file"`
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
}

type Local struct {
	Config string `mapstructure:"config"`
}

type Opentelemetry struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

type Debug struct {
	Enable bool `mapstructure:"enable"`
}
type OrbAgent struct {
	Backends      map[string]map[string]string      `mapstructure:"backends"`
	Policies      map[string]map[string]interface{} `mapstructure:"policies"`
	Tags          map[string]string                 `mapstructure:"tags"`
	ConfigManager string                            `mapstructure:"config_manager"`
	Cloud         Cloud                             `mapstructure:"orbcloud"`
	Local         Local                             `mapstructure:"local"`
	TLS           TLS                               `mapstructure:"tls"`
	DB            DBConfig                          `mapstructure:"db"`
	Otel          Opentelemetry                     `mapstructure:"otel"`
	Debug         Debug                             `mapstructure:"debug"`
}

type Config struct {
	Version  float64  `mapstructure:"version"`
	OrbAgent OrbAgent `mapstructure:"orb"`
}
