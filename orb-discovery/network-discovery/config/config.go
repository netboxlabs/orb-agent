package config

import "time"

// Status represents the status of the network-discovery service
type Status struct {
	StartTime     time.Time `json:"start_time"`
	UpTimeSeconds int64     `json:"up_time_seconds"`
	Version       string    `json:"version"`
}

// Scope represents the scope of a policy
type Scope struct {
	Targets []string `yaml:"targets"`
}

// PolicyConfig represents the configuration of a policy
type PolicyConfig struct {
	Schedule *string           `yaml:"schedule"`
	Defaults map[string]string `yaml:"defaults"`
	Timeout  int               `yaml:"timeout"`
}

// Policy represents a network-discovery policy
type Policy struct {
	Config PolicyConfig `yaml:"config"`
	Scope  Scope        `yaml:"scope"`
}

// Policies represents a collection of network-discovery policies
type Policies struct {
	Policies map[string]Policy `mapstructure:"policies"`
}
