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
	Targets      []string `yaml:"targets"`
	Ports        []string `yaml:"ports,omitempty"`
	ExcludePorts []string `yaml:"exclude_ports,omitempty"`
	Timing       *int     `yaml:"timing,omitempty"`
	FastMode     *bool    `yaml:"fast_mode,omitempty"`
	PingScan     *bool    `yaml:"ping_scan,omitempty"`
	TopPorts     *int     `yaml:"top_ports,omitempty"`
	L4Mode       *string  `yaml:"l4_mode,omitempty"`
}

// Defaults represents the supported default values for a policy
type Defaults struct {
	Description string   `yaml:"description,omitempty"`
	Comments    string   `yaml:"comments,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
}

// PolicyConfig represents the configuration of a policy
type PolicyConfig struct {
	Schedule *string  `yaml:"schedule,omitempty"`
	Defaults Defaults `yaml:"defaults"`
	Timeout  int      `yaml:"timeout"`
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
