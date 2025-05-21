package config

import "time"

// Status represents the status of the snmp-discovery service
type Status struct {
	StartTime     time.Time `json:"start_time"`
	UpTimeSeconds int64     `json:"up_time_seconds"`
	Version       string    `json:"version"`
}

// Scope represents the scope of a policy
type Scope struct {
	Targets        []Target       `yaml:"targets"`
	Authentication Authentication `yaml:"authentication"`
	Retries        int            `yaml:"retries"`
	MappingConfig  string         `yaml:"mapping_config,omitempty"`
	Mappings       []MappingEntry `yaml:"mappings,omitempty"`
}

// Target represents a target host to crawl
type Target struct {
	Host string `yaml:"host"`
	Port uint16 `yaml:"port" default:"161"`
}

// Authentication represents the authentication credentials for a target host
type Authentication struct {
	ProtocolVersion string `yaml:"protocol_version"`
	Community       string `yaml:"community"`
	SecurityLevel   string `yaml:"security_level"`
	Username        string `yaml:"username"`
	AuthProtocol    string `yaml:"auth_protocol"`
	AuthPassphrase  string `yaml:"auth_passphrase"`
	PrivProtocol    string `yaml:"priv_protocol"`
	PrivPassphrase  string `yaml:"priv_passphrase"`
}

// Defaults represents the supported default values for a policy
type Defaults struct {
	Description string   `yaml:"description,omitempty"`
	Comments    string   `yaml:"comments,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
}

// PolicyConfig represents the configuration of a policy
type PolicyConfig struct {
	Schedule    *string  `yaml:"schedule,omitempty"`
	Defaults    Defaults `yaml:"defaults"`
	Timeout     int      `yaml:"timeout"`
	DevicesFile string   `yaml:"devices_file,omitempty"`
}

// Policy represents a snmp-discovery policy
type Policy struct {
	Config PolicyConfig `yaml:"config"`
	Scope  Scope        `yaml:"scope"`
}

// Policies represents a collection of snmp-discovery policies
type Policies struct {
	Policies map[string]Policy `mapstructure:"policies"`
}

// Mapping represents the structure of the mapping YAML file
type Mapping struct {
	Entries []MappingEntry `yaml:"entries"`
}

// MappingEntry represents a single entry in the mapping YAML file
type MappingEntry struct {
	OID            string         `yaml:"oid"`
	Entity         string         `yaml:"entity"`
	Field          string         `yaml:"field"`
	Description    string         `yaml:"description"`
	MappingEntries []MappingEntry `yaml:"mapping_entries"`
	IdentifierSize int            `yaml:"identifier_size"`
	Relationship   Relationship   `yaml:"relationship"`
}

// Relationship represents a relationship between two entities
type Relationship struct {
	Type  string `yaml:"type"`
	Field string `yaml:"field"`
}
