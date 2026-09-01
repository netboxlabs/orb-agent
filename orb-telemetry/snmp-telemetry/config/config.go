package config

import "time"

// MaxDurationSeconds bounds every value this backend states in seconds before
// it is multiplied by time.Second. The multiply overflows an int64 above
// roughly 9.2e9 and the wrapped value is small, so an outsized number becomes a
// tight duration that every later check accepts for the wrong reason.
//
// The bound is a year rather than that representable ceiling of about 292
// years: no collection interval or export period reaches it, and keeping a
// duration this far inside the range also keeps snmp_timeout times the capped
// attempt count from wrapping. It is stated here so the policy fields and the
// export period flag share one number rather than each picking their own.
const MaxDurationSeconds = 365 * 24 * 60 * 60

// Status represents the status of the snmp-telemetry service
type Status struct {
	StartTime     time.Time `json:"start_time"`
	UpTimeSeconds int64     `json:"up_time_seconds"`
	Version       string    `json:"version"`
}

// Policies represents a collection of policies (used for HTTP API body parsing)
type Policies struct {
	Policies map[string]Policy `yaml:"policies"`
}

// Scope represents the scope of a policy
type Scope struct {
	Targets        []Target       `yaml:"targets"`
	Authentication Authentication `yaml:"authentication"`
}

// Target represents a target host to collect metrics from
type Target struct {
	Host           string          `yaml:"host"`
	Port           uint16          `yaml:"port" default:"161"`
	ID             string          `yaml:"id,omitempty"`
	Authentication *Authentication `yaml:"authentication,omitempty"`
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
	// ContextName is the SNMPv3 context name (snmpwalk -n). Devices that expose
	// their MIB data in a named context return nothing for the default context,
	// so an absent value looks like a successful empty walk. Rejected for
	// v1/v2c, which have no context concept.
	ContextName string `yaml:"context_name,omitempty"`
}

// PolicyConfig represents the configuration of a metrics collection policy
type PolicyConfig struct {
	Schedule        *string `yaml:"schedule,omitempty"`
	MetricsInterval *int    `yaml:"metrics_interval"`
	ProfilesDir     string  `yaml:"profiles_dir,omitempty"`
	SNMPTimeout     int     `yaml:"snmp_timeout"`
	Retries         int     `yaml:"retries"`
}

// Policy represents a snmp-telemetry metrics collection policy
type Policy struct {
	Config PolicyConfig `yaml:"config"`
	Scope  Scope        `yaml:"scope"`
}
