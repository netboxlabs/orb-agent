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
}

// Target represents a target host to crawl
type Target struct {
	Host             string          `yaml:"host"`
	Port             uint16          `yaml:"port" default:"161"`
	Authentication   *Authentication `yaml:"authentication,omitempty"`
	OverrideDefaults *Defaults       `yaml:"override_defaults,omitempty"`
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

// IPAddressDefaults represents default values for a specific entity type
type IPAddressDefaults struct {
	Description string   `yaml:"description,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	Comments    string   `yaml:"comments,omitempty"`
	Role        string   `yaml:"role,omitempty"`
	Tenant      string   `yaml:"tenant,omitempty"`
	Vrf         string   `yaml:"vrf,omitempty"`
}

// InterfaceDefaults represents default values for a specific entity type
type InterfaceDefaults struct {
	Description string   `yaml:"description,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	Type        string   `yaml:"if_type,omitempty"`
}

// InterfacePattern represents a regex pattern for interface type matching
type InterfacePattern struct {
	Match string `yaml:"match"` // Regex pattern for interface name
	Type  string `yaml:"type"`  // NetBox interface type to assign
}

// DeviceDefaults represents default values for a specific entity type
type DeviceDefaults struct {
	Description string   `yaml:"description,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	Comments    string   `yaml:"comments,omitempty"`
}

// Defaults represents the supported default values for a policy
type Defaults struct {
	Tags              []string           `yaml:"tags,omitempty"`
	Site              string             `yaml:"site,omitempty"`
	Location          string             `yaml:"location,omitempty"`
	Role              string             `yaml:"role,omitempty"`
	IPAddress         IPAddressDefaults  `yaml:"ip_address,omitempty"`
	Interface         InterfaceDefaults  `yaml:"interface,omitempty"`
	Device            DeviceDefaults     `yaml:"device,omitempty"`
	InterfacePatterns []InterfacePattern `yaml:"interface_patterns,omitempty"`
}

// MergeDefaults merges target-level override defaults with policy-level defaults
// Target overrides take precedence over policy defaults for non-zero values
func MergeDefaults(policyDefaults, overrideDefaults *Defaults) *Defaults {
	if overrideDefaults == nil {
		return policyDefaults
	}

	// Create a copy of policy defaults
	merged := *policyDefaults

	// Override top-level fields if set in override
	if overrideDefaults.Site != "" {
		merged.Site = overrideDefaults.Site
	}
	if overrideDefaults.Location != "" {
		merged.Location = overrideDefaults.Location
	}
	if overrideDefaults.Role != "" {
		merged.Role = overrideDefaults.Role
	}
	if len(overrideDefaults.Tags) > 0 {
		merged.Tags = overrideDefaults.Tags
	}

	// Merge IPAddress defaults
	if overrideDefaults.IPAddress.Description != "" {
		merged.IPAddress.Description = overrideDefaults.IPAddress.Description
	}
	if len(overrideDefaults.IPAddress.Tags) > 0 {
		merged.IPAddress.Tags = overrideDefaults.IPAddress.Tags
	}
	if overrideDefaults.IPAddress.Comments != "" {
		merged.IPAddress.Comments = overrideDefaults.IPAddress.Comments
	}
	if overrideDefaults.IPAddress.Role != "" {
		merged.IPAddress.Role = overrideDefaults.IPAddress.Role
	}
	if overrideDefaults.IPAddress.Tenant != "" {
		merged.IPAddress.Tenant = overrideDefaults.IPAddress.Tenant
	}
	if overrideDefaults.IPAddress.Vrf != "" {
		merged.IPAddress.Vrf = overrideDefaults.IPAddress.Vrf
	}

	// Merge Interface defaults
	if overrideDefaults.Interface.Description != "" {
		merged.Interface.Description = overrideDefaults.Interface.Description
	}
	if len(overrideDefaults.Interface.Tags) > 0 {
		merged.Interface.Tags = overrideDefaults.Interface.Tags
	}
	if overrideDefaults.Interface.Type != "" {
		merged.Interface.Type = overrideDefaults.Interface.Type
	}

	// Merge Device defaults
	if overrideDefaults.Device.Description != "" {
		merged.Device.Description = overrideDefaults.Device.Description
	}
	if len(overrideDefaults.Device.Tags) > 0 {
		merged.Device.Tags = overrideDefaults.Device.Tags
	}
	if overrideDefaults.Device.Comments != "" {
		merged.Device.Comments = overrideDefaults.Device.Comments
	}

	// Override InterfacePatterns if provided
	if len(overrideDefaults.InterfacePatterns) > 0 {
		merged.InterfacePatterns = overrideDefaults.InterfacePatterns
	}

	return &merged
}

// PolicyConfig represents the configuration of a policy
type PolicyConfig struct {
	Schedule            *string  `yaml:"schedule,omitempty"`
	Defaults            Defaults `yaml:"defaults"`
	Timeout             int      `yaml:"timeout"`
	SNMPTimeout         int      `yaml:"snmp_timeout"`
	SNMPProbeTimeout    int      `yaml:"snmp_probe_timeout"`
	Retries             int      `yaml:"retries"`
	LookupExtensionsDir string   `yaml:"lookup_extensions_dir,omitempty"`
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
