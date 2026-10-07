package config

import (
	"fmt"
	"time"

	"go.yaml.in/yaml/v3"
)

// Hostname represents a hostname associated with a host
type Hostname struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Port represents a network port
type Port struct {
	Number   int    `json:"number"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	State    string `json:"state"`
}

// ExtraPort represents additional port information
type ExtraPort struct {
	State string `json:"state"`
	Count int    `json:"count"`
}

// HostMetadata represents the metadata of a host
type HostMetadata struct {
	Hostnames  []Hostname  `json:"hostnames"`
	Ports      []Port      `json:"ports"`
	ExtraPorts []ExtraPort `json:"extra_ports"`
}

// Status represents the status of the network-discovery service
type Status struct {
	StartTime     time.Time `json:"start_time"`
	UpTimeSeconds int64     `json:"up_time_seconds"`
	Version       string    `json:"version"`
}

// Scope represents the scope of a policy
type Scope struct {
	Targets        []string `yaml:"targets"`
	Ports          []string `yaml:"ports,omitempty"`
	ExcludePorts   []string `yaml:"exclude_ports,omitempty"`
	Timing         *int     `yaml:"timing,omitempty"`
	FastMode       *bool    `yaml:"fast_mode,omitempty"`
	PingScan       *bool    `yaml:"ping_scan,omitempty"`
	TopPorts       *int     `yaml:"top_ports,omitempty"`
	ScanTypes      []string `yaml:"scan_types,omitempty"`
	MaxRetries     *int     `yaml:"max_retries,omitempty"`
	DNSServers     []string `yaml:"dns_servers,omitempty"`
	OSDetection    *bool    `yaml:"os_detection,omitempty"`
	UseTargetMasks *bool    `yaml:"use_target_masks,omitempty"`
	ICMPEcho       *bool    `yaml:"icmp_echo,omitempty"`
	ICMPTimestamp  *bool    `yaml:"icmp_timestamp,omitempty"`
	ICMPNetMask    *bool    `yaml:"icmp_netmask,omitempty"`
	SkipHost       *bool    `yaml:"skip_host,omitempty"`
}

// TenantParameters names the tenant applied to discovered IP addresses.
// Accepts either a plain string (tenant name) or a mapping, mirroring
// snmp-discovery and device-discovery defaults.tenant.
type TenantParameters struct {
	Name        string   `yaml:"name"`
	Group       string   `yaml:"group,omitempty"`
	Description string   `yaml:"description,omitempty"`
	Comments    string   `yaml:"comments,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
}

// UnmarshalYAML accepts a scalar tenant name or a mapping.
func (t *TenantParameters) UnmarshalYAML(node *yaml.Node) error {
	*t = TenantParameters{}
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag == "!!null" {
			return nil
		}
		t.Name = node.Value
		return nil
	case yaml.MappingNode:
		type alias TenantParameters
		var a alias
		if err := node.Decode(&a); err != nil {
			return err
		}
		if a.Name == "" {
			return fmt.Errorf("tenant: mapping requires name")
		}
		*t = TenantParameters(a)
		return nil
	default:
		return fmt.Errorf("tenant: expected string or mapping, got node kind %d", node.Kind)
	}
}

// VrfParameters names the VRF applied to discovered IP addresses. Accepts
// either a plain string (VRF name) or a mapping, mirroring snmp-discovery and
// device-discovery defaults.vrf. Tenant is the VRF's own tenant, so a VRF
// owned by a tenant in NetBox is matched instead of created again.
type VrfParameters struct {
	Name        string           `yaml:"name"`
	Rd          string           `yaml:"rd,omitempty"`
	Tenant      TenantParameters `yaml:"tenant,omitempty"`
	Description string           `yaml:"description,omitempty"`
	Comments    string           `yaml:"comments,omitempty"`
	Tags        []string         `yaml:"tags,omitempty"`
}

// UnmarshalYAML accepts a scalar VRF name or a mapping.
func (v *VrfParameters) UnmarshalYAML(node *yaml.Node) error {
	*v = VrfParameters{}
	switch node.Kind {
	case yaml.ScalarNode:
		v.Name = node.Value
		return nil
	case yaml.MappingNode:
		type alias VrfParameters
		var a alias
		if err := node.Decode(&a); err != nil {
			return err
		}
		if a.Name == "" {
			return fmt.Errorf("vrf: mapping requires name")
		}
		*v = VrfParameters(a)
		return nil
	default:
		return fmt.Errorf("vrf: expected string or mapping, got node kind %d", node.Kind)
	}
}

// Defaults represents the supported default values for a policy
type Defaults struct {
	Vrf         VrfParameters    `yaml:"vrf,omitempty"`
	Rd          string           `yaml:"rd,omitempty"`
	Tenant      TenantParameters `yaml:"tenant,omitempty"`
	Role        string           `yaml:"role,omitempty"`
	Description string           `yaml:"description,omitempty"`
	Comments    string           `yaml:"comments,omitempty"`
	Tags        []string         `yaml:"tags,omitempty"`
	NetworkMask *int             `yaml:"network_mask,omitempty"`
}

// Validate rejects defaults that name two different route distinguishers for
// the VRF, since either choice could match the wrong VRF.
func (d Defaults) Validate() error {
	if d.Rd != "" && d.Vrf.Rd != "" && d.Rd != d.Vrf.Rd {
		return fmt.Errorf("defaults.rd %q conflicts with defaults.vrf.rd %q; set the rd in one place", d.Rd, d.Vrf.Rd)
	}
	return nil
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
