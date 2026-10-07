package config

import (
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
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
			return errors.New("tenant: mapping requires name")
		}
		*t = TenantParameters(a)
		return nil
	default:
		return fmt.Errorf("tenant: expected string or mapping, got node kind %d", node.Kind)
	}
}

// VrfParameters names the VRF applied to discovered IP addresses. Accepts
// either a plain string (VRF name) or a mapping, the shape snmp-discovery and
// device-discovery use for defaults.vrf plus the VRF's own tenant, so a VRF
// owned by a tenant in NetBox is matched instead of created again.
type VrfParameters struct {
	Name        string           `yaml:"name"`
	Rd          string           `yaml:"rd,omitempty"`
	Tenant      TenantParameters `yaml:"tenant,omitempty"`
	Description string           `yaml:"description,omitempty"`
	Comments    string           `yaml:"comments,omitempty"`
	Tags        []string         `yaml:"tags,omitempty"`
}

// The keys a vrf mapping, and the tenant inside it, accept.
var (
	vrfKeys    = yamlFieldNames(reflect.TypeFor[VrfParameters]())
	tenantKeys = yamlFieldNames(reflect.TypeFor[TenantParameters]())
)

// UnmarshalYAML accepts a scalar VRF name or a mapping. An unknown key in the
// mapping or in its tenant is refused: a misspelt tenant or group would
// otherwise leave the VRF matching no tenant, and Diode would create the
// duplicate the tenant is there to prevent. Errors name the path rather than
// a line, since the agent re-marshals a policy before sending it.
func (v *VrfParameters) UnmarshalYAML(node *yaml.Node) error {
	*v = VrfParameters{}
	switch node.Kind {
	case yaml.ScalarNode:
		v.Name = node.Value
		return nil
	case yaml.MappingNode:
		fields, err := mappingFields(node, "vrf", vrfKeys)
		if err != nil {
			return err
		}
		if tenant, ok := fields["tenant"]; ok {
			if err := checkVrfTenant(tenant); err != nil {
				return err
			}
		}
		type alias VrfParameters
		var a alias
		if err := node.Decode(&a); err != nil {
			return err
		}
		if trim(a.Name) == "" {
			return errors.New("vrf: mapping requires name")
		}
		*v = VrfParameters(a)
		return nil
	default:
		return fmt.Errorf("vrf: expected string or mapping, got node kind %d", node.Kind)
	}
}

// mappingFields decodes a mapping once merge keys and aliases resolve, and
// refuses a key outside known.
func mappingFields(node *yaml.Node, path string, known map[string]bool) (map[string]yaml.Node, error) {
	var fields map[string]yaml.Node
	if err := node.Decode(&fields); err != nil {
		return nil, err
	}
	for _, key := range slices.Sorted(maps.Keys(fields)) {
		if !known[key] {
			return nil, fmt.Errorf("%s has no %q key", path, key)
		}
	}
	return fields, nil
}

// checkVrfTenant refuses a vrf.tenant mapping with an unknown key or no name,
// naming the path: the tenant's own error reads the same as defaults.tenant's.
func checkVrfTenant(node yaml.Node) error {
	for node.Kind == yaml.AliasNode {
		node = *node.Alias
	}
	if node.Kind != yaml.MappingNode {
		return nil
	}
	fields, err := mappingFields(&node, "vrf.tenant", tenantKeys)
	if err != nil {
		return err
	}
	var name string
	if n, ok := fields["name"]; !ok || n.Decode(&name) != nil || trim(name) == "" {
		return errors.New("vrf.tenant: mapping requires name")
	}
	return nil
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

// Validate rejects defaults Diode would apply wrongly or refuse: two different
// route distinguishers for the VRF, since either could match the wrong VRF,
// or the address's and the VRF's copies of one tenant written two ways, since
// Diode then refuses every address or rewrites the tenant on every run.
func (d Defaults) Validate() error {
	if d.Vrf.Name != "" && trim(d.Vrf.Name) == "" {
		return errors.New("defaults.vrf has a blank name; Diode trims it to nothing and refuses the address")
	}
	rd, vrfRd := trim(d.Rd), trim(d.Vrf.Rd)
	if rd != "" && vrfRd != "" && rd != vrfRd {
		return fmt.Errorf("defaults.rd %q conflicts with defaults.vrf.rd %q; set the rd in one place", d.Rd, d.Vrf.Rd)
	}
	if t := d.Vrf.Tenant; trim(t.Name) == "" && (t.Name != "" || t.Group != "" || t.Description != "" || t.Comments != "" || len(t.Tags) > 0) {
		return errors.New("defaults.vrf.tenant has no name; Diode trims it to nothing and refuses the address")
	}
	switch tenantConflict(d.Tenant, d.Vrf.Tenant) {
	case "group":
		return errors.New("defaults.tenant and defaults.vrf.tenant name the same NetBox tenant group in two ways; " +
			"write it the same way in both places")
	case "tenant":
		return errors.New("defaults.tenant and defaults.vrf.tenant name the same NetBox tenant but write it differently; " +
			"give it the same name, group, description, comments and tags, in the same order, in both places, " +
			"for example with a YAML anchor")
	}
	return nil
}

// VrfRd returns the rd the VRF is sent with: vrf.rd, else defaults.rd,
// trimmed as Diode trims it.
func (d Defaults) VrfRd() string {
	if rd := trim(d.Vrf.Rd); rd != "" {
		return rd
	}
	return trim(d.Rd)
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
