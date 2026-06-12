package config

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// VrfParameters mirrors device-discovery's VrfParameters: a polymorphic
// config primitive that accepts either a scalar string (interpreted as
// VRF Name) or a map of {name, rd, description, comments, tags}. This
// lets operators attach a Route Distinguisher (and richer metadata) to
// the discovered IP addresses' VRF so NetBox can match an existing
// (name, rd) tuple instead of being forced into the legacy rd=name
// fallback.
type VrfParameters struct {
	Name        string   `yaml:"name"`
	Rd          string   `yaml:"rd,omitempty"`
	Description string   `yaml:"description,omitempty"`
	Comments    string   `yaml:"comments,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
}

// UnmarshalYAML accepts both shapes:
//   - scalar:  vrf: production
//   - mapping: vrf: {name: production, rd: "65000:100"}
//
// The scalar form populates only Name (Rd left empty), which differs
// from the pre-fix behaviour where the agent silently set Rd=Name.
//
// Explicit YAML null (vrf: null, vrf: ~) decodes to the zero value
// instead of the literal string "null" — this is decode safety to
// avoid creating a phantom VRF named "null". It does NOT, by itself,
// clear an inherited VRF default at override merge time: MergeDefaults
// treats the zero value the same way as an absent override key
// (non-empty-wins, matching every other override_defaults field).
func (v *VrfParameters) UnmarshalYAML(node *yaml.Node) error {
	// Reset up front so a stale receiver (re-decoded into the same
	// struct) doesn't keep Rd / Description / Comments / Tags from a
	// previous pass when the new YAML only sets Name via the scalar
	// form.
	*v = VrfParameters{}
	switch node.Kind {
	case yaml.ScalarNode:
		// YAML null tag: leave the struct as the zero value.
		if node.Tag == "!!null" {
			return nil
		}
		v.Name = node.Value
		return nil
	case yaml.MappingNode:
		type alias VrfParameters
		var a alias
		if err := node.Decode(&a); err != nil {
			return err
		}
		*v = VrfParameters(a)
		return nil
	default:
		return fmt.Errorf("vrf: expected string or mapping, got node kind %d", node.Kind)
	}
}

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
	NetboxID         *int            `yaml:"netbox_id,omitempty"`
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
	Description string        `yaml:"description,omitempty"`
	Tags        []string      `yaml:"tags,omitempty"`
	Comments    string        `yaml:"comments,omitempty"`
	Role        string        `yaml:"role,omitempty"`
	Tenant      string        `yaml:"tenant,omitempty"`
	Vrf         VrfParameters `yaml:"vrf,omitempty"`
	// Per-address-family overrides mirroring device-discovery: when set,
	// the family-specific VRF wins for that AF's IP addresses; otherwise
	// the AF-agnostic Vrf above applies.
	VrfIpv4 VrfParameters `yaml:"vrf_ipv4,omitempty"`
	VrfIpv6 VrfParameters `yaml:"vrf_ipv6,omitempty"`
}

// IsZero reports whether no VrfParameters field is set.
func (v VrfParameters) IsZero() bool {
	return v.Name == "" && v.Rd == "" && v.Description == "" &&
		v.Comments == "" && len(v.Tags) == 0
}

// resolveVrfForFamily implements the shared per-AF selection rule: the
// family-specific override wins when any of its fields is set; otherwise
// the AF-agnostic vrf applies. The second return names the knob that
// resolved ("vrf", "vrf_ipv4", "vrf_ipv6") for diagnostics.
func resolveVrfForFamily(vrf, v4, v6 VrfParameters, family string) (VrfParameters, string) {
	var af VrfParameters
	switch family {
	case "ipv4":
		af = v4
	case "ipv6":
		af = v6
	}
	if !af.IsZero() {
		return af, "vrf_" + family
	}
	return vrf, "vrf"
}

// VrfForFamily resolves the effective VRF defaults for an address family
// ("ipv4" or "ipv6"). See resolveVrfForFamily.
func (d *IPAddressDefaults) VrfForFamily(family string) (VrfParameters, string) {
	return resolveVrfForFamily(d.Vrf, d.VrfIpv4, d.VrfIpv6, family)
}

// PrefixDefaults represents default values applied to derived Prefix
// entities. Mirrors device-discovery's defaults.prefix block.
type PrefixDefaults struct {
	Description string        `yaml:"description,omitempty"`
	Tags        []string      `yaml:"tags,omitempty"`
	Comments    string        `yaml:"comments,omitempty"`
	Role        string        `yaml:"role,omitempty"`
	Tenant      string        `yaml:"tenant,omitempty"`
	Vrf         VrfParameters `yaml:"vrf,omitempty"`
	VrfIpv4     VrfParameters `yaml:"vrf_ipv4,omitempty"`
	VrfIpv6     VrfParameters `yaml:"vrf_ipv6,omitempty"`
	// Explicit prefix scope. Setting either puts the operator in
	// "explicit mode" and the propagate_defaults_to_prefix_scope cascade
	// is skipped wholesale.
	ScopeSite     string `yaml:"scope_site,omitempty"`
	ScopeLocation string `yaml:"scope_location,omitempty"`
}

// VrfForFamily resolves the effective prefix VRF defaults for an address
// family. See resolveVrfForFamily.
func (d *PrefixDefaults) VrfForFamily(family string) (VrfParameters, string) {
	return resolveVrfForFamily(d.Vrf, d.VrfIpv4, d.VrfIpv6, family)
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
	Description  string   `yaml:"description,omitempty"`
	Tags         []string `yaml:"tags,omitempty"`
	Comments     string   `yaml:"comments,omitempty"`
	Model        string   `yaml:"model,omitempty"`
	Manufacturer string   `yaml:"manufacturer,omitempty"`
	Platform     string   `yaml:"platform,omitempty"`
}

// VLANDefaults represents default values applied to discovered VLAN entities.
type VLANDefaults struct {
	Description string   `yaml:"description,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	Group       string   `yaml:"group,omitempty"`
	Tenant      string   `yaml:"tenant,omitempty"`
	Status      string   `yaml:"status,omitempty"`
}

// Defaults represents the supported default values for a policy
type Defaults struct {
	Tags                     []string           `yaml:"tags,omitempty"`
	Site                     string             `yaml:"site,omitempty"`
	Location                 string             `yaml:"location,omitempty"`
	Role                     string             `yaml:"role,omitempty"`
	AssetTag                 string             `yaml:"asset_tag,omitempty"`
	IPAddress                IPAddressDefaults  `yaml:"ip_address,omitempty"`
	Prefix                   PrefixDefaults     `yaml:"prefix,omitempty"`
	Interface                InterfaceDefaults  `yaml:"interface,omitempty"`
	Device                   DeviceDefaults     `yaml:"device,omitempty"`
	VLAN                     VLANDefaults       `yaml:"vlan,omitempty"`
	InterfacePatterns        []InterfacePattern `yaml:"interface_patterns,omitempty"`
	InterfaceExcludePatterns []string           `yaml:"interface_exclude_patterns,omitempty"`
}

// mergeVrfParameters overlays non-zero override fields onto dst in place.
func mergeVrfParameters(dst, override *VrfParameters) {
	if override.Name != "" {
		dst.Name = override.Name
	}
	if override.Rd != "" {
		dst.Rd = override.Rd
	}
	if override.Description != "" {
		dst.Description = override.Description
	}
	if override.Comments != "" {
		dst.Comments = override.Comments
	}
	if len(override.Tags) > 0 {
		dst.Tags = override.Tags
	}
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
	if overrideDefaults.AssetTag != "" {
		merged.AssetTag = overrideDefaults.AssetTag
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
	// Merge VRF defaults field-by-field so a per-target override can refine
	// a single VrfParameters knob (e.g. rd) without having to restate every
	// other field already set at the policy level. Matches the
	// Device/VLAN/Interface non-zero-value-wins pattern. The per-AF
	// overrides merge the same way, each against its own policy-level
	// counterpart only — an override vrf_ipv4 never bleeds into vrf.
	mergeVrfParameters(&merged.IPAddress.Vrf, &overrideDefaults.IPAddress.Vrf)
	mergeVrfParameters(&merged.IPAddress.VrfIpv4, &overrideDefaults.IPAddress.VrfIpv4)
	mergeVrfParameters(&merged.IPAddress.VrfIpv6, &overrideDefaults.IPAddress.VrfIpv6)

	// Merge Prefix defaults
	if overrideDefaults.Prefix.Description != "" {
		merged.Prefix.Description = overrideDefaults.Prefix.Description
	}
	if len(overrideDefaults.Prefix.Tags) > 0 {
		merged.Prefix.Tags = overrideDefaults.Prefix.Tags
	}
	if overrideDefaults.Prefix.Comments != "" {
		merged.Prefix.Comments = overrideDefaults.Prefix.Comments
	}
	if overrideDefaults.Prefix.Role != "" {
		merged.Prefix.Role = overrideDefaults.Prefix.Role
	}
	if overrideDefaults.Prefix.Tenant != "" {
		merged.Prefix.Tenant = overrideDefaults.Prefix.Tenant
	}
	if overrideDefaults.Prefix.ScopeSite != "" {
		merged.Prefix.ScopeSite = overrideDefaults.Prefix.ScopeSite
	}
	if overrideDefaults.Prefix.ScopeLocation != "" {
		merged.Prefix.ScopeLocation = overrideDefaults.Prefix.ScopeLocation
	}
	mergeVrfParameters(&merged.Prefix.Vrf, &overrideDefaults.Prefix.Vrf)
	mergeVrfParameters(&merged.Prefix.VrfIpv4, &overrideDefaults.Prefix.VrfIpv4)
	mergeVrfParameters(&merged.Prefix.VrfIpv6, &overrideDefaults.Prefix.VrfIpv6)

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
	if overrideDefaults.Device.Model != "" {
		merged.Device.Model = overrideDefaults.Device.Model
	}
	if overrideDefaults.Device.Manufacturer != "" {
		merged.Device.Manufacturer = overrideDefaults.Device.Manufacturer
	}
	if overrideDefaults.Device.Platform != "" {
		merged.Device.Platform = overrideDefaults.Device.Platform
	}

	// Merge VLAN defaults
	if overrideDefaults.VLAN.Description != "" {
		merged.VLAN.Description = overrideDefaults.VLAN.Description
	}
	if len(overrideDefaults.VLAN.Tags) > 0 {
		merged.VLAN.Tags = overrideDefaults.VLAN.Tags
	}
	if overrideDefaults.VLAN.Group != "" {
		merged.VLAN.Group = overrideDefaults.VLAN.Group
	}
	if overrideDefaults.VLAN.Tenant != "" {
		merged.VLAN.Tenant = overrideDefaults.VLAN.Tenant
	}
	if overrideDefaults.VLAN.Status != "" {
		merged.VLAN.Status = overrideDefaults.VLAN.Status
	}

	// Override InterfacePatterns if provided
	if len(overrideDefaults.InterfacePatterns) > 0 {
		merged.InterfacePatterns = overrideDefaults.InterfacePatterns
	}

	// Override InterfaceExcludePatterns if provided
	if len(overrideDefaults.InterfaceExcludePatterns) > 0 {
		merged.InterfaceExcludePatterns = overrideDefaults.InterfaceExcludePatterns
	}

	return &merged
}

// DiscoverModules* are the accepted values for options.discover_modules.
// Off is the default when the field is unset.
const (
	DiscoverModulesOff       = "off"
	DiscoverModulesLinecards = "linecards"
	DiscoverModulesFull      = "full"
)

// Options represents per-policy global behavior toggles peer to Defaults.
type Options struct {
	CreateUnknownVlans *bool `yaml:"create_unknown_vlans,omitempty"`

	// Tri-state pointer so we can distinguish unset (default = "off") from
	// explicit "off". Values:
	//   nil         → treat as "off" (default; zero behaviour change)
	//   "off"       → no module / module bay entities emitted
	//   "linecards" → top-level chassis-slot modules (linecards + supervisors;
	//                 PSU/fan classified for labelling but NOT emitted);
	//                 transceiver sub-bays dropped
	//   "full"      → linecards plus per-transceiver sub-bays; populates
	//                 Interface.Module on physical ports
	DiscoverModules *string `yaml:"discover_modules,omitempty"`

	// Tri-state pointer so unset (default = off) is distinguishable from
	// an explicit false. When true, the VRF MIB tables (MPLS-L3VPN-STD-MIB,
	// the legacy MPLS-VPN-MIB, CISCO-VRF-MIB) are walked and discovered
	// VRFs are emitted and attached to the IP addresses of their member
	// interfaces, taking precedence over the vrf / vrf_ipv4 / vrf_ipv6
	// defaults for those interfaces.
	DiscoverVrfs *bool `yaml:"discover_vrfs,omitempty"`

	// Tri-state pointer; unset defaults to TRUE — Prefix entities are
	// derived from every discovered IP address (network of address/len),
	// matching device-discovery's behavior. Set false to opt out.
	EmitPrefixes *bool `yaml:"emit_prefixes,omitempty"`

	// When true AND no explicit defaults.prefix.scope_* is set,
	// defaults.site cascades to Prefix scope site and defaults.location
	// to Prefix scope location (the more specific location wins).
	// Defaults to false. Mirrors device-discovery.
	PropagateDefaultsToPrefixScope *bool `yaml:"propagate_defaults_to_prefix_scope,omitempty"`
}

// PrefixEmissionEnabled returns the effective emit_prefixes toggle,
// defaulting to TRUE.
func (o *Options) PrefixEmissionEnabled() bool {
	return o == nil || o.EmitPrefixes == nil || *o.EmitPrefixes
}

// PrefixScopeCascadeEnabled returns the effective
// propagate_defaults_to_prefix_scope toggle, defaulting to false.
func (o *Options) PrefixScopeCascadeEnabled() bool {
	return o != nil && o.PropagateDefaultsToPrefixScope != nil && *o.PropagateDefaultsToPrefixScope
}

// VrfDiscoveryEnabled returns the effective discover_vrfs toggle,
// defaulting to false.
func (o *Options) VrfDiscoveryEnabled() bool {
	return o != nil && o.DiscoverVrfs != nil && *o.DiscoverVrfs
}

// ModuleDiscoveryMode returns the effective mode, defaulting to "off".
func (o *Options) ModuleDiscoveryMode() string {
	if o == nil || o.DiscoverModules == nil {
		return DiscoverModulesOff
	}
	return *o.DiscoverModules
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
	Options             Options  `yaml:"options,omitempty"`
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
	IndexKind      string         `yaml:"index_kind"`
	Relationship   Relationship   `yaml:"relationship"`
	Vendor         string         `yaml:"vendor,omitempty"`
}

// Relationship represents a relationship between two entities
type Relationship struct {
	Type  string `yaml:"type"`
	Field string `yaml:"field"`
}
