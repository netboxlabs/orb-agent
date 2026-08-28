package config

import "time"

// Delivery mode constants (spec §5).
const (
	ModeAuto     = "auto"
	ModeOnChange = "on_change"
	ModeSample   = "sample"
	ModeGet      = "get"
)

// Default config values.
const (
	// DefaultGNMIPort is the IANA-registered gNMI port. Vendors differ in
	// practice (Arista 6030, Nokia 57400), so operators should set the port
	// explicitly — inline as host:port for a single endpoint, or via the port
	// field, which is the only option for a CIDR or range. This default applies
	// only when neither is given.
	DefaultGNMIPort       = 9339
	DefaultDebounceMs     = 2000
	DefaultSampleInterval = 300000 // 5m
	DefaultGetInterval    = 900000 // 15m

	// DefaultProbeTimeoutMs bounds one sweep probe. snmp-discovery's equivalent
	// is 1s, but a gNMI probe is a TLS handshake plus a gRPC call rather than a
	// UDP walk, so it needs longer.
	DefaultProbeTimeoutMs = 3000

	// MinRescanIntervalMs is the floor for a non-zero rescan_interval_ms.
	MinRescanIntervalMs = 60000
)

// Status represents the runtime status of the gnmi-discovery service.
type Status struct {
	StartTime     time.Time `json:"start_time"`
	UpTimeSeconds int64     `json:"up_time_seconds"`
	Version       string    `json:"version"`
}

// TLSConfig holds per-target TLS settings.
type TLSConfig struct {
	// SkipVerify keeps TLS but does not verify the target certificate (e.g. a
	// self-signed device cert). Insecure is an explicit opt-in to PLAINTEXT (no
	// TLS at all). With neither set and no CA/cert/key, the dialer uses TLS with
	// the system root CAs (secure by default).
	SkipVerify bool   `yaml:"skip_verify,omitempty"`
	Insecure   bool   `yaml:"insecure,omitempty"`
	CAFile     string `yaml:"ca,omitempty"`
	CertFile   string `yaml:"cert,omitempty"`
	KeyFile    string `yaml:"key,omitempty"`
}

// Target is one gNMI endpoint.
type Target struct {
	Host string `yaml:"host"`
	// Username and Password are pointers so that presence, not emptiness,
	// controls inheritance. An anonymous device inside a credentialed scope is
	// expressed as `username: ""` — present, so nothing is inherited — which a
	// plain string cannot distinguish from an omitted field. snmp-discovery
	// expresses the same thing through the presence of its authentication block.
	Username *string `yaml:"username,omitempty"`
	Password *string `yaml:"password,omitempty"`
	// Port is the gNMI port. An inline "host:port" suffix wins over this field,
	// which in turn wins over the scope's; unset everywhere means
	// DefaultGNMIPort. A CIDR or range cannot carry an inline port, which is
	// why this field exists.
	Port uint16 `yaml:"port,omitempty"`
	// TLS is a pointer so that "absent" is distinguishable from "present and
	// zero": nil inherits the scope's block, a present block replaces it
	// wholesale. Read it through ResolvedTLS, never directly — a nil
	// dereference here compiles cleanly and panics at runtime.
	TLS              *TLSConfig `yaml:"tls,omitempty"`
	Mode             string     `yaml:"mode,omitempty"`    // overrides PolicyConfig.Mode
	Profile          string     `yaml:"profile,omitempty"` // pins a profile; else auto-detect
	OverrideDefaults *Defaults  `yaml:"override_defaults,omitempty"`
	NetboxID         *int       `yaml:"netbox_id,omitempty"`
	// Origin is the gNMI path origin sent on Subscribe/Get requests. Unset (nil)
	// defaults to "openconfig" — the canonical OpenConfig origin, required by
	// strict targets like Nokia SR Linux (which otherwise resolves an origin-less
	// path against its native schema and rejects it). Set it explicitly to ""
	// for a target that needs origin-less paths, or to a vendor-specific origin.
	Origin *string `yaml:"origin,omitempty"`
}

// ResolvedTLS returns this target's TLS settings, or the zero value when no
// block is set.
//
// Every read of Target.TLS goes through here. Go auto-dereferences a pointer
// field selector, so `t.TLS.SkipVerify` on a nil TLS compiles without complaint
// and panics at runtime — and nil is the common case, since most policies set no
// tls block at all. The zero value is the secure default (TLS with the system
// root CAs), which is what the field meant before it became a pointer.
func (t Target) ResolvedTLS() TLSConfig {
	if t.TLS == nil {
		return TLSConfig{}
	}
	return *t.TLS
}

// ResolvedUsername returns this target's gNMI username, or "" when none is set.
func (t Target) ResolvedUsername() string {
	if t.Username == nil {
		return ""
	}
	return *t.Username
}

// ResolvedPassword returns this target's gNMI password, or "" when none is set.
func (t Target) ResolvedPassword() string {
	if t.Password == nil {
		return ""
	}
	return *t.Password
}

// ResolvedOrigin returns the gNMI request-path origin for this target: the
// explicit value when set (including ""), otherwise the "openconfig" default.
func (t Target) ResolvedOrigin() string {
	if t.Origin != nil {
		return *t.Origin
	}
	return "openconfig"
}

// Scope holds a policy's targets and the settings they inherit.
//
// The scope block carries five of Target's fields. It deliberately does not
// carry mode, override_defaults or profile: the first two duplicate
// policy-level knobs (PolicyConfig.Mode and PolicyConfig.Defaults), and a
// scope-level profile would pin one vendor profile across a whole range,
// bypassing capability auto-detection — which defeats the point of scanning a
// subnet whose contents are unknown.
//
// host and netbox_id are per-target by nature: host is the thing being
// enumerated, and one NetBox device id cannot describe a range.
type Scope struct {
	Username string     `yaml:"username,omitempty"`
	Password string     `yaml:"password,omitempty"`
	Port     uint16     `yaml:"port,omitempty"`
	Origin   *string    `yaml:"origin,omitempty"`
	TLS      *TLSConfig `yaml:"tls,omitempty"`
	Targets  []Target   `yaml:"targets"`
}

// DeviceDefaults mirrors snmp-discovery's device defaults subset.
type DeviceDefaults struct {
	Manufacturer string   `yaml:"manufacturer,omitempty"`
	Model        string   `yaml:"model,omitempty"`
	Platform     string   `yaml:"platform,omitempty"`
	Tags         []string `yaml:"tags,omitempty"`
	Comments     string   `yaml:"comments,omitempty"`
}

// InterfaceDefaults mirrors snmp-discovery's interface defaults subset.
type InterfaceDefaults struct {
	Type        string   `yaml:"if_type,omitempty"`
	Description string   `yaml:"description,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
}

// PrefixDefaults holds NetBox defaults applied to discovered IP prefixes.
type PrefixDefaults struct {
	Role        string   `yaml:"role,omitempty"`
	Tenant      string   `yaml:"tenant,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	Description string   `yaml:"description,omitempty"`
}

// VlanDefaults holds NetBox defaults applied to discovered VLANs.
type VlanDefaults struct {
	Group       string   `yaml:"group,omitempty"`
	Tenant      string   `yaml:"tenant,omitempty"`
	Role        string   `yaml:"role,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	Description string   `yaml:"description,omitempty"`
}

// IPAddressDefaults holds NetBox defaults applied to discovered IP addresses.
// Field names mirror snmp-discovery's IPAddressDefaults so policy YAML is
// portable between the two backends.
type IPAddressDefaults struct {
	Role        string   `yaml:"role,omitempty"`
	Tenant      string   `yaml:"tenant,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	Description string   `yaml:"description,omitempty"`
	Comments    string   `yaml:"comments,omitempty"`
}

// VRFDefaults holds NetBox defaults applied to discovered VRFs (the Name and Rd
// come from discovery; these are operator-supplied attributes).
type VRFDefaults struct {
	Tenant      string   `yaml:"tenant,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	Description string   `yaml:"description,omitempty"`
	Comments    string   `yaml:"comments,omitempty"`
}

// InterfacePattern maps an interface-name regex to a NetBox interface type.
// Mirrors snmp-discovery's InterfacePattern so policy YAML is portable between
// the two backends.
type InterfacePattern struct {
	Match string `yaml:"match"` // regex matched against the interface name
	Type  string `yaml:"type"`  // NetBox interface type assigned on match
}

// Defaults holds NetBox defaults applied to discovered entities.
type Defaults struct {
	Site     string   `yaml:"site,omitempty"`
	Location string   `yaml:"location,omitempty"`
	Role     string   `yaml:"role,omitempty"`
	Tags     []string `yaml:"tags,omitempty"`
	// AssetTag is the device asset tag: either a literal string, or a gNMI path
	// reference (a value beginning with "/", e.g.
	// "/components/component[name=Chassis]/state/id") resolved against the
	// discovered model snapshot. Resolved/literal values are vetted (placeholder
	// rejection, NetBox's 50-rune cap, valid UTF-8) before becoming
	// Device.AssetTag. Mirrors snmp-discovery's defaults.asset_tag placement.
	AssetTag  string            `yaml:"asset_tag,omitempty"`
	Device    DeviceDefaults    `yaml:"device,omitempty"`
	Interface InterfaceDefaults `yaml:"interface,omitempty"`
	Vlan      VlanDefaults      `yaml:"vlan,omitempty"`
	Prefix    PrefixDefaults    `yaml:"prefix,omitempty"`
	IPAddress IPAddressDefaults `yaml:"ip_address,omitempty"`
	Vrf       VRFDefaults       `yaml:"vrf,omitempty"`
	// InterfacePatterns map interface-name regexes to NetBox types (first match
	// wins) and take precedence over the discovered OpenConfig type and the
	// Interface.Type default. InterfaceExcludePatterns are name regexes that skip
	// an interface entirely. Both mirror snmp-discovery.
	InterfacePatterns        []InterfacePattern `yaml:"interface_patterns,omitempty"`
	InterfaceExcludePatterns []string           `yaml:"interface_exclude_patterns,omitempty"`
}

// Options holds per-policy behavior toggles, peer to Defaults. Mirrors
// snmp-discovery's Options convention (tri-state pointers + resolver methods)
// so unset is distinguishable from an explicit value.
type Options struct {
	// CaptureConfig enables one CONFIG-datastore Get per discovery cycle, stored
	// as DeviceConfig.Running (serialized JSON_IETF). nil → off (default; no
	// config Get is issued). gNMI exposes no startup/candidate datastore, so only
	// Running is populated.
	CaptureConfig *bool `yaml:"capture_config,omitempty"`
}

// ConfigCaptureEnabled reports the effective capture_config toggle (default off).
func (o *Options) ConfigCaptureEnabled() bool {
	return o != nil && o.CaptureConfig != nil && *o.CaptureConfig
}

// PolicyConfig holds policy-wide config (spec §7).
type PolicyConfig struct {
	Mode             string `yaml:"mode,omitempty"`
	DebounceMs       int    `yaml:"debounce_ms,omitempty"`
	SampleIntervalMs int    `yaml:"sample_interval_ms,omitempty"`
	GetIntervalMs    int    `yaml:"get_interval_ms,omitempty"`

	// ProbeTimeoutMs bounds one sweep probe. 0 or unset means
	// DefaultProbeTimeoutMs, not "no timeout": a probe without a deadline against
	// a silently-dropping address never returns, and the sweep would never finish.
	ProbeTimeoutMs int `yaml:"probe_timeout_ms,omitempty"`

	// SendCredentialsToUnverifiedTargets permits a CIDR or range target to carry
	// a password when TLS does not authenticate the server.
	//
	// Off by default, and the refusal is the point. A sweep admits anything that
	// answers on the gNMI port — deliberately, because only silence is absence —
	// and the subscription that follows sends this policy's password to whatever
	// was admitted. With skip_verify or insecure there is nothing authenticating
	// the far end, so an unrelated service listening on that port inside the
	// scanned range collects the credential. That is reachable by accident: a
	// range that overlaps a server VLAN is a typo, not an attack.
	//
	// Naming a host explicitly is unaffected. The operator said where the
	// credential may go.
	SendCredentialsToUnverifiedTargets bool `yaml:"send_credentials_to_unverified_targets,omitempty"`

	// RescanIntervalMs re-probes addresses this policy is not currently
	// subscribed to, picking up devices that were down when the policy was
	// applied. 0 or unset disables it. It exists because nothing else re-applies
	// a policy periodically: the config manager returns early on an unchanged git
	// ref, and on a new commit whose diff touches no matching policy file.
	//
	// Values below MinRescanIntervalMs are rejected rather than clamped. A sparse
	// /24 re-probes ~250 addresses per tick, which is fine hourly and is a
	// continuous scan per minute.
	RescanIntervalMs int `yaml:"rescan_interval_ms,omitempty"`

	Defaults Defaults `yaml:"defaults"`
	Options  Options  `yaml:"options,omitempty"`
}

// ResolvedProbeTimeout returns the effective sweep probe timeout.
func (c PolicyConfig) ResolvedProbeTimeout() time.Duration {
	if c.ProbeTimeoutMs <= 0 {
		return DefaultProbeTimeoutMs * time.Millisecond
	}
	return time.Duration(c.ProbeTimeoutMs) * time.Millisecond
}

// ResolvedRescanInterval returns the effective rescan period, or 0 when rescan
// is disabled.
func (c PolicyConfig) ResolvedRescanInterval() time.Duration {
	if c.RescanIntervalMs <= 0 {
		return 0
	}
	return time.Duration(c.RescanIntervalMs) * time.Millisecond
}

// Policy is a gnmi-discovery policy.
type Policy struct {
	Config PolicyConfig `yaml:"config"`
	Scope  Scope        `yaml:"scope"`
}

// Policies is the request envelope: {policies: {name: Policy}}.
type Policies struct {
	Policies map[string]Policy `yaml:"policies"`
}

// cloneStrings returns a new slice with the same elements as src, sharing no
// backing array with the original. A nil src returns nil.
func cloneStrings(src []string) []string {
	return append([]string(nil), src...)
}

// clonePatterns returns a new slice with the same elements as src, sharing no
// backing array with the original. A nil src returns nil.
func clonePatterns(src []InterfacePattern) []InterfacePattern {
	return append([]InterfacePattern(nil), src...)
}

// MergeDefaults returns policyDefaults overlaid with non-empty overrideDefaults.
// The returned *Defaults owns all of its slice fields — no backing array is
// shared with either input, so callers may freely append without corrupting the
// parsed config.
func MergeDefaults(policyDefaults, overrideDefaults *Defaults) *Defaults {
	if policyDefaults == nil {
		if overrideDefaults == nil {
			return &Defaults{}
		}
		// Return a deep copy of override so the caller still owns all slices.
		cp := *overrideDefaults
		cp.Tags = cloneStrings(overrideDefaults.Tags)
		cp.Device.Tags = cloneStrings(overrideDefaults.Device.Tags)
		cp.Interface.Tags = cloneStrings(overrideDefaults.Interface.Tags)
		cp.Vlan.Tags = cloneStrings(overrideDefaults.Vlan.Tags)
		cp.Prefix.Tags = cloneStrings(overrideDefaults.Prefix.Tags)
		cp.IPAddress.Tags = cloneStrings(overrideDefaults.IPAddress.Tags)
		cp.Vrf.Tags = cloneStrings(overrideDefaults.Vrf.Tags)
		cp.InterfacePatterns = clonePatterns(overrideDefaults.InterfacePatterns)
		cp.InterfaceExcludePatterns = cloneStrings(overrideDefaults.InterfaceExcludePatterns)
		return &cp
	}
	if overrideDefaults == nil {
		// Shallow-copy the struct, then clone every slice field so the result
		// doesn't alias policyDefaults' backing arrays.
		cp := *policyDefaults
		cp.Tags = cloneStrings(policyDefaults.Tags)
		cp.Device.Tags = cloneStrings(policyDefaults.Device.Tags)
		cp.Interface.Tags = cloneStrings(policyDefaults.Interface.Tags)
		cp.Vlan.Tags = cloneStrings(policyDefaults.Vlan.Tags)
		cp.Prefix.Tags = cloneStrings(policyDefaults.Prefix.Tags)
		cp.IPAddress.Tags = cloneStrings(policyDefaults.IPAddress.Tags)
		cp.Vrf.Tags = cloneStrings(policyDefaults.Vrf.Tags)
		cp.InterfacePatterns = clonePatterns(policyDefaults.InterfacePatterns)
		cp.InterfaceExcludePatterns = cloneStrings(policyDefaults.InterfaceExcludePatterns)
		return &cp
	}
	merged := *policyDefaults
	// Clone slices inherited from the policy copy so they don't alias the source.
	merged.Tags = cloneStrings(policyDefaults.Tags)
	merged.Device.Tags = cloneStrings(policyDefaults.Device.Tags)
	merged.Interface.Tags = cloneStrings(policyDefaults.Interface.Tags)
	merged.Vlan.Tags = cloneStrings(policyDefaults.Vlan.Tags)
	merged.Prefix.Tags = cloneStrings(policyDefaults.Prefix.Tags)
	merged.IPAddress.Tags = cloneStrings(policyDefaults.IPAddress.Tags)
	merged.Vrf.Tags = cloneStrings(policyDefaults.Vrf.Tags)
	merged.InterfacePatterns = clonePatterns(policyDefaults.InterfacePatterns)
	merged.InterfaceExcludePatterns = cloneStrings(policyDefaults.InterfaceExcludePatterns)

	if overrideDefaults.Site != "" {
		merged.Site = overrideDefaults.Site
	}
	if overrideDefaults.Role != "" {
		merged.Role = overrideDefaults.Role
	}
	if overrideDefaults.Location != "" {
		merged.Location = overrideDefaults.Location
	}
	if len(overrideDefaults.Tags) > 0 {
		merged.Tags = cloneStrings(overrideDefaults.Tags)
	}
	if overrideDefaults.Device.Manufacturer != "" {
		merged.Device.Manufacturer = overrideDefaults.Device.Manufacturer
	}
	if overrideDefaults.Device.Model != "" {
		merged.Device.Model = overrideDefaults.Device.Model
	}
	if overrideDefaults.Device.Platform != "" {
		merged.Device.Platform = overrideDefaults.Device.Platform
	}
	if overrideDefaults.Device.Comments != "" {
		merged.Device.Comments = overrideDefaults.Device.Comments
	}
	if len(overrideDefaults.Device.Tags) > 0 {
		merged.Device.Tags = cloneStrings(overrideDefaults.Device.Tags)
	}
	if overrideDefaults.Interface.Type != "" {
		merged.Interface.Type = overrideDefaults.Interface.Type
	}
	if overrideDefaults.Interface.Description != "" {
		merged.Interface.Description = overrideDefaults.Interface.Description
	}
	if len(overrideDefaults.Interface.Tags) > 0 {
		merged.Interface.Tags = cloneStrings(overrideDefaults.Interface.Tags)
	}
	if len(overrideDefaults.InterfacePatterns) > 0 {
		merged.InterfacePatterns = clonePatterns(overrideDefaults.InterfacePatterns)
	}
	if len(overrideDefaults.InterfaceExcludePatterns) > 0 {
		merged.InterfaceExcludePatterns = cloneStrings(overrideDefaults.InterfaceExcludePatterns)
	}
	if overrideDefaults.Vlan.Group != "" {
		merged.Vlan.Group = overrideDefaults.Vlan.Group
	}
	if overrideDefaults.Vlan.Tenant != "" {
		merged.Vlan.Tenant = overrideDefaults.Vlan.Tenant
	}
	if overrideDefaults.Vlan.Role != "" {
		merged.Vlan.Role = overrideDefaults.Vlan.Role
	}
	if overrideDefaults.Vlan.Description != "" {
		merged.Vlan.Description = overrideDefaults.Vlan.Description
	}
	if len(overrideDefaults.Vlan.Tags) > 0 {
		merged.Vlan.Tags = cloneStrings(overrideDefaults.Vlan.Tags)
	}
	if overrideDefaults.Prefix.Role != "" {
		merged.Prefix.Role = overrideDefaults.Prefix.Role
	}
	if overrideDefaults.Prefix.Tenant != "" {
		merged.Prefix.Tenant = overrideDefaults.Prefix.Tenant
	}
	if overrideDefaults.Prefix.Description != "" {
		merged.Prefix.Description = overrideDefaults.Prefix.Description
	}
	if len(overrideDefaults.Prefix.Tags) > 0 {
		merged.Prefix.Tags = cloneStrings(overrideDefaults.Prefix.Tags)
	}
	if overrideDefaults.AssetTag != "" {
		merged.AssetTag = overrideDefaults.AssetTag
	}
	if overrideDefaults.IPAddress.Role != "" {
		merged.IPAddress.Role = overrideDefaults.IPAddress.Role
	}
	if overrideDefaults.IPAddress.Tenant != "" {
		merged.IPAddress.Tenant = overrideDefaults.IPAddress.Tenant
	}
	if overrideDefaults.IPAddress.Description != "" {
		merged.IPAddress.Description = overrideDefaults.IPAddress.Description
	}
	if overrideDefaults.IPAddress.Comments != "" {
		merged.IPAddress.Comments = overrideDefaults.IPAddress.Comments
	}
	if len(overrideDefaults.IPAddress.Tags) > 0 {
		merged.IPAddress.Tags = cloneStrings(overrideDefaults.IPAddress.Tags)
	}
	if overrideDefaults.Vrf.Tenant != "" {
		merged.Vrf.Tenant = overrideDefaults.Vrf.Tenant
	}
	if overrideDefaults.Vrf.Description != "" {
		merged.Vrf.Description = overrideDefaults.Vrf.Description
	}
	if overrideDefaults.Vrf.Comments != "" {
		merged.Vrf.Comments = overrideDefaults.Vrf.Comments
	}
	if len(overrideDefaults.Vrf.Tags) > 0 {
		merged.Vrf.Tags = cloneStrings(overrideDefaults.Vrf.Tags)
	}
	return &merged
}
