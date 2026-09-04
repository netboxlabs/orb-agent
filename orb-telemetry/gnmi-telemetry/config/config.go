// Package config holds the policy model the API accepts and the resolution
// helpers the runner and collector read it through.
package config

import "time"

const (
	// MaxDurationSeconds bounds every duration a policy or flag names, one
	// year, so an interval times a bounded count cannot wrap.
	MaxDurationSeconds = 365 * 24 * 60 * 60
	// DefaultGNMIPort is the IANA port for gNMI, used when neither the scope
	// nor the target names one.
	DefaultGNMIPort = 9339
	// DefaultProbeTimeoutMs bounds a sweep probe of one address.
	DefaultProbeTimeoutMs = 3000
	// MinRescanIntervalMs is the floor for a non-zero rescan interval.
	MinRescanIntervalMs = 60000
	// DefaultOrigin is the request origin when a scope names none.
	DefaultOrigin = "openconfig"
)

// Status is what the API reports about the process.
type Status struct {
	StartTime     time.Time `json:"start_time"`
	UpTimeSeconds int64     `json:"up_time_seconds"`
	Version       string    `json:"version"`
}

// Policies is the API body: named policies.
type Policies struct {
	Policies map[string]Policy `yaml:"policies"`
}

// TLSConfig is how a session authenticates the target. TLS with system roots
// is the default; skip_verify keeps TLS without verification; insecure is an
// explicit opt-in to plaintext.
type TLSConfig struct {
	SkipVerify bool   `yaml:"skip_verify,omitempty"`
	Insecure   bool   `yaml:"insecure,omitempty"`
	CAFile     string `yaml:"ca,omitempty"`
	CertFile   string `yaml:"cert,omitempty"`
	KeyFile    string `yaml:"key,omitempty"`
}

// Target is one address, CIDR or range to subscribe to. Pointer fields tell
// an explicit empty value apart from an absent one, so a target can clear a
// scope-level credential rather than inherit it. Host never carries a port
// once parsed; Port does.
type Target struct {
	Host     string     `yaml:"host"`
	ID       string     `yaml:"id,omitempty"`
	Username *string    `yaml:"username,omitempty"`
	Password *string    `yaml:"password,omitempty"`
	Port     uint16     `yaml:"port,omitempty"`
	TLS      *TLSConfig `yaml:"tls,omitempty"`
	Mode     string     `yaml:"mode,omitempty"`
	Profile  string     `yaml:"profile,omitempty"`
	Origin   *string    `yaml:"origin,omitempty"`
}

// ResolvedTLS returns the target's tls block or an empty one.
func (t Target) ResolvedTLS() TLSConfig {
	if t.TLS != nil {
		return *t.TLS
	}
	return TLSConfig{}
}

// ResolvedUsername returns the target's username or "".
func (t Target) ResolvedUsername() string {
	if t.Username != nil {
		return *t.Username
	}
	return ""
}

// ResolvedPassword returns the target's password or "".
func (t Target) ResolvedPassword() string {
	if t.Password != nil {
		return *t.Password
	}
	return ""
}

// ResolvedOrigin returns the target's request origin, DefaultOrigin when
// unset. An explicit "" means the target's native schema.
func (t Target) ResolvedOrigin() string {
	if t.Origin != nil {
		return *t.Origin
	}
	return DefaultOrigin
}

// Scope is the policy's targets and the credentials they share.
type Scope struct {
	Username string     `yaml:"username,omitempty"`
	Password string     `yaml:"password,omitempty"`
	Port     uint16     `yaml:"port,omitempty"`
	Origin   *string    `yaml:"origin,omitempty"`
	TLS      *TLSConfig `yaml:"tls,omitempty"`
	Targets  []Target   `yaml:"targets"`
}

// EffectiveTarget fills a target's absent fields from the scope: a nil
// username, password, origin or tls block inherits the scope's, a zero port
// takes the scope's then DefaultGNMIPort. A target's own value, including an
// explicit empty one, is kept, so applying it twice changes nothing.
func EffectiveTarget(scope Scope, t Target) Target {
	out := t
	if out.Username == nil {
		u := scope.Username
		out.Username = &u
	}
	if out.Password == nil {
		p := scope.Password
		out.Password = &p
	}
	if out.Origin == nil {
		o := DefaultOrigin
		if scope.Origin != nil {
			o = *scope.Origin
		}
		out.Origin = &o
	}
	if out.TLS == nil && scope.TLS != nil {
		tls := *scope.TLS
		out.TLS = &tls
	}
	if out.Port == 0 {
		out.Port = scope.Port
	}
	if out.Port == 0 {
		out.Port = DefaultGNMIPort
	}
	return out
}

// PolicyConfig is the policy's collection settings.
type PolicyConfig struct {
	// MetricsInterval is the SAMPLE cadence in seconds, required.
	MetricsInterval *int `yaml:"metrics_interval"`
	// Mode overrides the profile's subscription modes: auto (default),
	// on_change or sample.
	Mode string `yaml:"mode,omitempty"`
	// ProfilesDir is a per-policy override tree, resolved inside the root the
	// process was started with.
	ProfilesDir string `yaml:"profiles_dir,omitempty"`
	// ProbeTimeoutMs bounds how long a sweep waits for one address.
	ProbeTimeoutMs int `yaml:"probe_timeout_ms,omitempty"`
	// RescanIntervalMs re-probes addresses the policy is not subscribed to.
	// Zero disables it; a non-zero value below MinRescanIntervalMs is
	// rejected.
	RescanIntervalMs int `yaml:"rescan_interval_ms,omitempty"`
	// SendCredentialsToUnverifiedTargets permits a range target to carry a
	// password when TLS does not verify the server. Off by default: a sweep
	// admits anything that answers on the port, and without verification an
	// unrelated service in the range would collect the credential.
	SendCredentialsToUnverifiedTargets bool `yaml:"send_credentials_to_unverified_targets,omitempty"`
}

// ResolvedProbeTimeout is the probe timeout with its default applied.
func (c PolicyConfig) ResolvedProbeTimeout() time.Duration {
	if c.ProbeTimeoutMs <= 0 {
		return DefaultProbeTimeoutMs * time.Millisecond
	}
	return time.Duration(c.ProbeTimeoutMs) * time.Millisecond
}

// ResolvedRescanInterval is the rescan interval, zero when disabled.
func (c PolicyConfig) ResolvedRescanInterval() time.Duration {
	if c.RescanIntervalMs <= 0 {
		return 0
	}
	return time.Duration(c.RescanIntervalMs) * time.Millisecond
}

// Policy is one named policy.
type Policy struct {
	Config PolicyConfig `yaml:"config"`
	Scope  Scope        `yaml:"scope"`
}
