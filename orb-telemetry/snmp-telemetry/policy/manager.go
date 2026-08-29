package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/collector"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/env"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/profiles"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/snmp"
)

const (
	// SNMPDefaultPort is the default SNMP port
	SNMPDefaultPort = 161
)

// Status represents the status of a policy
type Status struct {
	Name        string     `json:"name"`
	Status      string     `json:"status"`
	LastError   *string    `json:"last_error,omitempty"`
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
}

// Manager manages snmp-telemetry policy runners
type Manager struct {
	// mu guards the policies map. The HTTP server calls StartPolicy,
	// StopPolicy and GetPolicyStatuses from concurrent request goroutines, and
	// the agent polls status on a timer while pushing policy updates, so an
	// unguarded map hits Go's "concurrent map read and map write" fatal error.
	// Runner state has its own lock; mu only protects the map.
	mu                 sync.RWMutex
	policies           map[string]*Runner
	logger             *slog.Logger
	ctx                context.Context
	defaultProfilesDir string

	collectorsMu    sync.Mutex
	collectorsByDir map[string]*collector.MetricsCollector
}

// NewManager returns a new policy manager
func NewManager(ctx context.Context, logger *slog.Logger, defaultProfilesDir string) *Manager {
	return &Manager{
		ctx:                ctx,
		logger:             logger,
		policies:           make(map[string]*Runner),
		defaultProfilesDir: defaultProfilesDir,
		collectorsByDir:    make(map[string]*collector.MetricsCollector),
	}
}

// getOrCreateCollector returns the shared MetricsCollector for the given profiles directory,
// creating it (and loading profiles) on first use. Subsequent calls for the same dir return
// the cached instance without re-loading. Thread-safe.
func (m *Manager) getOrCreateCollector(profilesDir string) (*collector.MetricsCollector, error) {
	m.collectorsMu.Lock()
	defer m.collectorsMu.Unlock()
	if c, ok := m.collectorsByDir[profilesDir]; ok {
		return c, nil
	}
	if profilesDir != "" {
		if _, err := os.Stat(profilesDir); err != nil {
			return nil, fmt.Errorf("SNMP profiles directory not found: %s", profilesDir)
		}
	}
	loader, err := profiles.LoadProfiles(profilesDir, m.logger)
	if err != nil {
		return nil, fmt.Errorf("loading SNMP profiles: %w", err)
	}
	resolved, err := loader.AllResolved()
	if err != nil {
		return nil, fmt.Errorf("resolving SNMP profiles: %w", err)
	}
	matcher := profiles.NewMatcher(resolved, m.logger)
	clientFactory := func(host string, port uint16, retries int, timeout time.Duration, auth *config.Authentication, logger *slog.Logger) (snmp.Walker, error) {
		return snmp.NewClient(host, port, retries, timeout, auth, logger)
	}
	// Dial settings are per policy, so they are passed to each collection
	// rather than baked into the collector shared by every policy using this
	// profile set.
	c := collector.NewMetricsCollector(clientFactory, matcher, m.logger)
	m.collectorsByDir[profilesDir] = c
	m.logger.Info("loaded SNMP profiles", "override_dir", config.SanitizeLogValue(profilesDir), "count", loader.Count())
	return c, nil
}

// ParsePolicies parses and validates policies from a YAML request body
func (m *Manager) ParsePolicies(data []byte) (map[string]config.Policy, error) {
	var payload config.Policies
	if err := yaml.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	config.WarnUnknownPolicyKeys(data, m.logger)

	if len(payload.Policies) == 0 {
		return nil, errors.New("no policies found in the request")
	}

	for name, policy := range payload.Policies {
		normalizeAuthProtocolVersions(&policy)
		payload.Policies[name] = policy
		if err := m.validatePolicy(policy); err != nil {
			return nil, fmt.Errorf("%s: invalid policy: %w", name, err)
		}
	}

	for name := range payload.Policies {
		updated := payload.Policies[name]
		if err := m.resolveAuthenticationEnvVars(&updated); err != nil {
			return nil, fmt.Errorf("%s: failed to resolve environment variables: %w", name, err)
		}
		m.applyDefaults(&updated)
		payload.Policies[name] = updated
	}

	return payload.Policies, nil
}

// HasPolicy checks if the policy exists
func (m *Manager) HasPolicy(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.policies[name]
	return ok
}

// validateProfilesDir cleans a policy-supplied profiles directory and rejects
// one that walks upward. The value arrives over the API, and an override
// directory is named outright rather than reached by climbing out of another
// one, so ".." only ever widens what a policy can read. Absolute and relative
// paths are both accepted; the directory is documented as neither.
func validateProfilesDir(dir string) (string, error) {
	clean := filepath.Clean(dir)
	// Refuse any ".." at all rather than only a leading path element. Checking
	// elements would also accept a name such as /opt/a..b, but the substring
	// form is the barrier static analysis recognises, and a profiles directory
	// with dots in its name is not worth the weaker check.
	if strings.Contains(clean, "..") {
		return "", fmt.Errorf(`SNMP profiles directory must not contain "..": %s`, dir)
	}
	return clean, nil
}

// StartPolicy starts a single named policy. The duplicate check and the insert
// happen together under mu, so two concurrent requests for the same name cannot
// both start a runner.
func (m *Manager) StartPolicy(name string, policy config.Policy) error {
	profilesDir := m.defaultProfilesDir
	if policy.Config.ProfilesDir != "" {
		dir, err := validateProfilesDir(policy.Config.ProfilesDir)
		if err != nil {
			return err
		}
		profilesDir = dir
	}

	sharedCollector, err := m.getOrCreateCollector(profilesDir)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.policies[name]; ok {
		return fmt.Errorf("policy %s already exists", name)
	}

	r, err := NewRunner(m.ctx, m.logger, name, policy, sharedCollector)
	if err != nil {
		return err
	}

	r.Start()
	m.policies[name] = r
	m.logger.Info("started policy", "policy", config.SanitizeLogValue(name))
	return nil
}

// StopPolicy stops a single named policy. The runner is detached under mu and
// stopped outside it, since Stop blocks on the scheduler unwinding.
func (m *Manager) StopPolicy(name string) error {
	m.mu.Lock()
	r, ok := m.policies[name]
	if ok {
		delete(m.policies, name)
	}
	m.mu.Unlock()
	if !ok {
		return nil
	}
	if err := r.Stop(); err != nil {
		return fmt.Errorf("stopping policy %s: %w", name, err)
	}
	return nil
}

// Stop stops all running policies. Every runner is attempted even after one
// fails: the map is drained first, so a runner left unstopped keeps polling
// with no entry behind for GetPolicyStatuses to report it. Names are visited
// in order so the joined error reads the same on every run.
func (m *Manager) Stop() error {
	m.mu.Lock()
	runners := make(map[string]*Runner, len(m.policies))
	maps.Copy(runners, m.policies)
	m.policies = make(map[string]*Runner)
	m.mu.Unlock()

	var errs []error
	for _, name := range slices.Sorted(maps.Keys(runners)) {
		if err := runners[name].Stop(); err != nil {
			errs = append(errs, fmt.Errorf("stopping policy %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// GetCapabilities returns the capabilities of snmp-telemetry
func (m *Manager) GetCapabilities() []string {
	return []string{"targets"}
}

// GetPolicyStatuses returns the status of all known policies. RLock guards the
// map iteration against a concurrent StartPolicy or StopPolicy; GetLastError
// takes the runner's own lock, so there is no nesting on mu.
func (m *Manager) GetPolicyStatuses() []Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	statuses := make([]Status, 0, len(m.policies))
	for name, runner := range m.policies {
		s := Status{Name: name, Status: "running"}
		if at, err := runner.GetLastError(); err != nil {
			msg := err.Error()
			s.Status = "running_with_errors"
			s.LastError = &msg
			s.LastErrorAt = &at
		}
		statuses = append(statuses, s)
	}
	return statuses
}

// applyDefaults applies the default values to the policy
func (m *Manager) applyDefaults(policy *config.Policy) {
	for i, target := range policy.Scope.Targets {
		if target.Port == 0 {
			policy.Scope.Targets[i].Port = SNMPDefaultPort
		}
	}
}

// normalizeProtocolVersion canonicalises common shorthand aliases to the expected form.
// "2c", "v2c", "2" → "SNMPv2c"; "1", "v1" → "SNMPv1"; "3", "v3" → "SNMPv3".
func normalizeProtocolVersion(v string) string {
	switch strings.ToLower(v) {
	case "1", "v1":
		return "SNMPv1"
	case "2", "v2", "2c", "v2c":
		return "SNMPv2c"
	case "3", "v3":
		return "SNMPv3"
	default:
		return v
	}
}

// normalizeAuthProtocolVersions normalises protocol_version aliases across all
// authentication blocks in the policy (scope-level and per-target overrides).
func normalizeAuthProtocolVersions(policy *config.Policy) {
	policy.Scope.Authentication.ProtocolVersion = normalizeProtocolVersion(policy.Scope.Authentication.ProtocolVersion)
	for i := range policy.Scope.Targets {
		if policy.Scope.Targets[i].Authentication != nil {
			policy.Scope.Targets[i].Authentication.ProtocolVersion = normalizeProtocolVersion(policy.Scope.Targets[i].Authentication.ProtocolVersion)
		}
	}
}

// validateAuthentication validates a single authentication configuration
func (m *Manager) validateAuthentication(auth *config.Authentication, context string) error {
	if auth == nil {
		return fmt.Errorf("%s: authentication is nil", context)
	}

	if auth.ProtocolVersion == "" {
		return fmt.Errorf("%s: missing protocol version", context)
	}

	if auth.ProtocolVersion != "SNMPv1" && auth.ProtocolVersion != "SNMPv2c" && auth.ProtocolVersion != "SNMPv3" {
		return fmt.Errorf("%s: unsupported protocol version", context)
	}

	if auth.ContextName != "" && auth.ProtocolVersion != snmp.ProtocolVersion3 {
		return fmt.Errorf("%s: context_name is only valid for SNMPv3 (got %q)",
			context, auth.ProtocolVersion)
	}

	if auth.ProtocolVersion == "SNMPv2c" || auth.ProtocolVersion == "SNMPv1" {
		if auth.Community == "" {
			return fmt.Errorf("%s: missing community", context)
		}
	}

	if auth.ProtocolVersion == "SNMPv3" {
		if auth.SecurityLevel != "noAuthNoPriv" &&
			auth.SecurityLevel != "authNoPriv" &&
			auth.SecurityLevel != "authPriv" {
			return fmt.Errorf("%s: invalid security level %s", context, auth.SecurityLevel)
		}
		if auth.SecurityLevel == "authNoPriv" || auth.SecurityLevel == "authPriv" {
			if auth.Username == "" {
				return fmt.Errorf("%s: missing username", context)
			}
			if auth.AuthPassphrase == "" {
				return fmt.Errorf("%s: missing auth passphrase", context)
			}
			if auth.AuthProtocol == "" {
				return fmt.Errorf("%s: missing auth protocol", context)
			}
		}
		if auth.SecurityLevel == "authPriv" {
			if auth.PrivPassphrase == "" {
				return fmt.Errorf("%s: missing priv passphrase", context)
			}
			if auth.PrivProtocol == "" {
				return fmt.Errorf("%s: missing priv protocol", context)
			}
		}
	}

	return nil
}

// validatePolicy validates the policy
func (m *Manager) validatePolicy(policy config.Policy) error {
	hasPolicyAuth := policy.Scope.Authentication.ProtocolVersion != ""

	if hasPolicyAuth {
		if err := m.validateAuthentication(&policy.Scope.Authentication, "policy-level"); err != nil {
			return err
		}
	}

	for _, target := range policy.Scope.Targets {
		if err := checkTargetExpansion(target.Host); err != nil {
			return err
		}
		if target.Authentication != nil {
			context := fmt.Sprintf("target %s", target.Host)
			if err := m.validateAuthentication(target.Authentication, context); err != nil {
				return err
			}
		} else if !hasPolicyAuth {
			return fmt.Errorf("target %s: no authentication configured and no policy-level fallback available", target.Host)
		}
	}

	if policy.Config.MetricsInterval == nil || *policy.Config.MetricsInterval <= 0 {
		return fmt.Errorf("metrics_interval must be a positive integer")
	}

	if policy.Config.SNMPTimeout < 0 {
		return fmt.Errorf("snmp_timeout must not be negative")
	}

	if policy.Config.Retries < 0 {
		return fmt.Errorf("retries must not be negative")
	}

	return nil
}

// resolveAuthenticationEnvVarsForAuth resolves environment variables for a single Authentication
func (m *Manager) resolveAuthenticationEnvVarsForAuth(auth *config.Authentication, context string) error {
	if auth == nil {
		return nil
	}

	fields := []struct {
		field *string
		label string
	}{
		{&auth.Community, "community"},
		{&auth.Username, "username"},
		{&auth.AuthPassphrase, "auth_passphrase"},
		{&auth.PrivPassphrase, "priv_passphrase"},
	}

	for _, f := range fields {
		resolved, err := env.ResolveEnv(*f.field)
		if err != nil {
			return fmt.Errorf("%s: failed to resolve %s environment variable: %w", context, f.label, err)
		}
		*f.field = resolved
	}

	return nil
}

// resolveAuthenticationEnvVars resolves environment variables in authentication configuration
func (m *Manager) resolveAuthenticationEnvVars(policy *config.Policy) error {
	if err := m.resolveAuthenticationEnvVarsForAuth(&policy.Scope.Authentication, "policy-level"); err != nil {
		return err
	}

	for i := range policy.Scope.Targets {
		if policy.Scope.Targets[i].Authentication != nil {
			context := fmt.Sprintf("target %s", policy.Scope.Targets[i].Host)
			if err := m.resolveAuthenticationEnvVarsForAuth(policy.Scope.Targets[i].Authentication, context); err != nil {
				return err
			}
		}
	}

	return nil
}
