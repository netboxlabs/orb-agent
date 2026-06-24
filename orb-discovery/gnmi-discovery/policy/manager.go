package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/env"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
)

// maxIntervalMs is the largest interval (in ms) that can be multiplied by
// time.Millisecond without overflowing time.Duration (int64 ns).
const maxIntervalMs = int64(math.MaxInt64) / int64(time.Millisecond)

// Manager owns the set of running policies.
type Manager struct {
	// mu guards the policies map — the HTTP server calls StartPolicy /
	// StopPolicy / GetPolicyStatuses from concurrent request goroutines, so an
	// unguarded map would hit Go's "concurrent map iteration and map write"
	// panic. Runner-internal state has its own locks; mu only protects the map.
	mu       sync.RWMutex
	policies map[string]*Runner
	client   diode.Client
	logger   *slog.Logger
	ctx      context.Context
	dialer   gnmi.Dialer
	store    *mapping.Store
}

// NewManager returns a new policy manager.
func NewManager(ctx context.Context, logger *slog.Logger, client diode.Client, dialer gnmi.Dialer, profilesDir string) (*Manager, error) {
	store, err := mapping.LoadProfilesWithLogger(profilesDir, logger)
	if err != nil {
		return nil, err
	}
	return &Manager{
		ctx:      ctx,
		client:   client,
		logger:   logger,
		policies: make(map[string]*Runner),
		dialer:   dialer,
		store:    store,
	}, nil
}

// ParsePolicies unmarshals, validates, applies defaults and resolves env vars.
func (m *Manager) ParsePolicies(data []byte) (map[string]config.Policy, error) {
	var payload config.Policies
	if err := yaml.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	if len(payload.Policies) == 0 {
		return nil, errors.New("no policies found in the request")
	}
	for name, policy := range payload.Policies {
		if err := m.validatePolicy(policy); err != nil {
			return nil, fmt.Errorf("%s : invalid policy : %w", name, err)
		}
		// Resolve env BEFORE applying defaults: ResolveEnv only matches a
		// whole-string ${VAR}, so the host must be resolved before the default
		// port is appended (otherwise "${HOST}:9339" would never resolve).
		if err := m.resolveEnv(&policy); err != nil {
			return nil, fmt.Errorf("%s : failed to resolve environment variables : %w", name, err)
		}
		m.applyDefaults(&policy)
		payload.Policies[name] = policy
	}
	return payload.Policies, nil
}

func (m *Manager) validatePolicy(policy config.Policy) error {
	if len(policy.Scope.Targets) == 0 {
		return errors.New("no targets configured")
	}
	switch policy.Config.Mode {
	case "", config.ModeAuto, config.ModeOnChange, config.ModeSample, config.ModeGet:
	default:
		return fmt.Errorf("invalid mode %q (allowed: auto, on_change, sample, get)", policy.Config.Mode)
	}
	// Zero is allowed — applyDefaults will replace it with the built-in default.
	// Negative values are invalid: a negative get_interval_ms/sample_interval_ms
	// would reach time.NewTicker with a non-positive duration and panic.
	if policy.Config.GetIntervalMs < 0 || int64(policy.Config.GetIntervalMs) > maxIntervalMs {
		return fmt.Errorf("get_interval_ms must be >= 0 and <= %d, got %d", maxIntervalMs, policy.Config.GetIntervalMs)
	}
	if policy.Config.SampleIntervalMs < 0 || int64(policy.Config.SampleIntervalMs) > maxIntervalMs {
		return fmt.Errorf("sample_interval_ms must be >= 0 and <= %d, got %d", maxIntervalMs, policy.Config.SampleIntervalMs)
	}
	if policy.Config.DebounceMs < 0 || int64(policy.Config.DebounceMs) > maxIntervalMs {
		return fmt.Errorf("debounce_ms must be >= 0 and <= %d, got %d", maxIntervalMs, policy.Config.DebounceMs)
	}
	// Compile the interface name patterns/excludes at parse time so a bad regex
	// fails the POST /policies with a 400 instead of silently breaking at flush.
	if err := validateInterfaceRegexes(&policy.Config.Defaults); err != nil {
		return err
	}
	for _, t := range policy.Scope.Targets {
		if t.Host == "" {
			return errors.New("target with empty host")
		}
		switch t.Mode {
		case "", config.ModeAuto, config.ModeOnChange, config.ModeSample, config.ModeGet:
		default:
			return fmt.Errorf("target %s: invalid mode %q", t.Host, t.Mode)
		}
		if t.OverrideDefaults != nil {
			if err := validateInterfaceRegexes(t.OverrideDefaults); err != nil {
				return fmt.Errorf("target %s: %w", t.Host, err)
			}
		}
	}
	return nil
}

// validateInterfaceRegexes compiles every interface_patterns match and every
// interface_exclude_patterns entry in d, returning a clear error naming the
// offending pattern. d may be nil.
func validateInterfaceRegexes(d *config.Defaults) error {
	if d == nil {
		return nil
	}
	for _, p := range d.InterfacePatterns {
		// An empty type would set Interface.Type to "" (unresolvable by NetBox/Diode)
		// and short-circuit the OC/name/speed/default fallback — reject it up front.
		if strings.TrimSpace(p.Type) == "" {
			return fmt.Errorf("invalid interface_patterns entry %q: empty type", p.Match)
		}
		if _, err := regexp.Compile(p.Match); err != nil {
			return fmt.Errorf("invalid interface_patterns match %q: %w", p.Match, err)
		}
	}
	for _, m := range d.InterfaceExcludePatterns {
		if _, err := regexp.Compile(m); err != nil {
			return fmt.Errorf("invalid interface_exclude_patterns %q: %w", m, err)
		}
	}
	return nil
}

func (m *Manager) applyDefaults(policy *config.Policy) {
	if policy.Config.Mode == "" {
		policy.Config.Mode = config.ModeAuto
	}
	if policy.Config.DebounceMs == 0 {
		policy.Config.DebounceMs = config.DefaultDebounceMs
	}
	if policy.Config.SampleIntervalMs == 0 {
		policy.Config.SampleIntervalMs = config.DefaultSampleInterval
	}
	if policy.Config.GetIntervalMs == 0 {
		policy.Config.GetIntervalMs = config.DefaultGetInterval
	}
	if policy.Config.Defaults.Site == "" {
		policy.Config.Defaults.Site = "undefined"
	}
	if policy.Config.Defaults.Role == "" {
		policy.Config.Defaults.Role = "undefined"
	}
	if policy.Config.Defaults.Interface.Type == "" {
		policy.Config.Defaults.Interface.Type = "other"
	}
	for i := range policy.Scope.Targets {
		policy.Scope.Targets[i].Host = ensurePort(policy.Scope.Targets[i].Host)
	}
}

// ensurePort appends the default gNMI port when the host has none. It is
// IPv6-safe: a bare IPv6 literal (e.g. 2001:db8::1) has colons but no port, so
// net.SplitHostPort is used to detect a real port, and IPv6 literals are
// bracketed before the port is appended.
func ensurePort(h string) string {
	if h == "" {
		return h
	}
	if _, _, err := net.SplitHostPort(h); err == nil {
		return h // already host:port (handles bracketed IPv6 too)
	}
	// SplitHostPort failed. Append the default port only when the input clearly
	// has no port; never rewrite a value that already carries colons but isn't a
	// recognizable IPv6 literal (a malformed host:port like "a:b:c"), so the
	// dial/validation error points at the real bad value.
	//
	// net.ParseIP rejects a zone id, so validate against the zone-stripped host
	// (fe80::1%eth0 -> fe80::1) while still bracketing the original (with zone).
	ipPart := h
	if i := strings.IndexByte(h, '%'); i >= 0 {
		ipPart = h[:i]
	}
	switch {
	case strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]"):
		return fmt.Sprintf("%s:%d", h, config.DefaultGNMIPort) // bracketed IPv6, no port
	case net.ParseIP(ipPart) != nil && strings.Contains(h, ":"):
		return fmt.Sprintf("[%s]:%d", h, config.DefaultGNMIPort) // bare IPv6 literal (incl. zone) -> bracket
	case strings.Contains(h, ":"):
		return h // malformed host:port -> leave untouched
	default:
		return fmt.Sprintf("%s:%d", h, config.DefaultGNMIPort) // hostname / IPv4, no port
	}
}

func (m *Manager) resolveEnv(policy *config.Policy) error {
	for i := range policy.Scope.Targets {
		t := &policy.Scope.Targets[i]
		// Resolve every string field a user is likely to source from env: host,
		// credentials, and TLS material paths.
		for _, f := range []*string{
			&t.Host, &t.Username, &t.Password,
			&t.TLS.CAFile, &t.TLS.CertFile, &t.TLS.KeyFile,
		} {
			resolved, err := env.ResolveEnv(*f)
			if err != nil {
				return err
			}
			*f = resolved
		}
	}
	return nil
}

// HasPolicy reports whether a policy is running.
func (m *Manager) HasPolicy(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.policies[name]
	return ok
}

// ErrPolicyExists is returned by StartPolicy when a policy of the same name is
// already running. The check-and-insert is atomic under the manager lock, so
// the HTTP handler can map this to 409 Conflict without a separate (racy)
// pre-check.
var ErrPolicyExists = errors.New("policy already exists")

// ErrPolicyNotFound is returned by StopPolicy when no policy of that name is
// running. The check-and-delete is atomic under the manager lock, so the HTTP
// handler can map this to 404 without a separate (racy) pre-check.
var ErrPolicyNotFound = errors.New("policy not found")

// StartPolicy starts a policy.
func (m *Manager) StartPolicy(name string, policy config.Policy) error {
	if len(policy.Scope.Targets) == 0 {
		return fmt.Errorf("%s : no targets found in the policy", name)
	}
	// Fail fast on a pinned-but-unknown profile: a profile: typo is explicit
	// operator intent, not something to silently fall back from. This surfaces
	// as a 400 from POST /policies rather than a silent _base run.
	for _, tgt := range policy.Scope.Targets {
		if tgt.Profile != "" {
			if _, ok := m.store.Get(tgt.Profile); !ok {
				return fmt.Errorf("%s : target %s pins unknown profile %q", name, tgt.Host, tgt.Profile)
			}
		}
	}
	m.mu.Lock()
	if _, ok := m.policies[name]; ok {
		m.mu.Unlock()
		return ErrPolicyExists // already running
	}
	r, err := NewRunner(m.ctx, m.logger, name, policy, m.client, m.dialer, m.store)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	m.policies[name] = r
	r.Start() // under the lock: wg.Add happens-before any StopPolicy's wg.Wait
	m.mu.Unlock()
	return nil
}

// StopPolicy stops and removes a policy. The runner is detached under the lock,
// then stopped outside it (Stop blocks on goroutine unwind — not something to
// hold the map lock for).
func (m *Manager) StopPolicy(name string) error {
	m.mu.Lock()
	r, ok := m.policies[name]
	if ok {
		delete(m.policies, name)
	}
	m.mu.Unlock()
	if !ok {
		return ErrPolicyNotFound
	}
	return r.Stop()
}

// Stop stops all policies.
func (m *Manager) Stop() error {
	m.mu.Lock()
	runners := make([]*Runner, 0, len(m.policies))
	for _, r := range m.policies {
		runners = append(runners, r)
	}
	m.policies = make(map[string]*Runner)
	m.mu.Unlock()
	for _, r := range runners {
		if err := r.Stop(); err != nil {
			return err
		}
	}
	return nil
}

// GetCapabilities returns the backend capabilities.
func (m *Manager) GetCapabilities() []string {
	return []string{"targets", "on_change", "sample", "get"}
}

// Status is the per-policy status surfaced by /api/v1/status.
type Status struct {
	Name    string         `json:"name"`
	Status  string         `json:"status"`
	Targets []TargetStatus `json:"targets,omitempty"`
	Runs    []*Run         `json:"runs,omitempty"`
}

// GetPolicyStatuses returns each running policy with its derived status,
// per-target state, and recent runs. RLock guards the map iteration against
// concurrent StartPolicy/StopPolicy; the per-runner Runs()/TargetStatuses()
// take their own locks (no nesting on m.mu).
func (m *Manager) GetPolicyStatuses() []Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	statuses := make([]Status, 0, len(m.policies))
	for name, r := range m.policies {
		runs := r.Runs()
		statuses = append(statuses, Status{
			Name:    name,
			Status:  deriveStatus(runs),
			Targets: r.TargetStatuses(),
			Runs:    runs,
		})
	}
	return statuses
}

// deriveStatus returns "unknown" with no runs, "running" if any run is in-flight,
// otherwise the latest run's status. Runs are newest-first (GetRunsForPolicy).
func deriveStatus(runs []*Run) string {
	if len(runs) == 0 {
		return "unknown"
	}
	for _, r := range runs {
		if r.Status == RunStatusRunning {
			return string(RunStatusRunning)
		}
	}
	return string(runs[0].Status)
}
