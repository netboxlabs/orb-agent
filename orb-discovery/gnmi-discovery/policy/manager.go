package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/env"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/targets"
)

// maxIntervalMs is the largest interval (in ms) that can be multiplied by
// time.Millisecond without overflowing time.Duration (int64 ns).
const maxIntervalMs = int64(math.MaxInt64) / int64(time.Millisecond)

// maxScanWork bounds how many addresses a policy's targets enumerate in total,
// as opposed to how many distinct endpoints they describe. The two differ when
// ranges overlap, because each entry is expanded before the results are
// deduplicated. Four times the endpoint cap leaves ample room for a subnet plus
// pinned hosts, or nested prefixes carrying different credentials, while refusing
// the degenerate case.
const maxScanWork = 4 * uint64(targets.MaxExpand)

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
	config.WarnUnknownPolicyKeys(data, m.logger)
	config.WarnAmbiguousNullKeys(data, m.logger)
	if len(payload.Policies) == 0 {
		return nil, errors.New("no policies found in the request")
	}
	for name, policy := range payload.Policies {
		// The policy name reaches a log line on nearly every path through this
		// backend, so it is checked before anything else logs it.
		if err := checkNoControlChars(name, "policy name"); err != nil {
			return nil, err
		}
		// Inherit BEFORE resolving env. resolveEnv walks only the target list,
		// so inheriting afterwards would copy a scope-level ${GNMI_PASS} into
		// every target as that literal string with resolution already past —
		// every device in a subnet authenticating with the eleven characters
		// "${GNMI_PASS}". Inheriting first also lets validatePolicy see each
		// target's effective values rather than consulting two places.
		inheritScopeDefaults(&policy)

		if err := m.validatePolicy(policy); err != nil {
			return nil, fmt.Errorf("%s : invalid policy : %w", name, err)
		}
		// Resolve env BEFORE applying defaults: ResolveEnv only matches a
		// whole-string ${VAR}, so the host must be resolved before the port is
		// appended (otherwise "${HOST}:9339" would never resolve).
		if err := m.resolveEnv(&policy); err != nil {
			return nil, fmt.Errorf("%s : failed to resolve environment variables : %w", name, err)
		}
		// Host checks run here, after resolution, because a host written as
		// ${SUBNET} is an opaque string until now: checked earlier it parses as
		// a hostname and passes every bound, then resolves to a /8 that the
		// runner enumerates into hundreds of megabytes.
		if err := validateTargetHosts(&policy, m.logger); err != nil {
			return nil, fmt.Errorf("%s : invalid policy : %w", name, err)
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
	if policy.Config.ProbeTimeoutMs < 0 || int64(policy.Config.ProbeTimeoutMs) > maxIntervalMs {
		return fmt.Errorf("probe_timeout_ms must be >= 0 and <= %d, got %d", maxIntervalMs, policy.Config.ProbeTimeoutMs)
	}
	// Rejected rather than clamped: an operator who wrote 5000 meant seconds and
	// wants to know the field is milliseconds, not to be silently given an hour.
	if ms := policy.Config.RescanIntervalMs; ms != 0 {
		if ms < config.MinRescanIntervalMs || int64(ms) > maxIntervalMs {
			return fmt.Errorf("rescan_interval_ms must be 0 (disabled) or between %d and %d, got %d",
				config.MinRescanIntervalMs, maxIntervalMs, ms)
		}
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
		t := &policy.Scope.Targets[i]
		// A CIDR or range is not an endpoint yet. The runner appends the port to
		// each address once it expands, so stamping one here would produce
		// "10.0.0.0/24:9339" and break the parse it is about to do. Asked of
		// Expand's own branch decision, so a hostname that happens to begin with
		// an address still gets its port.
		if !targets.IsSingleEndpoint(t.Host) {
			continue
		}
		t.Host = ensurePort(t.Host, resolvedPort(t.Port))
	}
}

// ensurePort appends the default gNMI port when the host has none. It is
// IPv6-safe: a bare IPv6 literal (e.g. 2001:db8::1) has colons but no port, so
// net.SplitHostPort is used to detect a real port, and IPv6 literals are
// bracketed before the port is appended.
// resolvedPort returns the port to use for a target. Inheritance has already
// folded the scope's value into the target, so the precedence chain
// inline > target > scope > default reduces to this plus ensurePort's refusal
// to overwrite an inline suffix.
func resolvedPort(port uint16) uint16 {
	if port == 0 {
		return config.DefaultGNMIPort
	}
	return port
}

// ensurePort appends port to h unless h already carries one.
func ensurePort(h string, port uint16) string {
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
		return fmt.Sprintf("%s:%d", h, port) // bracketed IPv6, no port
	case net.ParseIP(ipPart) != nil && strings.Contains(h, ":"):
		return fmt.Sprintf("[%s]:%d", h, port) // bare IPv6 literal (incl. zone) -> bracket
	case strings.Contains(h, ":"):
		return h // malformed host:port -> leave untouched
	default:
		return fmt.Sprintf("%s:%d", h, port) // hostname / IPv4, no port
	}
}

// validateTargetHosts checks what only becomes checkable once ${VAR}s are
// resolved: how far each host expands, whether the forms are usable, and
// whether two entries name the same endpoint.
//
// Expansion itself is deferred to the runner — a sweep of a /22 cannot happen
// inside a policy POST — so this counts without enumerating.
func validateTargetHosts(policy *config.Policy, logger *slog.Logger) error {
	seen := make(map[string]int, len(policy.Scope.Targets))
	// Spans are grouped by port: the same address reached on two ports is two
	// endpoints, so merging across ports would undercount.
	spans := map[uint16][][2]uint32{}
	var namedHosts, scanWork uint64

	for i, t := range policy.Scope.Targets {
		if err := checkNoControlChars(t.Host, "target host"); err != nil {
			return err
		}

		bare, port, inline := splitEffectivePort(t.Host, t.Port)

		// Asked of the host with its port removed, so a hostname that merely
		// starts with an address — "10.0.0.1-switch.example.com:6030" — is not
		// mistaken for a range carrying an inline port.
		if inline && !targets.IsSingleEndpoint(bare) {
			return fmt.Errorf(
				"target %q: a CIDR or range cannot carry an inline port; use the port field", t.Host)
		}
		if inline && t.Port != 0 {
			// An inline port wins, so the field is dead weight here. Warn rather
			// than reject: an inline port on a single host is the documented form
			// and must keep working.
			logger.Warn("target sets both an inline port and the port field; the inline port wins",
				"host", t.Host, "ignored_port", t.Port)
		}

		// Per target first, so one oversized entry is named as the offender
		// rather than blamed on whatever happened to come last.
		count, err := targets.Count(bare)
		if err != nil {
			return fmt.Errorf("target %q: %w", t.Host, err)
		}
		if count > targets.MaxExpand {
			return fmt.Errorf(
				"target %q expands to %d addresses, more than the %d supported",
				t.Host, count, targets.MaxExpand)
		}

		scanWork += count

		start, end, enumerable, err := targets.Span(bare)
		if err != nil {
			return fmt.Errorf("target %q: %w", t.Host, err)
		}
		if enumerable {
			spans[port] = append(spans[port], [2]uint32{start, end})
		} else {
			namedHosts++
		}

		key := fmt.Sprintf("%s:%d", canonicalHost(bare), port)
		if first, dup := seen[key]; dup {
			return fmt.Errorf(
				"targets %d and %d both name %q; one device cannot have two entries", first, i, t.Host)
		}
		seen[key] = i
	}

	// The union, not the sum. Naming a subnet and then pinning hosts inside it to
	// give them their own credentials describes the subnet's endpoints and no
	// more, and summing the two rejected a policy that expands to fewer targets
	// than the cap allows.
	total := namedHosts
	for _, group := range spans {
		total += targets.UnionSize(group)
	}
	if total > targets.MaxExpand {
		return fmt.Errorf(
			"this policy expands to %d distinct addresses, more than the %d supported",
			total, targets.MaxExpand)
	}

	// Bounding the union alone bounds the subscriptions, which is what the cap
	// was for, but not the work: the runner expands every entry independently
	// before deduping, so heavily overlapping ranges cost the sum even though
	// they yield the union. Forty equivalent /22s passed the union check and
	// enumerated ~41k addresses per sweep, repeated on every rescan tick.
	if scanWork > maxScanWork {
		return fmt.Errorf(
			"this policy's targets enumerate %d addresses in total, more than the %d supported;"+
				" overlapping ranges are expanded separately before being deduplicated",
			scanWork, maxScanWork)
	}
	return nil
}

// splitEffectivePort returns a target's host without its port, and the port it
// will actually be reached on: an inline suffix wins over the port field, which
// wins over the scope's value and the default.
//
// Both halves have to come from the same decision. Taking the host from
// hostWithoutPort while taking the port from the field alone made
// "10.0.0.5:6030" and "10.0.0.5:57400" collide on one key — two real endpoints
// rejected as a duplicate — and let an inline ":6030" and a "port: 6030" on the
// same host produce two keys for one endpoint.
func splitEffectivePort(host string, field uint16) (bare string, port uint16, inline bool) {
	if h, p, err := net.SplitHostPort(host); err == nil {
		if n, cerr := strconv.ParseUint(p, 10, 16); cerr == nil {
			return strings.Trim(h, "[]"), uint16(n), true
		}
	}
	// Brackets come off here too, not only on the branch above. bare is what
	// Count, Span, IsSingleEndpoint and canonicalHost are all asked about, and it
	// was normalized on one path and not the other: canonicalHost trims its own
	// input, so "[10.0.0.1]" collapsed with the plain address for identity while
	// Span refused to parse it and counted it as a separate endpoint.
	return strings.Trim(host, "[]"), resolvedPort(field), false
}

// canonicalHost normalizes a bare host for comparison: an IP literal to the one
// spelling Go prints for it, a name to lower case.
//
// Validation and expansion must agree on what "the same endpoint" means, and
// they did not. Validation lowercased the raw text while expansion canonicalized
// through net.ParseIP, so `2001:db8::1` and `2001:0db8::1` passed validation as
// two targets with two sets of credentials and were then collapsed into one by
// the expansion dedupe — leaving the effective configuration to depend on which
// entry came first, with only a warning. Both layers now call this.
//
// Lower-casing a name rather than resolving it is deliberate: Expand never
// resolves DNS, so a name and an address cannot be known to be the same device,
// but DNS names are case-insensitive.
func canonicalHost(h string) string {
	h = strings.Trim(h, "[]")

	// A zone identifier is an interface name, and net.ParseIP refuses any address
	// carrying one — so the whole value fell to the lower-casing path meant for
	// hostnames, and got both halves wrong. Linux interface names are
	// case-sensitive, so fe80::1%Eth0 and fe80::1%eth0 are two different links
	// and were being rejected as one duplicate; meanwhile the address half was
	// never canonicalized, so fe80::0001%eth0 and fe80::1%eth0 were treated as
	// two endpoints when they are one.
	if addr, zone, ok := strings.Cut(h, "%"); ok {
		if ip := net.ParseIP(addr); ip != nil {
			return ip.String() + "%" + zone
		}
		return strings.ToLower(addr) + "%" + zone
	}

	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}

	// A prefix names a subnet, and 10.0.0.1/22 names the same subnet as
	// 10.0.0.0/22. Without masking, the two are separate entries that expand to
	// the same 1022 addresses, and the second expansion is discarded wholesale.
	if prefix, err := netip.ParsePrefix(h); err == nil {
		return prefix.Masked().String()
	}

	return strings.ToLower(h)
}

// checkNoControlChars rejects a policy-supplied string carrying control
// characters.
//
// No policy name, hostname, IP, CIDR or range contains one, so this refuses
// nothing legitimate. It closes at the source the route by which policy text
// reaches a log line as something other than one field value: a value holding a
// newline could otherwise forge whole log records, which is what CodeQL flags
// every log of a policy-derived host or policy name for.
func checkNoControlChars(value, what string) error {
	for i, r := range value {
		if r == 0x7f || r < 0x20 {
			return fmt.Errorf("%s contains a control character at byte offset %d", what, i)
		}
	}
	return nil
}

// inheritScopeDefaults folds the scope's settings into each target that has not
// set them. Scalars inherit individually; tls inherits as a whole block, because
// a bool cannot distinguish "unset" from "false" and a partial merge would
// silently zero the fields a target did not mention.
//
// Blocks are copied rather than aliased. A shared pointer would give every
// target in a 254-address expansion the same TLSConfig, which resolveEnv then
// writes through once per target — the aliasing MergeDefaults documents avoiding
// for the same reason.
func inheritScopeDefaults(policy *config.Policy) {
	scope := &policy.Scope
	for i := range scope.Targets {
		t := &scope.Targets[i]
		// Presence, not emptiness. A target that writes `username: ""` has said
		// it connects anonymously, and inheriting over that would send the scope
		// credentials to a device the operator marked as taking none.
		if t.Username == nil && scope.Username != "" {
			v := scope.Username
			t.Username = &v
		}
		if t.Password == nil && scope.Password != "" {
			v := scope.Password
			t.Password = &v
		}
		if t.Port == 0 {
			t.Port = scope.Port
		}
		// Origin distinguishes unset from an explicit "", so test for nil: a
		// target asking for origin-less paths must not inherit "openconfig".
		if t.Origin == nil && scope.Origin != nil {
			origin := *scope.Origin
			t.Origin = &origin
		}
		if t.TLS == nil && scope.TLS != nil {
			tls := *scope.TLS
			t.TLS = &tls
		}
	}
}

func (m *Manager) resolveEnv(policy *config.Policy) error {
	for i := range policy.Scope.Targets {
		t := &policy.Scope.Targets[i]
		// Resolve every string field a user is likely to source from env: host,
		// credentials, and TLS material paths.
		fields := []*string{&t.Host}
		if t.Username != nil {
			fields = append(fields, t.Username)
		}
		if t.Password != nil {
			fields = append(fields, t.Password)
		}
		// TLS is a pointer, and taking the address of a field through a nil one
		// panics rather than failing to compile. No tls block is the common
		// case, so this guard is on the hot path, not an edge case. ResolvedTLS
		// cannot serve here: it returns a copy, so writing through it would not
		// propagate.
		if t.TLS != nil {
			fields = append(fields, &t.TLS.CAFile, &t.TLS.CertFile, &t.TLS.KeyFile)
		}
		for _, f := range fields {
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
