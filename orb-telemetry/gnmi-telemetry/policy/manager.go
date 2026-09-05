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

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/collector"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/env"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/gnmi"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/profiles"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/targets"
)

// Status represents the status of a policy
type Status struct {
	Name        string                   `json:"name"`
	Status      string                   `json:"status"`
	LastError   *string                  `json:"last_error,omitempty"`
	LastErrorAt *time.Time               `json:"last_error_at,omitempty"`
	Targets     []collector.TargetStatus `json:"targets"`
}

// Manager manages gnmi-telemetry policy runners
type Manager struct {
	// mu guards the policies map. The HTTP server calls StartPolicy,
	// StopPolicy and GetPolicyStatuses from concurrent request goroutines, and
	// the agent polls status on a timer while pushing policy updates, so an
	// unguarded map hits Go's "concurrent map read and map write" fatal error.
	// Runner state has its own lock; mu only protects the map.
	mu       sync.RWMutex
	policies map[string]*Runner
	// stopping reserves a policy name while its runner unwinds, keyed by name
	// and closed once Stop has returned. A stopping runner calls ForgetPolicy,
	// which is keyed on the policy name alone, so a replacement started under
	// that name before Stop returns would have its observations and poll state
	// erased by the runner it replaced. Guarded by mu.
	stopping map[string]chan struct{}
	// policyDirs records the profiles directory each running policy uses, so
	// stopping one releases the profile set it charged. Guarded by mu, and
	// written together with policies so the two cannot disagree about which
	// directories are in use.
	policyDirs         map[string]string
	logger             *slog.Logger
	ctx                context.Context
	defaultProfilesDir string
	// profilesRoot confines a policy-supplied profiles_dir. Empty rejects every
	// per-policy override.
	profilesRoot string
	// allowedEnvVars is the set of environment variables a policy may read
	// through a ${NAME} credential reference. Empty reads none.
	allowedEnvVars map[string]struct{}
	// dialer is how every collector this manager builds reaches a target. It
	// is held here rather than per collector so a test can substitute one for
	// the whole manager.
	dialer gnmi.Dialer

	collectorsMu    sync.Mutex
	collectorsByDir map[string]*cachedCollector
}

// cachedCollector is one profile set and the number of running policies using
// it. The cache exists so policies naming one directory read the profiles once
// between them, and the count is what ends that: a collector holds a fully
// resolved profile set, so one kept per directory a request happened to name
// would grow without bound.
type cachedCollector struct {
	collector releasableCollector
	refs      int
}

// releasableCollector is the collector as the cache holds it: what a runner
// drives, plus the release the cache owes it. Dropping the map entry is not
// enough, because the meter holds a callback that closes over the collector.
type releasableCollector interface {
	Collector
	Close()
}

// Options configures a Manager.
type Options struct {
	// DefaultProfilesDir is the profile overlay every policy uses unless it
	// names its own. It comes from the command line, so it is not restricted.
	DefaultProfilesDir string
	// ProfilesRoot is the directory a policy-supplied profiles_dir must resolve
	// inside. Empty, the default, rejects every per-policy override: the value
	// arrives over an unauthenticated API and names a tree the backend walks,
	// so without a root there is nowhere it is known to be safe.
	ProfilesRoot string
	// AllowedEnvVars names the environment variables a policy may read through
	// a ${NAME} credential reference. Empty, the default, rejects every
	// reference: a policy arrives over an unauthenticated API and the backend
	// inherits the agent's environment, so an unrestricted resolver hands any
	// process secret to whatever host the policy targets.
	AllowedEnvVars []string
	// Dialer opens a gNMI session to a target. Nil, the default, uses the real
	// gnmic dialer; a test substitutes a fake so no policy touches the network.
	Dialer gnmi.Dialer
}

// NewManager returns a new policy manager
func NewManager(ctx context.Context, logger *slog.Logger, opts Options) *Manager {
	allowed := make(map[string]struct{}, len(opts.AllowedEnvVars))
	for _, name := range opts.AllowedEnvVars {
		if name = strings.TrimSpace(name); name != "" {
			allowed[name] = struct{}{}
		}
	}
	dialer := opts.Dialer
	if dialer == nil {
		dialer = &gnmi.GnmicDialer{}
	}
	return &Manager{
		ctx:                ctx,
		logger:             logger,
		policies:           make(map[string]*Runner),
		policyDirs:         make(map[string]string),
		stopping:           make(map[string]chan struct{}),
		defaultProfilesDir: opts.DefaultProfilesDir,
		profilesRoot:       opts.ProfilesRoot,
		allowedEnvVars:     allowed,
		collectorsByDir:    make(map[string]*cachedCollector),
		dialer:             dialer,
	}
}

// acquireCollector returns the shared collector for the given profiles
// directory, loading the profiles on first use, and charges one reference to
// it. Every caller must pair this with releaseCollector. Thread-safe.
func (m *Manager) acquireCollector(profilesDir string) (releasableCollector, error) {
	m.collectorsMu.Lock()
	defer m.collectorsMu.Unlock()
	if c, ok := m.collectorsByDir[profilesDir]; ok {
		c.refs++
		return c.collector, nil
	}
	if profilesDir != "" {
		if _, err := os.Stat(profilesDir); err != nil {
			return nil, fmt.Errorf("profiles directory not found: %s", profilesDir)
		}
	}
	store, err := profiles.LoadProfiles(profilesDir, m.logger)
	if err != nil {
		return nil, fmt.Errorf("loading gNMI metric profiles: %w", err)
	}
	// The subscription settings are per policy, so they are passed to each
	// target rather than baked into the collector shared by every policy using
	// this profile set.
	c := collector.New(m.dialer, store, m.logger)
	m.collectorsByDir[profilesDir] = &cachedCollector{collector: c, refs: 1}
	m.logger.Info("loaded gNMI metric profiles", "override_dir", config.SanitizeLogValue(profilesDir), "count", len(store.Names()))
	return c, nil
}

// releaseCollector drops one reference to a profiles directory's collector and
// discards it once the last policy using it has gone. A start that never
// completes releases what it charged, so a request naming a directory no policy
// ends up running does not leave a profile set behind.
//
// Close runs with the cache lock dropped. It waits out a collection cycle that
// is already running, which is the same reason StopPolicy stops a runner
// outside mu: holding the cache lock across it would stall every other policy
// request for the length of an export.
func (m *Manager) releaseCollector(profilesDir string) {
	m.collectorsMu.Lock()
	c, ok := m.collectorsByDir[profilesDir]
	discarded := false
	if ok {
		c.refs--
		discarded = c.refs <= 0
		if discarded {
			delete(m.collectorsByDir, profilesDir)
		}
	}
	m.collectorsMu.Unlock()
	if discarded {
		c.collector.Close()
	}
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
		if err := ValidatePolicyName(name); err != nil {
			return nil, err
		}
		normalizeTargetHosts(&policy)
		// Scope inheritance happens once, here, so validation, the runner and
		// the collector all read the credentials and the port a target will
		// actually be reached with. EffectiveTarget keeps a target's own value,
		// including an explicit empty one, so applying it twice changes nothing.
		for i := range policy.Scope.Targets {
			policy.Scope.Targets[i] = config.EffectiveTarget(policy.Scope, policy.Scope.Targets[i])
		}
		if err := m.validatePolicy(policy); err != nil {
			return nil, fmt.Errorf("%s: invalid policy: %w", name, err)
		}
		// Split an inline port out of the host, so a Host handed to the
		// collector never carries a port or brackets. Unconditional: the
		// non-inline branch trims the brackets off an IPv6 literal and returns
		// the port EffectiveTarget has already set. It runs after validation,
		// which is what rejects an inline port on a range.
		for i := range policy.Scope.Targets {
			t := &policy.Scope.Targets[i]
			t.Host, t.Port, _ = splitEffectivePort(t.Host, t.Port)
		}
		payload.Policies[name] = policy
	}

	for name := range payload.Policies {
		updated := payload.Policies[name]
		if err := m.resolveCredentialEnvVars(&updated); err != nil {
			return nil, fmt.Errorf("%s: failed to resolve environment variables: %w", name, err)
		}
		payload.Policies[name] = updated
	}

	return payload.Policies, nil
}

// ValidatePolicyName rejects a name DELETE /policies/:policy cannot address.
// The YAML map key becomes the policy name, so without this a policy starts
// under a name that can never be deleted or replaced, and the only way to get
// rid of it is to restart the backend.
//
// What the rule excludes was read off the router rather than guessed at, and the
// server package holds it to that. An empty segment matches no route. A slash
// makes a second segment even when the client escapes it, since net/http decodes
// %2F before gin sees the path; a trailing one is worse than a miss, because the
// redirect drops it and the request lands on the neighbouring name instead. A
// dot segment routes as it stands but carries no fixed meaning on the way: it is
// resolved away by anything that normalises the path, url.URL.JoinPath included,
// so DELETE for ".." addresses the parent collection.
//
// Nothing else is excluded. A space, a percent sequence, a query or fragment
// character and a non-ASCII name all survive the round trip. Invalid UTF-8
// cannot reach here at all, the YAML parser having refused the document, which
// is what the exported "policy" metric attribute needs of the name.
func ValidatePolicyName(name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("policy name must not be empty or only whitespace")
	}
	if strings.Contains(name, "/") {
		return fmt.Errorf(`policy name must be a single path segment, so it may not contain "/": %q`, name)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("policy name must be a single path segment, not a dot segment: %q", name)
	}
	return nil
}

// HasPolicy checks if the policy exists
func (m *Manager) HasPolicy(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.policies[name]
	return ok
}

// resolveExisting canonicalises path as far as the filesystem allows: it
// follows every symlink in the deepest ancestor that resolves and appends the
// components below it unchanged. A path that does not exist therefore still
// yields the location it would occupy, rather than the error EvalSymlinks
// returns for it. The walk terminates at the volume root, which always
// resolves.
func resolveExisting(path string) string {
	rest := ""
	for cur := path; ; {
		if got, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(got, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return path
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// validateProfilesDir resolves a policy-supplied profiles directory inside root
// and rejects anything root does not contain. The value arrives over the API
// and names a tree the backend stats and walks, so rejecting ".." alone is not
// enough: an absolute path such as "/" carries none and would still be walked.
// A relative path is read against root, so a policy names the subdirectory it
// wants rather than repeating the root, and root itself is made absolute first
// so both forms work however the operator spelled it. An empty root rejects
// every override.
//
// Containment is checked twice: once on the names, which needs no filesystem
// access and refuses the obvious cases, and again on the canonical paths, since
// a symlink inside the root is a name inside it that the filesystem resolves
// elsewhere. The canonical path is what comes back, so the caller stats and
// walks what was checked. That narrows the window between the check and the
// walk without closing it: a component can still be replaced afterwards.
func validateProfilesDir(root, dir string) (string, error) {
	if root == "" {
		return "", fmt.Errorf("profiles directory may not be set per policy: start the backend with --profiles-root to allow it")
	}
	clean := filepath.Clean(dir)
	// Refuse any ".." at all rather than only a leading path element. Checking
	// elements would also accept a name such as /opt/a..b, but the substring
	// form is the barrier static analysis recognises, and a profiles directory
	// with dots in its name is not worth the weaker check.
	if strings.Contains(clean, "..") {
		return "", fmt.Errorf(`profiles directory must not contain "..": %s`, dir)
	}
	// The root is an operator flag and may be spelled relative to the working
	// directory, while a policy may name the documented absolute form under it.
	// filepath.Rel cannot relate the two, so the root is made absolute before
	// either containment check and both then compare paths of one kind. It sits
	// after the ".." test, which stays the first thing the policy-supplied value
	// meets, and only reads the working directory, not the value itself.
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("profiles root cannot be resolved: %s: %w", root, err)
	}
	if !filepath.IsAbs(clean) {
		clean = filepath.Join(cleanRoot, clean)
	}
	// Compare by path element rather than by string prefix, which would accept
	// a sibling whose name starts with the root's, such as /opt/profiles-other
	// under /opt/profiles.
	rel, err := filepath.Rel(cleanRoot, clean)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("profiles directory must be inside %s: %s", cleanRoot, dir)
	}
	// Both sides are canonicalised. The root is often reached through a link
	// itself, and comparing a resolved candidate against an unresolved root
	// would reject every legitimate override under such a root. A path inside
	// the root that does not exist survives this, so the loader reports it as
	// missing rather than the confinement reporting a resolution failure.
	realRoot := resolveExisting(cleanRoot)
	realDir := resolveExisting(clean)
	rel, err = filepath.Rel(realRoot, realDir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("profiles directory must be inside %s: %s resolves outside it", cleanRoot, dir)
	}
	return realDir, nil
}

// reserveStopping marks name as owned by a runner that is still stopping and
// returns the release to call once Stop has returned. Must be called with mu
// held; the release takes mu itself, so it runs after the caller has unlocked.
func (m *Manager) reserveStopping(name string) func() {
	done := make(chan struct{})
	m.stopping[name] = done
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.stopping[name] == done {
			delete(m.stopping, name)
		}
		close(done)
	}
}

// Handle names one runner a start created. A caller that may have to undo its
// start keeps this rather than the policy name: by the time it rolls back, a
// concurrent delete and a recreate can have put a different runner under that
// name, and stopping by name alone would stop that replacement.
//
// The zero Handle names nothing, so stopping it does nothing.
type Handle struct {
	name   string
	runner *Runner
}

// StartPolicy starts a single named policy. For a caller with nothing to roll
// back, so the handle is dropped.
func (m *Manager) StartPolicy(name string, policy config.Policy) error {
	_, err := m.StartPolicyHandle(name, policy)
	return err
}

// StartPolicyHandle starts a single named policy and returns a handle to the
// runner it created, for a caller that may have to undo the start. The
// duplicate check and the insert happen together under mu, so two concurrent
// requests for the same name cannot both start a runner.
func (m *Manager) StartPolicyHandle(name string, policy config.Policy) (Handle, error) {
	// Checked here as well as in ParsePolicies, since this is the call that
	// puts the name in the map a delete has to reach.
	if err := ValidatePolicyName(name); err != nil {
		return Handle{}, err
	}
	if len(policy.Scope.Targets) == 0 {
		return Handle{}, fmt.Errorf("%s : no targets found in the policy", name)
	}

	profilesDir := m.defaultProfilesDir
	if policy.Config.ProfilesDir != "" {
		dir, err := validateProfilesDir(m.profilesRoot, policy.Config.ProfilesDir)
		if err != nil {
			return Handle{}, err
		}
		profilesDir = dir
	}

	sharedCollector, err := m.acquireCollector(profilesDir)
	if err != nil {
		return Handle{}, err
	}
	// Every way out below this point leaves no policy using the profile set, so
	// the reference is given back. Registered before mu is taken, so it runs
	// after mu is released.
	started := false
	defer func() {
		if !started {
			m.releaseCollector(profilesDir)
		}
	}()

	m.mu.Lock()
	for {
		if _, ok := m.policies[name]; ok {
			m.mu.Unlock()
			return Handle{}, fmt.Errorf("policy %s already exists", name)
		}
		stopping, ok := m.stopping[name]
		if !ok {
			break
		}
		// The name is still owned by a runner that is shutting down. Wait for
		// it outside mu: Stop blocks on the sweep unwinding, and holding mu
		// across that would serialise every other request on this one name.
		m.mu.Unlock()
		select {
		case <-stopping:
		case <-m.ctx.Done():
			return Handle{}, fmt.Errorf("policy %s: waiting for the previous runner to stop: %w", name, m.ctx.Err())
		}
		m.mu.Lock()
	}
	defer m.mu.Unlock()

	r, err := NewRunner(m.ctx, m.logger, name, policy, sharedCollector, m.dialer)
	if err != nil {
		return Handle{}, err
	}

	r.Start()
	m.policies[name] = r
	m.policyDirs[name] = profilesDir
	started = true
	m.logger.Info("started policy", "policy", config.SanitizeLogValue(name))
	return Handle{name: name, runner: r}, nil
}

// StopPolicy stops whichever runner is registered under name, which is what a
// DELETE for that name asks for.
func (m *Manager) StopPolicy(name string) error {
	return m.stopPolicy(name, nil)
}

// StopPolicyHandle stops the runner the handle names and does nothing if that
// runner is no longer the one registered under its name, so a caller undoing
// its own start cannot stop a replacement it never started. The zero Handle
// stops nothing.
func (m *Manager) StopPolicyHandle(h Handle) error {
	if h.runner == nil {
		return nil
	}
	return m.stopPolicy(h.name, h.runner)
}

// stopPolicy detaches the policy under name and stops it. A non-nil want
// requires the registered runner to be that one: the comparison and the detach
// happen together under mu, so a replacement started between the two cannot be
// caught by it.
//
// The runner is detached under mu and stopped outside it, since Stop blocks on
// the sweep unwinding. The name stays reserved for the whole of Stop so a
// POST for the same name cannot start a replacement that the outgoing runner
// would then forget.
func (m *Manager) stopPolicy(name string, want *Runner) error {
	m.mu.Lock()
	r, ok := m.policies[name]
	if ok && want != nil && r != want {
		// The runner this caller started is already gone and something else
		// holds the name. Nothing to stop, and stopping what is there would
		// delete a policy this caller never created.
		m.mu.Unlock()
		return nil
	}
	var release func()
	var profilesDir string
	if ok {
		delete(m.policies, name)
		profilesDir = m.policyDirs[name]
		delete(m.policyDirs, name)
		release = m.reserveStopping(name)
	}
	m.mu.Unlock()
	if !ok {
		return nil
	}
	// The profile set is given back only once the runner has stopped, so a
	// replacement waiting on the name finds it still loaded.
	defer func() {
		release()
		m.releaseCollector(profilesDir)
	}()
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
	dirs := make(map[string]string, len(m.policyDirs))
	maps.Copy(dirs, m.policyDirs)
	m.policyDirs = make(map[string]string)
	releases := make(map[string]func(), len(runners))
	for name := range runners {
		releases[name] = m.reserveStopping(name)
	}
	m.mu.Unlock()

	var errs []error
	for _, name := range slices.Sorted(maps.Keys(runners)) {
		err := runners[name].Stop()
		releases[name]()
		m.releaseCollector(dirs[name])
		if err != nil {
			errs = append(errs, fmt.Errorf("stopping policy %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// GetCapabilities returns the capabilities of gnmi-telemetry
func (m *Manager) GetCapabilities() []string {
	return []string{"targets", "on_change", "sample", "get"}
}

// GetPolicyStatuses returns the status of all known policies. RLock guards the
// map iteration against a concurrent StartPolicy or StopPolicy; the per-target
// state comes from the collector, which has its own lock, so there is no
// nesting on mu.
func (m *Manager) GetPolicyStatuses() []Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	statuses := make([]Status, 0, len(m.policies))
	for name, runner := range m.policies {
		s := Status{Name: name, Status: "running", Targets: runner.TargetStatuses()}
		// The runner keeps no error state of its own: a target's last error
		// belongs to the collector loop driving it, so the policy's error is
		// the first target reporting one. The collector timestamps
		// notifications rather than errors, so the read time is what stands in
		// for when it happened, and says the error is current as of now.
		for _, target := range s.Targets {
			if target.LastError == "" {
				continue
			}
			msg := target.LastError
			at := time.Now()
			s.Status = "running_with_errors"
			s.LastError = &msg
			s.LastErrorAt = &at
			break
		}
		statuses = append(statuses, s)
	}
	return statuses
}

// normalizeTargetHosts trims surrounding whitespace from every target host, so
// the blank check, the size guard and the expander all read the same value. A
// padded host is otherwise not blank, passes validation, and then expands to an
// unresolvable hostname.
func normalizeTargetHosts(policy *config.Policy) {
	for i := range policy.Scope.Targets {
		policy.Scope.Targets[i].Host = strings.TrimSpace(policy.Scope.Targets[i].Host)
	}
}

// validatePolicy validates the policy. It runs after scope inheritance, so
// every target already carries the credentials, TLS block and port it will be
// reached with.
func (m *Manager) validatePolicy(policy config.Policy) error {
	if len(policy.Scope.Targets) == 0 {
		return errors.New("no targets found in the policy")
	}
	if policy.Config.MetricsInterval == nil {
		return errors.New("metrics_interval is required")
	}
	if *policy.Config.MetricsInterval < 1 || *policy.Config.MetricsInterval > config.MaxDurationSeconds {
		return fmt.Errorf("metrics_interval must be from 1 to %d seconds, got %d", config.MaxDurationSeconds, *policy.Config.MetricsInterval)
	}
	if err := validMode(policy.Config.Mode); err != nil {
		return err
	}
	if policy.Config.RescanIntervalMs != 0 && policy.Config.RescanIntervalMs < config.MinRescanIntervalMs {
		return fmt.Errorf("rescan_interval_ms must be 0 or at least %d, got %d", config.MinRescanIntervalMs, policy.Config.RescanIntervalMs)
	}
	if policy.Config.ProbeTimeoutMs < 0 {
		return fmt.Errorf("probe_timeout_ms must not be negative, got %d", policy.Config.ProbeTimeoutMs)
	}
	for i, t := range policy.Scope.Targets {
		if strings.TrimSpace(t.Host) == "" {
			return fmt.Errorf("target %d: host is required", i+1)
		}
		if err := validMode(t.Mode); err != nil {
			return fmt.Errorf("target %s: %w", t.Host, err)
		}
		if err := checkInlinePort(t.Host); err != nil {
			return err
		}
		bare, _, inline := splitEffectivePort(t.Host, t.Port)
		if inline && !targets.IsSingleEndpoint(bare) {
			return fmt.Errorf("target %q: a CIDR or range cannot carry an inline port; use the port field", t.Host)
		}
		if !targets.IsSingleEndpoint(bare) {
			n, err := targets.Count(bare)
			if err != nil {
				return fmt.Errorf("target %s: %w", t.Host, err)
			}
			if n > targets.MaxExpand {
				return fmt.Errorf("target %s expands to %d addresses, more than the %d one target may hold", t.Host, n, targets.MaxExpand)
			}
			if t.ResolvedPassword() != "" {
				tls := t.ResolvedTLS()
				if (tls.Insecure || tls.SkipVerify) && !policy.Config.SendCredentialsToUnverifiedTargets {
					return fmt.Errorf("target %s: a range or CIDR carries a password while TLS does not verify the server; set send_credentials_to_unverified_targets to allow it", t.Host)
				}
			}
		}
	}
	return checkPolicyExpansion(policy.Scope.Targets)
}

// validMode accepts the subscription modes a policy or a target may name. An
// empty value means the profile decides.
func validMode(mode string) error {
	switch mode {
	case "", "auto", "on_change", "sample":
		return nil
	}
	return fmt.Errorf("mode must be auto, on_change or sample, got %q", mode)
}

// credentialField is one policy-supplied string a ${NAME} reference may appear
// in, together with the name an error reports it by.
type credentialField struct {
	field *string
	label string
}

// credentialFields lists the credential strings of one scope or target, each
// labelled with prefix. A nil pointer field is absent and carries no reference;
// a nil tls block has no file paths to resolve.
func credentialFields(username, password *string, tls *config.TLSConfig, prefix string) []credentialField {
	var out []credentialField
	if username != nil {
		out = append(out, credentialField{username, prefix + "username"})
	}
	if password != nil {
		out = append(out, credentialField{password, prefix + "password"})
	}
	if tls != nil {
		out = append(out,
			credentialField{&tls.CAFile, prefix + "tls.ca"},
			credentialField{&tls.CertFile, prefix + "tls.cert"},
			credentialField{&tls.KeyFile, prefix + "tls.key"},
		)
	}
	return out
}

// resolveCredentialEnvVars resolves the ${NAME} references in a policy's
// credentials and TLS file paths. A reference is substituted only when the
// operator allowed its name at startup: the value goes on the wire to the
// policy's own targets, or names a file the backend reads, so an unrestricted
// resolver would let a policy read any variable in the process.
//
// Targets have already inherited the scope's raw references, so resolving the
// scope and every target is idempotent rather than a double substitution.
func (m *Manager) resolveCredentialEnvVars(policy *config.Policy) error {
	fields := credentialFields(&policy.Scope.Username, &policy.Scope.Password, policy.Scope.TLS, "scope.")
	for i := range policy.Scope.Targets {
		t := &policy.Scope.Targets[i]
		fields = append(fields, credentialFields(t.Username, t.Password, t.TLS, fmt.Sprintf("target %s ", t.Host))...)
	}

	for _, f := range fields {
		if name, ok := env.Reference(*f.field); ok {
			if _, allowed := m.allowedEnvVars[name]; !allowed {
				return fmt.Errorf("%s may not reference environment variable %s: allow it with --policy-env-vars",
					f.label, name)
			}
		}
		resolved, err := env.ResolveEnv(*f.field)
		if err != nil {
			return fmt.Errorf("%s: failed to resolve environment variable: %w", f.label, err)
		}
		*f.field = resolved
	}

	return nil
}
