package secretsmgr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"regexp"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
	"github.com/google/uuid"

	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
)

var _ Manager = (*FleetSecretsManager)(nil)

// fleetRefRegex matches fleet secret references in the format ${fleet://path}
var fleetRefRegex = regexp.MustCompile(`\${fleet://([^}]+)}`)

const defaultSecretRequestTimeout = 30 * time.Second

// A refresh that fails is requested again after fleetRetryFirst, then after
// twice as long each time it fails again, up to fleetRetryMax, each wait
// spread by up to a fifth either way so that agents a Fleet outage failed
// together don't ask again together (see retryLaterLocked).
const (
	fleetRetryFirst = time.Minute
	fleetRetryMax   = 10 * time.Minute
)

// Publisher interface for MQTT publishing
type Publisher interface {
	Publish(ctx context.Context, topic string, payload []byte) error
}

// Subscriber interface for MQTT subscribing
type Subscriber interface {
	Subscribe(ctx context.Context, subscribe *paho.Subscribe) error
}

// FleetSecretsManager implements the Manager interface for Fleet-based secrets
type FleetSecretsManager struct {
	logger        *slog.Logger
	config        config.FleetSecretsManager
	ctx           context.Context
	usedVars      map[string]fleetCachedSecret
	callback      func(map[string]error)
	publisher     Publisher
	subscriber    Subscriber
	requestTopic  string
	responseTopic string
	updatedTopic  string
	mu            sync.RWMutex
	pendingReqs   map[string]chan *messages.SecretResponseMsg
	timeout       time.Duration
	// invalidations counts the refreshes that failed, so an answer can tell
	// whether its request started before a path's latest failure.
	invalidations uint64
	// retries holds, by path, the request a failed refresh scheduled, until
	// Fleet answers with the value or no policy uses the path any more.
	retries map[string]*fleetRetry
	// afterFunc sets a timer that calls f after d, as time.AfterFunc does.
	afterFunc func(d time.Duration, f func()) retryTimer
}

// retryTimer is the timer of a scheduled request (see afterFunc).
type retryTimer interface {
	Stop() bool
}

// fleetRetry is the request a failed refresh of a path scheduled.
type fleetRetry struct {
	// version is the newest version Fleet announced that the agent hasn't
	// fetched.
	version int
	// delay is the wait before the request, doubled each time it fails.
	delay time.Duration
	// timer fires the request; nil while it runs.
	timer retryTimer
	// stopped means Fleet refused the path, so the policies that use it were
	// stopped: when a delivery fetches the path again first, the request
	// finds it current and applies them again (see retry).
	stopped bool
}

type fleetCachedSecret struct {
	Value     string          // The actual secret value
	Version   int             // Version number from control plane
	policyIDs map[string]bool // The IDs of policies that have used this secret
	// stale means Fleet refused the request that followed a newer version,
	// with err (see refused), or the path's first request failed: Value is
	// outdated or unset, so the path is requested again, not served, when a
	// policy resolves it. A policy resolving it refreshes it; the other
	// policies stopped for it are applied again once a request Fleet answers
	// with the value: the next newer version, or the request a failed refresh
	// scheduled (see retryLaterLocked), and on their next delivery.
	stale bool
	err   error
	// staleAt is the invalidation that marked the path stale: an answer to a
	// request started before it may be older than the version it failed for,
	// so it does not clear the mark.
	staleAt uint64
}

// NewFleetSecretsManager creates a new Fleet secrets manager
func NewFleetSecretsManager(logger *slog.Logger, cfg config.FleetSecretsManager) *FleetSecretsManager {
	timeout := defaultSecretRequestTimeout
	if cfg.Timeout != nil && *cfg.Timeout > 0 {
		timeout = time.Duration(*cfg.Timeout) * time.Second
	}

	return &FleetSecretsManager{
		logger:      logger,
		config:      cfg,
		usedVars:    make(map[string]fleetCachedSecret),
		pendingReqs: make(map[string]chan *messages.SecretResponseMsg),
		timeout:     timeout,
		retries:     make(map[string]*fleetRetry),
		afterFunc:   func(d time.Duration, f func()) retryTimer { return time.AfterFunc(d, f) },
	}
}

// BindMQTT binds the secrets manager to MQTT connection and topics
func (f *FleetSecretsManager) BindMQTT(publisher Publisher, subscriber Subscriber, requestTopic, responseTopic, updatedTopic string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.publisher = publisher
	f.subscriber = subscriber
	f.requestTopic = requestTopic
	f.responseTopic = responseTopic
	f.updatedTopic = updatedTopic

	// Subscribe to response and updated topics
	// Use the manager's context if available, otherwise use background context
	ctx := f.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := f.subscriber.Subscribe(ctx, &paho.Subscribe{
		Subscriptions: []paho.SubscribeOptions{
			{Topic: responseTopic, QoS: 1},
			{Topic: updatedTopic, QoS: 1},
		},
	}); err != nil {
		return fmt.Errorf("failed to subscribe to secrets topics: %w", err)
	}

	f.logger.Info("Fleet secrets manager bound to MQTT",
		"request_topic", requestTopic,
		"response_topic", responseTopic,
		"updated_topic", updatedTopic)

	return nil
}

// HandleMessage handles incoming MQTT messages on secrets topics
func (f *FleetSecretsManager) HandleMessage(topic string, payload []byte) error {
	switch topic {
	case f.responseTopic:
		return f.handleResponse(payload)
	case f.updatedTopic:
		return f.handleUpdateNotification(payload)
	default:
		f.logger.Info("received unknown message on topic", "topic", topic)
		return nil
	}
}

func (f *FleetSecretsManager) handleResponse(payload []byte) error {
	var response messages.SecretResponseMsg
	if err := json.Unmarshal(payload, &response); err != nil {
		f.logger.Error("failed to unmarshal secret response", "error", err)
		return err
	}
	f.logger.Debug("handling secret response", "request_id", response.RequestID, "status", response.Status, "secrets", len(response.Secrets))

	f.mu.Lock()
	ch, exists := f.pendingReqs[response.RequestID]
	f.mu.Unlock()

	if !exists {
		f.logger.Warn("received response for unknown request", "request_id", response.RequestID)
		return nil
	}

	// Send response to waiting goroutine
	select {
	case ch <- &response:
	default:
		f.logger.Warn("response channel full, dropping response", "request_id", response.RequestID)
	}

	return nil
}

func (f *FleetSecretsManager) handleUpdateNotification(payload []byte) error {
	var notification messages.SecretUpdateNotificationMsg
	if err := json.Unmarshal(payload, &notification); err != nil {
		f.logger.Error("failed to unmarshal secret update notification", "error", err)
		return err
	}

	changedPolicyIDs := make(map[string]error)

	for _, update := range notification.Updates {
		f.mu.Lock()
		cached, exists := f.usedVars[update.Path]
		if !exists || update.Version <= cached.Version {
			f.mu.Unlock()
			continue
		}
		f.logger.Info("secret version changed, requesting update",
			"path", update.Path,
			"old_version", cached.Version,
			"new_version", update.Version)
		f.mu.Unlock()

		f.refresh(update.Path, update.Version, changedPolicyIDs)
	}

	f.report(changedPolicyIDs)
	return nil
}

// refresh requests the value of path after Fleet announced version, and
// records in changed what the policies that use the path are to do: nil to
// apply them with the new value, an error to stop them. A failed request is
// made again later (see retryLaterLocked). What happens to the policies
// meanwhile depends on why it failed: when Fleet refused the path (see
// refused) they stop, since the secret may be gone or no longer theirs; when
// Fleet didn't answer, the request couldn't be sent or Fleet reported a fault
// of its own, they keep running with the value they have, since the failure
// says nothing about the secret.
func (f *FleetSecretsManager) refresh(path string, version int, changed map[string]error) {
	f.mu.Lock()
	cached, exists := f.usedVars[path]
	if !exists {
		f.mu.Unlock()
		return
	}
	// Deep-copy policy IDs so they can be safely used while the lock is released
	policyIDsCopy := make(map[string]bool, len(cached.policyIDs))
	for id := range cached.policyIDs {
		policyIDsCopy[id] = true
	}
	started := f.invalidations
	// Release the lock before performing the potentially long-running network request
	f.mu.Unlock()

	ctx := f.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	// Request updated secret (do not merge into usedVars here: this handler must
	// compare versions and update the cache so the policy callback runs).
	byPath, err := f.requestSecrets(ctx, []string{path}, policyIDsCopy, false)

	// Re-acquire the lock before accessing or mutating shared state
	f.mu.Lock()
	defer f.mu.Unlock()
	sv, ok := byPath[path]
	if err == nil && !ok {
		err = fleetRefusal{msg: fmt.Sprintf("secret missing in response for path %s", path)}
	}
	if err != nil {
		current, exists := f.usedVars[path]
		if !exists {
			// No policy uses it any more.
			return
		}
		if current.Version >= version {
			// A later notification fetched this version or a newer one
			// while this request waited: the value held is current.
			return
		}
		stops := refused(err) && !current.stale
		if refused(err) {
			f.invalidations++
			current.stale, current.err, current.staleAt = true, err, f.invalidations
			f.usedVars[path] = current
		}
		if stops {
			// Every policy using it now is told: one that resolved it while
			// the request was in flight runs with the value it was to replace.
			// Those of a path already stale were told when it went stale, or
			// failed to resolve it since.
			for id := range current.policyIDs {
				if changed[id] == nil {
					changed[id] = err
				}
			}
		}
		first, wait := f.retryLaterLocked(path, version, refused(err))
		switch {
		case stops:
			f.logger.Error("Fleet refused the updated secret; stopping the policies that use it",
				"path", path, "error", err, "retry_in", wait)
		case first && current.stale:
			f.logger.Error("failed to request updated secret; the policies that use it stay stopped",
				"path", path, "error", err, "retry_in", wait)
		case first:
			f.logger.Error("failed to request updated secret; the policies that use it keep the value they run with",
				"path", path, "error", err, "retry_in", wait)
		default:
			f.logger.Debug("secret request failed again", "path", path, "error", err, "retry_in", wait)
		}
		return
	}
	secret := &sv

	// Re-fetch the cached entry in case it changed while the lock was released
	cached, exists = f.usedVars[path]
	if !exists {
		// The secret was removed while we were requesting it; skip updating.
		return
	}
	if cached.stale && cached.staleAt > started {
		// A later refresh of the path failed while this request waited:
		// this answer may be older than the version that one was for, and
		// the request that one scheduled stands.
		return
	}
	if secret.Version < version {
		// Fleet answered with an older version than the one it announced,
		// as a replica that lags would: the value is applied below when it is
		// newer than the one held, and the announced version is requested
		// again, as after a request that failed. At the version held, a path
		// whose refresh Fleet refused stays stale, its policies stopped.
		first, wait := f.retryLaterLocked(path, version, false)
		log := f.logger.Debug
		if first {
			log = f.logger.Warn
		}
		log("Fleet answered an older version of the secret than it announced; requesting it again",
			"path", path, "announced_version", version, "version", secret.Version, "retry_in", wait)
	} else if r, ok := f.retries[path]; ok && secret.Version >= r.version {
		// Fleet answered with the version the scheduled request is for, or
		// a newer one: no further request is needed. An answer with an
		// older version, to a request for one, leaves it scheduled.
		f.dropRetryLocked(path)
		f.logger.Info("Fleet answered the secret request again", "path", path, "version", secret.Version)
	}
	// An answer at the version held, or an older one, changes nothing. A
	// refresh is for a version newer than the one held, which a stale path
	// keeps until an answer replaces it, so for a stale path that answer is
	// older than the version announced, as from a replica that lags: the
	// value held is not current, and the policies stopped for it stay
	// stopped until Fleet answers with a newer one.
	if cached.Version >= secret.Version {
		return
	}

	// Update cache
	cached.Value = secret.Value
	cached.Version = secret.Version
	cached.stale, cached.err = false, nil
	f.usedVars[path] = cached

	// Mark policies as needing update, unless another path failed for them
	for id := range cached.policyIDs {
		if _, failed := changed[id]; !failed {
			changed[id] = nil
		}
	}
}

// retryLaterLocked schedules path to be requested again, for version or a
// newer one an earlier failure scheduled, refused saying whether Fleet
// refused the path, and returns whether it is the path's first failure
// since Fleet last answered with its value, and the wait before the
// request. A request already scheduled keeps its time; one that just failed
// waits twice as long as the last, up to fleetRetryMax. The caller holds
// f.mu.
func (f *FleetSecretsManager) retryLaterLocked(path string, version int, refused bool) (first bool, wait time.Duration) {
	r, ok := f.retries[path]
	if !ok {
		r = &fleetRetry{delay: fleetRetryFirst}
		f.retries[path] = r
	} else if r.timer == nil {
		r.delay = min(2*r.delay, fleetRetryMax)
	}
	r.version = max(r.version, version)
	r.stopped = r.stopped || refused
	wait = r.delay
	if r.timer == nil {
		wait = time.Duration(float64(r.delay) * (0.8 + 0.4*rand.Float64()))
		r.timer = f.afterFunc(wait, func() { f.retry(path, r) })
	}
	return !ok, wait
}

// dropRetryLocked cancels the request a failed refresh of path scheduled,
// and reports whether there was one. The caller holds f.mu.
func (f *FleetSecretsManager) dropRetryLocked(path string) bool {
	r, ok := f.retries[path]
	if !ok {
		return false
	}
	if r.timer != nil {
		r.timer.Stop()
	}
	delete(f.retries, path)
	return true
}

// retry makes the request r scheduled for path, unless it was cancelled or
// replaced meanwhile, the agent is stopping or no policy uses the path any
// more, and reports what it changed. A path a delivery fetched again
// meanwhile, at the version wanted or a newer one, needs no request, but
// the policies stopped for it are applied again: the delivery applied its
// own policy only.
func (f *FleetSecretsManager) retry(path string, r *fleetRetry) {
	f.mu.Lock()
	if f.retries[path] != r {
		f.mu.Unlock()
		return
	}
	r.timer = nil
	ctx := f.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	cached, exists := f.usedVars[path]
	if ctx.Err() != nil || !exists {
		delete(f.retries, path)
		f.mu.Unlock()
		return
	}
	if !cached.stale && cached.Version >= r.version {
		delete(f.retries, path)
		changed := make(map[string]error)
		if r.stopped {
			for id := range cached.policyIDs {
				changed[id] = nil
			}
		}
		f.mu.Unlock()
		f.report(changed)
		return
	}
	version := r.version
	f.mu.Unlock()

	f.logger.Debug("requesting the secret again", "path", path, "version", version)
	changed := make(map[string]error)
	f.refresh(path, version, changed)
	f.report(changed)
}

// report passes the policies whose secrets changed to the callback.
func (f *FleetSecretsManager) report(changed map[string]error) {
	if len(changed) > 0 && f.callback != nil {
		f.logger.Info("calling update callback for changed secrets", "policy_count", len(changed))
		f.callback(changed)
	}
}

// fleetRefusal is an answer in which Fleet refused a secret path, because it
// doesn't exist, the agent may not read it or it isn't valid, or held no
// value for it: the secret may be gone or no longer the agent's.
type fleetRefusal struct {
	msg string
}

func (e fleetRefusal) Error() string { return e.msg }

// refused reports whether err is Fleet's answer about the secret or the
// agent's access to it, rather than no answer, a request that couldn't be
// sent or a fault Fleet reported of its own.
func refused(err error) bool {
	return errors.As(err, new(fleetRefusal))
}

// answerError is the error Fleet answered for a path with code, worded as
// msg: a refusal for the codes that are about the secret or the agent's
// access to it (see refused).
func answerError(msg, code string) error {
	switch code {
	case messages.ErrorCodeNotFound, messages.ErrorCodeForbidden, messages.ErrorCodeInvalidPath:
		return fleetRefusal{msg: msg}
	default:
		return errors.New(msg)
	}
}

// Start initializes the Fleet secrets manager
func (f *FleetSecretsManager) Start(ctx context.Context) error {
	f.logger.Info("starting secrets manager", "active", "fleet")
	f.ctx = ctx
	f.mu.Lock()
	f.usedVars = make(map[string]fleetCachedSecret)
	for path := range f.retries {
		f.dropRetryLocked(path)
	}
	f.mu.Unlock()
	f.logger.Info("secrets manager started", "active", "fleet")
	return nil
}

// RegisterUpdatePoliciesCallback registers a callback for policy updates when secrets change
func (f *FleetSecretsManager) RegisterUpdatePoliciesCallback(callback func(map[string]error)) {
	f.callback = callback
}

// Unresolved returns the error of the failed refresh of a path the policy
// uses, in order, while the path is still stale, or nil.
func (f *FleetSecretsManager) Unresolved(policyID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, path := range slices.Sorted(maps.Keys(f.usedVars)) {
		if cached := f.usedVars[path]; cached.stale && cached.policyIDs[policyID] {
			return cached.err
		}
	}
	return nil
}

// PolicyApplied drops the policy from the paths the applied version's data
// does not name.
func (f *FleetSecretsManager) PolicyApplied(policyID string, data any) {
	paths := make(map[string]struct{})
	collectFleetPaths(data, paths)
	f.retain(policyID, paths)
}

// ForgetPolicy drops a removed policy from the paths it used, and the paths
// no policy uses any more.
func (f *FleetSecretsManager) ForgetPolicy(policyID string) {
	f.retain(policyID, nil)
}

// retain keeps policyID among the users of the paths in paths only, and
// drops the paths left with no user, with any request scheduled for them.
func (f *FleetSecretsManager) retain(policyID string, paths map[string]struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for path, cached := range f.usedVars {
		if _, kept := paths[path]; kept || !cached.policyIDs[policyID] {
			continue
		}
		delete(cached.policyIDs, policyID)
		if len(cached.policyIDs) == 0 {
			delete(f.usedVars, path)
			f.dropRetryLocked(path)
		}
	}
}

// SolvePolicySecrets resolves fleet secret references in a policy payload
func (f *FleetSecretsManager) SolvePolicySecrets(payload config.PolicyPayload) (config.PolicyPayload, error) {
	newPayload := payload

	pathSet := make(map[string]struct{})
	collectFleetPaths(payload.Data, pathSet)
	ctx := f.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := f.ensureSecrets(ctx, setToSortedSlice(pathSet), payload.ID); err != nil {
		return payload, err
	}

	processedData, err := f.processValue(payload.Data, payload.ID)
	if err != nil {
		return payload, err
	}

	newPayload.Data = processedData
	return newPayload, nil
}

// SolveConfigSecrets resolves fleet secret references in backend and config manager configurations
func (f *FleetSecretsManager) SolveConfigSecrets(backends map[string]any, configManager config.ManagerConfig) (map[string]any, config.ManagerConfig, error) {
	configManagerMap, err := structToMap(configManager)
	if err != nil {
		return backends, configManager, fmt.Errorf("failed to convert config manager to map: %w", err)
	}

	backPaths := make(map[string]struct{})
	collectFleetPaths(backends, backPaths)
	cfgPaths := make(map[string]struct{})
	collectFleetPaths(configManagerMap, cfgPaths)

	ctx := f.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := f.ensureSecrets(ctx, setToSortedSlice(backPaths), "_backends"); err != nil {
		return backends, configManager, fmt.Errorf("failed to process backends: %w", err)
	}
	if err := f.ensureSecrets(ctx, setToSortedSlice(cfgPaths), "_config_manager"); err != nil {
		return backends, configManager, fmt.Errorf("failed to process config manager: %w", err)
	}

	newBackends := backends
	processedBackends, err := f.processValue(newBackends, "_backends")
	if err != nil {
		return backends, configManager, fmt.Errorf("failed to process backends: %w", err)
	}
	newBackends, ok := processedBackends.(map[string]any)
	if !ok {
		return backends, configManager, fmt.Errorf("failed to cast processed backends to map[string]any")
	}

	processedConfigManagerMap, err := f.processValue(configManagerMap, "_config_manager")
	if err != nil {
		return backends, configManager, fmt.Errorf("failed to process config manager: %w", err)
	}
	newConfigManager, err := mapToStruct[config.ManagerConfig](processedConfigManagerMap)
	if err != nil {
		return backends, configManager, fmt.Errorf("failed to convert processed map to config manager: %w", err)
	}

	// Do not track updates on config vars for now
	f.mu.Lock()
	f.usedVars = make(map[string]fleetCachedSecret)
	for path := range f.retries {
		f.dropRetryLocked(path)
	}
	f.mu.Unlock()

	return newBackends, newConfigManager, nil
}

func collectFleetPaths(v any, set map[string]struct{}) {
	switch val := v.(type) {
	case string:
		// Align with processString: only the first ${fleet://...} is resolved; the rest
		// of the string is discarded when substituting (legacy single-token behavior).
		idx := fleetRefRegex.FindStringSubmatchIndex(val)
		if len(idx) >= 4 {
			set[val[idx[2]:idx[3]]] = struct{}{}
		}
	case map[string]any:
		for _, vv := range val {
			collectFleetPaths(vv, set)
		}
	case []any:
		for _, vv := range val {
			collectFleetPaths(vv, set)
		}
	default:
		return
	}
}

func setToSortedSlice(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func dedupeSortedStrings(paths []string) []string {
	if len(paths) <= 1 {
		return paths
	}
	seen := make(map[string]struct{}, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// ensureSecrets fetches any uncached fleet paths in one MQTT request (or skip if all cached).
func (f *FleetSecretsManager) ensureSecrets(ctx context.Context, paths []string, id string) error {
	paths = dedupeSortedStrings(paths)
	if len(paths) == 0 {
		return nil
	}
	policyIDs := map[string]bool{id: true}

	f.mu.Lock()
	var missing []string
	for _, path := range paths {
		cached, exists := f.usedVars[path]
		if exists && !cached.stale {
			if cached.policyIDs == nil {
				cached.policyIDs = make(map[string]bool)
			}
			cached.policyIDs[id] = true
			f.usedVars[path] = cached
			continue
		}
		missing = append(missing, path)
	}
	f.mu.Unlock()

	if len(missing) == 0 {
		return nil
	}

	if _, err := f.requestSecrets(ctx, missing, policyIDs, true); err != nil {
		// Kept stale, with the policy among the users, as the poller keeps a
		// reference whose read failed: Unresolved answers the failure, the
		// next resolve requests the path again, and a notification for it
		// is acted on.
		f.mu.Lock()
		f.invalidations++
		for _, path := range missing {
			cached, exists := f.usedVars[path]
			if cached.policyIDs == nil {
				cached.policyIDs = make(map[string]bool)
			}
			cached.policyIDs[id] = true
			// One another request refreshed meanwhile keeps its value.
			if !exists || cached.stale {
				cached.stale, cached.err, cached.staleAt = true, err, f.invalidations
			}
			f.usedVars[path] = cached
		}
		f.mu.Unlock()
		return err
	}
	// A path a later refresh failed for while the request waited stays stale:
	// its value is not served.
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, path := range missing {
		if cached := f.usedVars[path]; cached.stale {
			return cached.err
		}
	}
	return nil
}

func (f *FleetSecretsManager) processValue(value any, id string) (any, error) {
	switch val := value.(type) {
	case string:
		return f.processString(val, id)
	case map[string]any:
		return f.processMap(val, id)
	case []any:
		return f.processSlice(val, id)
	default:
		return val, nil
	}
}

// processString processes a string and replaces fleet secret references
func (f *FleetSecretsManager) processString(s string, id string) (string, error) {
	if !fleetRefRegex.MatchString(s) {
		return s, nil
	}

	match := fleetRefRegex.FindStringSubmatchIndex(s)
	if len(match) < 4 {
		return "", fmt.Errorf("failed to find fleet secret reference in string: %s", s)
	}

	fleetPath := s[match[2]:match[3]]

	// Check if secret exists in cache and update policy tracking
	f.mu.Lock()
	cached, exists := f.usedVars[fleetPath]
	if exists {
		if cached.policyIDs == nil {
			cached.policyIDs = make(map[string]bool)
		}
		cached.policyIDs[id] = true
		f.usedVars[fleetPath] = cached
		value, stale, staleErr := cached.Value, cached.stale, cached.err
		f.mu.Unlock()
		if stale {
			// A refresh failed after ensureSecrets checked the path: its
			// value is outdated, so it is not served.
			return "", staleErr
		}
		return value, nil
	}
	f.mu.Unlock()

	// Request secret from control plane
	ctx := f.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	policyIDs := map[string]bool{id: true}
	secret, err := f.requestSecret(ctx, fleetPath, policyIDs)
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s: %w", fleetPath, err)
	}

	f.logger.Info("got secret", "secret_path", fleetPath)
	return secret.Value, nil
}

// processMap processes a map recursively and replaces fleet secret references in its values
func (f *FleetSecretsManager) processMap(m map[string]any, id string) (map[string]any, error) {
	result := make(map[string]any)
	for key, val := range m {
		processedVal, err := f.processValue(val, id)
		if err != nil {
			return nil, fmt.Errorf("failed to process value for key %s: %w", key, err)
		}
		result[key] = processedVal
	}
	return result, nil
}

// processSlice processes a slice recursively and replaces fleet secret references in its elements
func (f *FleetSecretsManager) processSlice(s []any, id string) ([]any, error) {
	result := make([]any, len(s))
	for i, val := range s {
		processedVal, err := f.processValue(val, id)
		if err != nil {
			return nil, fmt.Errorf("failed to process value at index %d: %w", i, err)
		}
		result[i] = processedVal
	}
	return result, nil
}

// requestSecret requests a single secret from the control plane via MQTT.
func (f *FleetSecretsManager) requestSecret(ctx context.Context, path string, policyIDs map[string]bool) (*messages.SecretValue, error) {
	byPath, err := f.requestSecrets(ctx, []string{path}, policyIDs, true)
	if err != nil {
		return nil, err
	}
	sv, ok := byPath[path]
	if !ok {
		return nil, fmt.Errorf("no secret in response for path %s", path)
	}
	return &sv, nil
}

// requestSecrets requests one or more secrets in a single MQTT round-trip.
// When writeCache is true, results are merged into usedVars on success.
func (f *FleetSecretsManager) requestSecrets(ctx context.Context, paths []string, policyIDs map[string]bool, writeCache bool) (map[string]messages.SecretValue, error) {
	paths = dedupeSortedStrings(paths)
	if len(paths) == 0 {
		return map[string]messages.SecretValue{}, nil
	}

	f.logger.Info("requesting secrets", "paths", paths, "policy_ids", policyIDs)
	if f.publisher == nil {
		return nil, fmt.Errorf("MQTT publisher not bound")
	}
	f.mu.RLock()
	started := f.invalidations
	f.mu.RUnlock()

	requestID := uuid.New().String()
	reqItems := make([]messages.SecretRequest, len(paths))
	ctxStr := getContextFromPolicyIDs(policyIDs)
	for i, path := range paths {
		reqItems[i] = messages.SecretRequest{
			Path:    path,
			Context: ctxStr,
		}
	}
	request := messages.SecretRequestMsg{
		SchemaVersion: messages.CurrentSecretsSchemaVersion,
		RequestID:     requestID,
		Timestamp:     time.Now(),
		Secrets:       reqItems,
	}

	payload, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal secret request: %w", err)
	}

	responseCh := make(chan *messages.SecretResponseMsg, 1)
	f.mu.Lock()
	f.pendingReqs[requestID] = responseCh
	f.mu.Unlock()

	defer func() {
		f.mu.Lock()
		delete(f.pendingReqs, requestID)
		f.mu.Unlock()
	}()

	if err := f.publisher.Publish(ctx, f.requestTopic, payload); err != nil {
		return nil, fmt.Errorf("failed to publish secret request: %w", err)
	}

	select {
	case response := <-responseCh:
		if response.Status == "error" {
			if len(response.Errors) > 0 {
				err0 := response.Errors[0]
				return nil, answerError(fmt.Sprintf("secret request failed: %s (code: %s)", err0.Error, err0.Code), err0.Code)
			}
			return nil, fmt.Errorf("secret request failed with status: %s", response.Status)
		}

		if len(response.Secrets) == 0 && len(paths) > 0 {
			return nil, fleetRefusal{msg: "no secrets in response"}
		}

		want := make(map[string]struct{}, len(paths))
		for _, p := range paths {
			want[p] = struct{}{}
		}

		byPath := make(map[string]messages.SecretValue, len(response.Secrets))
		for _, sv := range response.Secrets {
			if _, ok := want[sv.Path]; ok {
				byPath[sv.Path] = sv
			}
		}

		failed := make([]messages.SecretError, 0, len(response.Errors))
		for _, secretErr := range response.Errors {
			if _, ok := want[secretErr.Path]; ok {
				failed = append(failed, secretErr)
			}
		}

		for _, p := range paths {
			if _, ok := byPath[p]; !ok {
				var combinedErr error
				for _, fe := range failed {
					if fe.Path == p {
						combinedErr = answerError(fmt.Sprintf("secret request failed for path %s: %s (code: %s)", fe.Path, fe.Error, fe.Code), fe.Code)
						break
					}
				}
				if combinedErr != nil {
					return nil, combinedErr
				}
				return nil, fleetRefusal{msg: fmt.Sprintf("secret missing in response for path %s", p)}
			}
		}

		if response.Status == "partial" && len(response.Errors) > 0 {
			for _, secretErr := range response.Errors {
				f.logger.Warn("partial secret response: some secrets failed",
					"path", secretErr.Path,
					"error", secretErr.Error,
					"code", secretErr.Code)
			}
		}

		if writeCache {
			f.mu.Lock()
			for _, p := range paths {
				sv := byPath[p]
				cached, exists := f.usedVars[p]
				// An answer handled late never replaces a newer version a
				// notification stored meanwhile, nor clears a failure that
				// came after its request started.
				outdated := cached.stale && cached.staleAt > started
				// Nor does an answer at the version held clear a path whose
				// refresh failed while a request for a newer version is
				// scheduled: it comes from a replica that lags (see refresh).
				lagging := cached.stale && sv.Version == cached.Version && f.retries[p] != nil
				if !outdated && !lagging && (!exists || sv.Version >= cached.Version) {
					cached.Value = sv.Value
					cached.Version = sv.Version
					cached.stale, cached.err = false, nil
				}
				if cached.policyIDs == nil {
					cached.policyIDs = make(map[string]bool)
				}
				for id := range policyIDs {
					cached.policyIDs[id] = true
				}
				f.usedVars[p] = cached
			}
			f.mu.Unlock()
		}

		return byPath, nil

	case <-ctx.Done():
		return nil, fmt.Errorf("context canceled while waiting for secret response")
	case <-time.After(f.timeout):
		return nil, fmt.Errorf("timeout waiting for secret response after %s", f.timeout)
	}
}

// getContextFromPolicyIDs extracts a context string from policy IDs
// For now, we use the first policy ID or "config" if it's a config secret
func getContextFromPolicyIDs(policyIDs map[string]bool) string {
	for id := range policyIDs {
		if id != "_backends" && id != "_config_manager" {
			return id
		}
	}
	return "config"
}

// CMAdapterPublisher adapts autopaho.ConnectionManager to implement Publisher
type CMAdapterPublisher struct {
	cm *autopaho.ConnectionManager
}

// NewCMAdapterPublisher creates a new adapter for an autopaho connection manager
func NewCMAdapterPublisher(cm *autopaho.ConnectionManager) *CMAdapterPublisher {
	return &CMAdapterPublisher{cm: cm}
}

// Publish sends the payload to the topic with QoS 0
func (p *CMAdapterPublisher) Publish(ctx context.Context, topic string, payload []byte) error {
	_, err := p.cm.Publish(ctx, &paho.Publish{
		Topic:   topic,
		Payload: payload,
		QoS:     0,
		Retain:  false,
	})
	return err
}

// CMAdapterSubscriber adapts autopaho.ConnectionManager to implement Subscriber
type CMAdapterSubscriber struct {
	cm *autopaho.ConnectionManager
}

// NewCMAdapterSubscriber creates a new adapter for an autopaho connection manager
func NewCMAdapterSubscriber(cm *autopaho.ConnectionManager) *CMAdapterSubscriber {
	return &CMAdapterSubscriber{cm: cm}
}

// Subscribe subscribes to topics
func (s *CMAdapterSubscriber) Subscribe(ctx context.Context, subscribe *paho.Subscribe) error {
	_, err := s.cm.Subscribe(ctx, subscribe)
	return err
}
