package secretsmgr

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"

	"github.com/go-co-op/gocron/v2"

	"github.com/netboxlabs/orb-agent/agent/config"
)

// fetchFunc retrieves the raw secret value for a placeholder body. Providers
// supply their own implementation when calling init().
type fetchFunc func(body string) (string, error)

// pollingBase holds the state shared by every Manager implementation that
// caches resolved placeholders, supports cron-driven change detection, and
// implements the standard SolvePolicySecrets / SolveConfigSecrets pipeline.
// Provider structs embed pollingBase and supply Start + fetch.
type pollingBase struct {
	logger    *slog.Logger
	scheme    string
	ctx       context.Context
	fetch     fetchFunc
	mu        sync.Mutex
	usedVars  map[string]cachedSecret
	entries   uint64 // the entries created, numbering each one's gen
	callback  func(map[string]error)
	scheduler gocron.Scheduler
}

// init wires the base into the provider. Must be called from the provider's
// Start, after the provider's fetch is callable (i.e., after any underlying
// client has been constructed).
func (b *pollingBase) init(ctx context.Context, logger *slog.Logger, scheme string, fetch fetchFunc) {
	b.ctx = ctx
	b.logger = logger
	b.scheme = scheme
	b.fetch = fetch
	b.usedVars = make(map[string]cachedSecret)
}

// RegisterUpdatePoliciesCallback registers the callback pollSecrets reports
// to when cached values change, stop resolving or resolve again. Safe to call
// at any time relative to a running poll cycle.
func (b *pollingBase) RegisterUpdatePoliciesCallback(callback func(map[string]error)) {
	b.mu.Lock()
	b.callback = callback
	b.mu.Unlock()
}

// SolvePolicySecrets walks the policy payload and replaces every
// ${<scheme>://<body>} placeholder with the resolved secret value. The policy
// keeps counting as a user of the references an earlier version named until
// this one is applied (PolicyApplied): that version may still run.
func (b *pollingBase) SolvePolicySecrets(payload config.PolicyPayload) (config.PolicyPayload, error) {
	newPayload := payload
	processed, err := processValue(payload.Data, b.scheme, payload.ID, b.resolveBody)
	if err != nil {
		return payload, err
	}
	newPayload.Data = processed
	return newPayload, nil
}

// SolveConfigSecrets resolves placeholders inside the backends map and the
// ManagerConfig struct at startup. Tracking is cleared afterwards — config
// references must not trigger re-applies.
func (b *pollingBase) SolveConfigSecrets(backends map[string]any, cm config.ManagerConfig) (map[string]any, config.ManagerConfig, error) {
	processedBackends, err := processValue(backends, b.scheme, "_backends", b.resolveBody)
	if err != nil {
		return backends, cm, fmt.Errorf("failed to process backends: %w", err)
	}
	newBackends, ok := processedBackends.(map[string]any)
	if !ok {
		return backends, cm, fmt.Errorf("failed to cast processed backends to map[string]any")
	}

	cmMap, err := structToMap(cm)
	if err != nil {
		return backends, cm, fmt.Errorf("failed to convert config manager to map: %w", err)
	}
	processedCMMap, err := processValue(cmMap, b.scheme, "_config_manager", b.resolveBody)
	if err != nil {
		return backends, cm, fmt.Errorf("failed to process config manager: %w", err)
	}
	newCM, err := mapToStruct[config.ManagerConfig](processedCMMap)
	if err != nil {
		return backends, cm, fmt.Errorf("failed to convert processed map to config manager: %w", err)
	}

	b.mu.Lock()
	b.usedVars = make(map[string]cachedSecret)
	b.mu.Unlock()
	return newBackends, newCM, nil
}

// PolicyApplied drops the policy from the references the applied version's
// data does not name, so a reference it was edited off can no longer stop it.
func (b *pollingBase) PolicyApplied(policyID string, data any) {
	b.retain(policyID, referencedBodies(data, b.scheme))
}

// ForgetPolicy drops a removed policy from the references it used; a
// reference no policy uses any more is no longer read.
func (b *pollingBase) ForgetPolicy(policyID string) {
	b.retain(policyID, nil)
}

// retain keeps policyID among the users of the references in bodies only,
// and drops the references left with no user.
func (b *pollingBase) retain(policyID string, bodies map[string]bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for body, cached := range b.usedVars {
		if !cached.policyIDs[policyID] || bodies[body] {
			continue
		}
		delete(cached.policyIDs, policyID)
		delete(cached.failing, policyID)
		if len(cached.policyIDs) == 0 {
			delete(b.usedVars, body)
		}
	}
}

// Unresolved returns the error of the last read of a reference the policy
// failed on, in order, while that reference still fails, or nil.
func (b *pollingBase) Unresolved(policyID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, body := range slices.Sorted(maps.Keys(b.usedVars)) {
		if cached := b.usedVars[body]; cached.failed && cached.failing[policyID] {
			return cached.err
		}
	}
	return nil
}

// resolveBody returns the cached value for body, or fetches and caches it.
// Race-safe via merge under the lock. A reference whose last read failed is
// read again rather than served; one that still fails is kept, with the
// policy among those failing on it, so the poll that finds it resolving again
// re-applies the policy, whether it failed here or on an earlier poll.
func (b *pollingBase) resolveBody(body, policyID string) (string, error) {
	b.mu.Lock()
	if cached, ok := b.usedVars[body]; ok && !cached.failed {
		cached.policyIDs[policyID] = true
		delete(cached.failing, policyID)
		value := cached.Value
		b.mu.Unlock()
		return value, nil
	}
	b.mu.Unlock()

	value, err := b.fetch(body)

	b.mu.Lock()
	cached, ok := b.usedVars[body]
	if !ok {
		b.entries++
		cached = cachedSecret{policyIDs: map[string]bool{}, failed: true, gen: b.entries}
	}
	cached.policyIDs[policyID] = true
	stored := false
	switch {
	case !cached.failed:
		// Another resolve or a poll read it meanwhile: its value is served.
		value, err = cached.Value, nil
	case err == nil:
		cached.Value, cached.failed, cached.err, stored = value, false, nil, true
	default:
		cached.err = err
	}
	if err != nil {
		if cached.failing == nil {
			cached.failing = map[string]bool{}
		}
		cached.failing[policyID] = true
	} else {
		delete(cached.failing, policyID)
	}
	b.usedVars[body] = cached
	b.mu.Unlock()
	if err != nil {
		return "", err
	}
	if stored {
		b.logger.Debug("Resolved secret", "scheme", b.scheme, "ref", body, "policy_id", policyID)
	}
	return value, nil
}

// pollSecrets re-reads every cached reference and reports, by policy ID, the
// policies to apply again (a nil error) and those a reference of which no
// longer resolves (the read's error). A reference whose read fails is
// reported once, when it first fails, and kept, marked failed, so the next
// polls read it again; the first poll that reads it again reports the
// policies still failing on it, to apply again. A changed value reports
// every policy that uses it. A policy's failure is sticky across references.
func (b *pollingBase) pollSecrets() {
	b.mu.Lock()
	if len(b.usedVars) == 0 || b.callback == nil {
		b.mu.Unlock()
		return
	}
	// In order, so a policy failing on two references is reported with the
	// same one every time.
	bodies := slices.Sorted(maps.Keys(b.usedVars))
	cb := b.callback
	b.mu.Unlock()

	b.logger.Debug("Polling secrets for changes", "scheme", b.scheme, "secretCount", len(bodies))
	changed := make(map[string]error)
	markFalse := func(id string, err error) {
		if prev := changed[id]; prev != nil {
			return // the first failure is kept
		}
		changed[id] = err
	}
	markTrue := func(id string) {
		if _, ok := changed[id]; ok {
			return // failure is sticky
		}
		changed[id] = nil
	}

	for _, body := range bodies {
		b.mu.Lock()
		before, ok := b.usedVars[body]
		b.mu.Unlock()
		if !ok {
			continue
		}
		current, err := b.fetch(body)
		b.mu.Lock()
		cached, ok := b.usedVars[body]
		if !ok || cached.gen != before.gen {
			// Dropped while it was read, and perhaps resolved again since
			// by another policy: this read was of the entry dropped.
			b.mu.Unlock()
			continue
		}
		if err != nil {
			if cached.failed {
				b.mu.Unlock()
				b.logger.Debug("Secret still fails to resolve", "scheme", b.scheme, "ref", body, "error", err)
				continue
			}
			if before.failed {
				// A resolve read it successfully while this read was in
				// flight, as a re-delivery does: that read stands.
				b.mu.Unlock()
				b.logger.Debug("Secret resolved by a policy while the poll's read failed", "scheme", b.scheme, "ref", body, "error", err)
				continue
			}
			// Every policy that uses it is told, and fails on it until it
			// resolves again or the policy resolves it. The policies told
			// are a copy: a resolve may change the set once unlocked.
			cached.Value, cached.failed, cached.err = "", true, err
			cached.failing = maps.Clone(cached.policyIDs)
			b.usedVars[body] = cached
			told := maps.Clone(cached.failing)
			b.mu.Unlock()
			b.logger.Error("Failed to retrieve secret during polling", "scheme", b.scheme, "ref", body, "error", err)
			for id := range told {
				markFalse(id, err)
			}
			continue
		}
		// The policies still failing on it are re-applied, recovered or not:
		// one a late failure report left running (see the policy manager's
		// stop) may hold a value read before the failure, while another
		// policy resolving it meanwhile stored the current one.
		recovered := cached.failed
		valueChanged := !recovered && current != cached.Value
		ids := cached.failing
		if valueChanged {
			ids = cached.policyIDs
		}
		ids = maps.Clone(ids)
		cached.Value, cached.failed, cached.err, cached.failing = current, false, nil, nil
		b.usedVars[body] = cached
		b.mu.Unlock()
		switch {
		case recovered:
			b.logger.Info("Secret resolves again", "scheme", b.scheme, "ref", body)
		case valueChanged:
			b.logger.Info("Detected changed secret", "scheme", b.scheme, "ref", body)
		}
		for id := range ids {
			markTrue(id)
		}
	}

	if len(changed) > 0 {
		b.logger.Info("Calling update callback for changed secrets", "scheme", b.scheme, "policyCount", len(changed))
		cb(changed)
	}
}

// startScheduler optionally starts a cron job that calls pollSecrets on the
// configured cadence. The scheduler is shut down when ctx (passed to init)
// is cancelled. No-op when schedule is nil.
func (b *pollingBase) startScheduler(schedule *string) error {
	if schedule == nil {
		return nil
	}
	s, err := gocron.NewScheduler()
	if err != nil {
		return fmt.Errorf("failed to create scheduler: %w", err)
	}
	b.scheduler = s
	task := gocron.NewTask(b.pollSecrets)
	if _, err = b.scheduler.NewJob(
		gocron.CronJob(*schedule, false),
		task,
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
	); err != nil {
		// gocron.NewScheduler spawns an internal goroutine immediately; if we
		// return here without shutting it down, that goroutine leaks for the
		// process lifetime. Surface the shutdown error in the log but always
		// return the NewJob failure (the actionable error for the operator).
		if shutdownErr := b.scheduler.Shutdown(); shutdownErr != nil {
			b.logger.Error("scheduler shutdown failed after NewJob error", "scheme", b.scheme, "error", shutdownErr)
		}
		b.scheduler = nil
		return fmt.Errorf("failed to create %s polling job: %w", b.scheme, err)
	}
	b.logger.Info("Starting secret polling", "scheme", b.scheme, "cron interval", *schedule)
	b.scheduler.Start()

	go func() {
		<-b.ctx.Done()
		if err := b.scheduler.Shutdown(); err != nil {
			b.logger.Error("scheduler shutdown failed", "scheme", b.scheme, "error", err)
		}
	}()
	return nil
}
