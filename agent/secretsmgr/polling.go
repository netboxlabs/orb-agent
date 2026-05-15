package secretsmgr

import (
	"context"
	"fmt"
	"log/slog"
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
	callback  func(map[string]bool)
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

// RegisterUpdatePoliciesCallback registers the policy-reapply callback used by
// pollSecrets when cached values change or become unreachable.
func (b *pollingBase) RegisterUpdatePoliciesCallback(callback func(map[string]bool)) {
	b.callback = callback
}

// SolvePolicySecrets walks the policy payload and replaces every
// ${<scheme>://<body>} placeholder with the resolved secret value.
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

// resolveBody returns the cached value for body, or fetches and caches it.
// Race-safe via merge under the lock.
func (b *pollingBase) resolveBody(body, policyID string) (string, error) {
	b.mu.Lock()
	if cached, ok := b.usedVars[body]; ok {
		cached.policyIDs[policyID] = true
		b.usedVars[body] = cached
		value := cached.Value
		b.mu.Unlock()
		return value, nil
	}
	b.mu.Unlock()

	value, err := b.fetch(body)
	if err != nil {
		return "", err
	}

	b.mu.Lock()
	fresh := false
	if existing, ok := b.usedVars[body]; ok {
		existing.policyIDs[policyID] = true
		value = existing.Value
	} else {
		b.usedVars[body] = cachedSecret{
			Value:     value,
			policyIDs: map[string]bool{policyID: true},
		}
		fresh = true
	}
	b.mu.Unlock()
	if fresh {
		b.logger.Debug("Resolved secret", "scheme", b.scheme, "ref", body, "policy_id", policyID)
	}
	return value, nil
}

// pollSecrets re-fetches every cached secret and fires the callback for
// changed entries (true) or failed refreshes (false). Failures are sticky
// per policy ID. Failed entries are evicted from the cache.
func (b *pollingBase) pollSecrets() {
	b.mu.Lock()
	if len(b.usedVars) == 0 || b.callback == nil {
		b.mu.Unlock()
		return
	}
	type snap struct{ body, value string }
	snapshots := make([]snap, 0, len(b.usedVars))
	for body, cached := range b.usedVars {
		snapshots = append(snapshots, snap{body: body, value: cached.Value})
	}
	b.mu.Unlock()

	b.logger.Debug("Polling secrets for changes", "scheme", b.scheme, "secretCount", len(snapshots))
	changed := make(map[string]bool)
	markFalse := func(id string) { changed[id] = false }
	markTrue := func(id string) {
		if prev, ok := changed[id]; ok && !prev {
			return // failure is sticky
		}
		changed[id] = true
	}

	for _, s := range snapshots {
		current, err := b.fetch(s.body)
		if err != nil {
			b.logger.Error("Failed to retrieve secret during polling", "scheme", b.scheme, "ref", s.body, "error", err)
			b.mu.Lock()
			cached, ok := b.usedVars[s.body]
			ids := make([]string, 0, len(cached.policyIDs))
			if ok {
				for id := range cached.policyIDs {
					ids = append(ids, id)
				}
				delete(b.usedVars, s.body)
			}
			b.mu.Unlock()
			for _, id := range ids {
				markFalse(id)
			}
			continue
		}
		if current != s.value {
			b.logger.Info("Detected changed secret", "scheme", b.scheme, "ref", s.body)
			b.mu.Lock()
			ids := []string{}
			if cached, ok := b.usedVars[s.body]; ok {
				cached.Value = current
				b.usedVars[s.body] = cached
				for id := range cached.policyIDs {
					ids = append(ids, id)
				}
			}
			b.mu.Unlock()
			for _, id := range ids {
				markTrue(id)
			}
		}
	}

	if len(changed) > 0 {
		b.logger.Info("Calling update callback for changed secrets", "scheme", b.scheme, "policyCount", len(changed))
		b.callback(changed)
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
