package secretsmgr

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"

	"github.com/DelineaXPM/tss-sdk-go/v3/server"
	"github.com/go-co-op/gocron/v2"

	"github.com/netboxlabs/orb-agent/agent/config"
)

var _ Manager = (*delineaManager)(nil)

// delineaManager resolves ${delinea://…} placeholders against Delinea Secret Server.
type delineaManager struct {
	logger    *slog.Logger
	config    config.DelineaManager
	ctx       context.Context
	client    *server.Server
	mu        sync.Mutex
	usedVars  map[string]cachedSecret
	callback  func(map[string]bool)
	scheduler gocron.Scheduler
}

// Start validates the configuration and constructs the SDK client. It does
// NOT eagerly authenticate — the SDK lazy-auths on first secret fetch.
func (d *delineaManager) Start(ctx context.Context) error {
	d.ctx = ctx
	d.usedVars = make(map[string]cachedSecret)

	envFields := []struct {
		name string
		ptr  *string
	}{
		{"server_url", &d.config.ServerURL},
		{"tenant", &d.config.Tenant},
		{"username", &d.config.Username},
		{"password", &d.config.Password},
	}
	for _, f := range envFields {
		resolved, err := config.ResolveEnv(*f.ptr)
		if err != nil {
			return fmt.Errorf("resolving delinea %s from environment: %w", f.name, err)
		}
		*f.ptr = resolved
	}

	if (d.config.ServerURL == "" && d.config.Tenant == "") ||
		(d.config.ServerURL != "" && d.config.Tenant != "") {
		return fmt.Errorf("exactly one of server_url or tenant must be set")
	}
	if d.config.Username == "" {
		return fmt.Errorf("username is required")
	}
	if d.config.Password == "" {
		return fmt.Errorf("password is required")
	}

	sdkCfg := server.Configuration{
		Credentials: server.UserCredential{
			Username: d.config.Username,
			Password: d.config.Password,
		},
		ServerURL: d.config.ServerURL,
		Tenant:    d.config.Tenant,
	}

	c, err := server.New(sdkCfg)
	if err != nil {
		return fmt.Errorf("failed to create delinea client: %w", err)
	}
	d.client = c

	if d.config.Schedule != nil {
		s, err := gocron.NewScheduler()
		if err != nil {
			return fmt.Errorf("failed to create scheduler: %w", err)
		}
		d.scheduler = s
		task := gocron.NewTask(d.pollSecrets)
		if _, err = d.scheduler.NewJob(
			gocron.CronJob(*d.config.Schedule, false),
			task,
			gocron.WithSingletonMode(gocron.LimitModeReschedule),
		); err != nil {
			return fmt.Errorf("failed to create delinea polling job: %w", err)
		}
		d.logger.Info("Starting delinea secret polling", "cron interval", *d.config.Schedule)
		d.scheduler.Start()
	}

	return nil
}

// pollSecrets re-fetches every cached secret and fires the update callback
// for every policy whose secret changed (true) or failed to refresh (false).
// Failures are sticky: a policy marked false by one secret cannot be flipped
// to true by another. policyIDs are re-read under the lock after each
// fetch so policies added to the cache during the unlocked fetch are also
// notified.
func (d *delineaManager) pollSecrets() {
	d.mu.Lock()
	if len(d.usedVars) == 0 || d.callback == nil {
		d.mu.Unlock()
		return
	}
	// Snapshot only (body, previous-value) under the lock; defer policyID
	// collection until after the unlocked fetch so we pick up any policies
	// added during the fetch window.
	type snap struct{ body, value string }
	snapshots := make([]snap, 0, len(d.usedVars))
	for body, cached := range d.usedVars {
		snapshots = append(snapshots, snap{body: body, value: cached.Value})
	}
	d.mu.Unlock()

	d.logger.Debug("Polling delinea secrets for changes", "secretCount", len(snapshots))
	changed := make(map[string]bool)
	markFalse := func(id string) { changed[id] = false }
	markTrue := func(id string) {
		if prev, ok := changed[id]; ok && !prev {
			return // failure is sticky
		}
		changed[id] = true
	}

	for _, s := range snapshots {
		current, err := d.fetch(s.body)
		if err != nil {
			d.logger.Error("Failed to retrieve delinea secret during polling", "ref", s.body, "error", err)
			d.mu.Lock()
			cached, ok := d.usedVars[s.body]
			ids := make([]string, 0, len(cached.policyIDs))
			if ok {
				for id := range cached.policyIDs {
					ids = append(ids, id)
				}
			}
			d.mu.Unlock()
			for _, id := range ids {
				markFalse(id)
			}
			continue
		}
		if current != s.value {
			d.logger.Info("Detected changed delinea secret", "ref", s.body)
			d.mu.Lock()
			ids := []string{}
			if cached, ok := d.usedVars[s.body]; ok {
				cached.Value = current
				d.usedVars[s.body] = cached
				for id := range cached.policyIDs {
					ids = append(ids, id)
				}
			}
			d.mu.Unlock()
			for _, id := range ids {
				markTrue(id)
			}
		}
	}

	if len(changed) > 0 {
		d.logger.Info("Calling update callback for changed delinea secrets", "policyCount", len(changed))
		d.callback(changed)
	}
}

// RegisterUpdatePoliciesCallback registers the policy-reapply callback.
func (d *delineaManager) RegisterUpdatePoliciesCallback(callback func(map[string]bool)) {
	d.callback = callback
}

// SolvePolicySecrets processes a policy payload and replaces ${delinea://...}
// references with the resolved secret value.
func (d *delineaManager) SolvePolicySecrets(payload config.PolicyPayload) (config.PolicyPayload, error) {
	newPayload := payload
	processed, err := processValue(payload.Data, "delinea", payload.ID, d.resolveBody)
	if err != nil {
		return payload, err
	}
	newPayload.Data = processed
	return newPayload, nil
}

// resolveBody parses a ${delinea://<body>} placeholder and returns the value.
// Grammar:
//
//	id/<numeric-id>/<field-slug>
//	path/<folder>/.../<name>/<field-slug>
func (d *delineaManager) resolveBody(body, policyID string) (string, error) {
	d.mu.Lock()
	if cached, ok := d.usedVars[body]; ok {
		cached.policyIDs[policyID] = true
		d.usedVars[body] = cached
		value := cached.Value
		d.mu.Unlock()
		return value, nil
	}
	d.mu.Unlock()

	value, err := d.fetch(body)
	if err != nil {
		return "", err
	}

	d.mu.Lock()
	d.usedVars[body] = cachedSecret{
		Value:     value,
		policyIDs: map[string]bool{policyID: true},
	}
	d.mu.Unlock()
	return value, nil
}

// fetch performs the actual SDK call for a parsed body.
func (d *delineaManager) fetch(body string) (string, error) {
	parts := strings.SplitN(body, "/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid delinea reference %q: expected 'id/<id>/<field>' or 'path/<path>/<field>'", body)
	}
	kind, rest := parts[0], parts[1]

	switch kind {
	case "id":
		idStr, field, ok := strings.Cut(rest, "/")
		if !ok || field == "" {
			return "", fmt.Errorf("invalid delinea id reference %q: expected exactly 'id/<id>/<field>'", body)
		}
		if strings.Contains(field, "/") {
			return "", fmt.Errorf("invalid delinea id reference %q: expected exactly 'id/<id>/<field>' (no extra path segments)", body)
		}
		id, err := strconv.Atoi(idStr)
		if err != nil || id <= 0 {
			return "", fmt.Errorf("invalid delinea numeric id %q in reference %q", idStr, body)
		}
		secret, err := d.client.Secret(id)
		if err != nil {
			return "", fmt.Errorf("delinea: get secret id=%d: %w", id, err)
		}
		return extractField(secret, field, body)

	case "path":
		idx := strings.LastIndex(rest, "/")
		if idx <= 0 || idx == len(rest)-1 {
			return "", fmt.Errorf("invalid delinea path reference %q: expected 'path/<folder>/<name>/<field>'", body)
		}
		secretPath := "/" + rest[:idx]
		field := rest[idx+1:]
		secret, err := d.client.SecretByPath(secretPath)
		if err != nil {
			return "", fmt.Errorf("delinea: get secret path=%q: %w", secretPath, err)
		}
		return extractField(secret, field, body)

	default:
		return "", fmt.Errorf("invalid delinea reference %q: unknown kind %q (want 'id' or 'path')", body, kind)
	}
}

func extractField(secret *server.Secret, field, body string) (string, error) {
	if secret == nil {
		return "", fmt.Errorf("delinea: secret not found for %q", body)
	}
	val, ok := secret.Field(field)
	if !ok {
		return "", fmt.Errorf("delinea: field %q not found in secret for %q", field, body)
	}
	if val == "" {
		return "", fmt.Errorf("delinea: field %q is empty in secret for %q", field, body)
	}
	return val, nil
}

// SolveConfigSecrets resolves ${delinea://...} references in the backends map
// and config-manager struct. Config-time references are NOT tracked for
// later re-apply.
func (d *delineaManager) SolveConfigSecrets(backends map[string]any, cm config.ManagerConfig) (map[string]any, config.ManagerConfig, error) {
	processedBackends, err := processValue(backends, "delinea", "_backends", d.resolveBody)
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
	processedCMMap, err := processValue(cmMap, "delinea", "_config_manager", d.resolveBody)
	if err != nil {
		return backends, cm, fmt.Errorf("failed to process config manager: %w", err)
	}
	newCM, err := mapToStruct[config.ManagerConfig](processedCMMap)
	if err != nil {
		return backends, cm, fmt.Errorf("failed to convert processed map to config manager: %w", err)
	}

	// Do not track updates on config vars
	d.mu.Lock()
	d.usedVars = make(map[string]cachedSecret)
	d.mu.Unlock()
	return newBackends, newCM, nil
}
