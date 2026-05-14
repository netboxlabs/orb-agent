package secretsmgr

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"strings"

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
	usedVars  map[string]cachedSecret
	callback  func(map[string]bool)
	scheduler gocron.Scheduler
}

// Start validates the configuration and constructs the SDK client. It does
// NOT eagerly authenticate — the SDK lazy-auths on first secret fetch.
func (d *delineaManager) Start(ctx context.Context) error {
	d.ctx = ctx
	d.usedVars = make(map[string]cachedSecret)

	for _, field := range []*string{&d.config.ServerURL, &d.config.Tenant, &d.config.Username, &d.config.Password} {
		resolved, err := config.ResolveEnv(*field)
		if err != nil {
			return fmt.Errorf("resolving delinea credential from environment: %w", err)
		}
		*field = resolved
	}

	if (d.config.ServerURL == "" && d.config.Tenant == "") ||
		(d.config.ServerURL != "" && d.config.Tenant != "") {
		return fmt.Errorf("either server_url or tenant must be set (not both and not neither)")
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
	// NOTE: server.New mutates http.DefaultTransport.TLSClientConfig globally
	// when this field is non-nil. Only set it when the operator explicitly
	// opted into skip_tls.
	if d.config.SkipTLS {
		sdkCfg.TLSClientConfig = &tls.Config{InsecureSkipVerify: d.config.SkipTLS} //nolint:gosec // operator opted in via skip_tls
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
func (d *delineaManager) pollSecrets() {
	if len(d.usedVars) == 0 || d.callback == nil {
		return
	}
	d.logger.Debug("Polling delinea secrets for changes", "secretCount", len(d.usedVars))
	changed := make(map[string]bool)

	for body, cached := range d.usedVars {
		current, err := d.fetch(body)
		if err != nil {
			d.logger.Error("Failed to retrieve delinea secret during polling", "ref", body, "error", err)
			for id := range cached.policyIDs {
				changed[id] = false
			}
			continue
		}
		if current != cached.Value {
			d.logger.Info("Detected changed delinea secret", "ref", body)
			cached.Value = current
			d.usedVars[body] = cached
			for id := range cached.policyIDs {
				changed[id] = true
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
	if cached, ok := d.usedVars[body]; ok {
		cached.policyIDs[policyID] = true
		d.usedVars[body] = cached
		return cached.Value, nil
	}

	value, err := d.fetch(body)
	if err != nil {
		return "", err
	}
	d.usedVars[body] = cachedSecret{
		Value:     value,
		policyIDs: map[string]bool{policyID: true},
	}
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
			return "", fmt.Errorf("invalid delinea id reference %q: expected 'id/<id>/<field>'", body)
		}
		if strings.Contains(field, "/") {
			return "", fmt.Errorf("invalid delinea id reference %q: id may not contain '/'", body)
		}
		var id int
		if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil || id <= 0 {
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
	d.usedVars = make(map[string]cachedSecret)
	return newBackends, newCM, nil
}
