package secretsmgr

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/netboxlabs/orb-agent/agent/config"
)

const (
	defaultDopplerAPIHost = "https://api.doppler.com"
	defaultDopplerTimeout = 60 * time.Second
)

var _ Manager = (*dopplerManager)(nil)

// dopplerManager resolves ${doppler://…} placeholders against Doppler's REST API.
type dopplerManager struct {
	logger     *slog.Logger
	config     config.DopplerManager
	ctx        context.Context
	apiHost    string
	httpClient *http.Client
	usedVars   map[string]cachedSecret
	callback   func(map[string]bool)
}

// Start validates the configuration, resolves env-var placeholders, and
// constructs the HTTP client. It does NOT eagerly authenticate — the first
// real lookup surfaces a 401 with a meaningful error.
func (d *dopplerManager) Start(ctx context.Context) error {
	d.ctx = ctx
	d.usedVars = make(map[string]cachedSecret)

	envFields := []struct {
		name string
		ptr  *string
	}{
		{"token", &d.config.Token},
		{"api_host", &d.config.APIHost},
		{"project", &d.config.Project},
		{"config", &d.config.Config},
	}
	for _, f := range envFields {
		resolved, err := config.ResolveEnv(*f.ptr)
		if err != nil {
			return fmt.Errorf("resolving doppler %s from environment: %w", f.name, err)
		}
		*f.ptr = resolved
	}

	if d.config.Token == "" {
		return fmt.Errorf("doppler: token is required")
	}

	d.apiHost = d.config.APIHost
	if d.apiHost == "" {
		d.apiHost = defaultDopplerAPIHost
	}

	timeout := defaultDopplerTimeout
	if d.config.Timeout != nil && *d.config.Timeout > 0 {
		timeout = time.Duration(*d.config.Timeout) * time.Second
	}
	d.httpClient = &http.Client{Timeout: timeout}

	return nil
}

// RegisterUpdatePoliciesCallback registers the policy-reapply callback.
func (d *dopplerManager) RegisterUpdatePoliciesCallback(callback func(map[string]bool)) {
	d.callback = callback
}

// SolvePolicySecrets is filled in in Task 4.
func (d *dopplerManager) SolvePolicySecrets(payload config.PolicyPayload) (config.PolicyPayload, error) {
	return payload, fmt.Errorf("doppler: SolvePolicySecrets not yet implemented")
}

// SolveConfigSecrets is filled in in Task 5.
func (d *dopplerManager) SolveConfigSecrets(backends map[string]any, cm config.ManagerConfig) (map[string]any, config.ManagerConfig, error) {
	return backends, cm, fmt.Errorf("doppler: SolveConfigSecrets not yet implemented")
}
