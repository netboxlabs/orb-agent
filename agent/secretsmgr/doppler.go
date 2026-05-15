package secretsmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
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

// parseBody splits a placeholder body into (project, config, name) according
// to the two supported grammars:
//
//	<name>                                — uses configured defaults
//	<project>/<config>/<name>             — fully qualified
//
// Returns an error for any other shape, or for short-form bodies when no
// defaults are configured.
func (d *dopplerManager) parseBody(body string) (project, cfg, name string, err error) {
	if body == "" {
		return "", "", "", fmt.Errorf("invalid doppler reference: empty body")
	}
	parts := strings.Split(body, "/")
	switch len(parts) {
	case 1:
		if d.config.Project == "" || d.config.Config == "" {
			return "", "", "", fmt.Errorf("invalid doppler reference %q: short form requires project and config defaults in the agent config", body)
		}
		return d.config.Project, d.config.Config, parts[0], nil
	case 3:
		if parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return "", "", "", fmt.Errorf("invalid doppler reference %q: project, config, and name must all be non-empty", body)
		}
		return parts[0], parts[1], parts[2], nil
	default:
		return "", "", "", fmt.Errorf("invalid doppler reference %q: expected '<name>' or '<project>/<config>/<name>'", body)
	}
}

type dopplerSecretResponse struct {
	Name  string `json:"name"`
	Value struct {
		Raw      string `json:"raw"`
		Computed string `json:"computed"`
	} `json:"value"`
	Messages []string `json:"messages,omitempty"`
}

// fetch performs the single-secret REST call for the given placeholder body.
func (d *dopplerManager) fetch(body string) (string, error) {
	project, cfg, name, err := d.parseBody(body)
	if err != nil {
		return "", err
	}

	u, err := url.Parse(d.apiHost + "/v3/configs/config/secret")
	if err != nil {
		return "", fmt.Errorf("doppler: bad api_host %q: %w", d.apiHost, err)
	}
	q := u.Query()
	q.Set("project", project)
	q.Set("config", cfg)
	q.Set("name", name)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(d.ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("doppler: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+d.config.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("doppler: get secret %q: %w", body, err)
	}
	defer func() { _ = resp.Body.Close() }()

	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("doppler: secret not found: %s", body)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("doppler: get secret %q: HTTP %d: %s", body, resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var parsed dopplerSecretResponse
	if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
		return "", fmt.Errorf("doppler: decode response for %q: %w", body, err)
	}
	if parsed.Value.Computed == "" {
		return "", fmt.Errorf("doppler: computed value is empty for %s", body)
	}
	return parsed.Value.Computed, nil
}
