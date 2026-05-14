package secretsmgr

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"strings"

	"github.com/DelineaXPM/tss-sdk-go/v3/server"

	"github.com/netboxlabs/orb-agent/agent/config"
)

var _ Manager = (*delineaManager)(nil)

// delineaManager resolves ${delinea://…} placeholders against Delinea Secret Server.
type delineaManager struct {
	logger   *slog.Logger
	config   config.DelineaManager
	ctx      context.Context
	client   *server.Server
	usedVars map[string]cachedSecret
	callback func(map[string]bool)
}

// Start validates the configuration and constructs the SDK client. It does
// NOT eagerly authenticate — the SDK lazy-auths on first secret fetch.
func (d *delineaManager) Start(ctx context.Context) error {
	d.ctx = ctx
	d.usedVars = make(map[string]cachedSecret)

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
		sdkCfg.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // operator opted in via config
	}

	c, err := server.New(sdkCfg)
	if err != nil {
		return fmt.Errorf("failed to create delinea client: %w", err)
	}
	d.client = c

	return nil
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

// SolveConfigSecrets is a stub for Task 6.
func (d *delineaManager) SolveConfigSecrets(backends map[string]any, cm config.ManagerConfig) (map[string]any, config.ManagerConfig, error) {
	return backends, cm, nil
}
