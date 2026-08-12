package secretsmgr

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/DelineaXPM/dsv-sdk-go/v2/vault"

	"github.com/netboxlabs/orb-agent/agent/config"
)

var _ Manager = (*dsvManager)(nil)

// dsvManager resolves ${dsv://…} placeholders against Delinea DevOps Secrets
// Vault (DSV) using the official dsv-sdk-go vault package. DSV is a distinct
// product from Delinea Secret Server (see delineaManager).
type dsvManager struct {
	pollingBase

	config    config.DSVManager
	preLogger *slog.Logger
	client    *vault.Vault
}

// Start resolves env-var placeholders, validates the configuration, and
// constructs the SDK client. It does NOT eagerly authenticate — the SDK lazily
// fetches a token on the first secret lookup, so the first real lookup surfaces
// an auth error.
func (d *dsvManager) Start(ctx context.Context) error {
	envFields := []struct {
		name string
		ptr  *string
	}{
		{"tenant", &d.config.Tenant},
		{"client_id", &d.config.ClientID},
		{"client_secret", &d.config.ClientSecret},
		{"tld", &d.config.TLD},
		{"url_template", &d.config.URLTemplate},
	}
	for _, f := range envFields {
		resolved, err := config.ResolveEnv(*f.ptr)
		if err != nil {
			return fmt.Errorf("resolving dsv %s from environment: %w", f.name, err)
		}
		*f.ptr = resolved
	}

	if d.config.Schedule != nil {
		resolved, err := config.ResolveEnv(*d.config.Schedule)
		if err != nil {
			return fmt.Errorf("resolving dsv schedule from environment: %w", err)
		}
		*d.config.Schedule = resolved
	}

	d.preLogger.Info("starting secrets manager", "active", "dsv", "tenant", d.config.Tenant, "tld", d.config.TLD)

	if d.config.Tenant == "" {
		return fmt.Errorf("dsv: tenant is required")
	}
	if d.config.ClientID == "" {
		return fmt.Errorf("dsv: client_id is required")
	}
	if d.config.ClientSecret == "" {
		return fmt.Errorf("dsv: client_secret is required")
	}

	cfg := vault.Configuration{
		Credentials: vault.ClientCredential{
			ClientID:     d.config.ClientID,
			ClientSecret: d.config.ClientSecret,
		},
		Tenant: d.config.Tenant,
	}
	// Leave TLD/URLTemplate unset when empty so the SDK applies its defaults
	// ("com" and https://%s.secretsvaultcloud.%s/v1/%s%s respectively).
	if d.config.TLD != "" {
		cfg.TLD = d.config.TLD
	}
	if d.config.URLTemplate != "" {
		cfg.URLTemplate = d.config.URLTemplate
	}

	client, err := vault.New(cfg)
	if err != nil {
		return fmt.Errorf("dsv: failed to create client: %w", err)
	}
	d.client = client

	d.init(ctx, d.preLogger, "dsv", d.fetch)
	if err := d.startScheduler(d.config.Schedule); err != nil {
		return err
	}
	d.preLogger.Info("secrets manager started", "active", "dsv")
	return nil
}

// fetch performs the SDK Secret lookup for a parsed placeholder body.
//
// Grammar:
//
//	<secret-path>/<field-key>
//
// The body is split on its last "/": everything before is the DSV secret path,
// and the final segment is a key inside the secret's Data map.
func (d *dsvManager) fetch(body string) (string, error) {
	// The SDK caches its bearer token in the process-global DSV_AT env var,
	// which backend subprocesses inherit. Drop it after every call.
	defer os.Unsetenv("DSV_AT")

	idx := strings.LastIndex(body, "/")
	if idx <= 0 || idx == len(body)-1 {
		return "", fmt.Errorf("invalid dsv reference %q: expected '<secret-path>/<field-key>'", body)
	}
	path := body[:idx]
	field := body[idx+1:]

	secret, err := d.client.Secret(path)
	if err != nil {
		return "", fmt.Errorf("dsv: get secret path=%q: %w", path, err)
	}
	if secret == nil {
		return "", fmt.Errorf("dsv: secret not found for %q", body)
	}

	raw, ok := secret.Data[field]
	if !ok {
		return "", fmt.Errorf("dsv: field %q not found in secret %q", field, body)
	}
	val, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("dsv: field %q is not a string in secret %q", field, body)
	}
	if val == "" {
		return "", fmt.Errorf("dsv: field %q is empty in secret %q", field, body)
	}
	return val, nil
}
