package secretsmgr

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/DelineaXPM/tss-sdk-go/v3/server"

	"github.com/netboxlabs/orb-agent/agent/config"
)

var _ Manager = (*delineaManager)(nil)

// delineaManager resolves ${delinea://…} placeholders against Delinea Secret Server.
type delineaManager struct {
	pollingBase

	config    config.DelineaManager
	preLogger *slog.Logger
	client    *server.Server
}

// Start validates the configuration and constructs the SDK client. It does
// NOT eagerly authenticate — the SDK lazy-auths on first secret fetch.
func (d *delineaManager) Start(ctx context.Context) error {
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

	d.init(ctx, d.preLogger, "delinea", d.fetch)
	return d.startScheduler(d.config.Schedule)
}

// fetch performs the actual SDK call for a parsed body.
//
// Grammar:
//
//	id/<numeric-id>/<field-slug>
//	path/<folder>/.../<name>/<field-slug>
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
