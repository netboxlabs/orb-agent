package secretsmgr

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/DelineaXPM/tss-sdk-go/v3/server"

	"github.com/netboxlabs/orb-agent/agent/config"
)

const defaultDelineaTimeout = 60 * time.Second

var _ Manager = (*delineaManager)(nil)

// delineaManager resolves ${delinea://…} placeholders against Delinea Secret Server.
type delineaManager struct {
	pollingBase

	config    config.DelineaManager
	preLogger *slog.Logger
	client    *server.Server
	// timeout bounds one read: the first read's health check and sign-in,
	// the request and its body. Start sets it from config.Timeout when it is
	// zero; tests set it beforehand for a limit shorter than a second.
	timeout time.Duration
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

	d.preLogger.Info("starting secrets manager", "active", "delinea", "server_url", displayURL(d.config.ServerURL), "tenant", d.config.Tenant)

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

	vaultHosts, err := delineaVaultHosts(d.config.AllowedVaultHosts)
	if err != nil {
		return err
	}

	if d.timeout == 0 {
		d.timeout = defaultDelineaTimeout
		if d.config.Timeout != nil && *d.config.Timeout > 0 {
			d.timeout = time.Duration(*d.config.Timeout) * time.Second
		}
	}

	// The SDK refuses plain HTTP to a host other than the loopback unless
	// told otherwise; an http:// server_url is taken as the operator's choice,
	// as it was before the SDK refused it.
	plainHTTP := isPlainHTTP(d.config.ServerURL)
	if plainHTTP {
		d.preLogger.Warn("delinea: Secret Server is reached over plain HTTP; the service user's password and the secrets read cross the network unencrypted")
	}

	sdkCfg := server.Configuration{
		Credentials: server.UserCredential{
			Username: d.config.Username,
			Password: d.config.Password,
		},
		ServerURL:         d.config.ServerURL,
		Tenant:            d.config.Tenant,
		AllowInsecureHTTP: plainHTTP,
		AllowedVaultHosts: strings.Join(vaultHosts, ","),
		// The SDK bounds each attempt by Timeout, and fetch bounds the whole
		// read by the same limit. No retries, as before the SDK learned to
		// retry: a read that fails is read again by the next poll, and a
		// retry, or a Retry-After wait of up to 30 s, would only hold the
		// poll for longer. The SDK still signs in again and resends a read
		// once when the server rejects a token it had kept, within the limit.
		Timeout:        d.timeout,
		DisableRetries: true,
	}

	c, err := server.New(sdkCfg)
	if err != nil {
		return fmt.Errorf("failed to create delinea client: %w", err)
	}
	d.client = c

	d.init(ctx, d.preLogger, "delinea", d.fetch)
	if err := d.startScheduler(d.config.Schedule); err != nil {
		return err
	}
	d.preLogger.Info("secrets manager started", "active", "delinea")
	return nil
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

	ctx, cancel := context.WithTimeout(d.ctx, d.timeout)
	defer cancel()

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
		secret, err := d.client.SecretContext(ctx, id)
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
		secret, err := d.client.SecretByPathContext(ctx, secretPath)
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

// isPlainHTTP reports whether a server_url uses the http scheme, in any case.
func isPlainHTTP(serverURL string) bool {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	return err == nil && strings.EqualFold(u.Scheme, "http")
}

// delineaVaultHosts checks the allowed_vault_hosts entries and returns them
// as the SDK matches them. The SDK compares an entry with the vault URL's host
// as written, port included, and an entry without a port with the host on
// port 443; so "host:443" is given as "host", which trusts the same vault
// whether or not its URL spells out the port. An entry may hold several hosts
// separated by commas, as an ORB_* override sets the list.
func delineaVaultHosts(entries []string) ([]string, error) {
	var hosts []string
	for _, entry := range entries {
		n := len(hosts)
		for _, host := range strings.Split(entry, ",") {
			host = strings.TrimSpace(host)
			if host == "" {
				continue
			}
			if strings.Contains(host, "/") {
				return nil, fmt.Errorf("delinea: allowed_vault_hosts entry %q must be a host or host:port, without a scheme or path", entry)
			}
			if h, port, err := net.SplitHostPort(host); err == nil && port == "443" {
				host = h
			}
			hosts = append(hosts, host)
		}
		if len(hosts) == n {
			return nil, fmt.Errorf("delinea: allowed_vault_hosts entry %q must be a host or host:port, without a scheme or path", entry)
		}
	}
	return hosts, nil
}
