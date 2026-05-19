package secretsmgr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/netboxlabs/orb-agent/agent/config"
)

const (
	defaultCyberArkTimeoutUnit = time.Second
	defaultCyberArkTimeout     = 60 * time.Second
)

var _ Manager = (*cyberarkManager)(nil)

// cyberarkManager resolves ${cyberark://…} placeholders against the CyberArk
// CCP REST endpoint (/AIMWebService/api/Accounts).
type cyberarkManager struct {
	pollingBase

	config     config.CyberArkManager
	preLogger  *slog.Logger
	baseURL    string
	httpClient *http.Client
}

// Start validates configuration, builds the TLS-aware HTTP client, and wires
// pollingBase. It does NOT eagerly authenticate; the first real lookup
// surfaces a 401/403 with a meaningful error.
func (c *cyberarkManager) Start(ctx context.Context) error {
	envFields := []struct {
		name string
		ptr  *string
	}{
		{"url", &c.config.URL},
		{"app_id", &c.config.AppID},
		{"reason", &c.config.Reason},
		{"ca_bundle", &c.config.CABundle},
		{"client_cert", &c.config.ClientCert},
		{"client_key", &c.config.ClientKey},
	}
	for _, f := range envFields {
		resolved, err := config.ResolveEnv(*f.ptr)
		if err != nil {
			return fmt.Errorf("resolving cyberark %s from environment: %w", f.name, err)
		}
		*f.ptr = resolved
	}

	if c.config.URL == "" {
		return fmt.Errorf("cyberark: url is required")
	}
	if c.config.AppID == "" {
		return fmt.Errorf("cyberark: app_id is required")
	}
	parsedURL, err := url.Parse(c.config.URL)
	if err != nil {
		return fmt.Errorf("cyberark: url %q does not parse: %w", c.config.URL, err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("cyberark: url %q must use http or https (got scheme %q)", c.config.URL, parsedURL.Scheme)
	}
	c.baseURL = strings.TrimRight(c.config.URL, "/")

	if (c.config.ClientCert == "") != (c.config.ClientKey == "") {
		return fmt.Errorf("cyberark: client_cert and client_key must both be set or both empty")
	}

	tlsCfg := &tls.Config{InsecureSkipVerify: c.config.SkipTLSVerify} //nolint:gosec // operator opt-in
	if c.config.SkipTLSVerify {
		c.preLogger.Warn("cyberark: TLS peer verification disabled via skip_tls_verify")
	}

	if c.config.CABundle != "" {
		pemBytes, err := os.ReadFile(c.config.CABundle)
		if err != nil {
			return fmt.Errorf("cyberark: read ca_bundle %q: %w", c.config.CABundle, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			// AppendCertsFromPEM silently ignores junk; fail when the file
			// has no usable PEM blocks at all.
			if !containsPEMBlock(pemBytes) {
				return fmt.Errorf("cyberark: ca_bundle %q contains no PEM blocks", c.config.CABundle)
			}
		}
		tlsCfg.RootCAs = pool
	}

	if c.config.ClientCert != "" {
		cert, err := tls.LoadX509KeyPair(c.config.ClientCert, c.config.ClientKey)
		if err != nil {
			return fmt.Errorf("cyberark: load client cert/key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	timeout := defaultCyberArkTimeout
	if c.config.Timeout != nil && *c.config.Timeout > 0 {
		timeout = time.Duration(*c.config.Timeout) * defaultCyberArkTimeoutUnit
	}
	c.httpClient = &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}

	// pollingBase wiring + scheduler are added in Task 5 once fetch exists.
	_ = ctx
	return nil
}

// containsPEMBlock returns true if bytes contain at least one valid PEM
// block.
func containsPEMBlock(b []byte) bool {
	block, _ := pem.Decode(b)
	return block != nil
}
